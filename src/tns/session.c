/* Protocol core - connection and statement lifecycle.
 *
 * Implements the TNS connection phase (PROTOCOL.md §2): build a TNS_CONNECT
 * with the fixed 58-byte header and a connect descriptor, send it, and react
 * to the server's reply - ACCEPT (negotiate SDU), REDIRECT (reconnect and
 * retry), RESEND (resend), or REFUSE (surface the error). This reaches the
 * point of an accepted TNS session; the TTC protocol negotiation and O5LOGON
 * authentication that follow (PROTOCOL.md §3-4) are the next M1 increment, so
 * seer_connect currently returns SEER_ENOTIMPL once the handshake succeeds.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "seer/seertns.h"

#include "ano.h"
#include "conn.h"
#include "log.h"
#include "netcompat.h" /* gethostname(): <unistd.h> on POSIX, Winsock on Windows */
#include "wire.h"      /* the host name and OS user a connect sends (#396) */
#include "packet.h"
#include "reader.h"
#include "tns_consts.h"
#include "transport.h"
#include "ttc.h"
#include "writer.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <pwd.h>
#endif

/* TNS_CONNECT fixed-header constants (PROTOCOL.md §2.1). */
#define TNS_VERSION_DESIRED 0x013F /* 319 - large-SDU handshake (#155) */
/* A negotiated version >= 315 switches to the 4-byte ("large") packet length
 * (§1.1); older servers (10g/11g cap at 313, 9i at 312) stay on legacy framing. */
#define TNS_VERSION_MIN_LARGE_SDU 315
/* Lowest-compatible version we accept. Kept low (300) so pre-11g servers can
 * settle at their own ceiling - Oracle 9i's max is 312, so a 313 floor would make
 * it reject the CONNECT. Newer servers still negotiate up to TNS_VERSION_DESIRED. */
#define TNS_VERSION_MIN_COMPAT 0x012C /* 300 */
#define TNS_GSO_OPTIONS 0x0401        /* global service options (319 handshake) */
#define TNS_SDU_DEFAULT 0x2000        /* 8192 */
#define TNS_PROTO_CHARS 0x4F98
#define TNS_HW_BYTE_ORDER 0x0001 /* big-endian */
/* Connect-data offset from the packet start (8-byte TNS header + 66-byte body).
 * The 319 body is the legacy 50 bytes plus a 16-byte trailer (large SDU/TDU +
 * two connect-flag words) that sits before the connect descriptor (#155). */
#define TNS_CONNECT_DATA_OFF 74
/* The most connect data a server reads from the CONNECT packet itself. */
#define TNS_MAX_CONNECT_DATA 230
/* ANO-capable (§33.1). The legacy 0x8484 ("disabled") makes an ANO server RESET
 * after negotiation round 1; advertising 0x0101 commits us to running the ANO
 * negotiation (gated on the accept's ACFL flags) before PRO. */
#define TNS_ANO_FLAGS 0x0101
#define TNS_CONNECT_HDR_RSVD 24 /* zero padding to reach the 50-byte body */

#define MAX_REDIRECTS 5
#define MAX_RESENDS 3

/* struct SeerConn lives in conn.h (shared with ttc.c). */

/* ------------------------------------------------------------------ helpers */

void seer_client_os_user(char *out, size_t n)
{
  out[0] = '\0';
  const char *fixed = seer_wire_os_user(); /* a corpus run's (#396) */
  if (fixed != NULL) {
    snprintf(out, n, "%s", fixed);
    return;
  }
#ifndef _WIN32
  struct passwd pw, *pwres = NULL;
  char pwbuf[1024];
  if (getpwuid_r(geteuid(), &pw, pwbuf, sizeof pwbuf, &pwres) == 0 && pwres != NULL &&
      pwres->pw_name != NULL)
    snprintf(out, n, "%s", pwres->pw_name);
#endif
  if (!out[0]) {
    const char *e = getenv("USER");
    if (e == NULL || !e[0])
      e = getenv("LOGNAME");
    if (e == NULL || !e[0])
      e = getenv("USERNAME"); /* Windows */
    snprintf(out, n, "%s", (e != NULL && e[0]) ? e : "unknown");
  }
}

/* Make `v` safe as a CID value, as python-oracledb does: a character outside
 * [A-Za-z0-9<>/,.:;-_$+*#&!%?@] becomes '?'. A '(' ')' or '=' would end the
 * field; a host or account name can hold any of them. */
static void cid_sanitize(char *v)
{
  static const char ok[] = "<>/,.:;-_$+*#&!%?@";
  for (char *c = v; *c; c++) {
    unsigned char u = (unsigned char)*c;
    bool alnum = (u >= '0' && u <= '9') || (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z');
    if (!alnum && strchr(ok, *c) == NULL)
      *c = '?';
  }
}

/* Build the TNS_CONNECT body (everything after the 8-byte TNS header): the
 * 50-byte fixed header followed by the connect descriptor string. */
static SeerStatus build_connect_body(const SeerConnParams *p, SeerWriter *w)
{
  char hostname[256];
  if (seer_wire_hostname(hostname, sizeof hostname - 1) != 0)
    strcpy(hostname, "localhost");
  hostname[sizeof hostname - 1] = '\0';
  cid_sanitize(hostname);

  /* CID USER is the client's OS account, as python-oracledb writes it - not
   * the database user. 8i and 9i take v$session.osuser from it before the
   * login's (seerdb PROTOCOL.md §19.8.1): with the database user there, both
   * reported that as the OS user. 10g+ take AUTH_SID over it. */
  char osuser[128];
  seer_client_os_user(osuser, sizeof osuser);
  cid_sanitize(osuser);
  const char *proto = p->use_tls ? "TCPS" : "TCP";
  /* DRCP: route to the connection broker's pooled server (#130). */
  const char *pooled = ((p->cclass && p->cclass[0]) || p->purity) ? "(SERVER=POOLED)" : "";

  /* Address by SID (older servers, e.g. 9i) if given, else by SERVICE_NAME. */
  char target[288];
  if (p->sid && p->sid[0])
    snprintf(target, sizeof target, "(SID=%s)", p->sid);
  else
    snprintf(target, sizeof target, "(SERVICE_NAME=%s)", p->service_name ? p->service_name : "");

  /* EXPIRE_TIME opens the DESCRIPTION, where python-oracledb 26.1 writes it. */
  char expire[32] = "";
  if (p->expire_time > 0)
    snprintf(expire, sizeof expire, "(EXPIRE_TIME=%d)", p->expire_time);

  char desc[1024];
  int dlen = snprintf(desc, sizeof desc,
                      "(DESCRIPTION="
                      "%s"
                      "(CONNECT_DATA="
                      "%s"
                      "%s"
                      "(CID=(PROGRAM=seerodbc)(HOST=%s)(USER=%s)))"
                      "(ADDRESS=(PROTOCOL=%s)(HOST=%s)(PORT=%u)))",
                      expire, target, pooled, hostname, osuser, proto, p->host ? p->host : "",
                      (unsigned)(p->port ? p->port : 1521));
  if (dlen < 0 || (size_t)dlen >= sizeof desc)
    return SEER_EPARAM;

  if (!seer_writer_init(w, 64 + (size_t)dlen))
    return SEER_ENOMEM;

  seer_writer_u16(w, TNS_VERSION_DESIRED);    /* off  0: protocol version     */
  seer_writer_u16(w, TNS_VERSION_MIN_COMPAT); /* off  2: lowest compatible    */
  seer_writer_u16(w, TNS_GSO_OPTIONS);        /* off  4: global svc options   */
  seer_writer_u16(w, TNS_SDU_DEFAULT);        /* off  6: SDU                  */
  seer_writer_u16(w, TNS_SDU_DEFAULT);        /* off  8: TDU (= SDU at v319)  */
  seer_writer_u16(w, TNS_PROTO_CHARS);        /* off 10: proto characteristics*/
  seer_writer_u16(w, 0x0000);                 /* off 12: max packets before ACK*/
  seer_writer_u16(w, TNS_HW_BYTE_ORDER);      /* off 14: hardware byte order  */
  seer_writer_u16(w, 0x0000);                 /* off 16: connect data length  */
  seer_writer_u16(w, TNS_CONNECT_DATA_OFF);   /* off 18: connect data offset  */
  seer_writer_u32(w, 0x00000000);             /* off 20: max recv connect data*/
  seer_writer_u16(w, TNS_ANO_FLAGS);          /* off 24: ANO flags            */
  for (int i = 0; i < TNS_CONNECT_HDR_RSVD; i++)
    seer_writer_u8(w, 0x00); /* off 26..50: reserved         */
  /* 319-era trailer (off 50..66): 32-bit SDU + TDU, then connect_flags_1 (0)
   * and connect_flags_2 (1 = OOB check), per the reference client (#155). */
  seer_writer_u32(w, TNS_SDU_DEFAULT); /* off 50: large SDU (ub4)      */
  seer_writer_u32(w, TNS_SDU_DEFAULT); /* off 54: large TDU (ub4)      */
  seer_writer_u32(w, 0x00000000);      /* off 58: connect flags 1      */
  seer_writer_u32(w, 0x00000001);      /* off 62: connect flags 2      */

  seer_writer_bytes(w, desc, (size_t)dlen); /* off 66: connect descriptor   */
  seer_writer_patch_u16(w, 16, (uint16_t)dlen);

  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    return SEER_ENOMEM;
  }
  return SEER_OK;
}

/* Send the CONNECT. A server reads at most TNS_MAX_CONNECT_DATA bytes of
 * connect data from the CONNECT packet itself; given more, it waits for data
 * that never comes and the connect hangs (10g..23ai alike). A longer
 * descriptor goes in a DATA packet (data flags 0) straight after the CONNECT,
 * which keeps its stated length and offset but ends where the descriptor
 * would start - as the reference client does (seerdb#1768). Nothing is
 * negotiated yet, so both go in the legacy 16-bit envelope. */
static SeerStatus send_connect(SeerTransport *t, const SeerWriter *body)
{
  const size_t head = TNS_CONNECT_DATA_OFF - TNS_HEADER_LEN;
  if (body->len - head <= TNS_MAX_CONNECT_DATA)
    return seer_packet_send(t, TNS_PT_CONNECT, body->buf, body->len);

  SeerStatus st = seer_packet_send(t, TNS_PT_CONNECT, body->buf, head);
  if (st != SEER_OK)
    return st;
  size_t dlen = body->len - head;
  uint8_t *data = malloc(2 + dlen);
  if (data == NULL)
    return SEER_ENOMEM;
  data[0] = 0x00; /* data flags */
  data[1] = 0x00;
  memcpy(data + 2, body->buf + head, dlen);
  st = seer_packet_send(t, TNS_PT_DATA, data, 2 + dlen);
  free(data);
  return st;
}

/* Copy the value of `key` (e.g. "(HOST=") from `s` up to the next ')'. */
static bool find_kv(const char *s, const char *key, char *out, size_t out_sz)
{
  const char *p = strstr(s, key);
  if (p == NULL)
    return false;
  p += strlen(key);
  size_t i = 0;
  while (*p != '\0' && *p != ')' && i + 1 < out_sz)
    out[i++] = *p++;
  out[i] = '\0';
  return i > 0;
}

/* Pull HOST/PORT out of the ADDRESS block of a REDIRECT descriptor. */
static bool parse_redirect(const uint8_t *body, size_t len, char *host, size_t host_sz,
                           uint16_t *port)
{
  if (body == NULL || len == 0)
    return false;

  const uint8_t *s = body;
  size_t n = len;
  if (n >= 2 && s[0] != '(') { /* optional 2-byte data-length prefix */
    s += 2;
    n -= 2;
  }

  char *str = malloc(n + 1);
  if (str == NULL)
    return false;
  memcpy(str, s, n);
  str[n] = '\0';

  /* Scope to ADDRESS so we don't grab the client HOST echoed in CID. */
  const char *scope = strstr(str, "(ADDRESS=");
  if (scope == NULL)
    scope = str;

  char portbuf[16];
  bool ok =
      find_kv(scope, "(HOST=", host, host_sz) && find_kv(scope, "(PORT=", portbuf, sizeof portbuf);
  if (ok)
    *port = (uint16_t)atoi(portbuf);

  free(str);
  return ok;
}

/* Log a listener's REFUSE, and put its error on the connection: the
 * descriptor it carries names the code, "(ERR=12514)", and no message text,
 * so the connection gets "ORA-12514: the listener refused the connection". */
static void log_refuse(SeerConn *conn, const uint8_t *body, size_t len)
{
  if (body == NULL || len < 4) {
    seer_log(SEER_LOG_DEBUG, "TNS: REFUSE (no detail)");
    return;
  }
  size_t errlen = ((size_t)body[2] << 8) | body[3];
  size_t avail = len - 4;
  if (errlen > avail)
    errlen = avail;
  seer_log(SEER_LOG_DEBUG, "TNS: REFUSE: %.*s", (int)errlen, (const char *)(body + 4));
  const char *text = (const char *)(body + 4);
  for (size_t i = 0; i + 5 < errlen; i++) {
    if (memcmp(text + i, "(ERR=", 5) != 0)
      continue;
    long code = 0;
    for (size_t k = i + 5; k < errlen && text[k] >= '0' && text[k] <= '9' && code < 100000; k++)
      code = code * 10 + (text[k] - '0');
    if (code > 0) {
      char m[64];
      snprintf(m, sizeof m, "ORA-%05ld: the listener refused the connection", code);
      char *d = strdup(m);
      if (d != NULL) {
        free(conn->last_error);
        conn->last_error = d;
      }
    }
    return;
  }
}

/* ------------------------------------------------------------- public API */

/* The connection's error text, when there is one to give. */
static void set_conn_error(SeerConn *conn, const char *m)
{
  char *d = m != NULL ? strdup(m) : NULL;
  if (d == NULL)
    return;
  free(conn->last_error);
  conn->last_error = d;
}

/* One address: the TNS handshake, then the login. *accepted says the
 * listener let the connection through (an ACCEPT came), after which another
 * address would give the same answer. */
static SeerStatus connect_address(const SeerConnParams *params, SeerConn **out, char *err,
                                  size_t errlen, bool *accepted)
{
  *accepted = false;

  SeerWriter body;
  SeerStatus st = build_connect_body(params, &body);
  if (st != SEER_OK)
    return st;

  SeerConn *conn = calloc(1, sizeof *conn);
  if (conn == NULL) {
    seer_writer_free(&body);
    return SEER_ENOMEM;
  }
  conn->seq = 1;           /* TTC sequence numbers start at 1 */
  conn->autocommit = true; /* ODBC default */
  conn->lob_inline = params->lob_inline != 0;
  conn->xa = params->xa != 0;

  char cur_host[256];
  snprintf(cur_host, sizeof cur_host, "%s", params->host);
  uint16_t cur_port = params->port ? params->port : 1521;

  int redirects = 0;
  int resends = 0;
  bool ano_gate = false; /* the accept advertised ANO; negotiate before PRO */
  /* The connect / login time limit: 0 is the transport's default (30 s), and
   * "no limit" is the largest bound. */
  int limit_ms = params->connect_timeout_ms < 0 ? 0x7FFFFFFF : params->connect_timeout_ms;

  for (;;) {
    if (conn->t == NULL) {
      char why[320];
      st = seer_transport_connect_diag(cur_host, cur_port, limit_ms, &conn->t, why, sizeof why);
      if (st != SEER_OK) {
        set_conn_error(conn, why[0] ? why : NULL);
        goto fail;
      }
      if (params->expire_time > 0) /* minutes -> seconds; each socket, redirects too */
        seer_transport_set_keepalive(conn->t, params->expire_time * 60);
      /* TCPS: wrap the (possibly redirected) socket in TLS before any TNS
       * bytes flow. The SNI / verified hostname is the host we dialled. */
      if (params->use_tls) {
        st = seer_transport_start_tls(conn->t, cur_host, params->tls_ca, params->tls_verify);
        if (st != SEER_OK) {
          char m[320];
          snprintf(m, sizeof m, "TLS handshake with %s:%u failed", cur_host, (unsigned)cur_port);
          set_conn_error(conn, m);
          goto fail;
        }
      }
    }

    st = send_connect(conn->t, &body);
    if (st != SEER_OK)
      goto fail;

    uint8_t type = 0;
    uint8_t *rbody = NULL;
    size_t rlen = 0;
    st = seer_packet_recv(conn->t, &type, &rbody, &rlen);
    if (st != SEER_OK)
      goto fail;

    if (type == TNS_PT_ACCEPT) {
      SeerReader r;
      seer_reader_init(&r, rbody, rlen);
      conn->version = seer_reader_u16(&r); /* body off 0 */
      /* body off 2: service options; CAN_RECV_ATTENTION (0x0400) says the
       * server takes an out-of-band break (seerdb PROTOCOL.md §25, #224). */
      conn->supports_oob = (seer_reader_u16(&r) & 0x0400) != 0;
      uint16_t legacy_sdu = seer_reader_u16(&r); /* body off 4 (ub2)   */
      /* A >= 315 ("large SDU") accept carries the real negotiated SDU as a
       * ub4 at body offset 24; below that the legacy ub2 at offset 4 is it. */
      conn->sdu = legacy_sdu;
      if (conn->version >= TNS_VERSION_MIN_LARGE_SDU && rlen >= 28) {
        uint32_t large_sdu = (uint32_t)rbody[24] << 24 | (uint32_t)rbody[25] << 16 |
                             (uint32_t)rbody[26] << 8 | (uint32_t)rbody[27];
        if (large_sdu > 0 && large_sdu <= 0xFFFF)
          conn->sdu = (uint16_t)large_sdu;
      }
      /* End-of-response framing (§32/#155): a >= 318 accept carries the
       * extended flags2 ub4 at body offset 33; its HAS_END_OF_RESPONSE bit
       * says the server will honour the EOR cap we opt into at DTY time. */
      if (conn->version >= TNS_VERSION_MIN_OOB_CHECK && rlen >= TNS_ACCEPT_FLAGS2_OFFSET + 4) {
        const uint8_t *f = rbody + TNS_ACCEPT_FLAGS2_OFFSET;
        uint32_t flags2 =
            (uint32_t)f[0] << 24 | (uint32_t)f[1] << 16 | (uint32_t)f[2] << 8 | (uint32_t)f[3];
        conn->supports_eor = (flags2 & TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE) != 0;
      }
      /* ANO gate (§33.1): once we advertised ANO-capable, negotiate iff
       * the accept's ACFL0 (off 14) bit0 is set, bit2 clear, and ACFL1
       * (off 15) bit3 clear. A server that only supports ANO answers with
       * the null algorithm and the session stays plaintext. */
      uint8_t acfl0 = (rlen > 14) ? rbody[14] : 0;
      uint8_t acfl1 = (rlen > 15) ? rbody[15] : 0;
      ano_gate = (acfl0 & 0x01) && !(acfl0 & 0x04) && !(acfl1 & 0x08);
      free(rbody);

      /* The ACCEPT itself is legacy-framed; from here on, a version >= 315
       * server frames every packet with the 4-byte length (§1.1, #155). */
      if (conn->version >= TNS_VERSION_MIN_LARGE_SDU)
        seer_transport_set_large_frames(conn->t, 1);

      seer_log(SEER_LOG_INFO, "TNS: ACCEPT from %s:%u (version=%u, sdu=%u, large=%d, eor=%d)",
               cur_host, cur_port, conn->version, conn->sdu,
               conn->version >= TNS_VERSION_MIN_LARGE_SDU, conn->supports_eor);
      *accepted = true;
      break; /* TNS session established; proceed to TTC negotiation */
    }

    if (type == TNS_PT_RESEND) {
      free(rbody);
      if (++resends > MAX_RESENDS) {
        seer_log(SEER_LOG_ERROR, "TNS: too many RESEND requests");
        st = SEER_EPROTO;
        goto fail;
      }
      seer_log(SEER_LOG_DEBUG, "TNS: RESEND (%d)", resends);
      continue;
    }

    if (type == TNS_PT_REDIRECT) {
      char nh[256];
      uint16_t np = 0;
      bool ok = parse_redirect(rbody, rlen, nh, sizeof nh, &np);
      free(rbody);
      if (!ok) {
        seer_log(SEER_LOG_ERROR, "TNS: REDIRECT could not be parsed");
        st = SEER_EPROTO;
        goto fail;
      }
      if (++redirects > MAX_REDIRECTS) {
        seer_log(SEER_LOG_ERROR, "TNS: too many redirects");
        st = SEER_EPROTO;
        goto fail;
      }
      seer_log(SEER_LOG_INFO, "TNS: REDIRECT -> %s:%u", nh, np);
      seer_transport_close(conn->t);
      conn->t = NULL;
      snprintf(cur_host, sizeof cur_host, "%s", nh);
      cur_port = np;
      continue;
    }

    if (type == TNS_PT_REFUSE) {
      log_refuse(conn, rbody, rlen);
      free(rbody);
      st = SEER_EPROTO;
      goto fail;
    }

    seer_log(SEER_LOG_ERROR, "TNS: unexpected packet type %u during handshake", type);
    free(rbody);
    st = SEER_EPROTO;
    goto fail;
  }

  /* TNS session is up. The connect body is no longer needed. */
  seer_writer_free(&body);

  /* Native network encryption (§33): run the ANO negotiation before PRO. It
   * is plaintext and only activates the per-packet cipher + MAC if the server
   * actually selects an algorithm; a bare-supported server stays plaintext. */
  if (ano_gate) {
    st = seer_ttc_ano_negotiate(conn);
    if (st != SEER_OK) {
      goto fail;
    }
  }

  /* TTC negotiation (PRO/DTY) + session setup, ending at the auth challenge. */
  SeerAuthChallenge challenge;
  st = seer_ttc_login(conn, params, &challenge);
  if (st != SEER_OK) {
    goto fail;
  }

  /* O5LOGON: answer the challenge, send TTI_AUTH, validate the response. */
  st = seer_ttc_authenticate(conn, params, &challenge);
  seer_auth_challenge_free(&challenge);
  if (st != SEER_OK) {
    goto fail;
  }

  /* The connect timeout bounds connecting and logging in, not every later
   * call: a query or a lock wait may take longer than it, and the socket
   * timeout would kill the session mid-reply (EAGAIN -> SEER_EIO). */
  seer_transport_set_io_timeout(conn->t, 0);

  *out = conn;
  return SEER_OK;

fail:
  seer_writer_free(&body);
  /* A read or write that ran out of time: the login timeout expired, waiting
   * for the server (#403). Said so, not as a bare I/O error, so the ODBC
   * shim can report HYT00. */
  if (st == SEER_EIO && conn->t != NULL && seer_transport_timed_out(conn->t)) {
    char m[400];
    int secs = (limit_ms > 0 ? limit_ms : SEER_TRANSPORT_DEFAULT_TIMEOUT_MS) / 1000;
    snprintf(m, sizeof m, "login timed out after %d s waiting for %s:%u", secs, cur_host,
             (unsigned)cur_port);
    set_conn_error(conn, m);
    st = SEER_ETIMEOUT;
  }
  /* Hand back why, before the connection and its error go. */
  if (err != NULL && errlen > 0 && conn->last_error != NULL)
    snprintf(err, errlen, "%s", conn->last_error);
  seer_disconnect(conn);
  return st;
}

/* One address of a HOST list into host / *port: `host`, `host:port` or
 * `[ipv6]:port`; a bare IPv6 literal (two colons or more) is a host. Without a
 * port of its own the address keeps *port. */
static SeerStatus parse_address(const char *a, size_t n, char *host, size_t hostcap, uint16_t *port)
{
  while (n > 0 && (*a == ' ' || *a == '\t'))
    a++, n--;
  while (n > 0 && (a[n - 1] == ' ' || a[n - 1] == '\t'))
    n--;
  const char *h = a, *colon = NULL;
  size_t hn = n;
  if (n > 0 && a[0] == '[') {
    const char *close = memchr(a, ']', n);
    if (close == NULL)
      return SEER_EPARAM;
    h = a + 1;
    hn = (size_t)(close - h);
    size_t rest = n - (size_t)(close + 1 - a);
    if (rest > 0) {
      if (close[1] != ':')
        return SEER_EPARAM;
      colon = close + 1;
    }
  } else {
    const char *c1 = memchr(a, ':', n);
    if (c1 != NULL && memchr(c1 + 1, ':', n - (size_t)(c1 + 1 - a)) == NULL) {
      colon = c1;
      hn = (size_t)(c1 - a);
    }
  }
  if (hn == 0 || hn >= hostcap)
    return SEER_EPARAM;
  memcpy(host, h, hn);
  host[hn] = '\0';
  if (colon != NULL) {
    const char *d = colon + 1, *end = a + n;
    unsigned long v = 0;
    if (d == end)
      return SEER_EPARAM;
    for (; d < end; d++) {
      if (*d < '0' || *d > '9' || (v = v * 10 + (unsigned long)(*d - '0')) > 65535)
        return SEER_EPARAM;
    }
    if (v == 0)
      return SEER_EPARAM;
    *port = (uint16_t)v;
  }
  return SEER_OK;
}

/* Connect-time failover (#201): HOST may list addresses, comma-separated,
 * tried in order. A failure before the listener accepts - no TCP connect, no
 * TLS, a REFUSE such as ORA-12514 - moves on to the next; one after it (a
 * wrong password, an error at login) is the answer, as another address would
 * give the same. With every address failing, the last one's error is. */
SeerStatus seer_connect_diag(const SeerConnParams *params, SeerConn **out, char *err, size_t errlen)
{
  if (err != NULL && errlen > 0)
    err[0] = '\0';
  if (params == NULL || out == NULL || params->host == NULL)
    return SEER_EPARAM;
  *out = NULL;
  /* Sharding keys are not on the thin wire (§37): shard routing is an OCI-only
   * capability below the TTC/TNS protocol, so a non-empty key can't be honoured.
   * Reject up front (accepted for API parity) rather than connect and mislead. */
  if ((params->shardingkey && params->shardingkey[0]) ||
      (params->supershardingkey && params->supershardingkey[0])) {
    seer_log(SEER_LOG_WARNING, "sharding keys are not supported in thin mode (§37): shard "
                               "routing is available only through the OCI-based client");
    return SEER_ENOTIMPL;
  }

  const char *list = params->host;
  SeerStatus st = SEER_EPARAM;
  char tried[1024] = ""; /* "addr: why; " for each address passed over */
  int ntried = 0;
  char local[320];
  if (err == NULL || errlen == 0) {
    err = local;
    errlen = sizeof local;
  }
  for (const char *a = list;;) {
    const char *comma = strchr(a, ',');
    size_t n = comma ? (size_t)(comma - a) : strlen(a);
    char host[256];
    SeerConnParams one = *params;
    one.port = params->port ? params->port : 1521;
    st = parse_address(a, n, host, sizeof host, &one.port);
    if (st != SEER_OK) {
      seer_log(SEER_LOG_ERROR, "connect: bad address '%.*s' in HOST", (int)n, a);
      if (err != NULL && errlen > 0)
        snprintf(err, errlen, "bad address '%.*s' in HOST", (int)n, a);
      return st;
    }
    one.host = host;
    bool accepted = false;
    err[0] = '\0';
    st = connect_address(&one, out, err, errlen, &accepted);
    if (st == SEER_OK || accepted)
      return st;
    /* This address's failure as the list names it: a transport error names
     * its address already, a listener's ORA- refusal is prefixed with it. */
    char this_one[400];
    int w;
    if (!err[0] || strncmp(err, "ORA-", 4) == 0)
      w = snprintf(this_one, sizeof this_one, "%s:%u: %s", host, (unsigned)one.port,
                   err[0] ? err : seer_strerror(st));
    else
      w = snprintf(this_one, sizeof this_one, "%s", err);
    if (w < 0) /* cut short at the buffer is fine; an encoding error leaves it empty */
      this_one[0] = '\0';
    if (comma == NULL) {
      /* Every address failed: name each, the last one's error last (#203). A
       * single address keeps its own text (an ORA- code ODBC reads). */
      if (ntried > 0)
        snprintf(err, errlen, "no address in HOST answered: %s%s", tried, this_one);
      else if (!err[0])
        snprintf(err, errlen, "%s", this_one);
      return st;
    }
    seer_log(SEER_LOG_WARNING, "connect: %s failed, trying the next address", this_one);
    size_t tl = strlen(tried);
    snprintf(tried + tl, sizeof tried - tl, "%s; ", this_one);
    ntried++;
    a = comma + 1;
  }
}

SeerStatus seer_connect(const SeerConnParams *params, SeerConn **out)
{
  return seer_connect_diag(params, out, NULL, 0);
}

void seer_disconnect(SeerConn *conn)
{
  if (conn == NULL)
    return;
  /* Bound the best-effort logoff again, so a dead peer cannot hang it. */
  seer_transport_set_io_timeout(conn->t, -1);
  seer_ttc_logoff(conn); /* best-effort TTI_LOGOFF + EOF on a live session */
  seer_transport_close(conn->t);
  seer_ano_free(conn->ano);
  seer_stmt_cache_clear(conn);
  free(conn->last_error);
  free(conn->tpc_context);
  for (int i = 0; i < conn->n_free_lobs; i++)
    free(conn->free_lobs[i]); /* the session end frees them server-side */
  free(conn->free_lobs);
  free(conn->free_lob_lens);
  free(conn);
}

/* seer_stmt_* live in stmt.c. */

const char *seer_last_error(SeerConn *conn)
{
  return conn ? conn->last_error : NULL;
}

long seer_last_error_offset(SeerConn *conn)
{
  return conn ? conn->last_error_offset : 0;
}

SeerStatus seer_server_version(SeerConn *conn, int version[5])
{
  if (conn == NULL || version == NULL)
    return SEER_EPARAM;
  if (conn->server_release == 0)
    return SEER_ENOTIMPL;
  seer_release_fields(conn->server_release, version);
  return SEER_OK;
}

int seer_max_identifier_length(SeerConn *conn)
{
  return conn != NULL ? (int)conn->max_iden_len : 0;
}

/* Continuous Query Notification (§38): not on the thin wire. CQN needs the server
 * to open a callback connection back to a client-hosted listener, which a
 * pure-protocol request/response client cannot host. Accepted for API parity and
 * rejected with a clear message; see seertns.h. */
static SeerStatus reject_cqn(SeerConn *conn)
{
  /* The feature does not exist on the thin wire, so the answer is ENOTIMPL for
   * any input; record an explanatory message when a connection is available. */
  if (conn != NULL) {
    static const char msg[] = "Continuous Query Notification / server-initiated subscriptions are "
                              "not supported in thin mode (§38): the callback channel is available "
                              "only through the OCI-based client";
    char *copy = malloc(sizeof msg);
    if (copy != NULL) {
      memcpy(copy, msg, sizeof msg);
      free(conn->last_error);
      conn->last_error = copy;
    }
  }
  return SEER_ENOTIMPL;
}

SeerStatus seer_subscribe(SeerConn *conn)
{
  return reject_cqn(conn);
}

SeerStatus seer_unsubscribe(SeerConn *conn)
{
  return reject_cqn(conn);
}

void seer_set_autocommit(SeerConn *conn, int on)
{
  if (conn != NULL)
    conn->autocommit = (on != 0);
}

const char *seer_strerror(SeerStatus status)
{
  switch (status) {
  case SEER_OK:
    return "ok";
  case SEER_ENOTIMPL:
    return "not implemented";
  case SEER_EIO:
    return "I/O error";
  case SEER_EPROTO:
    return "protocol error";
  case SEER_EAUTH:
    return "authentication failed";
  case SEER_ENOMEM:
    return "out of memory";
  case SEER_EPARAM:
    return "invalid parameter";
  case SEER_ENODATA:
    return "no more data";
  case SEER_EDB:
    return "database error";
  case SEER_ETIMEOUT:
    return "timed out";
  }
  return "unknown error";
}
