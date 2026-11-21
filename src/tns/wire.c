/* The replay corpus's recorder and deterministic mode (#396); see wire.h.
 * Built only with the `wire_corpus` option.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wire.h"

#include <openssl/rand.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netcompat.h"

#ifndef SEER_WIRE_CORPUS
#error "wire.c is built only with the wire_corpus option"
#endif

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static FILE *rec;
static unsigned next_id;
static uint64_t rng = 0x5EE2DBC0FFEE2026ULL; /* the fixed seed */

static void open_record(void)
{
  const char *path = getenv("SEER_WIRE_RECORD");
  if (path == NULL || path[0] == '\0')
    return;
  rec = fopen(path, "a");
  if (rec != NULL)
    fprintf(rec, "# SeerODBC wire record (#396)\n");
}

int seer_wire_replaying(void);

int seer_wire_active(void)
{
  pthread_once(&once, open_record);
  return rec != NULL || seer_wire_replaying();
}

/* splitmix64: a repeatable stream, not a secure one - only test builds. */
static uint64_t next_random(void)
{
  uint64_t z = (rng += 0x9E3779B97F4A7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

int seer_wire_rand(unsigned char *buf, int n)
{
  if (!seer_wire_active())
    return RAND_bytes(buf, n);
  pthread_mutex_lock(&mu);
  for (int i = 0; i < n; i += 8) {
    uint64_t v = next_random();
    for (int k = 0; k < 8 && i + k < n; k++)
      buf[i + k] = (unsigned char)(v >> (8 * k));
  }
  pthread_mutex_unlock(&mu);
  return 1;
}

long seer_wire_pid(void)
{
  return seer_wire_active() ? 4242L : (long)getpid();
}

int seer_wire_hostname(char *buf, size_t n)
{
  if (!seer_wire_active())
    return gethostname(buf, (int)n);
  snprintf(buf, n, "seer-corpus");
  return 0;
}

const char *seer_wire_os_user(void)
{
  return seer_wire_active() ? "seer" : NULL;
}

static void put_hex(const char *dir, unsigned id, const void *buf, size_t len)
{
  const unsigned char *p = buf;
  fprintf(rec, "%s %u %zu\n", dir, id, len);
  for (size_t i = 0; i < len; i++)
    fprintf(rec, "%02x", p[i]);
  fputc('\n', rec);
}

unsigned seer_wire_connect(const char *host, uint16_t port, int ok)
{
  if (!seer_wire_active())
    return 0;
  pthread_mutex_lock(&mu);
  unsigned id = ++next_id;
  fprintf(rec, "CONNECT %u %s:%u %s\n", id, host, (unsigned)port, ok ? "ok" : "refused");
  fflush(rec);
  pthread_mutex_unlock(&mu);
  return id;
}

void seer_wire_sent(unsigned id, const void *buf, size_t len)
{
  if (id == 0 || rec == NULL)
    return;
  pthread_mutex_lock(&mu);
  put_hex("C2S", id, buf, len);
  fflush(rec);
  pthread_mutex_unlock(&mu);
}

void seer_wire_received(unsigned id, const void *buf, size_t len)
{
  if (id == 0 || rec == NULL)
    return;
  pthread_mutex_lock(&mu);
  put_hex("S2C", id, buf, len);
  fflush(rec);
  pthread_mutex_unlock(&mu);
}

void seer_wire_event(unsigned id, const char *what)
{
  if (id == 0 || rec == NULL)
    return;
  pthread_mutex_lock(&mu);
  fprintf(rec, "%s %u\n", what, id);
  fflush(rec);
  pthread_mutex_unlock(&mu);
}

/* ------------------------------------------------------------------ replay */

/* One recorded event: a connect (with its address and outcome), the bytes
 * sent or received, or a marker (RFAIL, WAIT0, OOB, CLOSE). */
typedef enum { EV_CONNECT, EV_C2S, EV_S2C, EV_RFAIL, EV_WAIT0, EV_OOB, EV_CLOSE } EvKind;
typedef struct {
  EvKind kind;
  unsigned id;
  size_t len;
  unsigned char *data; /* C2S / S2C bytes; CONNECT: "host:port" */
  int ok;              /* CONNECT: 1 ok, 0 refused */
} Ev;

static pthread_once_t replay_once = PTHREAD_ONCE_INIT;
static Ev *evs;
static size_t nevs;
static size_t next_connect; /* the next CONNECT to take, in file order */
static size_t *conn_pos;    /* per connection id: its next event */
static size_t *conn_off;    /* per connection id: bytes taken of a partly read S2C */
static unsigned max_id;
static int replay_bad; /* a difference was found: the replay no longer holds */
static const char *replay_path;

static int hexval(int c)
{
  return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static void load_replay(void)
{
  replay_path = getenv("SEER_WIRE_REPLAY");
  if (replay_path == NULL || replay_path[0] == '\0')
    return;
  FILE *f = fopen(replay_path, "r");
  if (f == NULL) {
    fprintf(stderr, "seerodbc: wire replay: can't open %s\n", replay_path);
    replay_bad = 1;
    return;
  }
  char *line = NULL;
  size_t cap = 0, evcap = 0;
  ssize_t n;
  while ((n = getline(&line, &cap, f)) > 0) {
    if (line[0] == '#' || line[0] == '\n')
      continue;
    char word[16], addr[300], outcome[16];
    unsigned id = 0;
    size_t len = 0;
    Ev e = {0};
    if (sscanf(line, "CONNECT %u %299s %15s", &id, addr, outcome) == 3) {
      e.kind = EV_CONNECT;
      e.data = (unsigned char *)strdup(addr);
      e.ok = strcmp(outcome, "ok") == 0;
    } else if (sscanf(line, "%15s %u %zu", word, &id, &len) == 3 &&
               (strcmp(word, "C2S") == 0 || strcmp(word, "S2C") == 0)) {
      e.kind = word[0] == 'C' ? EV_C2S : EV_S2C;
      e.len = len;
      e.data = malloc(len ? len : 1);
      if (getline(&line, &cap, f) < (ssize_t)(2 * len) || e.data == NULL) {
        replay_bad = 1;
        break;
      }
      for (size_t i = 0; i < len; i++)
        e.data[i] = (unsigned char)(hexval(line[2 * i]) << 4 | hexval(line[2 * i + 1]));
    } else if (sscanf(line, "%15s %u", word, &id) == 2) {
      e.kind = strcmp(word, "RFAIL") == 0   ? EV_RFAIL
               : strcmp(word, "WAIT0") == 0 ? EV_WAIT0
               : strcmp(word, "OOB") == 0   ? EV_OOB
                                            : EV_CLOSE;
    } else {
      continue;
    }
    e.id = id;
    if (id > max_id)
      max_id = id;
    if (nevs == evcap) {
      evcap = evcap ? 2 * evcap : 4096;
      Ev *ne = realloc(evs, evcap * sizeof *ne);
      if (ne == NULL) {
        replay_bad = 1;
        break;
      }
      evs = ne;
    }
    evs[nevs++] = e;
  }
  free(line);
  fclose(f);
  conn_pos = calloc((size_t)max_id + 1, sizeof *conn_pos);
  conn_off = calloc((size_t)max_id + 1, sizeof *conn_off);
}

int seer_wire_replaying(void)
{
  pthread_once(&replay_once, load_replay);
  return replay_path != NULL && replay_path[0] != '\0';
}

/* A difference from the record: reported once, and the replay fails from
 * here on - a recording is only replayed while every send matches it. */
static SeerStatus differs(unsigned id, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static SeerStatus differs(unsigned id, const char *fmt, ...)
{
  if (!replay_bad) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "seerodbc: wire replay differs, connection %u: ", id);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
  }
  replay_bad = 1;
  return SEER_EIO;
}

/* The connection's next event, past those of other connections. */
static Ev *next_of(unsigned id)
{
  if (id == 0 || id > max_id)
    return NULL;
  size_t i = conn_pos[id];
  while (i < nevs && evs[i].id != id)
    i++;
  conn_pos[id] = i;
  return i < nevs ? &evs[i] : NULL;
}

static void take(unsigned id)
{
  conn_pos[id]++;
  conn_off[id] = 0;
}

SeerStatus seer_wire_replay_connect(const char *host, uint16_t port, unsigned *id, char *err,
                                    size_t errlen)
{
  pthread_mutex_lock(&mu);
  while (next_connect < nevs && evs[next_connect].kind != EV_CONNECT)
    next_connect++;
  char want[300];
  snprintf(want, sizeof want, strchr(host, ':') ? "%s:%u" : "%s:%u", host, (unsigned)port);
  SeerStatus st;
  if (replay_bad || next_connect >= nevs) {
    st = differs(0, "a connect to %s the record doesn't have", want);
  } else {
    Ev *e = &evs[next_connect++];
    if (strcmp((const char *)e->data, want) != 0) {
      st = differs(e->id, "connect to %s, recorded %s", want, (const char *)e->data);
    } else if (!e->ok) {
      if (err != NULL && errlen > 0)
        snprintf(err, errlen, "connection to %s refused", want);
      st = SEER_EIO;
    } else {
      *id = e->id;
      conn_pos[e->id] = (size_t)(e - evs) + 1;
      st = SEER_OK;
    }
  }
  pthread_mutex_unlock(&mu);
  return st;
}

SeerStatus seer_wire_replay_send(unsigned id, const void *buf, size_t len)
{
  pthread_mutex_lock(&mu);
  SeerStatus st = SEER_OK;
  Ev *e = replay_bad ? NULL : next_of(id);
  if (replay_bad) {
    st = SEER_EIO;
  } else if (e == NULL || e->kind != EV_C2S) {
    st = differs(id, "sent %zu bytes where the record has no send", len);
  } else if (e->len != len || memcmp(e->data, buf, len) != 0) {
    size_t at = 0;
    const unsigned char *p = buf;
    while (at < len && at < e->len && p[at] == e->data[at])
      at++;
    st = differs(id, "event %zu: sent %zu bytes, recorded %zu; first difference at byte %zu",
                 (size_t)(e - evs), len, e->len, at);
  } else {
    take(id);
  }
  pthread_mutex_unlock(&mu);
  return st;
}

SeerStatus seer_wire_replay_recv(unsigned id, void *buf, size_t len)
{
  pthread_mutex_lock(&mu);
  SeerStatus st = SEER_OK;
  unsigned char *p = buf;
  size_t got = 0;
  while (st == SEER_OK && got < len) {
    Ev *e = replay_bad ? NULL : next_of(id);
    if (replay_bad) {
      st = SEER_EIO;
    } else if (e != NULL && e->kind == EV_RFAIL && got == 0) {
      take(id); /* the read failed (or timed out) live too */
      st = SEER_EIO;
    } else if (e == NULL || e->kind != EV_S2C) {
      st = differs(id, "read %zu bytes where the record has %s", len,
                   e == NULL ? "nothing more" : "no reply");
    } else {
      size_t n = e->len - conn_off[id];
      if (n > len - got)
        n = len - got;
      memcpy(p + got, e->data + conn_off[id], n);
      got += n;
      conn_off[id] += n;
      if (conn_off[id] == e->len)
        take(id);
    }
  }
  pthread_mutex_unlock(&mu);
  return st;
}

int seer_wire_replay_wait(unsigned id)
{
  pthread_mutex_lock(&mu);
  Ev *e = next_of(id);
  int ready = 1;
  if (e != NULL && e->kind == EV_WAIT0) {
    take(id); /* nothing came in time, live */
    ready = 0;
  }
  pthread_mutex_unlock(&mu);
  return ready;
}

SeerStatus seer_wire_replay_oob(unsigned id)
{
  pthread_mutex_lock(&mu);
  Ev *e = replay_bad ? NULL : next_of(id);
  SeerStatus st = SEER_OK;
  if (e != NULL && e->kind == EV_OOB)
    take(id);
  else if (!replay_bad)
    st = differs(id, "a break the record doesn't have");
  else
    st = SEER_EIO;
  pthread_mutex_unlock(&mu);
  return st;
}

void seer_wire_replay_close(unsigned id)
{
  pthread_mutex_lock(&mu);
  Ev *e = next_of(id);
  if (e != NULL && e->kind == EV_CLOSE)
    take(id);
  pthread_mutex_unlock(&mu);
}

int seer_wire_replay_failed(void)
{
  return replay_bad;
}
