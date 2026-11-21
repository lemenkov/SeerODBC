/* The replay corpus's hooks (#396): record every byte a connection exchanges,
 * and make the values a client draws itself repeat from run to run, so a
 * recording can be replayed offline byte for byte.
 *
 * Compiled in only with the `wire_corpus` build option (SEER_WIRE_CORPUS),
 * for test builds. Without it every hook below is the plain call it stands
 * for, and a driver holds no recorder and no deterministic path: a fixed
 * "random" stream in a shipped driver would make its logins predictable.
 *
 * With it, the hooks are live only when SEER_WIRE_RECORD names a file:
 * - the client's random bytes (session keys, salts, the ANO Diffie-Hellman
 *   key) come from a fixed seeded stream; the process id, the host name and
 *   the OS user are fixed - each is sent at login, and the server's replies
 *   depend on the keys;
 * - each connection's traffic is appended to the file, in the C2S / S2C
 *   form seerdb's tools/capture_proxy.py writes, tagged with the connection.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_WIRE_H
#define SEER_TNS_WIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef SEER_WIRE_CORPUS

/* Whether the deterministic, recording mode is on (SEER_WIRE_RECORD set). */
int seer_wire_active(void);
/* RAND_bytes, from the fixed stream when active: 1 on success. */
int seer_wire_rand(unsigned char *buf, int n);
/* getpid(), fixed when active. */
long seer_wire_pid(void);
/* gethostname(), fixed when active: 0 on success. */
int seer_wire_hostname(char *buf, size_t n);
/* The fixed OS user, or NULL when not active. */
const char *seer_wire_os_user(void);

/* A connection attempt to host:port and its outcome; returns the
 * connection's id for the events after it (0 when not recording). */
unsigned seer_wire_connect(const char *host, uint16_t port, int ok);
/* Bytes the client sent (C2S) or received (S2C) on connection `id`. */
void seer_wire_sent(unsigned id, const void *buf, size_t len);
void seer_wire_received(unsigned id, const void *buf, size_t len);
/* A read that failed or timed out, a wait that found nothing, an
 * out-of-band break, and the close. */
void seer_wire_event(unsigned id, const char *what);

#else /* the hooks are the calls they stand for */

#include <openssl/rand.h>

#include "netcompat.h" /* gethostname() */
#include <unistd.h>

static inline int seer_wire_active(void)
{
  return 0;
}
static inline int seer_wire_rand(unsigned char *buf, int n)
{
  return RAND_bytes(buf, n);
}
static inline long seer_wire_pid(void)
{
  return (long)getpid();
}
static inline int seer_wire_hostname(char *buf, size_t n)
{
  return gethostname(buf, (int)n);
}
static inline const char *seer_wire_os_user(void)
{
  return NULL;
}
static inline unsigned seer_wire_connect(const char *host, uint16_t port, int ok)
{
  (void)host, (void)port, (void)ok;
  return 0;
}
static inline void seer_wire_sent(unsigned id, const void *buf, size_t len)
{
  (void)id, (void)buf, (void)len;
}
static inline void seer_wire_received(unsigned id, const void *buf, size_t len)
{
  (void)id, (void)buf, (void)len;
}
static inline void seer_wire_event(unsigned id, const char *what)
{
  (void)id, (void)what;
}

#endif /* SEER_WIRE_CORPUS */
#endif /* SEER_TNS_WIRE_H */
