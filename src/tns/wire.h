/* The replay corpus's hooks (#396): record every byte a connection exchanges,
 * and make the values a client draws itself repeat from run to run, so a
 * recording can be replayed offline byte for byte.
 *
 * Compiled in only with the `wire_corpus` build option (SEER_WIRE_CORPUS),
 * for test builds. Without it every hook below is the plain call it stands
 * for, and a driver holds no recorder and no deterministic path: a fixed
 * "random" stream in a shipped driver would make its logins predictable.
 *
 * With it, the hooks are live only when SEER_WIRE_RECORD names a file to
 * record into, or SEER_WIRE_REPLAY one to replay:
 * - the client's random bytes (session keys, salts, the ANO Diffie-Hellman
 *   key) come from a fixed seeded stream; the process id, the host name and
 *   the OS user are fixed - each is sent at login, and the server's replies
 *   depend on the keys;
 * - each connection's traffic is appended to the file, in the C2S / S2C
 *   form seerdb's tools/capture_proxy.py writes, tagged with the connection;
 * - in a replay no socket is opened: each connect takes the record's next
 *   CONNECT, each send must match its next C2S byte for byte, each read is
 *   answered from its S2C, and a recorded failed read (RFAIL), empty wait
 *   (WAIT0) or break (OOB) happens again, so the driver's timeout and cancel
 *   paths run as they did live. The first difference is reported on stderr
 *   and fails every call after it.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_WIRE_H
#define SEER_TNS_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"

#ifdef SEER_WIRE_CORPUS

/* Whether the deterministic mode is on: recording or replaying. */
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

/* Replaying (SEER_WIRE_REPLAY set): the transport's calls, answered from the
 * record. A connect sets `id`, or fails as it failed live (`err` says so). */
int seer_wire_replaying(void);
SeerStatus seer_wire_replay_connect(const char *host, uint16_t port, unsigned *id, char *err,
                                    size_t errlen);
SeerStatus seer_wire_replay_send(unsigned id, const void *buf, size_t len);
SeerStatus seer_wire_replay_recv(unsigned id, void *buf, size_t len);
int seer_wire_replay_wait(unsigned id); /* 1 data, 0 nothing came in time */
SeerStatus seer_wire_replay_oob(unsigned id);
void seer_wire_replay_close(unsigned id);
int seer_wire_replay_failed(void);

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
static inline int seer_wire_replaying(void)
{
  return 0;
}
/* never called without the option: seer_wire_replaying() is 0 */
static inline SeerStatus seer_wire_replay_connect(const char *host, uint16_t port, unsigned *id,
                                                  char *err, size_t errlen)
{
  (void)host, (void)port, (void)id, (void)err, (void)errlen;
  return SEER_ENOTIMPL;
}
static inline SeerStatus seer_wire_replay_send(unsigned id, const void *buf, size_t len)
{
  (void)id, (void)buf, (void)len;
  return SEER_ENOTIMPL;
}
static inline SeerStatus seer_wire_replay_recv(unsigned id, void *buf, size_t len)
{
  (void)id, (void)buf, (void)len;
  return SEER_ENOTIMPL;
}
static inline int seer_wire_replay_wait(unsigned id)
{
  (void)id;
  return -1;
}
static inline SeerStatus seer_wire_replay_oob(unsigned id)
{
  (void)id;
  return SEER_ENOTIMPL;
}
static inline void seer_wire_replay_close(unsigned id)
{
  (void)id;
}

#endif /* SEER_WIRE_CORPUS */
#endif /* SEER_TNS_WIRE_H */
