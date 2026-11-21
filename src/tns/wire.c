/* The replay corpus's recorder and deterministic mode (#396); see wire.h.
 * Built only with the `wire_corpus` option.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wire.h"

#include <openssl/rand.h>
#include <pthread.h>
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

int seer_wire_active(void)
{
  pthread_once(&once, open_record);
  return rec != NULL;
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
