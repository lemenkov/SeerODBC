/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_ONCE_H
#define SEER_ONCE_H

/*
 * Run an initialisation function exactly once, race-free: threads that arrive
 * while it runs wait until it has finished. pthread_once on POSIX; on Windows
 * the kernel32 one-time initialisation (InitOnceExecuteOnce), so the driver DLL
 * needs no pthreads runtime there.
 *
 *   static SeerOnce once = SEER_ONCE_INIT;
 *   seer_once(&once, init_fn);
 *
 * Kept out of compat.h: on Windows it pulls in <windows.h>, which only its own
 * users should see.
 */

#ifdef _WIN32
#include <windows.h>

typedef INIT_ONCE SeerOnce;

#define SEER_ONCE_INIT INIT_ONCE_STATIC_INIT

struct seer_once_call {
  void (*fn)(void);
};

static BOOL CALLBACK seer_once_trampoline(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
  (void)once;
  (void)ctx;
  ((struct seer_once_call *)param)->fn();
  return TRUE;
}

static inline void seer_once(SeerOnce *o, void (*fn)(void))
{
  /* The function rides in this call's own parameter, not in shared state: the
   * one thread that runs it reads it, the others only wait. */
  struct seer_once_call call = {fn};
  InitOnceExecuteOnce(o, seer_once_trampoline, &call, NULL);
}

#else
#include <pthread.h>

typedef pthread_once_t SeerOnce;

#define SEER_ONCE_INIT PTHREAD_ONCE_INIT

static inline void seer_once(SeerOnce *o, void (*fn)(void))
{
  pthread_once(o, fn);
}
#endif

#endif /* SEER_ONCE_H */
