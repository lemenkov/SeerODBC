/* SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* What test_core.c shares with its feature modules (core_*.c): the verdicts,
 * the gates, and a second connection to the same server. One binary, one
 * GATES table, one SUMMARY line (#148). */
#ifndef SEER_TESTS_CORE_H
#define SEER_TESTS_CORE_H

#include "seer/seertns.h"

void pass(const char *name);
void fail(const char *name, const char *why);
void skip(const char *name, const char *why);

/* Whether `gate` is gated on the connected release; if so, `name` is reported
 * as SKIP with the gate's reason. A gate names a check, or a feature several
 * checks share ("object binds"). */
int gated_as(const char *gate, const char *name);

/* Skip the check `nm` and return when its release is gated. */
#define GATE(nm)                                                                                   \
  do {                                                                                             \
    if (gated_as((nm), (nm)))                                                                      \
      return;                                                                                      \
  } while (0)

/* A new connection with the suite's parameters, or NULL. */
SeerConn *core_connect(void);
/* The same, opened for two-phase commit (SeerConnParams.xa, which 9i needs). */
SeerConn *core_connect_xa(void);

/* The feature modules, run by main() in this order. */
void core_tpc(void);
void core_reqbound(void);
void core_sessionless(void);
void core_pipeline(void);
void core_objbind(void);
void core_aq(void);

#endif
