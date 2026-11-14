/* SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Skips by server release, shared by the live suites (#148).
 *
 * Every tier runs the same checks. A check that can't apply to the connected
 * release opens with GATE(name) and is reported as SKIP with its reason,
 * without running. A gate is one of two kinds:
 *
 *   SERVER - the release lacks what the check needs ("8.1.7 has no
 *            TIMESTAMP", "no VECTOR before 23ai");
 *   TODO   - the server has it, but SeerODBC doesn't reach it yet; the reason
 *            names the issue that tracks it.
 *
 * Where only the expected outcome differs by release - a value one release
 * refuses and the next takes - the check branches on g_release itself.
 *
 * The release comes from SEER_TEST_RELEASE (8, 9, 10, 11, 18, 21, 23, 26),
 * which tests/odbc/run-matrix.sh sets per tier: the matrix knows what each
 * tier is, so the tests detect nothing themselves. */
#ifndef SEER_TESTS_GATES_H
#define SEER_TESTS_GATES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { GATE_SERVER, GATE_TODO } GateKind;

typedef struct {
  const char *check; /* the check's name, as it reports it */
  int from, to;      /* the releases it is skipped on, inclusive */
  GateKind kind;
  const char *why;
} Gate;

/* The connected server's release, from SEER_TEST_RELEASE. */
static int g_release;

/* Read SEER_TEST_RELEASE into g_release; 0 if unset or not a number. */
static int gate_release_init(void)
{
  const char *e = getenv("SEER_TEST_RELEASE");
  g_release = e != NULL ? atoi(e) : 0;
  return g_release;
}

/* The gate of `name` on the connected release, or NULL. */
static const Gate *gate_find(const Gate *gates, size_t n, const char *name)
{
  for (size_t i = 0; i < n; i++)
    if (strcmp(gates[i].check, name) == 0 && g_release >= gates[i].from && g_release <= gates[i].to)
      return &gates[i];
  return NULL;
}

/* The reason a gate prints: "server: ..." or "todo: ...". */
static void gate_reason(const Gate *g, char *out, size_t n)
{
  snprintf(out, n, "%s: %s", g->kind == GATE_SERVER ? "server" : "todo", g->why);
}

#endif
