/* test_core: request boundaries (§35) through the core API.
 *
 * Request boundaries need a server that advertises them (21c+:
 * compile_caps[40] bit 0x40 and runtime_caps[6] bit 0x10). Drives a logical
 * request: begin -> a query (the REQUEST_BEGIN marker rides its message) ->
 * end (REQUEST_END on a rollback). Correctness is that the server accepts the
 * piggybacks (the query succeeds, no ORA error) and the connection stays
 * usable afterwards (no stream desync). Also covers the begin-with-no-op
 * cancel path.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>

#include "core.h"

/* Run "SELECT <lit> FROM dual" and return the value as a long (-1 on failure). */
static long select_lit(SeerConn *c, int lit)
{
  char sql[64];
  snprintf(sql, sizeof sql, "SELECT %d FROM dual", lit);
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(c, sql, &s) != SEER_OK)
    return -1;
  long n = -1;
  if (seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int isnull = 0;
    if (seer_stmt_get_string(s, 0, &v, &isnull) == SEER_OK && v)
      n = atol(v);
  }
  seer_stmt_close(s);
  return n;
}

void core_reqbound(void)
{
  GATE("request boundaries");
  SeerConn *c = core_connect();
  if (c == NULL) {
    fail("request boundaries", "connect failed");
    return;
  }

  if (seer_request_begin(c) != SEER_OK) {
    fail("request boundaries", "request_begin failed on a capable server");
    seer_disconnect(c);
    return;
  }

  /* Full request: BEGIN rode the arming above; run a query so it flushes in
   * front of that message, then end the request (REQUEST_END on a rollback). */
  seer_set_autocommit(c, 0);
  if (select_lit(c, 41) == 41)
    pass("begin marker rides the query (server accepted it)");
  else
    fail("begin+query", "query after request_begin did not return");

  if (seer_request_end(c) == SEER_OK)
    pass("end marker on rollback accepted");
  else
    fail("end", "request_end failed");

  if (select_lit(c, 42) == 42)
    pass("connection usable after the request (no desync)");
  else
    fail("post-request query", "connection unusable after end");

  /* Cancel path: begin then end with no op in between sends nothing and leaves
   * the connection clean. */
  if (seer_request_begin(c) == SEER_OK && seer_request_end(c) == SEER_OK && select_lit(c, 7) == 7)
    pass("begin-then-end with no op cancels cleanly");
  else
    fail("cancel path", "begin/end with no op left the connection unusable");

  seer_disconnect(c);
}
