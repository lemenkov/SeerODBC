/* test_core: two-phase commit (XA/TPC) through the core API.
 *
 * Drives a full 2PC cycle (begin -> DML -> end -> prepare -> commit) and a
 * rollback, verifying the outcome on a second connection.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"

static void exec_sql(SeerConn *c, const char *sql)
{
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(c, sql, &s) != SEER_OK)
    return;
  seer_stmt_execute(s);
  seer_stmt_close(s);
}

static long count_rows(SeerConn *c, const char *where)
{
  char sql[160];
  snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM seerxa WHERE %s", where);
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

void core_tpc(void)
{
  int gc = gated_as("two-phase commit", "two-phase commit");
  int gr = gated_as("two-phase rollback", "two-phase rollback");
  if (gc && gr)
    return;
  SeerConn *c = core_connect_xa();
  SeerConn *v = core_connect();
  if (!c || !v) {
    fail("two-phase commit", "connect failed");
    if (c)
      seer_disconnect(c);
    if (v)
      seer_disconnect(v);
    return;
  }

  exec_sql(c, "DROP TABLE seerxa");
  exec_sql(c, "CREATE TABLE seerxa (n NUMBER)"); /* DDL autocommits */
  seer_set_autocommit(c, 0);                     /* XA branch DML must not autocommit */

  SeerXid xc = {.format_id = 100,
                .gtrid = (const uint8_t *)"seerxa-commit",
                .gtrid_len = 13,
                .bqual = (const uint8_t *)"br1",
                .bqual_len = 3};
  if (!gc) {
    int needed = 0;
    if (seer_tpc_begin(c, &xc, SEER_TPC_BEGIN_NEW, 60) != SEER_OK)
      fail("two-phase commit", seer_last_error(c) ? seer_last_error(c) : "begin");
    else {
      exec_sql(c, "INSERT INTO seerxa VALUES (42)");
      if (seer_tpc_end(c, &xc, SEER_TPC_END_NORMAL) == SEER_OK &&
          seer_tpc_prepare(c, &xc, &needed) == SEER_OK && seer_tpc_commit(c, &xc, 0) == SEER_OK &&
          count_rows(v, "n=42") == 1)
        pass("two-phase commit");
      else
        fail("two-phase commit", seer_last_error(c) ? seer_last_error(c) : "cycle/durability");
    }
  }

  SeerXid xr = {.format_id = 100,
                .gtrid = (const uint8_t *)"seerxa-rollbk",
                .gtrid_len = 13,
                .bqual = (const uint8_t *)"br1",
                .bqual_len = 3};
  if (!gr) {
    if (seer_tpc_begin(c, &xr, SEER_TPC_BEGIN_NEW, 60) == SEER_OK) {
      exec_sql(c, "INSERT INTO seerxa VALUES (99)");
      if (seer_tpc_end(c, &xr, SEER_TPC_END_NORMAL) == SEER_OK &&
          seer_tpc_rollback(c, &xr) == SEER_OK && count_rows(v, "n=99") == 0)
        pass("two-phase rollback");
      else
        fail("two-phase rollback", "cycle/rollback");
    } else {
      fail("two-phase rollback", "begin");
    }
  }

  seer_set_autocommit(c, 1);
  exec_sql(c, "DROP TABLE seerxa");
  seer_disconnect(c);
  seer_disconnect(v);
}
