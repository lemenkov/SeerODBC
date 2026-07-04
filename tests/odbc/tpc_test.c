/* Live test for two-phase commit (XA/TPC) against the core protocol API.
 *
 * Self-gating: exits 77 (skip) unless SEER_TEST_HOST/SERVICE/USER are set, so it
 * is harmless in an offline `meson test`. Drives a full 2PC cycle
 * (begin -> DML -> end -> prepare -> commit) and a rollback, verifying the
 * outcome on a SECOND connection. TPC is 12c+; on an older server the begin
 * returns "not implemented" and the test skips.
 *
 *   SEER_TEST_HOST, SEER_TEST_PORT (default 1521), SEER_TEST_SERVICE,
 *   SEER_TEST_USER, SEER_TEST_PASS
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "seer/seertns.h"

static int pass_n, fail_n, skip_n;
static void pass(const char *n) { printf("  PASS %s\n", n); pass_n++; }
static void fail(const char *n, const char *w) { printf("  FAIL %s: %s\n", n, w); fail_n++; }
static void skip(const char *n, const char *w) { printf("  SKIP %s: %s\n", n, w); skip_n++; }

static SeerConn *connect_one(void)
{
    const char *port = getenv("SEER_TEST_PORT");
    SeerConnParams p = {
        .host = getenv("SEER_TEST_HOST"),
        .port = (uint16_t)(port ? atoi(port) : 1521),
        .service_name = getenv("SEER_TEST_SERVICE"),
        .username = getenv("SEER_TEST_USER"),
        .password = getenv("SEER_TEST_PASS"),
    };
    SeerConn *c = NULL;
    return seer_connect(&p, &c) == SEER_OK ? c : NULL;
}

static void exec_sql(SeerConn *c, const char *sql)
{
    SeerStmt *s = NULL;
    if (seer_stmt_prepare(c, sql, &s) != SEER_OK) return;
    seer_stmt_execute(s);
    seer_stmt_close(s);
}

static long count_rows(SeerConn *c, const char *where)
{
    char sql[160];
    snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM seerxa WHERE %s", where);
    SeerStmt *s = NULL;
    if (seer_stmt_prepare(c, sql, &s) != SEER_OK) return -1;
    long n = -1;
    if (seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
        const char *v = NULL; int isnull = 0;
        if (seer_stmt_get_string(s, 0, &v, &isnull) == SEER_OK && v) n = atol(v);
    }
    seer_stmt_close(s);
    return n;
}

int main(void)
{
    if (!getenv("SEER_TEST_HOST") || !getenv("SEER_TEST_SERVICE") || !getenv("SEER_TEST_USER")) {
        fprintf(stderr, "tpc_test: set SEER_TEST_HOST/SERVICE/USER[/PORT/PASS] - skipping\n");
        return 77;
    }
    SeerConn *c = connect_one();
    SeerConn *v = connect_one();
    if (!c || !v) { fprintf(stderr, "tpc_test: connect failed\n"); return 1; }

    exec_sql(c, "DROP TABLE seerxa");
    exec_sql(c, "CREATE TABLE seerxa (n NUMBER)");   /* DDL autocommits */
    seer_set_autocommit(c, 0);                        /* XA branch DML must not autocommit */

    SeerXid xc = { .format_id = 100, .gtrid = (const uint8_t *)"seerxa-commit",
                   .gtrid_len = 13, .bqual = (const uint8_t *)"br1", .bqual_len = 3 };
    SeerStatus st = seer_tpc_begin(c, &xc, SEER_TPC_BEGIN_NEW, 60);
    if (st == SEER_ENOTIMPL) {
        skip("two-phase commit", "TPC requires a 12c+ server");
        skip("two-phase rollback", "TPC requires a 12c+ server");
        goto done;
    }
    if (st != SEER_OK) { fail("two-phase commit", seer_last_error(c) ? seer_last_error(c) : "begin"); goto done; }
    exec_sql(c, "INSERT INTO seerxa VALUES (42)");
    int needed = 0;
    if (seer_tpc_end(c, &xc, SEER_TPC_END_NORMAL) == SEER_OK
        && seer_tpc_prepare(c, &xc, &needed) == SEER_OK
        && seer_tpc_commit(c, &xc, 0) == SEER_OK
        && count_rows(v, "n=42") == 1)
        pass("two-phase commit");
    else
        fail("two-phase commit", seer_last_error(c) ? seer_last_error(c) : "cycle/durability");

    SeerXid xr = { .format_id = 100, .gtrid = (const uint8_t *)"seerxa-rollbk",
                   .gtrid_len = 13, .bqual = (const uint8_t *)"br1", .bqual_len = 3 };
    if (seer_tpc_begin(c, &xr, SEER_TPC_BEGIN_NEW, 60) == SEER_OK) {
        exec_sql(c, "INSERT INTO seerxa VALUES (99)");
        if (seer_tpc_end(c, &xr, SEER_TPC_END_NORMAL) == SEER_OK
            && seer_tpc_rollback(c, &xr) == SEER_OK
            && count_rows(v, "n=99") == 0)
            pass("two-phase rollback");
        else
            fail("two-phase rollback", "cycle/rollback");
    } else {
        fail("two-phase rollback", "begin");
    }

done:
    seer_set_autocommit(c, 1);
    exec_sql(c, "DROP TABLE seerxa");
    seer_disconnect(c);
    seer_disconnect(v);
    printf("SUMMARY pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
    return fail_n > 0 ? 1 : 0;
}
