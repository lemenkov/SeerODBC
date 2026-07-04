/* Offline unit tests for the SQL preprocessor (src/odbc/sqlprep.c): ODBC escape
 * expansion, '?'->:n rewriting, parameter counting, and updatable-cursor
 * rewriting. No Driver Manager or database connection required.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#include "sqlprep.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void eq(const char *what, const char *got, const char *want)
{
    if (got == NULL || strcmp(got, want) != 0) {
        fprintf(stderr, "FAIL %s:\n  got : %s\n  want: %s\n", what, got ? got : "(null)", want);
        exit(1);
    }
}

static void check_prepare(const char *in, const char *want)
{
    char *out = seer_sql_prepare(in);
    eq(in, out, want);
    free(out);
}

static void check_count(const char *in, int want)
{
    int n = seer_sql_count_params(in);
    if (n != want) {
        fprintf(stderr, "FAIL count(%s): got %d want %d\n", in, n, want);
        exit(1);
    }
}

/* make_updatable should rewrite to start with `pre` and contain ROWIDTOCHAR.
 * With `lock` set the output must also end in FOR UPDATE; without it, must not. */
static void check_updatable_lock(const char *in, int lock, const char *want_table,
                                 const char *contains)
{
    char *tbl = NULL;
    char *out = seer_sql_make_updatable(in, &tbl, lock);
    if (want_table == NULL) {
        if (out != NULL) { fprintf(stderr, "FAIL updatable(%s): expected read-only\n", in); exit(1); }
        return;
    }
    int has_fu = out != NULL && strstr(out, "FOR UPDATE") != NULL;
    if (out == NULL || tbl == NULL || strcmp(tbl, want_table) != 0 ||
        strstr(out, contains) == NULL || strstr(out, "ROWIDTOCHAR(ROWID)") == NULL ||
        has_fu != (lock != 0 || strstr(in, "FOR UPDATE") != NULL)) {
        fprintf(stderr, "FAIL updatable(%s, lock=%d):\n  out  : %s\n  table: %s (want %s)\n",
                in, lock, out ? out : "(null)", tbl ? tbl : "(null)", want_table);
        exit(1);
    }
    free(out);
    free(tbl);
}

static void check_updatable(const char *in, const char *want_table, const char *contains)
{
    check_updatable_lock(in, 0, want_table, contains);
}

int main(void)
{
    /* --- '?' markers -> :1, :2 (string-literal aware) --- */
    check_prepare("SELECT ?+? FROM dual", "SELECT :1+:2 FROM dual");
    check_prepare("SELECT '? not a marker', ? FROM dual",
                  "SELECT '? not a marker', :1 FROM dual");
    check_prepare("INSERT INTO t VALUES (?,?,?)", "INSERT INTO t VALUES (:1,:2,:3)");
    check_prepare("SELECT 1 FROM dual", "SELECT 1 FROM dual");   /* no markers */

    /* --- {call} / {?=call} statement escapes --- */
    check_prepare("{call proc(?)}", "BEGIN proc(:1); END;");
    check_prepare("{? = call func(?, ?)}", "BEGIN :1 := func(:2, :3); END;");

    /* --- inline {ts}/{d}/{fn} escapes --- */
    check_prepare("SELECT {d '2026-06-18'} FROM dual", "SELECT DATE '2026-06-18' FROM dual");
    check_prepare("SELECT {ts '2026-06-18 14:30:45'} FROM dual",
                  "SELECT TIMESTAMP '2026-06-18 14:30:45' FROM dual");
    check_prepare("SELECT {fn UCASE(name)} FROM t", "SELECT UPPER(name) FROM t");
    check_prepare("SELECT {fn SUBSTRING(s,1,3)} FROM t", "SELECT SUBSTR(s,1,3) FROM t");
    check_prepare("SELECT {fn IFNULL(a,b)} FROM t", "SELECT NVL(a,b) FROM t");
    /* a {ts} literal is left alone inside a string */
    check_prepare("SELECT '{ts x}' FROM dual", "SELECT '{ts x}' FROM dual");

    /* --- parameter counting (operates on prepared :n / :name SQL) --- */
    check_count("SELECT :1+:2 FROM dual", 2);
    check_count("SELECT :x+:y FROM dual", 2);
    check_count("SELECT :x+:x FROM dual", 1);          /* dedup by name */
    check_count("INSERT INTO t VALUES (:a,:b,:c)", 3);
    check_count("SELECT ':x literal' || :y FROM dual", 1);   /* literal ignored */
    check_count("SELECT 1 FROM dual /* :nope */ WHERE 1=:k", 1);  /* comment ignored */
    check_count("BEGIN x := :p + :q; END;", 2);        /* := is not a marker */
    check_count("SELECT 1 FROM dual", 0);
    check_count(":X and :x are one", 1);               /* case-insensitive dedup */

    /* --- updatable-cursor rewrite --- */
    check_updatable("SELECT a, b FROM emp WHERE x > 1", "emp", "FROM emp WHERE x > 1");
    check_updatable("SELECT * FROM emp", "emp", "emp.*");          /* '*' qualified */
    check_updatable("SELECT a FROM scott.emp e", "scott.emp", "FROM scott.emp e");
    /* not updatable -> NULL */
    check_updatable("SELECT a FROM t1, t2", NULL, NULL);          /* join (comma) */
    check_updatable("SELECT DISTINCT a FROM t", NULL, NULL);
    check_updatable("SELECT a FROM t1 UNION SELECT a FROM t2", NULL, NULL);
    check_updatable("SELECT count(*) FROM t GROUP BY a", NULL, NULL);
    check_updatable("SELECT a FROM (SELECT a FROM t)", NULL, NULL);  /* subquery */
    check_updatable("INSERT INTO t VALUES (1)", NULL, NULL);
    /* --- FOR UPDATE (SQL_CONCUR_LOCK) --- */
    check_updatable_lock("SELECT a FROM emp", 1, "emp", "FOR UPDATE");
    check_updatable_lock("SELECT a FROM emp WHERE x > 1", 1, "emp",
                         "WHERE x > 1 FOR UPDATE");
    check_updatable_lock("SELECT a FROM emp ORDER BY a", 1, "emp",
                         "ORDER BY a FOR UPDATE");
    /* already locked -> not doubled */
    check_updatable_lock("SELECT a FROM emp FOR UPDATE", 1, "emp", "FOR UPDATE");
    /* lock not requested -> no FOR UPDATE appended */
    check_updatable_lock("SELECT a FROM emp", 0, "emp", "ROWIDTOCHAR");

    printf("test_sqlprep: all assertions passed\n");
    return 0;
}
