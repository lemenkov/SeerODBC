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
#include <strings.h>

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

/* {fn} on a server of release `major`; want NULL: refused with a reason. */
static void check_fn(const char *in, int major, const char *want)
{
  const char *err = NULL;
  char *out = seer_sql_prepare_for(in, 1, major, &err);
  if (want == NULL) {
    if (out != NULL || err == NULL) {
      fprintf(stderr, "FAIL %s: want a refusal, got %s\n", in, out ? out : "(null, no reason)");
      exit(1);
    }
    return;
  }
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
    if (out != NULL) {
      fprintf(stderr, "FAIL updatable(%s): expected read-only\n", in);
      exit(1);
    }
    return;
  }
  int has_fu = out != NULL && strstr(out, "FOR UPDATE") != NULL;
  if (out == NULL || tbl == NULL || strcmp(tbl, want_table) != 0 || strstr(out, contains) == NULL ||
      strstr(out, "ROWIDTOCHAR(ROWID)") == NULL ||
      has_fu != (lock != 0 || strstr(in, "FOR UPDATE") != NULL)) {
    fprintf(stderr, "FAIL updatable(%s, lock=%d):\n  out  : %s\n  table: %s (want %s)\n", in, lock,
            out ? out : "(null)", tbl ? tbl : "(null)", want_table);
    exit(1);
  }
  free(out);
  free(tbl);
}

static void check_updatable(const char *in, const char *want_table, const char *contains)
{
  check_updatable_lock(in, 0, want_table, contains);
}

/* seer_sql_current_of: `name` NULL wants no match; else that name, with the
 * text before CURRENT equal to `head` and nothing but the name between. */
static void check_current_of(const char *in, const char *name, const char *head)
{
  size_t a = 0, b = 0;
  char got[64] = "";
  int m = seer_sql_current_of(in, &a, &b, got, sizeof got);
  if (name == NULL) {
    if (m) {
      fprintf(stderr, "FAIL current_of(%s): matched '%s', want no match\n", in, got);
      exit(1);
    }
    return;
  }
  if (!m || strcmp(got, name) != 0 || a != strlen(head) || strncmp(in, head, a) != 0 ||
      strncasecmp(in + a, "CURRENT", 7) != 0 || b > strlen(in) || b <= a) {
    fprintf(stderr, "FAIL current_of(%s): m=%d name '%s' (want '%s') start %zu end %zu\n", in, m,
            got, name, a, b);
    exit(1);
  }
}

int main(void)
{
  /* --- SQL_ATTR_NOSCAN (#248): escapes left as written, markers rewritten --- */
  {
    char *out =
        seer_sql_prepare_scan("SELECT {fn UCASE(?)} FROM dual WHERE d = {d '2020-01-02'}", 0);
    eq("noscan", out, "SELECT {fn UCASE(:1)} FROM dual WHERE d = {d '2020-01-02'}");
    free(out);
    out = seer_sql_prepare_scan("SELECT {fn UCASE(?)} FROM dual", 1);
    char *want = seer_sql_prepare("SELECT {fn UCASE(?)} FROM dual");
    eq("scan", out, want);
    free(out);
    free(want);
  }

  /* --- '?' markers -> :1, :2 (string-literal aware) --- */
  check_prepare("SELECT ?+? FROM dual", "SELECT :1+:2 FROM dual");
  check_prepare("SELECT '? not a marker', ? FROM dual", "SELECT '? not a marker', :1 FROM dual");
  check_prepare("INSERT INTO t VALUES (?,?,?)", "INSERT INTO t VALUES (:1,:2,:3)");
  check_prepare("SELECT 1 FROM dual", "SELECT 1 FROM dual"); /* no markers */

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

  /* --- {fn} scalar functions (#301) --- */
  check_fn("{fn LEFT(s, 2)}", 0, "SUBSTR(s, 1, 2)");
  check_fn("{fn locate('c', s)}", 0, "INSTR(s, 'c')"); /* any case */
  check_fn("{fn LOCATE('c', s, 4)}", 0, "INSTR(s, 'c', 4)");
  check_fn("{fn POSITION('a,b' IN s)}", 0, "INSTR(s, 'a,b')");
  check_fn("{fn LOCATE(f(a, b), s)}", 0, "INSTR(s, f(a, b))"); /* nested commas */
  check_fn("{fn CHAR(65)}", 0, "CHR(65)");
  check_fn("{fn USER()}", 0, "USER");
  check_fn("{fn USER}", 0, "USER");
  check_fn("{fn PI()}", 0, "ACOS(-1)");
  check_fn("{fn LOG(x)}", 0, "LN(x)");
  check_fn("{fn ABS(x)}", 0, "ABS(x)");                     /* Oracle's own: as written */
  check_fn("{fn DIFFERENCE(a, b)}", 0, "DIFFERENCE(a, b)"); /* no form: as written */
  check_fn("{fn scott.f(x)}", 0, "scott.f(x)");
  check_fn("{fn LEFT({fn UCASE(s)}, 1)}", 0, "SUBSTR(UPPER(s), 1, 1)");
  /* the release decides: 8i has no LOCALTIMESTAMP, INTERVAL or TIMESTAMP */
  check_fn("{fn NOW()}", 23, "LOCALTIMESTAMP");
  check_fn("{fn NOW()}", 9, "LOCALTIMESTAMP");
  check_fn("{fn NOW()}", 8, "SYSDATE");
  check_fn("{fn CURRENT_TIMESTAMP(3)}", 0, "LOCALTIMESTAMP(3)");
  check_fn("{fn TIMESTAMPADD(SQL_TSI_DAY, 1, d)}", 11, "(NUMTODSINTERVAL(1, 'DAY') + d)");
  check_fn("{fn TIMESTAMPADD(SQL_TSI_DAY, 1, d)}", 8, "((1) + d)");
  check_fn("{fn TIMESTAMPADD(DAY, 1, d)}", 8, "((1) + d)"); /* SQL_TSI_ optional */
  check_fn("{fn TIMESTAMPADD(SQL_TSI_MONTH, n, d)}", 0, "ADD_MONTHS(d, n)");
  check_fn("{fn TIMESTAMPADD(SQL_TSI_FRAC_SECOND, 1, d)}", 8,
           "TIMESTAMPADD(SQL_TSI_FRAC_SECOND, 1, d)"); /* none on 8i */
  check_fn("{fn TIMESTAMPDIFF(SQL_TSI_MONTH, a, b)}", 0, "TRUNC(-MONTHS_BETWEEN(a, b))");
  check_fn("{fn CONVERT(x, SQL_INTEGER)}", 0, "TRUNC(CAST(x AS NUMBER))");
  check_fn("{fn CONVERT(x, SQL_DOUBLE)}", 10, "CAST(x AS BINARY_DOUBLE)");
  check_fn("{fn CONVERT(x, SQL_DOUBLE)}", 9, "CAST(x AS NUMBER)");
  check_fn("{fn CONVERT(x, SQL_TIMESTAMP)}", 8, "CAST(x AS DATE)");
  check_fn("{fn CONVERT(x, SQL_GUID)}", 0, "CONVERT(x, SQL_GUID)");
  /* markers: kept in order, one occurrence each, or refused */
  check_fn("SELECT {fn LOCATE(?, s)} FROM t", 0, "SELECT INSTR(s, :1) FROM t");
  check_fn("SELECT {fn LEFT(?, ?)}, ? FROM t", 0, "SELECT SUBSTR(:1, 1, :2), :3 FROM t");
  check_fn("SELECT {fn LOCATE(?, ?)} FROM t", 0, NULL); /* would swap */
  check_fn("SELECT {fn REPEAT(?, 2)}, ? FROM t", 0,     /* one parameter, repeated (#302) */
           "SELECT RPAD(:1, LENGTH(:1) * (2), :1), :2 FROM t");
  check_fn("SELECT {fn REPEAT(s, ?)} FROM t", 0, "SELECT RPAD(s, LENGTH(s) * (:1), s) FROM t");
  check_fn("{? = call f({fn LEFT(?, 1)})}", 0, "BEGIN :1 := f(SUBSTR(:2, 1, 1)); END;");

  /* --- parameter counting (operates on prepared :n / :name SQL) --- */
  check_count("SELECT :1+:2 FROM dual", 2);
  check_count("SELECT :x+:y FROM dual", 2);
  check_count("SELECT :x+:x FROM dual", 1); /* dedup by name */
  check_count("INSERT INTO t VALUES (:a,:b,:c)", 3);
  check_count("SELECT ':x literal' || :y FROM dual", 1);       /* literal ignored */
  check_count("SELECT 1 FROM dual /* :nope */ WHERE 1=:k", 1); /* comment ignored */
  check_count("BEGIN x := :p + :q; END;", 2);                  /* := is not a marker */
  check_count("SELECT 1 FROM dual", 0);
  check_count(":X and :x are one", 1); /* case-insensitive dedup */

  /* --- updatable-cursor rewrite --- */
  check_updatable("SELECT a, b FROM emp WHERE x > 1", "emp", "FROM emp WHERE x > 1");
  check_updatable("SELECT * FROM emp", "emp", "emp.*"); /* '*' qualified */
  check_updatable("SELECT a FROM scott.emp e", "scott.emp", "FROM scott.emp e");
  /* not updatable -> NULL */
  check_updatable("SELECT a FROM t1, t2", NULL, NULL); /* join (comma) */
  check_updatable("SELECT DISTINCT a FROM t", NULL, NULL);
  check_updatable("SELECT a FROM t1 UNION SELECT a FROM t2", NULL, NULL);
  check_updatable("SELECT count(*) FROM t GROUP BY a", NULL, NULL);
  check_updatable("SELECT a FROM (SELECT a FROM t)", NULL, NULL); /* subquery */
  check_updatable("INSERT INTO t VALUES (1)", NULL, NULL);
  /* --- FOR UPDATE (SQL_CONCUR_LOCK) --- */
  check_updatable_lock("SELECT a FROM emp", 1, "emp", "FOR UPDATE");
  check_updatable_lock("SELECT a FROM emp WHERE x > 1", 1, "emp", "WHERE x > 1 FOR UPDATE");
  check_updatable_lock("SELECT a FROM emp ORDER BY a", 1, "emp", "ORDER BY a FOR UPDATE");
  /* already locked -> not doubled */
  check_updatable_lock("SELECT a FROM emp FOR UPDATE", 1, "emp", "FOR UPDATE");
  /* lock not requested -> no FOR UPDATE appended */
  check_updatable_lock("SELECT a FROM emp", 0, "emp", "ROWIDTOCHAR");

  /* --- positioned UPDATE / DELETE: WHERE CURRENT OF (#288) --- */
  check_current_of("UPDATE t SET v = 1 WHERE CURRENT OF SQL_CUR1", "SQL_CUR1",
                   "UPDATE t SET v = 1 WHERE ");
  check_current_of("delete from t where current of c1 ;  ", "c1", "delete from t where ");
  check_current_of("UPDATE t SET v = 'WHERE CURRENT OF x' WHERE CURRENT OF \"My Cur\"", "My Cur",
                   "UPDATE t SET v = 'WHERE CURRENT OF x' WHERE ");
  check_current_of("UPDATE t SET v = 1\nWHERE\tCURRENT  OF\nc", "c", "UPDATE t SET v = 1\nWHERE\t");
  check_current_of("SELECT * FROM t WHERE CURRENT OF c", NULL, NULL); /* not UPDATE/DELETE */
  check_current_of("UPDATE t SET v = 1 WHERE CURRENT OF c AND x = 1", NULL, NULL); /* not last */
  check_current_of("UPDATE t SET v = 1 WHERE x = 1", NULL, NULL);
  check_current_of("UPDATE t SET v = 1 -- WHERE CURRENT OF c", NULL, NULL); /* in a comment */
  check_current_of("UPDATE t SET v = 'x' WHERE CURRENT OF", NULL, NULL);    /* no name */
  check_current_of("UPDATE t SET nowhere = 1 WHERE CURRENT OF c", "c",
                   "UPDATE t SET nowhere = 1 WHERE ");

  printf("test_sqlprep: all assertions passed\n");
  return 0;
}
