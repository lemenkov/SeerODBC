/* Oracle 8i (8.1.7) core-API integration test (seerdb PROTOCOL.md §19.8-19.10).
 * LOCAL ONLY, like test_9i: 8i runs as a VM, so tests/odbc/run-matrix.sh runs
 * this against it and it is not a meson test(). Exit 0 with a skip when the
 * server is unreachable.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "seer/seertns.h"

static int pass_n, fail_n, skip_n;
static void pass(const char *n)
{
  printf("  PASS %s\n", n);
  pass_n++;
}
static void fail(const char *n, const char *w)
{
  printf("  FAIL %s: %s\n", n, w);
  fail_n++;
}

static SeerConn *C;

/* Run a query; return its row count (-1 on failure) and copy row `r`, column
 * `col` into `out` (empty when NULL or absent). */
static long query(const char *sql, long r, int col, char *out, size_t osz)
{
  if (out != NULL)
    out[0] = '\0';
  SeerStmt *s = NULL;
  long rows = -1;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK) {
    rows = 0;
    while (seer_stmt_fetch(s) == SEER_OK) {
      if (rows == r && out != NULL) {
        const char *v = NULL;
        int isn = 0;
        if (seer_stmt_get_string(s, col, &v, &isn) == SEER_OK && v != NULL)
          snprintf(out, osz, "%s", v);
      }
      rows++;
    }
  }
  seer_stmt_close(s);
  return rows;
}

static void check_scalar_types(void)
{
  const char *name = "SELECT NUMBER / VARCHAR2 / CHAR / DATE / decimal";
  char a[64], b[64], c[64], d[64], e[64];
  long n = query("SELECT 42, 'hello', CAST('ab' AS CHAR(4)), "
                 "TO_DATE('2026-02-28 13:45:06', 'YYYY-MM-DD HH24:MI:SS'), -3.25 FROM dual",
                 0, 0, a, sizeof a);
  query("SELECT 42, 'hello' FROM dual", 0, 1, b, sizeof b);
  query("SELECT CAST('ab' AS CHAR(4)) FROM dual", 0, 0, c, sizeof c);
  query("SELECT TO_DATE('2026-02-28 13:45:06', 'YYYY-MM-DD HH24:MI:SS') FROM dual", 0, 0, d,
        sizeof d);
  query("SELECT -3.25 FROM dual", 0, 0, e, sizeof e);
  if (n == 1 && strcmp(a, "42") == 0 && strcmp(b, "hello") == 0 && strcmp(c, "ab  ") == 0 &&
      strcmp(d, "2026-02-28 13:45:06") == 0 && strcmp(e, "-3.25") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "rows=%ld '%s' '%s' '%s' '%s' '%s'", n, a, b, c, d, e);
    fail(name, m);
  }
}

static void check_nulls_and_empty(void)
{
  const char *name = "NULL cells and an empty result";
  char a[16] = "x", b[16];
  SeerStmt *s = NULL;
  int isn0 = 0, isn2 = 0;
  if (seer_stmt_prepare(C, "SELECT NULL, 'x', TO_NUMBER(NULL) FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    seer_stmt_get_string(s, 0, &v, &isn0);
    seer_stmt_get_string(s, 1, &v, &isn2);
    snprintf(a, sizeof a, "%s", v ? v : "");
    seer_stmt_get_string(s, 2, &v, &isn2);
  }
  seer_stmt_close(s);
  long empty = query("SELECT 1 FROM dual WHERE 1 = 0", 0, 0, b, sizeof b);
  if (isn0 && isn2 && strcmp(a, "x") == 0 && empty == 0)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "null0=%d null2=%d mid='%s' empty=%ld", isn0, isn2, a, empty);
    fail(name, m);
  }
}

/* 250 rows over three fetches; the constant column repeats, so 8i omits it
 * from rows (the row header's bit vector), across batch boundaries too. */
static void check_multibatch(void)
{
  const char *name = "250 rows across fetch batches, repeated columns";
  SeerStmt *s = NULL;
  long rows = 0, bad = 0;
  if (seer_stmt_prepare(C,
                        "SELECT ROWNUM, 'tail', MOD(ROWNUM, 3) FROM all_objects "
                        "WHERE ROWNUM <= 250",
                        &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK) {
    while (seer_stmt_fetch(s) == SEER_OK) {
      const char *a = NULL, *t = NULL, *m = NULL;
      int isn = 0;
      seer_stmt_get_string(s, 0, &a, &isn);
      seer_stmt_get_string(s, 1, &t, &isn);
      seer_stmt_get_string(s, 2, &m, &isn);
      rows++;
      if (a == NULL || atol(a) != rows || t == NULL || strcmp(t, "tail") != 0 || m == NULL ||
          atol(m) != rows % 3)
        bad++;
    }
  }
  seer_stmt_close(s);
  if (rows == 250 && bad == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "rows=%ld bad=%ld", rows, bad);
    fail(name, m);
  }
}

/* V$SESSION's 45 columns describe past one 2 KB packet, unmarked. */
static void check_wide_describe(void)
{
  const char *name = "describe across packets (V$SESSION)";
  SeerStmt *s = NULL;
  int ncols = 0;
  long rows = 0;
  if (seer_stmt_prepare(C, "SELECT * FROM v$session WHERE ROWNUM <= 3", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK) {
    ncols = seer_stmt_num_cols(s);
    while (seer_stmt_fetch(s) == SEER_OK)
      rows++;
  }
  seer_stmt_close(s);
  if (ncols >= 40 && rows == 3)
    pass(name);
  else {
    char m[64];
    snprintf(m, sizeof m, "ncols=%d rows=%ld", ncols, rows);
    fail(name, m);
  }
}

static void check_errors(void)
{
  const char *name = "errors: refused query, describe cut short, then recovery";
  SeerStmt *s = NULL;
  char e1[128] = "", e2[128] = "", e3[128] = "", ok[16];
  if (seer_stmt_prepare(C, "SELECT * FROM no_such_table_8i", &s) == SEER_OK &&
      seer_stmt_execute(s) != SEER_OK && seer_last_error(C))
    snprintf(e1, sizeof e1, "%s", seer_last_error(C));
  seer_stmt_close(s);
  s = NULL;
  /* 8i has no USERENV SID: the describe stops partway and the error follows */
  if (seer_stmt_prepare(C, "SELECT * FROM v$session WHERE sid = sys_context('userenv','sid')",
                        &s) == SEER_OK &&
      seer_stmt_execute(s) != SEER_OK && seer_last_error(C))
    snprintf(e2, sizeof e2, "%s", seer_last_error(C));
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT 1 / 0 FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) != SEER_OK && seer_last_error(C))
    snprintf(e3, sizeof e3, "%s", seer_last_error(C));
  seer_stmt_close(s);
  query("SELECT 'alive' FROM dual", 0, 0, ok, sizeof ok);
  if (strncmp(e1, "ORA-00942", 9) == 0 && strncmp(e2, "ORA-02003", 9) == 0 &&
      strncmp(e3, "ORA-01476", 9) == 0 && strcmp(ok, "alive") == 0)
    pass(name);
  else {
    char m[480];
    snprintf(m, sizeof m, "'%s' / '%s' / '%s' / '%s'", e1, e2, e3, ok);
    fail(name, m);
  }
}

/* 8i's session charset is WE8ISO8859P1: Latin-1 text reads back as UTF-8, and
 * the SQL text goes out in Latin-1. */
static void check_latin1(void)
{
  const char *name = "Latin-1 text both ways";
  char a[32], b[32];
  query("SELECT CHR(252) || 'ber' FROM dual", 0, 0, a, sizeof a);
  query("SELECT LENGTH('\xc3\xa9t\xc3\xa9') || ASCII(SUBSTR('\xc3\xa9', 1, 1)) FROM dual", 0, 0, b,
        sizeof b);
  if (strcmp(a, "\xc3\xbc"
                "ber") == 0 &&
      strcmp(b, "3233") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "'%s' / '%s'", a, b);
    fail(name, m);
  }
}

/* SQL text past 64 bytes goes in 64-byte chunks, and its length past 255 as
 * the fixed ub4 (a variable-width one draws ORA-01009). */
static void check_long_sql(void)
{
  const char *name = "300-byte SQL text";
  char sql[512] = "SELECT ";
  for (int i = 1; i <= 100; i++) {
    char item[8];
    snprintf(item, sizeof item, "%s%d", i > 1 ? "+" : "", i);
    strncat(sql, item, sizeof sql - strlen(sql) - 1);
  }
  strncat(sql, " FROM dual", sizeof sql - strlen(sql) - 1);
  char v[16];
  query(sql, 0, 0, v, sizeof v);
  if (strlen(sql) > 255 && strcmp(v, "5050") == 0)
    pass(name);
  else {
    char m[64];
    snprintf(m, sizeof m, "len=%zu got '%s'", strlen(sql), v);
    fail(name, m);
  }
}

static void check_rowid(void)
{
  const char *name = "ROWID column";
  char r[32], back[16];
  query("SELECT ROWID FROM dual", 0, 0, r, sizeof r);
  char sql[96];
  snprintf(sql, sizeof sql, "SELECT 'found' FROM dual WHERE ROWID = '%s'", r);
  query(sql, 0, 0, back, sizeof back);
  if (strlen(r) == 18 && strcmp(back, "found") == 0)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "rowid='%s' back='%s'", r, back);
    fail(name, m);
  }
}

/* Every statement's cursor is closed (piggybacked on the next call); left
 * open, a session runs out at open_cursors with ORA-01000. */
static void check_cursor_hygiene(void)
{
  const char *name = "300 queries in one session (cursors closed)";
  long ok = 0;
  char v[16];
  for (int i = 0; i < 300; i++)
    if (query("SELECT 1 FROM dual", 0, 0, v, sizeof v) == 1 && strcmp(v, "1") == 0)
      ok++;
  if (ok == 300)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "%ld/300 succeeded (%s)", ok,
             seer_last_error(C) ? seer_last_error(C) : "");
    fail(name, m);
  }
}

/* A wrong password is refused, and says so as the server did: ORA-01017,
 * not a connection that seems to work and then fails every call. */
static void check_wrong_password(const SeerConnParams *good)
{
  const char *name = "a wrong password is refused with ORA-01017";
  SeerConnParams p = *good;
  p.password = "not-the-password";
  SeerConn *c = NULL;
  char why[256];
  SeerStatus st = seer_connect_diag(&p, &c, why, sizeof why);
  if (c != NULL)
    seer_disconnect(c);
  if (st == SEER_EAUTH && strncmp(why, "ORA-01017", 9) == 0) {
    pass(name);
  } else {
    char m[320];
    snprintf(m, sizeof m, "status %d, '%s'", (int)st, why);
    fail(name, m);
  }
}

/* Row 0 of a bound query, its columns joined with '|' into `out` (NULL for a
 * NULL); the execute's status. */
static SeerStatus bound_row(SeerStmt *s, char *out, size_t osz)
{
  out[0] = '\0';
  SeerStatus st = seer_stmt_execute(s);
  if (st == SEER_OK && seer_stmt_fetch(s) == SEER_OK)
    for (int i = 0; i < seer_stmt_num_cols(s); i++) {
      const char *v = NULL;
      int isn = 0;
      seer_stmt_get_string(s, i, &v, &isn);
      size_t k = strlen(out);
      snprintf(out + k, osz - k, "%s%s", i ? "|" : "", isn || v == NULL ? "NULL" : v);
    }
  return st;
}

/* IN binds (seerdb PROTOCOL.md §19.11, #132): NUMBER, text (in Latin-1, inline
 * and past 64 bytes in chunks), NULL, DATE and RAW, and a bound WHERE. */
static void check_binds(void)
{
  const char *name = "IN binds: NUMBER, text, NULL, DATE, RAW";
  char a[128] = "", b[128] = "", c[128] = "", d[64] = "";
  SeerStmt *s = NULL;
  char wide[301];
  memset(wide, 'x', 300);
  wide[300] = '\0';
  if (seer_stmt_prepare(C, "SELECT :1 + :2, :3 || '-' || :4, LENGTH(:5) FROM dual", &s) ==
      SEER_OK) {
    seer_stmt_bind_int64(s, 1, 40);
    seer_stmt_bind_int64(s, 2, 2);
    seer_stmt_bind_text(s, 3, "abc", -1);
    seer_stmt_bind_text(s, 4,
                        "d\xc3\xa9"
                        "f",
                        -1);
    seer_stmt_bind_text(s, 5, wide, -1);
    bound_row(s, a, sizeof a);
  }
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT NVL(:1, 'none'), NVL(:2, 7) + 0 FROM dual", &s) == SEER_OK) {
    seer_stmt_bind_null(s, 1);
    seer_stmt_bind_null_typed(s, 2, 2);
    bound_row(s, b, sizeof b);
  }
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT TO_CHAR(:1, 'YYYY-MM-DD HH24:MI:SS'), RAWTOHEX(:2) FROM dual",
                        &s) == SEER_OK) {
    seer_stmt_bind_date(s, 1, 2001, 2, 3, 4, 5, 6);
    seer_stmt_bind_raw(s, 2, "\x01\xab\xff", 3);
    bound_row(s, c, sizeof c);
  }
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT COUNT(*) FROM all_users WHERE username = :1", &s) == SEER_OK) {
    seer_stmt_bind_text(s, 1, "SYSTEM", -1);
    bound_row(s, d, sizeof d);
  }
  seer_stmt_close(s);
  if (strcmp(a, "42|abc-d\xc3\xa9"
                "f|300") == 0 &&
      strcmp(b, "none|7") == 0 && strcmp(c, "2001-02-03 04:05:06|01ABFF") == 0 &&
      strcmp(d, "1") == 0)
    pass(name);
  else {
    char m[512];
    snprintf(m, sizeof m, "'%s' / '%s' / '%s' / '%s'", a, b, c, d);
    fail(name, m);
  }
}

/* A bind 8i can't take (BINARY_DOUBLE, a 10g type) is refused before anything
 * is sent, and the session goes on. */
static void check_bind_refused(void)
{
  const char *name = "a BINARY_DOUBLE bind is refused, the session goes on";
  SeerStmt *s = NULL;
  SeerStatus st = SEER_OK;
  if (seer_stmt_prepare(C, "SELECT :1 FROM dual", &s) == SEER_OK) {
    seer_stmt_bind_double(s, 1, 1.5);
    st = seer_stmt_execute(s);
  }
  seer_stmt_close(s);
  char after[16];
  query("SELECT 1 FROM dual", 0, 0, after, sizeof after);
  if (st == SEER_ENOTIMPL && strcmp(after, "1") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "status %d, then '%s'", (int)st, after);
    fail(name, m);
  }
}

/* Run a statement that returns no rows; its status, and its row count into
 * *rows when given. */
static SeerStatus run(const char *sql, long *rows)
{
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, sql, &s);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  if (rows != NULL)
    *rows = seer_stmt_row_count(s);
  seer_stmt_close(s);
  return st;
}

/* DDL, DML with binds and an array INSERT (8i has no array DML: a row at a
 * time), batch errors, row counts and the error of a refused statement
 * (seerdb PROTOCOL.md §19.12, #133). */
static void check_dml(void)
{
  const char *name = "DDL, DML with binds, array INSERT, batch errors";
  char m[512] = "", n[16];
  run("DROP TABLE seer_t8", NULL);
  SeerStatus c1 = run("CREATE TABLE seer_t8 (id NUMBER PRIMARY KEY, txt VARCHAR2(20))", NULL);
  SeerStmt *s = NULL;
  long one = -1, three = -1, two = -1, upd = -1;
  if (seer_stmt_prepare(C, "INSERT INTO seer_t8 VALUES (:1, :2)", &s) == SEER_OK) {
    seer_stmt_bind_int64(s, 1, 1);
    seer_stmt_bind_text(s, 2, "one", -1);
    if (seer_stmt_execute(s) == SEER_OK)
      one = seer_stmt_row_count(s);
  }
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "INSERT INTO seer_t8 VALUES (:1, 'array')", &s) == SEER_OK) {
    seer_stmt_set_array_size(s, 3);
    for (int r = 0; r < 3; r++) {
      seer_stmt_bind_row(s, r);
      seer_stmt_bind_int64(s, 1, 2 + r);
    }
    if (seer_stmt_execute(s) == SEER_OK)
      three = seer_stmt_row_count(s);
  }
  seer_stmt_close(s);
  s = NULL;
  /* 5, then 1 again (a duplicate), then 6: with batch errors the two good rows
   * go in and row 1 is reported with ORA-00001. */
  unsigned erow = 99, ecode = 0;
  size_t nerr = 0;
  if (seer_stmt_prepare(C, "INSERT INTO seer_t8 VALUES (:1, 'batch')", &s) == SEER_OK) {
    seer_stmt_set_array_size(s, 3);
    seer_stmt_set_batch_errors(s, 1);
    const int ids[3] = {5, 1, 6};
    for (int r = 0; r < 3; r++) {
      seer_stmt_bind_row(s, r);
      seer_stmt_bind_int64(s, 1, ids[r]);
    }
    if (seer_stmt_execute(s) == SEER_OK) {
      two = seer_stmt_row_count(s);
      nerr = seer_stmt_batch_error_count(s);
      if (nerr > 0)
        seer_stmt_batch_error(s, 0, &erow, &ecode, NULL);
    }
  }
  seer_stmt_close(s);
  SeerStatus u = run("UPDATE seer_t8 SET txt = 'u' WHERE id > 2", &upd);
  SeerStatus dup = run("INSERT INTO seer_t8 VALUES (1, 'dup')", NULL);
  bool dup_ok = dup == SEER_EDB && seer_last_error(C) != NULL &&
                strncmp(seer_last_error(C), "ORA-00001", 9) == 0;
  SeerStatus miss = run("INSERT INTO seer_nope VALUES (1)", NULL);
  long off = seer_last_error_offset(C);
  query("SELECT COUNT(*) FROM seer_t8", 0, 0, n, sizeof n);
  run("DROP TABLE seer_t8", NULL);
  if (c1 == SEER_OK && one == 1 && three == 3 && two == 2 && nerr == 1 && erow == 1 && ecode == 1 &&
      u == SEER_OK && upd == 4 && dup_ok && miss == SEER_EDB && off == 12 && strcmp(n, "6") == 0)
    pass(name);
  else {
    snprintf(m, sizeof m,
             "create=%d one=%ld three=%ld two=%ld errs=%zu row=%u code=%u update=%d/%ld dup=%d "
             "missing=%d@%ld count=%s",
             (int)c1, one, three, two, nerr, erow, ecode, (int)u, upd, (int)dup, (int)miss, off, n);
    fail(name, m);
  }
}

/* COMMIT and ROLLBACK go as statements (8i has no TTI_COMMIT), and autocommit
 * commits after each DML. */
static void check_transactions(void)
{
  const char *name = "ROLLBACK, COMMIT and autocommit";
  char a[16], b[16], c[16];
  run("DROP TABLE seer_x8", NULL);
  run("CREATE TABLE seer_x8 (id NUMBER)", NULL);
  run("INSERT INTO seer_x8 VALUES (1)", NULL); /* autocommit: kept */
  seer_set_autocommit(C, 0);
  run("INSERT INTO seer_x8 VALUES (2)", NULL);
  query("SELECT COUNT(*) FROM seer_x8", 0, 0, a, sizeof a); /* 2, in the transaction */
  SeerStatus rb = seer_rollback(C);
  query("SELECT COUNT(*) FROM seer_x8", 0, 0, b, sizeof b); /* 1 */
  run("INSERT INTO seer_x8 VALUES (3)", NULL);
  SeerStatus cm = seer_commit(C);
  seer_set_autocommit(C, 1);
  query("SELECT COUNT(*) FROM seer_x8", 0, 0, c, sizeof c); /* 2 */
  run("DROP TABLE seer_x8", NULL);
  if (strcmp(a, "2") == 0 && rb == SEER_OK && strcmp(b, "1") == 0 && cm == SEER_OK &&
      strcmp(c, "2") == 0)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "in-txn=%s rollback=%d after=%s commit=%d end=%s", a, (int)rb, b, (int)cm,
             c);
    fail(name, m);
  }
}

/* ALTER SESSION's reply carries the session's NLS settings as keyword pairs
 * ahead of its status; and a CREATE whose object compiles with errors
 * succeeds with the compile-warning flag. */
static void check_alter_session_and_compile(void)
{
  const char *name = "ALTER SESSION, and a CREATE that compiles with errors";
  char y[16];
  SeerStatus as = run("ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY'", NULL);
  query("SELECT TO_CHAR(TO_DATE('2003-04-05', 'YYYY-MM-DD')) FROM dual", 0, 0, y, sizeof y);
  run("ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD HH24:MI:SS'", NULL);
  SeerStmt *s = NULL;
  SeerStatus cr = SEER_EPROTO;
  int warn = 0;
  if (seer_stmt_prepare(C, "CREATE OR REPLACE PROCEDURE seer_bad8 AS BEGIN nonsense; END;", &s) ==
      SEER_OK) {
    cr = seer_stmt_execute(s);
    warn = seer_stmt_compile_warning(s);
  }
  seer_stmt_close(s);
  run("DROP PROCEDURE seer_bad8", NULL);
  if (as == SEER_OK && strcmp(y, "2003") == 0 && cr == SEER_OK && warn)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "alter=%d '%s' create=%d warning=%d", (int)as, y, (int)cr, warn);
    fail(name, m);
  }
}

/* An OUT parameter's value as text into `out` ("NULL" for a NULL). */
static const char *out_text(SeerStmt *s, int param, char *out, size_t osz)
{
  const void *d = NULL;
  size_t len = 0;
  int isn = 0, isb = 0;
  if (seer_stmt_out_data(s, param, &d, &len, &isn, &isb) != SEER_OK)
    snprintf(out, osz, "(error)");
  else if (isn || d == NULL)
    snprintf(out, osz, "NULL");
  else
    snprintf(out, osz, "%.*s", (int)len, (const char *)d);
  return out;
}

/* PL/SQL blocks (seerdb PROTOCOL.md §19.13-19.14, #134): IN values inline,
 * OUT and IN OUT values back in one round trip, in the order the text names
 * the placeholders; a NULL and a never-assigned OUT; a 4000-character OUT,
 * whose reply spans packets; DECLARE; CALL ... INTO; a failing block. */
static void check_blocks(void)
{
  const char *name = "PL/SQL blocks: IN, OUT, IN OUT, CALL, a failing block";
  char a[32], b[32], c[32], d[32], e[80], f[4100], g[32], h[32];
  SeerStmt *s = NULL;
  a[0] = b[0] = c[0] = d[0] = e[0] = f[0] = g[0] = h[0] = '\0';
  if (seer_stmt_prepare(C, "BEGIN :1 := :2 * 2; :3 := 'got ' || :4; END;", &s) == SEER_OK) {
    seer_stmt_bind_out(s, 1, 2 /* NUMBER */, 22);
    seer_stmt_bind_int64(s, 2, 21);
    seer_stmt_bind_out(s, 3, 1 /* VARCHAR2 */, 100);
    seer_stmt_bind_text(s, 4, "caf\xc3\xa9", -1);
    if (seer_stmt_execute(s) == SEER_OK) {
      out_text(s, 1, a, sizeof a);
      out_text(s, 3, b, sizeof b);
    }
  }
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "BEGIN :1 := :1 + 1; END;", &s) == SEER_OK) {
    seer_stmt_bind_int64(s, 1, 41);
    seer_stmt_bind_set_inout(s, 1, 22);
    if (seer_stmt_execute(s) == SEER_OK)
      out_text(s, 1, c, sizeof c);
  }
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "BEGIN :2 := :1 || '-x'; END;", &s) == SEER_OK) {
    seer_stmt_bind_text(s, 1, "in", -1);
    seer_stmt_bind_out(s, 2, 1, 20);
    if (seer_stmt_execute(s) == SEER_OK)
      out_text(s, 2, d, sizeof d);
  }
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "BEGIN :1 := NULL; IF 1 = 0 THEN :2 := 5; END IF; END;", &s) ==
      SEER_OK) {
    seer_stmt_bind_out(s, 1, 1, 20);
    seer_stmt_bind_out(s, 2, 2, 22);
    if (seer_stmt_execute(s) == SEER_OK) {
      char x[32], y[32];
      snprintf(e, sizeof e, "%s/%s", out_text(s, 1, x, sizeof x), out_text(s, 2, y, sizeof y));
    }
  }
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "DECLARE v NUMBER := 3; BEGIN :1 := RPAD('w', 4000, 'w'); :2 := v; END;",
                        &s) == SEER_OK) {
    seer_stmt_bind_out(s, 1, 1, 4000);
    seer_stmt_bind_out(s, 2, 2, 22);
    if (seer_stmt_execute(s) == SEER_OK) {
      out_text(s, 1, f, sizeof f);
      out_text(s, 2, g, sizeof g);
    }
  }
  seer_stmt_close(s);
  s = NULL;
  run("CREATE OR REPLACE FUNCTION seer_nine8 RETURN NUMBER AS BEGIN RETURN 9; END;", NULL);
  if (seer_stmt_prepare(C, "CALL seer_nine8() INTO :1", &s) == SEER_OK) {
    seer_stmt_bind_out(s, 1, 2, 22);
    if (seer_stmt_execute(s) == SEER_OK)
      out_text(s, 1, h, sizeof h);
  }
  seer_stmt_close(s);
  run("DROP FUNCTION seer_nine8", NULL);
  SeerStatus bad = run("BEGIN no_such_proc; END;", NULL);
  bool bad_ok = bad == SEER_EDB && seer_last_error(C) != NULL &&
                strncmp(seer_last_error(C), "ORA-06550", 9) == 0;
  if (strcmp(a, "42") == 0 && strcmp(b, "got caf\xc3\xa9") == 0 && strcmp(c, "42") == 0 &&
      strcmp(d, "in-x") == 0 && strcmp(e, "NULL/NULL") == 0 && strlen(f) == 4000 &&
      strcmp(g, "3") == 0 && strcmp(h, "9") == 0 && bad_ok)
    pass(name);
  else {
    char m[512];
    snprintf(m, sizeof m, "'%s' '%s' '%s' '%s' '%s' len=%zu '%s' '%s' failing=%d", a, b, c, d, e,
             strlen(f), g, h, (int)bad);
    fail(name, m);
  }
}

/* DML RETURNING ... INTO runs as a block, as on 9i: the row's values come
 * back, and the row count; a statement that matched no row returns NULLs. */
static void check_returning(void)
{
  const char *name = "DML RETURNING ... INTO";
  char a[32] = "", b[32] = "", c[32] = "";
  long rows = -1, none = -1;
  run("DROP TABLE seer_r8", NULL);
  run("CREATE TABLE seer_r8 (id NUMBER, t VARCHAR2(20))", NULL);
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(
          C, "INSERT INTO seer_r8 VALUES (:1, 'seven') RETURNING id + 100, t INTO :2, :3", &s) ==
      SEER_OK) {
    seer_stmt_bind_int64(s, 1, 7);
    seer_stmt_bind_out(s, 2, 2, 22);
    seer_stmt_bind_out(s, 3, 1, 20);
    if (seer_stmt_execute(s) == SEER_OK) {
      rows = seer_stmt_row_count(s);
      out_text(s, 2, a, sizeof a);
      out_text(s, 3, b, sizeof b);
    }
  }
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "UPDATE seer_r8 SET id = id WHERE id = 999 RETURNING t INTO :1", &s) ==
      SEER_OK) {
    seer_stmt_bind_out(s, 1, 1, 20);
    if (seer_stmt_execute(s) == SEER_OK) {
      none = seer_stmt_row_count(s);
      out_text(s, 1, c, sizeof c);
    }
  }
  seer_stmt_close(s);
  run("DROP TABLE seer_r8", NULL);
  if (rows == 1 && strcmp(a, "107") == 0 && strcmp(b, "seven") == 0 && none == 0 &&
      strcmp(c, "NULL") == 0)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "rows=%ld '%s' '%s'; no match rows=%ld '%s'", rows, a, b, none, c);
    fail(name, m);
  }
}

int main(void)
{
  const char *port = getenv("SEER_TEST_PORT");
  SeerConnParams p = {
      .host = getenv("SEER_TEST_HOST"),
      .port = (uint16_t)(port ? atoi(port) : 1521),
      .service_name = getenv("SEER_TEST_SERVICE"),
      .username = getenv("SEER_TEST_USER"),
      .password = getenv("SEER_TEST_PASS"),
  };
  if (p.host == NULL || seer_connect(&p, &C) != SEER_OK) {
    printf("  SKIP 8i: not reachable (%s)\n",
           seer_last_error(NULL) ? seer_last_error(NULL) : "connect failed");
    printf("SUMMARY pass=0 fail=0 skip=1\n");
    return 0;
  }
  check_scalar_types();
  check_nulls_and_empty();
  check_multibatch();
  check_wide_describe();
  check_errors();
  check_latin1();
  check_long_sql();
  check_rowid();
  check_cursor_hygiene();
  check_binds();
  check_bind_refused();
  check_dml();
  check_transactions();
  check_alter_session_and_compile();
  check_blocks();
  check_returning();
  check_wrong_password(&p);
  seer_disconnect(C);
  printf("SUMMARY pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
  return fail_n > 0 ? 1 : 0;
}
