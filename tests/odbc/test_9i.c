/* Oracle 9i (field-version-2) core-API integration test.
 *
 * 9i speaks the legacy fv2 dialect (O3LOGON auth + the TTI_ALL7 query/DML/PLSQL
 * path + the two-call TTI_LOBOPS LOB read), which the containerized 10g-23ai
 * matrix never exercises. It is validated ONLY here, against a local 9i VM (9i
 * can't be containerized - it needs an old kernel/glibc - so this is deliberately
 * local-only; it is not part of any GitHub CI).
 *
 * Driven through the core seer_* API (not the ODBC DM): 9i is addressed by SID
 * (it predates service-name routing), so set SEER_TEST_SID. Self-gating: if the
 * 9i VM is unreachable, every check skips and the process exits 0.
 *
 * Env: SEER_TEST_HOST, SEER_TEST_PORT, SEER_TEST_SID, SEER_TEST_USER,
 *      SEER_TEST_PASS.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "seer/seertns.h"

#define T_VARCHAR 1
#define T_NUMBER 2

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
static void skip(const char *n, const char *w)
{
  printf("  SKIP %s: %s\n", n, w);
  skip_n++;
}

static SeerConn *C;

/* Best-effort DDL/DML (setup); ignore "table does not exist" on pre-drops. */
static void run(const char *sql)
{
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK) {
    seer_stmt_execute(s);
    seer_stmt_close(s);
  }
}

/* First column of the first row as text, into `out` (empty on failure). */
static void scalar(const char *sql, char *out, size_t osz)
{
  out[0] = '\0';
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int isn = 0;
    if (seer_stmt_get_string(s, 0, &v, &isn) == SEER_OK && v)
      snprintf(out, osz, "%s", v);
  }
  seer_stmt_close(s);
}

/* ---- checks ---- */

static void check_select_scalar(void)
{
  char out[64];
  scalar("SELECT 42 FROM dual", out, sizeof out);
  if (strcmp(out, "42") == 0)
    pass("SELECT scalar");
  else {
    char m[96];
    snprintf(m, sizeof m, "got '%s'", out);
    fail("SELECT scalar", m);
  }
}

static void check_zero_length_columns(void)
{
  /* A bare NULL / '' is described with MaxLen 0 and the row carries only the
   * NULL indicator (81 01) for it - no value bytes; the next column must still
   * decode. */
  const char *name = "zero-length columns (NULL / '')";
  SeerStmt *s = NULL;
  const char *a = NULL, *b = NULL, *t = NULL;
  int na = 0, nb = 0, nt = 0, ok = 0;
  if (seer_stmt_prepare(C, "SELECT NULL, '', 'tail' FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK &&
      seer_stmt_get_string(s, 0, &a, &na) == SEER_OK &&
      seer_stmt_get_string(s, 1, &b, &nb) == SEER_OK &&
      seer_stmt_get_string(s, 2, &t, &nt) == SEER_OK)
    ok = na && nb && !nt && t && strcmp(t, "tail") == 0;
  if (ok)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "null=%d/%d tail='%s'", na, nb, t ? t : "(none)");
    fail(name, m);
  }
  seer_stmt_close(s);
}

static void check_select_table(void)
{
  /* A dictionary view: VARCHAR + NUMBER, multiple rows, real NOT-NULL columns
   * (the fv2 describe null_ok path). */
  const char *name = "SELECT multi-col/row (dictionary)";
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C,
                        "SELECT username, user_id FROM all_users "
                        "WHERE rownum <= 5 ORDER BY user_id",
                        &s) != SEER_OK ||
      seer_stmt_execute(s) != SEER_OK) {
    fail(name, seer_last_error(C) ? seer_last_error(C) : "prepare/exec");
    seer_stmt_close(s);
    return;
  }
  int rows = 0, ok = 1;
  while (seer_stmt_fetch(s) == SEER_OK) {
    const char *u = NULL, *id = NULL;
    int n = 0;
    seer_stmt_get_string(s, 0, &u, &n);
    seer_stmt_get_string(s, 1, &id, &n);
    if (u == NULL || u[0] == '\0' || id == NULL)
      ok = 0; /* SYS etc. non-empty */
    rows++;
  }
  seer_stmt_close(s);
  if (ok && rows >= 1)
    pass(name);
  else {
    char m[64];
    snprintf(m, sizeof m, "%d rows, ok=%d", rows, ok);
    fail(name, m);
  }
}

static void check_dml_binds(void)
{
  const char *name = "DDL + DML + binds round-trip";
  char out[64];
  run("DROP TABLE seer9t");
  run("CREATE TABLE seer9t (id NUMBER, nm VARCHAR2(20))");
  SeerStmt *s = NULL;
  int inserts_ok = 1;
  const char *names[] = {"alice", "bob", "carol"};
  for (int i = 0; i < 3; i++) {
    s = NULL;
    if (seer_stmt_prepare(C, "INSERT INTO seer9t (id, nm) VALUES (:1, :2)", &s) != SEER_OK ||
        seer_stmt_bind_int64(s, 1, (i + 1) * 10) != SEER_OK ||
        seer_stmt_bind_text(s, 2, names[i], -1) != SEER_OK || seer_stmt_execute(s) != SEER_OK)
      inserts_ok = 0;
    seer_stmt_close(s);
  }
  s = NULL;
  int update_ok =
      seer_stmt_prepare(C, "UPDATE seer9t SET nm='robert' WHERE id=:1", &s) == SEER_OK &&
      seer_stmt_bind_int64(s, 1, 20) == SEER_OK && seer_stmt_execute(s) == SEER_OK;
  seer_stmt_close(s);
  /* SELECT back with a bind on the WHERE; sum ids >= 10 = 60, robert present. */
  long sum = 0;
  int has_robert = 0;
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT id, nm FROM seer9t WHERE id >= :1 ORDER BY id", &s) == SEER_OK &&
      seer_stmt_bind_int64(s, 1, 10) == SEER_OK && seer_stmt_execute(s) == SEER_OK) {
    while (seer_stmt_fetch(s) == SEER_OK) {
      const char *id = NULL, *nm = NULL;
      int n = 0;
      seer_stmt_get_string(s, 0, &id, &n);
      seer_stmt_get_string(s, 1, &nm, &n);
      sum += id ? atol(id) : 0;
      if (nm && strcmp(nm, "robert") == 0)
        has_robert = 1;
    }
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9t");
  if (inserts_ok && update_ok && sum == 60 && has_robert)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "ins=%d upd=%d sum=%ld robert=%d", inserts_ok, update_ok, sum,
             has_robert);
    fail(name, m);
    (void)out;
  }
}

static void check_plsql(void)
{
  /* Block with an OUT NUMBER (:1 := 42*2 => 84). */
  {
    const char *name = "PL/SQL block OUT (number)";
    SeerStmt *s = NULL;
    seer_stmt_prepare(C, "BEGIN :1 := 42 * 2; END;", &s);
    SeerStatus b = seer_stmt_bind_out(s, 1, T_NUMBER, 22);
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    const void *d = NULL;
    size_t l = 0;
    int isn = 0, isb = 0;
    seer_stmt_out_data(s, 1, &d, &l, &isn, &isb);
    if (e == SEER_OK && d && strcmp((const char *)d, "84") == 0)
      pass(name);
    else
      fail(name, e ? (seer_last_error(C) ? seer_last_error(C) : "exec") : "wrong OUT");
    seer_stmt_close(s);
  }

  /* Block with IN + OUT VARCHAR (:2 := :1 || '_x'). */
  {
    const char *name = "PL/SQL block IN+OUT (varchar)";
    SeerStmt *s = NULL;
    seer_stmt_prepare(C, "BEGIN :2 := :1 || '_x'; END;", &s);
    seer_stmt_bind_text(s, 1, "hi", -1);
    SeerStatus b = seer_stmt_bind_out(s, 2, T_VARCHAR, 100);
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    const void *d = NULL;
    size_t l = 0;
    int isn = 0, isb = 0;
    seer_stmt_out_data(s, 2, &d, &l, &isn, &isb);
    if (e == SEER_OK && d && strcmp((const char *)d, "hi_x") == 0)
      pass(name);
    else
      fail(name, e ? (seer_last_error(C) ? seer_last_error(C) : "exec") : "wrong OUT");
    seer_stmt_close(s);
  }
}

static void check_block_directions(void)
{
  /* An IN OUT bind: the block reads it and assigns it. The bind prompt's masks
   * say so; sending no value for it (it's declared OUT) gave the block NULL. */
  {
    const char *name = "PL/SQL block IN OUT (number)";
    SeerStmt *s = NULL;
    seer_stmt_prepare(C, "BEGIN :1 := :1 + 1; END;", &s);
    SeerStatus b = seer_stmt_bind_int64(s, 1, 41);
    if (b == SEER_OK)
      b = seer_stmt_bind_set_inout(s, 1, 22);
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    const void *d = NULL;
    size_t l = 0;
    int isn = 0, isb = 0;
    seer_stmt_out_data(s, 1, &d, &l, &isn, &isb);
    if (e == SEER_OK && !isn && d && strcmp((const char *)d, "42") == 0)
      pass(name);
    else
      fail(name, e ? (seer_last_error(C) ? seer_last_error(C) : "exec") : "wrong IN OUT value");
    seer_stmt_close(s);
  }
  /* Declared IN OUT but only read by the block: the masks say IN only, so it
   * gets a value sent and none back - counting it as an output shifted :1's
   * value (seerdb/seerdb@c730f2b). */
  {
    const char *name = "PL/SQL block: IN OUT bind the block only reads";
    SeerStmt *s = NULL;
    seer_stmt_prepare(C, "BEGIN :1 := :2 * 10; END;", &s);
    SeerStatus b = seer_stmt_bind_out(s, 1, T_NUMBER, 22);
    if (b == SEER_OK)
      b = seer_stmt_bind_int64(s, 2, 5);
    if (b == SEER_OK)
      b = seer_stmt_bind_set_inout(s, 2, 22);
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    const void *d = NULL;
    size_t l = 0;
    int isn = 0, isb = 0;
    seer_stmt_out_data(s, 1, &d, &l, &isn, &isb);
    if (e == SEER_OK && !isn && d && strcmp((const char *)d, "50") == 0)
      pass(name);
    else
      fail(name, e ? (seer_last_error(C) ? seer_last_error(C) : "exec") : "wrong OUT value");
    seer_stmt_close(s);
  }
}

static void check_lob(void)
{
  run("DROP TABLE seer9l");
  run("CREATE TABLE seer9l (c CLOB, b BLOB)");
  run("INSERT INTO seer9l VALUES (RPAD(TO_CLOB('c'), 5000, 'c'), HEXTORAW('cafe1234babe'))");
  seer_commit(C);
  char out[64];
  scalar("SELECT c FROM seer9l", out, sizeof out);
  /* 5000-char CLOB spans multiple TTI_LOBOPS READ chunks. */
  {
    SeerStmt *s = NULL;
    long len = -1;
    if (seer_stmt_prepare(C, "SELECT LENGTH(c) FROM seer9l", &s) == SEER_OK &&
        seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
      const char *v = NULL;
      int n = 0;
      seer_stmt_get_string(s, 0, &v, &n);
      len = v ? atol(v) : -1;
    }
    seer_stmt_close(s);
    if (len == 5000 && out[0] == 'c')
      pass("CLOB read (5000, chunked)");
    else {
      char m[64];
      snprintf(m, sizeof m, "len=%ld head=%c", len, out[0] ? out[0] : '?');
      fail("CLOB read (5000, chunked)", m);
    }
  }
  /* BLOB read: 6 bytes. */
  {
    SeerStmt *s = NULL;
    size_t blen = 0;
    int ok = 0;
    if (seer_stmt_prepare(C, "SELECT b FROM seer9l", &s) == SEER_OK &&
        seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
      const void *d = NULL;
      int isn = 0, isb = 0;
      seer_stmt_get_data(s, 0, &d, &blen, &isn, &isb);
      ok = (blen == 6 && isb == 1);
    }
    seer_stmt_close(s);
    if (ok)
      pass("BLOB read");
    else {
      char m[48];
      snprintf(m, sizeof m, "len=%zu", blen);
      fail("BLOB read", m);
    }
  }
  run("DROP TABLE seer9l");
}

static void check_bfile(void)
{
  /* Needs the local fixture DIRECTORY BFDIR -> a dir holding hello.bin
   * ("BFILE-9i-content" + ca fe ba be, 20 bytes). Skips if not present. */
  const char *name = "BFILE read (BFDIR/hello.bin)";
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, "SELECT BFILENAME('BFDIR','hello.bin') FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const void *d = NULL;
    size_t len = 0;
    int isn = 0, isb = 0;
    seer_stmt_get_data(s, 0, &d, &len, &isn, &isb);
    if (len == 20 && d && memcmp(d, "BFILE-9i-content", 16) == 0)
      pass(name);
    else if (len == 0)
      skip(name, "BFDIR/hello.bin fixture not present");
    else {
      char m[64];
      snprintf(m, sizeof m, "len=%zu", len);
      fail(name, m);
    }
  } else {
    skip(name, "BFDIR directory not available");
  }
  seer_stmt_close(s);
}

static void check_national(void)
{
  /* U+00C4 and U+4E2D: the first has a Latin-1 form, the second has none, so
   * any detour through the WE8ISO8859P1 database charset shows. */
  static const char text[] = "\xC3\x84\xE4\xB8\xAD-9i";
  const char *name = "national charset: NVARCHAR2 bind + fetch, UNISTR";
  char out[64], lit[64];
  run("DROP TABLE seer9n");
  run("CREATE TABLE seer9n (n NVARCHAR2(20))");
  SeerStmt *s = NULL;
  SeerStatus b = SEER_EPARAM, e = SEER_EPARAM;
  if (seer_stmt_prepare(C, "INSERT INTO seer9n VALUES (:1)", &s) == SEER_OK) {
    b = seer_stmt_bind_ntext(s, 1, text, -1);
    e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
  }
  seer_stmt_close(s);
  seer_commit(C);
  /* The column itself, not TO_CHAR(n): a national value is fetched in the
   * national form, so it must come back whole. */
  scalar("SELECT n FROM seer9n", out, sizeof out);
  scalar("SELECT UNISTR('\\00C4\\4E2D') FROM dual", lit, sizeof lit);
  run("DROP TABLE seer9n");
  if (e == SEER_OK && strcmp(out, text) == 0 && strcmp(lit, "\xC3\x84\xE4\xB8\xAD") == 0)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "exec=%d column='%s' unistr='%s'", e, out, lit);
    fail(name, m);
  }
}

static void check_nullability(void)
{
  /* The fv2 describe null_ok field (§19.1 dispute; SeerODBC's ROOT_CAUSE fix).
   * A NOT-NULL and a nullable column must decode to distinct nullability -
   * the exact bug that garbled describe when read as a phantom ub4. */
  const char *name = "describe null_ok (NOT NULL vs nullable)";
  run("DROP TABLE seer9k");
  run("CREATE TABLE seer9k (a VARCHAR2(8) NOT NULL, b VARCHAR2(8))");
  SeerStmt *s = NULL;
  int ncols = 0, notnull = -1, nullable = -1;
  if (seer_stmt_prepare(C, "SELECT a, b FROM seer9k", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK) {
    ncols = seer_stmt_num_cols(s);
    notnull = seer_stmt_col_nullable(s, 0);  /* a NOT NULL -> 0 */
    nullable = seer_stmt_col_nullable(s, 1); /* b nullable  -> nonzero */
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9k");
  if (ncols == 2 && notnull == 0 && nullable != 0)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "ncols=%d notnull=%d nullable=%d", ncols, notnull, nullable);
    fail(name, m);
  }
}

static void check_null_fetch(void)
{
  /* A SQL NULL cell decodes to is_null (the 81 01 indicator), and a present
   * cell in the same row still reads correctly. */
  const char *name = "NULL cell fetch (indicator)";
  run("DROP TABLE seer9m");
  run("CREATE TABLE seer9m (id NUMBER, v VARCHAR2(10))");
  run("INSERT INTO seer9m VALUES (1, NULL)");
  seer_commit(C);
  SeerStmt *s = NULL;
  int id_ok = 0, v_null = 0, got = 0;
  if (seer_stmt_prepare(C, "SELECT id, v FROM seer9m", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *id = NULL, *v = NULL;
    int idn = 0, vn = 0;
    seer_stmt_get_string(s, 0, &id, &idn);
    seer_stmt_get_string(s, 1, &v, &vn);
    id_ok = (idn == 0 && id && strcmp(id, "1") == 0);
    v_null = (vn == 1 && v == NULL);
    got = 1;
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9m");
  if (got && id_ok && v_null)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "got=%d id_ok=%d v_null=%d", got, id_ok, v_null);
    fail(name, m);
  }
}

static void check_error_recovery(void)
{
  /* A server error must surface (not silently succeed) AND leave the
   * connection usable for the next statement - covers both the SQL error
   * path (ORA-00942) and the PL/SQL compile-error path (ORA-06550). */
  const char *name = "error surfaced + connection reusable";
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, "SELECT * FROM seer_no_such_table_9i", &s);
  SeerStatus ex = (st == SEER_OK) ? seer_stmt_execute(s) : st;
  int sql_err = (ex != SEER_OK);
  seer_stmt_close(s);

  s = NULL;
  st = seer_stmt_prepare(C, "BEGIN this_is_not_valid_plsql END;", &s);
  ex = (st == SEER_OK) ? seer_stmt_execute(s) : st;
  int plsql_err = (ex != SEER_OK);
  seer_stmt_close(s);

  /* The connection must still work after both failures. */
  char out[64];
  scalar("SELECT 7 FROM dual", out, sizeof out);
  if (sql_err && plsql_err && strcmp(out, "7") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "sql_err=%d plsql_err=%d after='%s'", sql_err, plsql_err, out);
    fail(name, m);
  }
}

static void check_multibatch_fetch(void)
{
  /* 200 rows in a real table span many fetch batches (fv2 re-sends the define
   * block per batch, ~10 rows each), exercising the RXH/batch-boundary loop. */
  const char *name = "multi-batch fetch (200 rows)";
  run("DROP TABLE seer9b");
  run("CREATE TABLE seer9b (id NUMBER)");
  run("INSERT INTO seer9b SELECT level FROM dual CONNECT BY level <= 200");
  seer_commit(C);
  SeerStmt *s = NULL;
  long rows = 0, sum = 0;
  if (seer_stmt_prepare(C, "SELECT id FROM seer9b ORDER BY id", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK) {
    while (seer_stmt_fetch(s) == SEER_OK) {
      const char *v = NULL;
      int n = 0;
      seer_stmt_get_string(s, 0, &v, &n);
      sum += v ? atol(v) : 0;
      rows++;
    }
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9b");
  /* 1..200 => 200 rows, sum 20100. */
  if (rows == 200 && sum == 20100)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "rows=%ld sum=%ld", rows, sum);
    fail(name, m);
  }
}

/* Many statements in one session, then a DDL. Each 9i statement used to OOPEN
 * a cursor of its own and leave it open. Past open_cursors the OOPEN itself
 * failed, unseen: plain queries still ran on cursor 1, but whatever needed the
 * server's own recursive SQL - a CREATE TABLE - failed with ORA-00604 /
 * ORA-01000. Queries, DML and blocks alternate, good and failing, 400 in all,
 * past this bed's open_cursors of 300. */
static void check_cursor_hygiene(void)
{
  const char *name = "400 statements, then a DDL, in one session (cursors closed)";
  static const char *const bad[] = {"SELECT * FROM seer9_no_such_table",
                                    "INSERT INTO seer9_no_such_table VALUES (1)",
                                    "BEGIN seer9_no_such_proc; END;"};
  long refused = 0, ok = 0;
  run("DROP TABLE seer9g");
  run("CREATE TABLE seer9g (n NUMBER)");
  for (int i = 0; i < 100; i++) {
    SeerStmt *s = NULL;
    if (seer_stmt_prepare(C, bad[i % 3], &s) != SEER_OK || seer_stmt_execute(s) != SEER_OK)
      refused++;
    seer_stmt_close(s);
    s = NULL;
    if (seer_stmt_prepare(C, "SELECT 1 FROM dual", &s) == SEER_OK &&
        seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK)
      ok++;
    seer_stmt_close(s);
    s = NULL;
    if (seer_stmt_prepare(C, "BEGIN NULL; END;", &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK)
      ok++;
    seer_stmt_close(s);
    s = NULL;
    if (seer_stmt_prepare(C, "UPDATE seer9g SET n = n + 1", &s) == SEER_OK &&
        seer_stmt_execute(s) == SEER_OK)
      ok++;
    seer_stmt_close(s);
  }
  run("DROP TABLE seer9g");
  run("DROP TABLE seer9h");
  SeerStmt *d = NULL;
  int ddl = seer_stmt_prepare(C, "CREATE TABLE seer9h (n NUMBER)", &d) == SEER_OK &&
            seer_stmt_execute(d) == SEER_OK;
  char err[256];
  snprintf(err, sizeof err, "%s", seer_last_error(C) ? seer_last_error(C) : "");
  seer_stmt_close(d);
  run("DROP TABLE seer9h");
  if (refused == 100 && ok == 300 && ddl)
    pass(name);
  else {
    char m[360];
    snprintf(m, sizeof m, "%ld/100 refused, %ld/300 ran, CREATE TABLE %s (%s)", refused, ok,
             ddl ? "ok" : "failed", err);
    fail(name, m);
  }
}

/* Array DML: three rows in one execute. The 9i parse carried only the first
 * row's values and a row count of 1, so one row went in and the rest were
 * dropped without an error (seerdb #2245: one RXD a row, the count in the
 * call's tail). */
static void check_array_dml(void)
{
  const char *name = "array DML (3 rows, one execute)";
  run("DROP TABLE seer9a");
  run("CREATE TABLE seer9a (n NUMBER, s VARCHAR2(10))");
  static const char *const txt[3] = {"one", "two", "three"};
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, "INSERT INTO seer9a VALUES (:1, :2)", &s);
  if (st == SEER_OK)
    st = seer_stmt_set_array_size(s, 3);
  for (int row = 0; row < 3 && st == SEER_OK; row++) {
    st = seer_stmt_bind_row(s, row);
    if (st == SEER_OK)
      st = seer_stmt_bind_int64(s, 1, row + 1);
    if (st == SEER_OK)
      st = seer_stmt_bind_text(s, 2, txt[row], -1);
  }
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  seer_stmt_close(s);
  seer_commit(C);
  char out[64] = "";
  scalar("SELECT COUNT(*) || ':' || SUM(n) || ':' || MAX(s) FROM seer9a", out, sizeof out);
  run("DROP TABLE seer9a");
  if (st == SEER_OK && strcmp(out, "3:6:two") == 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "status %d, got '%s' want '3:6:two' (%s)", (int)st, out,
             seer_last_error(C) ? seer_last_error(C) : "");
    fail(name, m);
  }
}

/* A LONG column comes back as its text: it fell to the unknown-type branch
 * and came back as hex, twice its length. */
static void check_long_fetch(void)
{
  const char *name = "LONG column (1000 chars) fetched as text";
  run("DROP TABLE seer9l");
  run("CREATE TABLE seer9l (l LONG)");
  run("INSERT INTO seer9l VALUES (RPAD('q', 999, 'q') || 'Z')");
  seer_commit(C);
  SeerStmt *s = NULL;
  size_t len = 0;
  char last = 0;
  if (seer_stmt_prepare(C, "SELECT l FROM seer9l", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int is_null = 0;
    seer_stmt_get_string(s, 0, &v, &is_null);
    len = v ? strlen(v) : 0;
    last = len ? v[len - 1] : 0;
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9l");
  if (len == 1000 && last == 'Z')
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "length %zu, last '%c' (want 1000, 'Z')", len, last ? last : '-');
    fail(name, m);
  }
}

/* Where in the statement an error is: 9i's status carries it as 10g+'s does
 * (seerdb #2263: `select nosuch from dual` is ORA-00904 at 7), and it was
 * never read. */
static void check_error_offset(void)
{
  const char *name = "error offset (ORA-00904 at 7)";
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, "SELECT nosuch FROM dual", &s);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  long off = seer_last_error_offset(C);
  const char *e = seer_last_error(C);
  int is904 = e != NULL && strncmp(e, "ORA-00904", 9) == 0;
  seer_stmt_close(s);
  if (st == SEER_EDB && is904 && off == 7)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "status %d, offset %ld, '%.60s'", (int)st, off, e ? e : "");
    fail(name, m);
  }
}

/* A CREATE whose object compiles with errors succeeds; only the status's
 * warning flags (0x20) say so (seerdb #2262). */
static void check_compile_warning(void)
{
  const char *name = "CREATE with compilation errors flagged";
  SeerStmt *s = NULL;
  int warned = -1, clean = -1;
  if (seer_stmt_prepare(C, "CREATE OR REPLACE PROCEDURE seer9w AS BEGIN no_such_thing; END;", &s) ==
          SEER_OK &&
      seer_stmt_execute(s) == SEER_OK)
    warned = seer_stmt_compile_warning(s);
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "CREATE OR REPLACE PROCEDURE seer9w AS BEGIN NULL; END;", &s) ==
          SEER_OK &&
      seer_stmt_execute(s) == SEER_OK)
    clean = seer_stmt_compile_warning(s);
  seer_stmt_close(s);
  run("DROP PROCEDURE seer9w");
  if (warned == 1 && clean == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "broken body warned=%d, clean body warned=%d (want 1, 0)", warned, clean);
    fail(name, m);
  }
}

/* Array DML in batch-errors mode: a failing row no longer aborts the execute;
 * the good rows apply and each failure comes back with its row (seerdb #2247,
 * whose capture this is: 1, 2, 1, 4, 5 into a primary key, ORA-00001 at row
 * 2). Without it the first failure aborted the batch. */
static void check_batch_errors(void)
{
  const char *name = "array DML batch errors (ORA-00001 at row 2)";
  run("DROP TABLE seer9e");
  run("CREATE TABLE seer9e (n NUMBER PRIMARY KEY)");
  static const int vals[5] = {1, 2, 1, 4, 5};
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, "INSERT INTO seer9e VALUES (:1)", &s);
  if (st == SEER_OK)
    st = seer_stmt_set_array_size(s, 5);
  if (st == SEER_OK)
    st = seer_stmt_set_batch_errors(s, 1);
  for (int row = 0; row < 5 && st == SEER_OK; row++) {
    st = seer_stmt_bind_row(s, row);
    if (st == SEER_OK)
      st = seer_stmt_bind_int64(s, 1, vals[row]);
  }
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  size_t n = seer_stmt_batch_error_count(s);
  unsigned erow = 99, ecode = 0;
  const char *emsg = NULL;
  if (n > 0)
    seer_stmt_batch_error(s, 0, &erow, &ecode, &emsg);
  char msg[64] = ""; /* the message is the statement's: copy it before the close */
  snprintf(msg, sizeof msg, "%s", emsg ? emsg : "");
  seer_stmt_close(s);
  seer_commit(C);
  char out[32] = "";
  scalar("SELECT COUNT(*) || ':' || SUM(n) FROM seer9e", out, sizeof out);
  run("DROP TABLE seer9e");
  int msg_ok = strncmp(msg, "ORA-00001", 9) == 0;
  if (st == SEER_OK && n == 1 && erow == 2 && ecode == 1 && msg_ok && strcmp(out, "4:12") == 0)
    pass(name);
  else {
    char m[240];
    snprintf(m, sizeof m,
             "status %d, %zu error(s), first row %u code %u '%.40s', table '%s' (want 4:12)",
             (int)st, n, erow, ecode, msg, out);
    fail(name, m);
  }
}

/* A prepared query is described before it executes (SQLPrepare, then
 * SQLNumResultCols / SQLDescribeCol), placeholders and all: a parse without
 * the EXECUTE bit needs no bind values, where with it 9i answered ORA-01008.
 * The execute that follows, with its bind, still returns the row. */
static void check_describe_before_execute(void)
{
  const char *name = "describe before execute, with a placeholder";
  SeerStmt *s = NULL;
  SeerStatus st =
      seer_stmt_prepare(C, "SELECT 42 AS answer, 'x' AS letter FROM dual WHERE 1 = :1", &s);
  if (st == SEER_OK)
    st = seer_stmt_describe(s);
  int described = seer_stmt_num_cols(s);
  const char *cname = seer_stmt_col_name(s, 1);
  char col2[32] = "";
  snprintf(col2, sizeof col2, "%s", cname ? cname : "");
  SeerStatus dst = st;
  if (st == SEER_OK)
    st = seer_stmt_bind_int64(s, 1, 1);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  char v[16] = "";
  if (st == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *val = NULL;
    int is_null = 0;
    seer_stmt_get_string(s, 0, &val, &is_null);
    snprintf(v, sizeof v, "%s", val ? val : "");
  }
  seer_stmt_close(s);
  if (dst == SEER_OK && described == 2 && strcmp(col2, "LETTER") == 0 && st == SEER_OK &&
      strcmp(v, "42") == 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "describe %d (%d cols, col 2 '%s'), execute %d value '%s' (%s)", (int)dst,
             described, col2, (int)st, v, seer_last_error(C) ? seer_last_error(C) : "");
    fail(name, m);
  }
}

/* DML RETURNING ... INTO: 9.2 refuses it in a plain statement (ORA-00439),
 * so it runs as an anonymous block whose INTO targets are OUT binds, and an
 * appended bind brings back SQL%ROWCOUNT (seerdb #801) - the block's own count
 * is 1 whatever the DML touched. One UPDATE matching a row, one matching none. */
static void check_returning(void)
{
  const char *name = "DML RETURNING ... INTO, with the row count";
  run("DROP TABLE seer9r");
  run("CREATE TABLE seer9r (id NUMBER, v VARCHAR2(20))");
  run("INSERT INTO seer9r VALUES (7, 'seven')");
  seer_commit(C);
  long rows[2] = {-1, -1};
  char got[2][32] = {"", ""};
  SeerStatus sts[2] = {SEER_EPARAM, SEER_EPARAM};
  for (int k = 0; k < 2; k++) {
    SeerStmt *s = NULL;
    SeerStatus st = seer_stmt_prepare(
        C, "UPDATE seer9r SET v = v || '!' WHERE id = :1 RETURNING id + 100, v INTO :2, :3", &s);
    if (st == SEER_OK)
      st = seer_stmt_bind_int64(s, 1, k == 0 ? 7 : 8);
    if (st == SEER_OK)
      st = seer_stmt_bind_out(s, 2, 2, 22);
    if (st == SEER_OK)
      st = seer_stmt_bind_out(s, 3, 1, 20);
    if (st == SEER_OK)
      st = seer_stmt_execute(s);
    sts[k] = st;
    if (st == SEER_OK) {
      rows[k] = seer_stmt_row_count(s);
      const void *a = NULL, *b = NULL;
      size_t al = 0, bl = 0;
      int an = 0, bn = 0, ab = 0, bb = 0;
      seer_stmt_out_data(s, 2, &a, &al, &an, &ab);
      seer_stmt_out_data(s, 3, &b, &bl, &bn, &bb);
      snprintf(got[k], sizeof got[k], "%.*s:%.*s", an ? 4 : (int)al, an ? "NULL" : (const char *)a,
               bn ? 4 : (int)bl, bn ? "NULL" : (const char *)b);
    }
    seer_stmt_close(s);
  }
  seer_commit(C);
  run("DROP TABLE seer9r");
  if (sts[0] == SEER_OK && rows[0] == 1 && strcmp(got[0], "107:seven!") == 0 && sts[1] == SEER_OK &&
      rows[1] == 0 && strcmp(got[1], "NULL:NULL") == 0)
    pass(name);
  else {
    char m[240];
    snprintf(m, sizeof m, "match: %d, %ld row(s), '%s'; no match: %d, %ld row(s), '%s' (%s)",
             (int)sts[0], rows[0], got[0], (int)sts[1], rows[1], got[1],
             seer_last_error(C) ? seer_last_error(C) : "");
    fail(name, m);
  }
}

/* Text binds past 4000 bytes: 9.2 has no form for one in a plain statement,
 * and takes it in a PL/SQL block, declared VARCHAR 32767 (seerdb PROTOCOL.md
 * §19.3.1), so such a DML runs as a block. A 5000-byte value goes into a CLOB
 * ahead of a NUMBER bind (the two must not swap), the row count is the DML's,
 * and past the 32512 bytes measured to work the bind is refused. */
static void check_long_text_bind(void)
{
  const char *name = "text bind over 4000 bytes into a CLOB (5000; 32513 refused)";
  run("DROP TABLE seer9t");
  run("CREATE TABLE seer9t (c CLOB, id NUMBER)");
  static char big[32514];
  memset(big, 'x', sizeof big - 1);
  big[sizeof big - 1] = '\0';
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, "INSERT INTO seer9t (c, id) VALUES (:1, :2)", &s);
  if (st == SEER_OK)
    st = seer_stmt_bind_text(s, 1, big, 5000);
  if (st == SEER_OK)
    st = seer_stmt_bind_int64(s, 2, 42);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  long rows = st == SEER_OK ? seer_stmt_row_count(s) : -1;
  seer_stmt_close(s);
  s = NULL;
  SeerStatus too_long = seer_stmt_prepare(C, "INSERT INTO seer9t (c, id) VALUES (:1, :2)", &s);
  if (too_long == SEER_OK)
    too_long = seer_stmt_bind_text(s, 1, big, 32513);
  if (too_long == SEER_OK)
    too_long = seer_stmt_bind_int64(s, 2, 43);
  if (too_long == SEER_OK)
    too_long = seer_stmt_execute(s);
  seer_stmt_close(s);
  seer_commit(C);
  char out[32] = "";
  scalar("SELECT COUNT(*) || ':' || MAX(id) || ':' || MAX(DBMS_LOB.GETLENGTH(c)) FROM seer9t", out,
         sizeof out);
  run("DROP TABLE seer9t");
  if (st == SEER_OK && rows == 1 && strcmp(out, "1:42:5000") == 0 && too_long == SEER_ENOTIMPL)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m,
             "5000: status %d, %ld row(s); 32513: status %d; table '%s' (want 1:42:5000)", (int)st,
             rows, (int)too_long, out);
    fail(name, m);
  }
}

static void check_date_bind(void)
{
  /* DATE bind (fv2 OAC type 12/7) round-trips to second precision. */
  const char *name = "DATE bind + fetch";
  char out[64];
  run("DROP TABLE seer9d");
  run("CREATE TABLE seer9d (d DATE)");
  SeerStmt *s = NULL;
  SeerStatus e = SEER_EPARAM;
  if (seer_stmt_prepare(C, "INSERT INTO seer9d VALUES (:1)", &s) == SEER_OK &&
      seer_stmt_bind_date(s, 1, 2026, 7, 4, 13, 30, 15) == SEER_OK)
    e = seer_stmt_execute(s);
  seer_stmt_close(s);
  seer_commit(C);
  scalar("SELECT TO_CHAR(d, 'YYYY-MM-DD HH24:MI:SS') FROM seer9d", out, sizeof out);
  run("DROP TABLE seer9d");
  if (e == SEER_OK && strcmp(out, "2026-07-04 13:30:15") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "exec=%d got '%s'", e, out);
    fail(name, m);
  }
}

static void check_raw_bind(void)
{
  /* RAW bind (fv2 OAC type 23) round-trips as binary. */
  const char *name = "RAW bind + fetch";
  const uint8_t raw[] = {0xca, 0xfe, 0xba, 0xbe};
  run("DROP TABLE seer9r");
  run("CREATE TABLE seer9r (r RAW(8))");
  SeerStmt *s = NULL;
  SeerStatus e = SEER_EPARAM;
  if (seer_stmt_prepare(C, "INSERT INTO seer9r VALUES (:1)", &s) == SEER_OK &&
      seer_stmt_bind_raw(s, 1, raw, (int)sizeof raw) == SEER_OK)
    e = seer_stmt_execute(s);
  seer_stmt_close(s);
  seer_commit(C);
  int ok = 0;
  size_t len = 0;
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT r FROM seer9r", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const void *d = NULL;
    int isn = 0, isb = 0;
    seer_stmt_get_data(s, 0, &d, &len, &isn, &isb);
    ok = (len == sizeof raw && isb == 1 && d && memcmp(d, raw, sizeof raw) == 0);
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9r");
  if (e == SEER_OK && ok)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "exec=%d ok=%d len=%zu", e, ok, len);
    fail(name, m);
  }
}

static void check_rollback(void)
{
  /* With autocommit off, an uncommitted INSERT is discarded by rollback;
   * a committed one survives. (fv2 DML has no autocommit bit - the driver
   * commits explicitly, so rollback must actually reach the server.) */
  const char *name = "rollback discards uncommitted DML";
  run("DROP TABLE seer9x");
  run("CREATE TABLE seer9x (id NUMBER)"); /* DDL implicitly commits */
  seer_set_autocommit(C, 0);
  SeerStmt *s = NULL;
  int ins1 = 0;
  if (seer_stmt_prepare(C, "INSERT INTO seer9x VALUES (:1)", &s) == SEER_OK &&
      seer_stmt_bind_int64(s, 1, 1) == SEER_OK)
    ins1 = (seer_stmt_execute(s) == SEER_OK);
  seer_stmt_close(s);
  seer_rollback(C);
  char after_rb[32];
  scalar("SELECT COUNT(*) FROM seer9x", after_rb, sizeof after_rb);
  /* Now a committed insert must persist. */
  s = NULL;
  if (seer_stmt_prepare(C, "INSERT INTO seer9x VALUES (:1)", &s) == SEER_OK &&
      seer_stmt_bind_int64(s, 1, 2) == SEER_OK)
    seer_stmt_execute(s);
  seer_stmt_close(s);
  seer_commit(C);
  char after_cm[32];
  scalar("SELECT COUNT(*) FROM seer9x", after_cm, sizeof after_cm);
  seer_set_autocommit(C, 1);
  run("DROP TABLE seer9x");
  if (ins1 && strcmp(after_rb, "0") == 0 && strcmp(after_cm, "1") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "ins1=%d after_rb='%s' after_cm='%s'", ins1, after_rb, after_cm);
    fail(name, m);
  }
}

/* A rowid column is defined as its text (the native form desyncs the 9i row
 * stream, ORA-01002), and a UROWID at its full 5267 characters: an IOT's
 * logical rowid holds the key, and a 900-character key gives a 1212-character
 * rowid, which must come back whole and bind back to its row. */
static void check_rowid(void)
{
  const char *name = "ROWID / UROWID fetched as text";
  char rid[64] = "", tail[16] = "";
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, "SELECT ROWID, 'tail' FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 0, &v, &n) == SEER_OK && v)
      snprintf(rid, sizeof rid, "%s", v);
    if (seer_stmt_get_string(s, 1, &v, &n) == SEER_OK && v)
      snprintf(tail, sizeof tail, "%s", v);
  }
  seer_stmt_close(s);

  run("DROP TABLE seer9iot");
  run("CREATE TABLE seer9iot (k VARCHAR2(1000) PRIMARY KEY, v NUMBER) ORGANIZATION INDEX");
  run("INSERT INTO seer9iot VALUES (RPAD('k', 900, 'x'), 7)");
  char *urowid = NULL;
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT ROWID FROM seer9iot", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 0, &v, &n) == SEER_OK && v)
      urowid = strdup(v);
  }
  seer_stmt_close(s);
  char back[16] = "";
  s = NULL;
  if (urowid != NULL &&
      seer_stmt_prepare(C, "SELECT v FROM seer9iot WHERE ROWID = :1", &s) == SEER_OK &&
      seer_stmt_bind_text(s, 1, urowid, -1) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 0, &v, &n) == SEER_OK && v)
      snprintf(back, sizeof back, "%s", v);
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9iot");

  size_t ulen = urowid ? strlen(urowid) : 0;
  free(urowid);
  if (strlen(rid) == 18 && strcmp(tail, "tail") == 0 && ulen == 1212 && strcmp(back, "7") == 0)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "rowid='%s' tail='%s' urowid len=%zu bound back='%s'", rid, tail, ulen,
             back);
    fail(name, m);
  }
}

/* The describe's column count and the execute's define count are ub4s: 300
 * columns are `02 01 2c`, which one byte cannot carry. A column named by an
 * expression longer than 255 bytes has its name chunked. */
static void check_wide_select(void)
{
  const char *name = "300-column SELECT + long column name";
  char sql[4096];
  /* "SELECT 1 c1,2 c2,...,300 c300 FROM dual" (about 2.7 KB) */
  strcpy(sql, "SELECT ");
  for (int i = 1; i <= 300; i++) {
    char item[24];
    snprintf(item, sizeof item, "%s%d c%d", i > 1 ? "," : "", i, i);
    strncat(sql, item, sizeof sql - strlen(sql) - 1);
  }
  strncat(sql, " FROM dual", sizeof sql - strlen(sql) - 1);
  int ncols = 0;
  char last[16] = "";
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    ncols = seer_stmt_num_cols(s);
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 299, &v, &n) == SEER_OK && v)
      snprintf(last, sizeof last, "%s", v);
  }
  seer_stmt_close(s);

  char a[151], b[151];
  memset(a, 'a', 150);
  memset(b, 'b', 150);
  a[150] = b[150] = '\0';
  snprintf(sql, sizeof sql, "SELECT '%s' || '%s', 'tail' FROM dual", a, b);
  size_t vlen = 0;
  char tail[16] = "";
  s = NULL;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 0, &v, &n) == SEER_OK && v)
      vlen = strlen(v);
    if (seer_stmt_get_string(s, 1, &v, &n) == SEER_OK && v)
      snprintf(tail, sizeof tail, "%s", v);
  }
  seer_stmt_close(s);

  if (ncols == 300 && strcmp(last, "300") == 0 && vlen == 300 && strcmp(tail, "tail") == 0)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "ncols=%d last='%s' long value=%zu tail='%s'", ncols, last, vlen, tail);
    fail(name, m);
  }
}

/* An ORA message past 64 bytes comes in 64-byte chunks (0xFE ... 00): it must
 * reach the connection's error text whole, not as its last chunk. */
static void check_long_error_text(void)
{
  const char *name = "long ORA message text (chunked)";
  run("DROP TABLE seer9_a_rather_long_table_name");
  run("CREATE TABLE seer9_a_rather_long_table_name (a_long_column_name_here NUMBER NOT NULL)");
  SeerStmt *s = NULL;
  SeerStatus st = SEER_OK;
  if (seer_stmt_prepare(C, "INSERT INTO seer9_a_rather_long_table_name VALUES (NULL)", &s) ==
      SEER_OK)
    st = seer_stmt_execute(s);
  seer_stmt_close(s);
  const char *e = seer_last_error(C);
  const char *want =
      "ORA-01400: cannot insert NULL into (\"PYO\".\"SEER9_A_RATHER_LONG_TABLE_NAME\""
      ".\"A_LONG_COLUMN_NAME_HERE\")";
  int ok = st != SEER_OK && e != NULL && strncmp(e, want, strlen(want)) == 0;
  char m[300];
  snprintf(m, sizeof m, "status=%d text='%s'", (int)st, e ? e : "(none)");
  run("DROP TABLE seer9_a_rather_long_table_name");
  if (ok)
    pass(name);
  else
    fail(name, m);
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

int main(void)
{
  const char *port = getenv("SEER_TEST_PORT");
  const char *sid = getenv("SEER_TEST_SID");
  SeerConnParams p = {
      .host = getenv("SEER_TEST_HOST"),
      .port = (uint16_t)(port ? atoi(port) : 1526),
      .sid = (sid && sid[0]) ? sid : NULL,
      .service_name = getenv("SEER_TEST_SERVICE"),
      .username = getenv("SEER_TEST_USER"),
      .password = getenv("SEER_TEST_PASS"),
  };
  if (seer_connect(&p, &C) != SEER_OK) {
    /* Local-only: the 9i VM isn't reachable -> report nothing ran, exit clean. */
    printf("  SKIP 9i: VM not reachable (%s)\n",
           seer_last_error(NULL) ? seer_last_error(NULL) : "connect failed");
    printf("SUMMARY pass=0 fail=0 skip=1\n");
    return 0;
  }

  check_select_scalar();
  check_zero_length_columns();
  check_select_table();
  check_wide_select();
  check_nullability();
  check_null_fetch();
  check_dml_binds();
  check_date_bind();
  check_raw_bind();
  check_rowid();
  check_multibatch_fetch();
  check_error_recovery();
  check_long_error_text();
  check_rollback();
  check_plsql();
  check_block_directions();
  check_lob();
  check_bfile();
  check_national();
  check_array_dml();
  check_long_fetch();
  check_error_offset();
  check_compile_warning();
  check_batch_errors();
  check_describe_before_execute();
  check_returning();
  check_long_text_bind();
  check_cursor_hygiene();
  check_wrong_password(&p);

  seer_disconnect(C);
  printf("SUMMARY pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
  return fail_n > 0 ? 1 : 0;
}
