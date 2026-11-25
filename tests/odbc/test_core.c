/* The core-API live suite: one set of checks for every tier, 8i to 26ai
 * (#148). Driven through the seer_* API, not the ODBC Driver Manager.
 *
 * Every tier runs every check; one that can't apply to the connected release
 * is a SKIP with its reason (GATES below, tests/odbc/gates.h): what the
 * release lacks ("server: ...") or what SeerODBC doesn't reach yet ("todo:
 * ..." and the issue). Where only the expected outcome differs by release,
 * the check branches on g_release.
 *
 * The feature modules core_*.c (two-phase commit, request boundaries,
 * sessionless transactions, pipelining, object binds, AQ) are part of the
 * suite: they share its verdicts and GATES through core.h.
 *
 * Env: SEER_TEST_RELEASE (required: 8, 9, 10, 11, 18, 21, 23, 26 - the
 * matrix knows each tier), SEER_TEST_HOST, SEER_TEST_PORT, SEER_TEST_SID or
 * SEER_TEST_SERVICE, SEER_TEST_USER, SEER_TEST_PASS. Run by
 * tests/odbc/run-matrix.sh and, in CI, as the meson test 'core API (live)'.
 * Without SEER_TEST_HOST it exits 77 (skipped); an unreachable server is one
 * SKIP and exit 0.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netcompat.h" /* gethostname(): <unistd.h> on POSIX, Winsock on Windows */

#include "seer/seertns.h"

#include "core.h"
#include "gates.h"

#define T_VARCHAR 1
#define T_NUMBER 2
#define T_RAW 23
#define T_REFCURSOR 102

static int pass_n, fail_n, skip_n;
void pass(const char *n)
{
  printf("  PASS %s\n", n);
  pass_n++;
}
void fail(const char *n, const char *w)
{
  printf("  FAIL %s: %s\n", n, w);
  fail_n++;
}
void skip(const char *n, const char *w)
{
  printf("  SKIP %s: %s\n", n, w);
  skip_n++;
}

/* The checks each release skips (gates.h), and the features several checks
 * share. Ordered as the checks run. */
static const Gate GATES[] = {
    {"national charset: NVARCHAR2 bind + fetch, UNISTR", 8, 8, GATE_SERVER,
     "8.1.7's national charset is WE8ISO8859P1, and it has no UNISTR"},
    /* core_tpc.c */
    /* core_reqbound.c */
    {"request boundaries", 8, 18, GATE_SERVER, "no request boundaries before 21c"},
    /* core_sessionless.c */
    {"sessionless transactions", 8, 21, GATE_SERVER, "no sessionless transactions before 23ai"},
    /* core_objbind.c */
    {"a 400-row query with a CURSOR() column", 10, 26, GATE_SERVER,
     "from 10g the server holds each nested cursor while its query is open (ORA-01000)"},
    {"package record bind", 8, 11, GATE_SERVER,
     "package-level PL/SQL types bind only from 12.1: no client can before (#193)"},
    {"package record nesting a record bind", 8, 11, GATE_SERVER,
     "package-level PL/SQL types bind only from 12.1: no client can before (#193)"},
    {"package nested table bind", 8, 11, GATE_SERVER,
     "package-level PL/SQL types bind only from 12.1: no client can before (#193)"},
    {"package index-by table bind", 8, 11, GATE_SERVER,
     "package-level PL/SQL types bind only from 12.1: no client can before (#193)"},
    {"package record OUT bind", 8, 11, GATE_SERVER,
     "package-level PL/SQL types bind only from 12.1: no client can before (#193)"},
    {"index-by table OUT bind", 8, 11, GATE_SERVER,
     "package-level PL/SQL types bind only from 12.1: no client can before (#193)"},
    {"assoc-array bind (NUMBER)", 9, 9, GATE_TODO,
     "9i compact: no reference client binds an associative array (#254)"},
    {"assoc-array bind (VARCHAR)", 9, 9, GATE_TODO,
     "9i compact: no reference client binds an associative array (#254)"},
    {"OUT assoc-array (NUMBER)", 9, 9, GATE_TODO,
     "9i compact: no reference client binds an associative array (#254)"},
    {"OUT assoc-array (VARCHAR)", 9, 9, GATE_TODO,
     "9i compact: no reference client binds an associative array (#254)"},
    {"TIMESTAMP / WITH TIME ZONE / LTZ / DATE attribute bind", 8, 8, GATE_SERVER,
     "8.1.7 has no TIMESTAMP"},
    {"NVARCHAR2 object attribute + element bind", 8, 8, GATE_SERVER,
     "8.1.7's national charset is WE8ISO8859P1"},
    {"native JSON bind", 8, 18, GATE_SERVER, "no JSON type before 21c"},
    {"native VECTOR bind", 8, 21, GATE_SERVER, "no VECTOR type before 23ai"},
    {"XMLType bind", 8, 8, GATE_SERVER, "8.1.7 has no XMLType"},
    {"SQL OBJECT with a BOOLEAN attribute", 8, 21, GATE_SERVER, "no BOOLEAN type before 23ai"},
    /* core_aq.c */
    {"AQ JSON payload", 8, 18, GATE_SERVER, "no JSON queues before 21c"},
};

int feature_gated(const char *gate)
{
  return gate_find(GATES, sizeof GATES / sizeof GATES[0], gate) != NULL;
}

int gated_as(const char *gate, const char *name)
{
  /* The check's own gate first, then the feature's it falls under. */
  const Gate *g = gate_find(GATES, sizeof GATES / sizeof GATES[0], name);
  if (g == NULL && strcmp(gate, name) != 0)
    g = gate_find(GATES, sizeof GATES / sizeof GATES[0], gate);
  if (g == NULL)
    return 0;
  char why[256];
  gate_reason(g, why, sizeof why);
  skip(name, why);
  return 1;
}

static SeerConn *C;
static SeerConnParams P; /* the suite's connection parameters, for core_connect() */

SeerConn *core_connect(void)
{
  SeerConn *c = NULL;
  return seer_connect(&P, &c) == SEER_OK ? c : NULL;
}

SeerConn *core_connect_xa(void)
{
  SeerConnParams p = P;
  p.xa = 1;
  SeerConn *c = NULL;
  return seer_connect(&p, &c) == SEER_OK ? c : NULL;
}

/* Whether this account can read V$SESSION: a grant some beds lack. */
static bool can_read_v_session(void);

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

/* Columns the server describes with size 0 but that are defined at a fixed
 * size - TO_NUMBER(NULL), 1 + NULL, TO_DATE(NULL) - come with a cell in the
 * row; taken as carrying none, the reader fell a cell behind and the fetch
 * failed with ORA-01002 (#156). Beside them a bare NULL, which carries none. */
static void check_zero_size_numbers(void)
{
  const char *name = "zero-size NUMBER / DATE columns (TO_NUMBER(NULL), 1 + NULL)";
  SeerStmt *s = NULL;
  int isn[5] = {-1, -1, -1, -1, -1};
  char x[8] = "";
  SeerStatus st = SEER_EPROTO;
  if (seer_stmt_prepare(C, "SELECT NULL, 'x', TO_NUMBER(NULL), 1 + NULL, TO_DATE(NULL) FROM dual",
                        &s) == SEER_OK &&
      (st = seer_stmt_execute(s)) == SEER_OK && seer_stmt_fetch(s) == SEER_OK)
    for (int i = 0; i < 5; i++) {
      const char *v = NULL;
      seer_stmt_get_string(s, i, &v, &isn[i]);
      if (i == 1 && v != NULL)
        snprintf(x, sizeof x, "%s", v);
    }
  seer_stmt_close(s);
  if (st == SEER_OK && isn[0] == 1 && isn[1] == 0 && strcmp(x, "x") == 0 && isn[2] == 1 &&
      isn[3] == 1 && isn[4] == 1)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "status %d, null flags %d%d%d%d%d, '%s'", (int)st, isn[0], isn[1], isn[2],
             isn[3], isn[4], x);
    fail(name, m);
  }
}

/* A query that fails as its rows are made: the fetch's reply carries the
 * error, and its text reaches the caller - taken after the reply was freed,
 * it had none (#159) - and the session goes on. */
static void check_fetch_error_text(void)
{
  const char *name = "a query failing at fetch (ORA-01476) reports its error";
  SeerStmt *s = NULL;
  SeerStatus st = SEER_OK;
  char err[128] = "", after[8] = "";
  if (seer_stmt_prepare(C, "SELECT 1 / (ROWNUM - 3) FROM all_objects WHERE ROWNUM <= 5", &s) ==
      SEER_OK)
    st = seer_stmt_execute(s);
  if (seer_last_error(C) != NULL)
    snprintf(err, sizeof err, "%s", seer_last_error(C));
  seer_stmt_close(s);
  scalar("SELECT 1 FROM dual", after, sizeof after);
  if (st == SEER_EDB && strncmp(err, "ORA-01476", 9) == 0 && strcmp(after, "1") == 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "status %d '%s', then '%s'", (int)st, err, after);
    fail(name, m);
  }
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

  /* Block with IN + OUT VARCHAR, labels out of order: binds go by order of
   * appearance (#146), so position 1 is :2, the target, and position 2 is :1. */
  {
    const char *name = "PL/SQL block IN+OUT (varchar)";
    SeerStmt *s = NULL;
    seer_stmt_prepare(C, "BEGIN :2 := :1 || '_x'; END;", &s);
    SeerStatus b = seer_stmt_bind_out(s, 1, T_VARCHAR, 100);
    seer_stmt_bind_text(s, 2, "hi", -1);
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    const void *d = NULL;
    size_t l = 0;
    int isn = 0, isb = 0;
    seer_stmt_out_data(s, 1, &d, &l, &isn, &isb);
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
  /* The 5000 characters go as a bind: 8.1.7 has no TO_CLOB. */
  {
    static char cs[5001];
    memset(cs, 'c', 5000);
    cs[5000] = '\0';
    SeerStmt *ins = NULL;
    if (seer_stmt_prepare(C, "INSERT INTO seer9l VALUES (:1, HEXTORAW('cafe1234babe'))", &ins) ==
        SEER_OK) {
      seer_stmt_bind_text(ins, 1, cs, -1);
      seer_stmt_execute(ins);
    }
    seer_stmt_close(ins);
  }
  seer_commit(C);
  char out[64];
  scalar("SELECT c FROM seer9l", out, sizeof out);
  /* 5000-char CLOB spans multiple TTI_LOBOPS READ chunks. */
  {
    SeerStmt *s = NULL;
    long len = -1;
    if (seer_stmt_prepare(C, "SELECT DBMS_LOB.GETLENGTH(c) FROM seer9l", &s) == SEER_OK &&
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

static void check_national(void)
{
  /* U+00C4 and U+4E2D: the first has a Latin-1 form, the second has none, so
   * any detour through the WE8ISO8859P1 database charset shows. */
  static const char text[] = "\xC3\x84\xE4\xB8\xAD-9i";
  const char *name = "national charset: NVARCHAR2 bind + fetch, UNISTR";
  GATE(name);
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
  /* ROWNUM over a big view, not CONNECT BY level: 8.1.7 hasn't that. */
  run("INSERT INTO seer9b SELECT ROWNUM FROM all_objects WHERE ROWNUM <= 200");
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
  GATE(name);
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

/* An array UPDATE ... RETURNING: 8i and 9i run it a row at a time (#418),
 * so the row counts add up and the OUT bind keeps the last matching row's
 * value, as the last RXD of a 10g+ array RETURNING does. Ids 1, 9, 3: the
 * middle row matches nothing. */
static void check_array_returning(void)
{
  const char *name = "array DML RETURNING ... INTO (row count, last row's value)";
  run("DROP TABLE seer9ra");
  run("CREATE TABLE seer9ra (id NUMBER, v VARCHAR2(20))");
  run("INSERT INTO seer9ra VALUES (1, 'a')");
  run("INSERT INTO seer9ra VALUES (3, 'c')");
  seer_commit(C);
  static const int ids[3] = {1, 9, 3};
  SeerStmt *s = NULL;
  SeerStatus st =
      seer_stmt_prepare(C, "UPDATE seer9ra SET v = v || '!' WHERE id = :1 RETURNING v INTO :2", &s);
  if (st == SEER_OK)
    st = seer_stmt_set_array_size(s, 3);
  for (int row = 0; row < 3 && st == SEER_OK; row++) {
    st = seer_stmt_bind_row(s, row);
    if (st == SEER_OK)
      st = seer_stmt_bind_int64(s, 1, ids[row]);
    if (st == SEER_OK)
      st = seer_stmt_bind_out(s, 2, 1, 20);
  }
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  long rows = -1;
  char got[32] = "";
  if (st == SEER_OK) {
    rows = seer_stmt_row_count(s);
    const void *v = NULL;
    size_t vl = 0;
    int vn = 0, vb = 0;
    seer_stmt_out_data(s, 2, &v, &vl, &vn, &vb);
    snprintf(got, sizeof got, "%.*s", vn ? 4 : (int)vl, vn ? "NULL" : (const char *)v);
  }
  char err[160] = "";
  snprintf(err, sizeof err, "%s", seer_last_error(C) ? seer_last_error(C) : "");
  seer_stmt_close(s);
  seer_commit(C);
  char out[32] = "";
  scalar("SELECT MIN(v) || ':' || MAX(v) FROM seer9ra", out, sizeof out);
  run("DROP TABLE seer9ra");
  if (st == SEER_OK && rows == 2 && strcmp(got, "c!") == 0 && strcmp(out, "a!:c!") == 0)
    pass(name);
  else {
    char m[320];
    snprintf(m, sizeof m, "status %d, %ld row(s), OUT '%s', table '%s' (want 2, 'c!', 'a!:c!') %s",
             (int)st, rows, got, out, err);
    fail(name, m);
  }
}

/* One national-text bind (seer_stmt_bind_ntext) in `sql`; the first cell as
 * text, or "status N: error". */
static void ntext_scalar(const char *sql, const char *v, char *out, size_t osz)
{
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, sql, &s);
  if (st == SEER_OK)
    st = seer_stmt_bind_ntext(s, 1, v, -1);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  const char *cell = NULL;
  int is_null = 0;
  if (st == SEER_OK && seer_stmt_fetch(s) == SEER_OK)
    seer_stmt_get_string(s, 0, &cell, &is_null);
  if (st == SEER_OK)
    snprintf(out, osz, "%s", cell ? cell : (is_null ? "NULL" : ""));
  else
    snprintf(out, osz, "status %d: %s", (int)st, seer_last_error(C) ? seer_last_error(C) : "");
  seer_stmt_close(s);
}

/* National text binds meet NCHAR values: 8.1.7 won't mix a plain text bind
 * with one (ORA-12704), so a national bind goes with the national form there
 * too (#419). One INSERT binds a VARCHAR2 column as text and an NVARCHAR2 one
 * as national text: 8.1.7 wants each form to match its target, both ways.
 * Only characters WE8ISO8859P1 has, the 8i bed's national charset. */
static void check_national_bind(void)
{
  const char *name = "national text bind meets NCHAR values and fills an NVARCHAR2";
  char m[400] = "", got[96];
  ntext_scalar("SELECT COUNT(*) FROM dual WHERE N'ab\xc3\xa9' = :1", "ab\xc3\xa9", got, sizeof got);
  if (strcmp(got, "1") != 0)
    snprintf(m, sizeof m, "N'...' = :1: '%s' (want 1)", got);
  if (m[0] == '\0') {
    ntext_scalar("SELECT N'ab' || :1 FROM dual", "c\xc3\xa9", got, sizeof got);
    if (strcmp(got, "abc\xc3\xa9") != 0)
      snprintf(m, sizeof m, "N'ab' || :1: '%s' (want 'abc\xc3\xa9')", got);
  }
  if (m[0] == '\0') {
    run("DROP TABLE seer9n");
    run("CREATE TABLE seer9n (v VARCHAR2(10), n NVARCHAR2(10))");
    SeerStmt *s = NULL;
    SeerStatus st = seer_stmt_prepare(C, "INSERT INTO seer9n VALUES (:1, :2)", &s);
    if (st == SEER_OK)
      st = seer_stmt_bind_text(s, 1, "v\xc3\xa9", -1);
    if (st == SEER_OK)
      st = seer_stmt_bind_ntext(s, 2, "n\xc3\xa9", -1);
    if (st == SEER_OK)
      st = seer_stmt_execute(s);
    if (st != SEER_OK)
      snprintf(m, sizeof m, "INSERT: status %d: %s", (int)st,
               seer_last_error(C) ? seer_last_error(C) : "");
    seer_stmt_close(s);
    seer_commit(C);
    if (m[0] == '\0') {
      scalar("SELECT v || '/' || TO_CHAR(n) FROM seer9n", got, sizeof got);
      if (strcmp(got, "v\xc3\xa9/n\xc3\xa9") != 0)
        snprintf(m, sizeof m, "read back '%s' (want 'v\xc3\xa9/n\xc3\xa9')", got);
    }
    run("DROP TABLE seer9n");
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A query with an array of parameter sets is refused on every tier
 * (SEER_ENOTIMPL, with the reason as the last error) rather than answering
 * one set's rows (#430); the connection goes on. */
static void check_array_query_refused(void)
{
  const char *name = "array execute of a query: refused, the connection usable";
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, "SELECT :1 * 10 FROM dual", &s);
  if (st == SEER_OK)
    st = seer_stmt_set_array_size(s, 3);
  for (int row = 0; row < 3 && st == SEER_OK; row++) {
    st = seer_stmt_bind_row(s, row);
    if (st == SEER_OK)
      st = seer_stmt_bind_int64(s, 1, row + 1);
  }
  SeerStatus ex = st == SEER_OK ? seer_stmt_execute(s) : st;
  char why[160] = "";
  snprintf(why, sizeof why, "%s", seer_last_error(C) ? seer_last_error(C) : "");
  seer_stmt_close(s);
  char out[16] = "";
  scalar("SELECT 7 * 6 FROM dual", out, sizeof out);
  if (ex == SEER_ENOTIMPL && strstr(why, "array of parameter sets") != NULL &&
      strcmp(out, "42") == 0)
    pass(name);
  else {
    char m[260];
    snprintf(m, sizeof m, "status %d '%s', then '%s' (want %d, then 42)", (int)ex, why, out,
             (int)SEER_ENOTIMPL);
    fail(name, m);
  }
}

/* Batch errors on an array that 9i runs a row at a time (text past 4000
 * bytes goes in a PL/SQL block, #418): the failing row is recorded at its
 * offset with its error and the other rows go in. */
static void check_array_long_batch_errors(void)
{
  const char *name = "array DML batch errors with text over 4000 bytes";
  run("DROP TABLE seer9el");
  run("CREATE TABLE seer9el (n NUMBER PRIMARY KEY, c CLOB)");
  static const int vals[4] = {1, 2, 1, 4};
  static char big[5001];
  memset(big, 'y', sizeof big - 1);
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, "INSERT INTO seer9el VALUES (:1, :2)", &s);
  if (st == SEER_OK)
    st = seer_stmt_set_array_size(s, 4);
  if (st == SEER_OK)
    st = seer_stmt_set_batch_errors(s, 1);
  for (int row = 0; row < 4 && st == SEER_OK; row++) {
    st = seer_stmt_bind_row(s, row);
    if (st == SEER_OK)
      st = seer_stmt_bind_int64(s, 1, vals[row]);
    if (st == SEER_OK)
      st = seer_stmt_bind_text(s, 2, big, 5000);
  }
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  size_t n = seer_stmt_batch_error_count(s);
  unsigned erow = 99, ecode = 0;
  const char *emsg = NULL;
  if (n > 0)
    seer_stmt_batch_error(s, 0, &erow, &ecode, &emsg);
  char msg[64] = "";
  snprintf(msg, sizeof msg, "%s", emsg ? emsg : "");
  seer_stmt_close(s);
  seer_commit(C);
  char out[32] = "";
  scalar("SELECT COUNT(*) || ':' || SUM(n) || ':' || SUM(DBMS_LOB.GETLENGTH(c)) FROM seer9el", out,
         sizeof out);
  run("DROP TABLE seer9el");
  int msg_ok = strncmp(msg, "ORA-00001", 9) == 0;
  if (st == SEER_OK && n == 1 && erow == 2 && ecode == 1 && msg_ok && strcmp(out, "3:7:15000") == 0)
    pass(name);
  else {
    char m[240];
    snprintf(m, sizeof m,
             "status %d, %zu error(s), first row %u code %u '%.40s', table '%s' (want 3:7:15000)",
             (int)st, n, erow, ecode, msg, out);
    fail(name, m);
  }
}

/* Text binds past 4000 bytes: 9.2 has no form for one in a plain statement,
 * and takes it in a PL/SQL block, declared VARCHAR 32767 (seerdb PROTOCOL.md
 * §19.3.1), so such a DML runs as a block; past 32512 bytes, as a temporary
 * LOB (#169). A 5000-byte value goes into a CLOB ahead of a NUMBER bind (the
 * two must not swap), the row count is the DML's, and so does a 32513-byte
 * one. */
static void check_long_text_bind(void)
{
  const char *name = "text bind over 4000 bytes into a CLOB (5000 and 32513)";
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
  const char *want = "2:43:32513";
  if (st == SEER_OK && rows == 1 && strcmp(out, want) == 0 && too_long == SEER_OK)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "5000: status %d, %ld row(s); 32513: status %d; table '%s' (want %s)",
             (int)st, rows, (int)too_long, out, want);
    fail(name, m);
  }
}

/* RAW binds past 2000 bytes take the same route as long text: a PL/SQL block,
 * declared RAW 32767, values up to 32512 bytes, past that a temporary BLOB
 * (seerdb PROTOCOL.md §19.3.1, #169). */
static void check_long_raw_bind(void)
{
  const char *name = "RAW bind over 2000 bytes into a BLOB (5000 and 32513)";
  run("DROP TABLE seer9w");
  run("CREATE TABLE seer9w (b BLOB, id NUMBER)");
  static unsigned char big[32513];
  for (size_t i = 0; i < sizeof big; i++)
    big[i] = (unsigned char)(i * 7);
  SeerStatus sts[2] = {SEER_EPARAM, SEER_EPARAM};
  for (int k = 0; k < 2; k++) {
    SeerStmt *s = NULL;
    SeerStatus st = seer_stmt_prepare(C, "INSERT INTO seer9w (b, id) VALUES (:1, :2)", &s);
    if (st == SEER_OK)
      st = seer_stmt_bind_raw(s, 1, big, k == 0 ? 5000 : 32513);
    if (st == SEER_OK)
      st = seer_stmt_bind_int64(s, 2, 42 + k);
    if (st == SEER_OK)
      st = seer_stmt_execute(s);
    sts[k] = st;
    seer_stmt_close(s);
  }
  seer_commit(C);
  char out[64] = "";
  /* the length, the id, and the last byte: 4999 * 7 mod 256 = 0xB1 */
  scalar("SELECT COUNT(*) || ':' || MAX(id) || ':' || MAX(DBMS_LOB.GETLENGTH(b)) || ':' || "
         "MAX(RAWTOHEX(DBMS_LOB.SUBSTR(b, 1, 5000))) FROM seer9w",
         out, sizeof out);
  run("DROP TABLE seer9w");
  const char *want = "2:43:32513:B1";
  if (sts[0] == SEER_OK && sts[1] == SEER_OK && strcmp(out, want) == 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "5000: status %d; 32513: status %d; table '%s' (want %s)", (int)sts[0],
             (int)sts[1], out, want);
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
    char m[192];
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

/* A statement with a non-ASCII character in its text: 9i reads the SQL's
 * length in characters, and sent the byte count it waited for the rest and
 * the call hung (#140). A query, then a block, then the session goes on. */
static void check_non_ascii_sql(void)
{
  const char *name = "SQL text with a non-ASCII character (query and block)";
  char a[32], b[16], c[16];
  scalar("SELECT 'caf\xc3\xa9' || LENGTH('caf\xc3\xa9') FROM dual", a, sizeof a);
  SeerStmt *s = NULL;
  SeerStatus st = SEER_EPROTO;
  if (seer_stmt_prepare(C, "BEGIN :1 := LENGTH('d\xc3\xa9j\xc3\xa0'); END;", &s) == SEER_OK) {
    seer_stmt_bind_out(s, 1, 2 /* NUMBER */, 22);
    st = seer_stmt_execute(s);
    const void *d = NULL;
    size_t len = 0;
    int isn = 0, isb = 0;
    b[0] = '\0';
    if (st == SEER_OK && seer_stmt_out_data(s, 1, &d, &len, &isn, &isb) == SEER_OK && d != NULL)
      snprintf(b, sizeof b, "%.*s", (int)len, (const char *)d);
  }
  seer_stmt_close(s);
  scalar("SELECT 1 FROM dual", c, sizeof c);
  if (strcmp(a, "caf\xc3\xa9"
                "4") == 0 &&
      st == SEER_OK && strcmp(b, "4") == 0 && strcmp(c, "1") == 0)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "'%s' / block %d '%s' / then '%s'", a, (int)st, b, c);
    fail(name, m);
  }
}

/* The session names this client: program "seerodbc" and this machine, the
 * login's AUTH_PROGRAM_NM and AUTH_MACHINE (#123). JDBC thin's positional
 * login, sent until then, named every 9i session "JDBC Thin Client" on "o9i". */
/* A replay-corpus run (#396): the driver then sends a fixed host name and OS
 * user (src/tns/wire.c). */
static int wire_corpus_run(void)
{
  const char *r = getenv("SEER_WIRE_RECORD"), *p = getenv("SEER_WIRE_REPLAY");
  return (r != NULL && r[0] != '\0') || (p != NULL && p[0] != '\0');
}

static void check_session_identity(void)
{
  const char *name = "the session reports program seerodbc on this machine";
  if (!can_read_v_session()) {
    skip(name, "fixture: this account can't read V$SESSION");
    return;
  }
  char host[256];
  if (gethostname(host, sizeof host - 1) != 0) {
    skip(name, "gethostname failed");
    return;
  }
  host[sizeof host - 1] = '\0';
  /* A replay-corpus run sends a fixed host name (#396, src/tns/wire.c). */
  if (wire_corpus_run())
    snprintf(host, sizeof host, "seer-corpus");
  char prog[128], mach[256];
  scalar("SELECT program FROM v$session WHERE audsid = USERENV('SESSIONID')", prog, sizeof prog);
  scalar("SELECT machine FROM v$session WHERE audsid = USERENV('SESSIONID')", mach, sizeof mach);
  if (strcmp(prog, "seerodbc") == 0 && strcmp(mach, host) == 0) {
    pass(name);
  } else {
    char m[768];
    snprintf(m, sizeof m, "program '%s', machine '%s', want 'seerodbc' on '%s'", prog, mach, host);
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

/* ---- checks first written for 8i ---- */

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

/* Run a statement that returns no rows; its status, and its row count into
 * *rows when given. */
static SeerStatus run_rows(const char *sql, long *rows)
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
  if (!can_read_v_session()) {
    skip(name, "fixture: this account can't read V$SESSION");
    return;
  }
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
  /* 8i has no USERENV SID: the describe stops partway and the error follows.
   * From 9i the query is good, so only the session going on is checked. */
  if (g_release == 8) {
    if (seer_stmt_prepare(C, "SELECT * FROM v$session WHERE sid = sys_context('userenv','sid')",
                          &s) == SEER_OK &&
        seer_stmt_execute(s) != SEER_OK && seer_last_error(C))
      snprintf(e2, sizeof e2, "%s", seer_last_error(C));
    seer_stmt_close(s);
  } else
    snprintf(e2, sizeof e2, "ORA-02003 (8i only)");
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
  /* Non-ASCII text out and back, whatever the database charset: 8i's and
   * 9i's are WE8ISO8859P1, the containers' AL32UTF8. */
  const char *name = "non-ASCII text both ways";
  char a[32], b[32];
  query("SELECT '\xc3\xbc' || 'ber' FROM dual", 0, 0, a, sizeof a);
  query("SELECT LENGTH('\xc3\xa9t\xc3\xa9') FROM dual", 0, 0, b, sizeof b);
  if (strcmp(a, "\xc3\xbc"
                "ber") == 0 &&
      strcmp(b, "3") == 0)
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

static void check_rowid_column(void)
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
  /* A double and a float bind keep their value on every release: 10g+ bind
   * them as BINARY_DOUBLE / BINARY_FLOAT; 8i and 9i, which have neither, as
   * the NUMBER with the fewest digits that reads back the same (#151). There
   * NaN has no form and is refused, the session going on. */
  const char *name = "double and float binds keep their value";
  static const double vals[] = {0.1, 1.5, -2.5e-7, 123456789.125, 1e20};
  char m[160] = "";
  for (size_t i = 0; i < sizeof vals / sizeof vals[0] && m[0] == '\0'; i++) {
    SeerStmt *s = NULL;
    const char *v = NULL;
    int isn = 0;
    SeerStatus st = seer_stmt_prepare(C, "SELECT :1 FROM dual", &s);
    if (st == SEER_OK)
      st = seer_stmt_bind_double(s, 1, vals[i]);
    if (st == SEER_OK)
      st = seer_stmt_execute(s);
    if (st == SEER_OK && seer_stmt_fetch(s) == SEER_OK)
      seer_stmt_get_string(s, 0, &v, &isn);
    double back = v != NULL ? strtod(v, NULL) : 0; /* must be the same bits */
    if (st != SEER_OK || v == NULL || memcmp(&back, &vals[i], sizeof back) != 0)
      snprintf(m, sizeof m, "%.17g: status %d, read back '%s'", vals[i], (int)st, v ? v : "");
    seer_stmt_close(s);
  }
  if (m[0] == '\0') {
    SeerStmt *s = NULL;
    const char *v = NULL;
    int isn = 0;
    if (seer_stmt_prepare(C, "SELECT :1 FROM dual", &s) == SEER_OK &&
        seer_stmt_bind_float(s, 1, 2.25f) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
        seer_stmt_fetch(s) == SEER_OK)
      seer_stmt_get_string(s, 0, &v, &isn);
    if (v == NULL || strtof(v, NULL) != 2.25f)
      snprintf(m, sizeof m, "float 2.25: read back '%s'", v ? v : "");
    seer_stmt_close(s);
  }
  if (m[0] == '\0' && g_release < 10) {
    SeerStmt *s = NULL;
    SeerStatus st = SEER_OK;
    if (seer_stmt_prepare(C, "SELECT :1 FROM dual", &s) == SEER_OK) {
      st = seer_stmt_bind_double(s, 1, NAN);
      if (st == SEER_OK)
        st = seer_stmt_execute(s);
    }
    seer_stmt_close(s);
    char after[8];
    query("SELECT 1 FROM dual", 0, 0, after, sizeof after);
    if (st != SEER_ENOTIMPL || strcmp(after, "1") != 0)
      snprintf(m, sizeof m, "NaN: status %d (want refused), then '%s'", (int)st, after);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* DDL, DML with binds and an array INSERT (8i has no array DML: a row at a
 * time), batch errors, row counts and the error of a refused statement
 * (seerdb PROTOCOL.md §19.12, #133). */
static void check_dml(void)
{
  const char *name = "DDL, DML with binds, array INSERT, batch errors";
  char m[512] = "", n[16];
  run_rows("DROP TABLE seer_t8", NULL);
  SeerStatus c1 = run_rows("CREATE TABLE seer_t8 (id NUMBER PRIMARY KEY, txt VARCHAR2(20))", NULL);
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
  SeerStatus u = run_rows("UPDATE seer_t8 SET txt = 'u' WHERE id > 2", &upd);
  SeerStatus dup = run_rows("INSERT INTO seer_t8 VALUES (1, 'dup')", NULL);
  bool dup_ok = dup == SEER_EDB && seer_last_error(C) != NULL &&
                strncmp(seer_last_error(C), "ORA-00001", 9) == 0;
  SeerStatus miss = run_rows("INSERT INTO seer_nope VALUES (1)", NULL);
  long off = seer_last_error_offset(C);
  query("SELECT COUNT(*) FROM seer_t8", 0, 0, n, sizeof n);
  run_rows("DROP TABLE seer_t8", NULL);
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
  run_rows("DROP TABLE seer_x8", NULL);
  run_rows("CREATE TABLE seer_x8 (id NUMBER)", NULL);
  run_rows("INSERT INTO seer_x8 VALUES (1)", NULL); /* autocommit: kept */
  seer_set_autocommit(C, 0);
  run_rows("INSERT INTO seer_x8 VALUES (2)", NULL);
  query("SELECT COUNT(*) FROM seer_x8", 0, 0, a, sizeof a); /* 2, in the transaction */
  SeerStatus rb = seer_rollback(C);
  query("SELECT COUNT(*) FROM seer_x8", 0, 0, b, sizeof b); /* 1 */
  run_rows("INSERT INTO seer_x8 VALUES (3)", NULL);
  SeerStatus cm = seer_commit(C);
  seer_set_autocommit(C, 1);
  query("SELECT COUNT(*) FROM seer_x8", 0, 0, c, sizeof c); /* 2 */
  run_rows("DROP TABLE seer_x8", NULL);
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
  SeerStatus as = run_rows("ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY'", NULL);
  query("SELECT TO_CHAR(TO_DATE('2003-04-05', 'YYYY-MM-DD')) FROM dual", 0, 0, y, sizeof y);
  run_rows("ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD HH24:MI:SS'", NULL);
  SeerStmt *s = NULL;
  SeerStatus cr = SEER_EPROTO;
  int warn = 0;
  if (seer_stmt_prepare(C, "CREATE OR REPLACE PROCEDURE seer_bad8 AS BEGIN nonsense; END;", &s) ==
      SEER_OK) {
    cr = seer_stmt_execute(s);
    warn = seer_stmt_compile_warning(s);
  }
  seer_stmt_close(s);
  run_rows("DROP PROCEDURE seer_bad8", NULL);
  if (as == SEER_OK && strcmp(y, "2003") == 0 && cr == SEER_OK && warn)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "alter=%d '%s' create=%d warning=%d", (int)as, y, (int)cr, warn);
    fail(name, m);
  }
}

/* A commit refused by a deferred constraint is an error, ORA-02091, and it
 * ends that transaction: the next statement runs, and a valid row then
 * commits alone. The refusal once went unreported on 9i and later (#184), and
 * a 9i session that logged on with the XA names keeps the refused transaction,
 * failing the next commit too (#183). */
static void check_refused_commit(void)
{
  const char *name = "a commit refused by a deferred constraint is an error, and ends there";
  run_rows("DROP TABLE seer_defer", NULL);
  run_rows("CREATE TABLE seer_defer (n NUMBER CONSTRAINT seer_defer_pos CHECK (n > 0) "
           "DEFERRABLE INITIALLY DEFERRED)",
           NULL);
  seer_set_autocommit(C, 0);
  SeerStatus ins = run_rows("INSERT INTO seer_defer VALUES (-1)", NULL);
  SeerStatus com = seer_commit(C);
  const char *e = seer_last_error(C);
  int refused = com == SEER_EDB && e != NULL && strstr(e, "ORA-02091") != NULL;
  char one[16] = "";
  query("SELECT 1 FROM dual", 0, 0, one, sizeof one);
  SeerStatus ins2 = run_rows("INSERT INTO seer_defer VALUES (5)", NULL);
  SeerStatus com2 = seer_commit(C);
  if (com2 != SEER_OK)
    seer_rollback(C);
  seer_set_autocommit(C, 1);
  char kept[16] = "";
  query("SELECT COUNT(*) FROM seer_defer", 0, 0, kept, sizeof kept);
  run_rows("DROP TABLE seer_defer", NULL);
  if (ins == SEER_OK && refused && strcmp(one, "1") == 0 && ins2 == SEER_OK && com2 == SEER_OK &&
      strcmp(kept, "1") == 0)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "commit=%d refused=%d next='%s' insert=%d commit=%d kept='%s'", (int)com,
             refused, one, (int)ins2, (int)com2, kept);
    fail(name, m);
  }
}

/* PL/SQL OUT values past the inline limits - text past 4000 bytes, RAW past
 * 2000 - come back whole. 9i declares such an OUT at 32767, as a wide IN, and
 * returns it in the chunked long form (seerdb PROTOCOL.md §19.3.1, #189). */
static void check_wide_out(void)
{
  const char *name = "PL/SQL OUT past the inline limits: 5000-char text, 3000-byte RAW";
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(
      C, "BEGIN :1 := RPAD('x', 5000, 'y'); :2 := UTL_RAW.COPIES(HEXTORAW('A5'), 3000); END;", &s);
  if (st == SEER_OK)
    st = seer_stmt_bind_out(s, 1, T_VARCHAR, 5000);
  if (st == SEER_OK)
    st = seer_stmt_bind_out(s, 2, T_RAW, 3000);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  const void *t = NULL, *r = NULL;
  size_t tl = 0, rl = 0;
  int tn = 1, rn = 1, tb = 0, rb = 0;
  int ok = 0;
  if (st == SEER_OK && seer_stmt_out_data(s, 1, &t, &tl, &tn, &tb) == SEER_OK &&
      seer_stmt_out_data(s, 2, &r, &rl, &rn, &rb) == SEER_OK && !tn && !rn && tl == 5000 &&
      rl == 3000) {
    const char *tc = t;
    const uint8_t *rc = r;
    ok = tc[0] == 'x' && tc[4999] == 'y';
    for (size_t i = 0; ok && i < rl; i++)
      ok = rc[i] == 0xA5;
  }
  if (ok)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "st=%d text=%zu raw=%zu %.80s", (int)st, tl, rl,
             st != SEER_OK && seer_last_error(C) ? seer_last_error(C) : "");
    fail(name, m);
  }
  seer_stmt_close(s);
}

/* A REF CURSOR OUT bind's rows become the statement's result set. 9i frees
 * the cursor only on a close followed by a free (0x08); a close alone left
 * one open per block, ORA-01000 within open_cursors blocks (#166). */
static void check_refcursor_rounds(void)
{
  const char *name = "REF CURSOR OUT: its rows, 320 times on one session";
  GATE(name);
  int round = 0;
  long got = 0;
  SeerStatus st = SEER_OK;
  for (; round < 320 && st == SEER_OK; round++) {
    SeerStmt *s = NULL;
    st = seer_stmt_prepare(C, "BEGIN OPEN :1 FOR SELECT 7, 'seven' FROM dual; END;", &s);
    if (st == SEER_OK)
      st = seer_stmt_bind_out(s, 1, T_REFCURSOR, 0);
    if (st == SEER_OK)
      st = seer_stmt_execute(s);
    got = 0;
    while (st == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
      const char *v = NULL;
      int isnull = 0;
      if (seer_stmt_get_string(s, 0, &v, &isnull) == SEER_OK && v != NULL && atol(v) == 7)
        got++;
    }
    if (st == SEER_OK && got != 1)
      st = SEER_EPROTO;
    seer_stmt_close(s);
  }
  if (st == SEER_OK)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "round %d: st=%d rows=%ld %.80s", round, (int)st, got,
             seer_last_error(C) ? seer_last_error(C) : "");
    fail(name, m);
  }
}

/* A query whose 400 rows each hold a CURSOR() column: each row's nested
 * cursor is freed before the next fetch batch, so the query outlives
 * open_cursors (300 on the beds) on 9i (#196). */
static void check_cursor_column_rows(void)
{
  const char *name = "a 400-row query with a CURSOR() column";
  GATE(name);
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(
      C, "SELECT CURSOR(SELECT 1 FROM dual), rownum FROM all_objects WHERE rownum <= 400", &s);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  int rows = 0, nulls = 0;
  while (st == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int isnull = 0;
    rows++;
    if (seer_stmt_get_string(s, 0, &v, &isnull) == SEER_OK && isnull)
      nulls++;
  }
  seer_stmt_close(s);
  if (st == SEER_OK && rows == 400 && nulls == 400)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "st=%d rows=%d nulls=%d %.80s", (int)st, rows, nulls,
             st != SEER_OK && seer_last_error(C) ? seer_last_error(C) : "");
    fail(name, m);
  }
}

/* PL/SQL blocks (seerdb PROTOCOL.md §19.13-19.14, #134): IN values inline,
 * OUT and IN OUT values back in one round trip, bound by order of appearance
 * (#146); a NULL and a never-assigned OUT; a 4000-character OUT,
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
  /* Labels out of order: position 1 is :2, the target (#146). */
  if (seer_stmt_prepare(C, "BEGIN :2 := :1 || '-x'; END;", &s) == SEER_OK) {
    seer_stmt_bind_out(s, 1, 1, 20);
    seer_stmt_bind_text(s, 2, "in", -1);
    if (seer_stmt_execute(s) == SEER_OK)
      out_text(s, 1, d, sizeof d);
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
  run_rows("CREATE OR REPLACE FUNCTION seer_nine8 RETURN NUMBER AS BEGIN RETURN 9; END;", NULL);
  if (seer_stmt_prepare(C, "CALL seer_nine8() INTO :1", &s) == SEER_OK) {
    seer_stmt_bind_out(s, 1, 2, 22);
    if (seer_stmt_execute(s) == SEER_OK)
      out_text(s, 1, h, sizeof h);
  }
  seer_stmt_close(s);
  run_rows("DROP FUNCTION seer_nine8", NULL);
  SeerStatus bad = run_rows("BEGIN no_such_proc; END;", NULL);
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

/* CLOB and BLOB columns (seerdb PROTOCOL.md §19.15, #135): each read in one
 * TTI_LOBOPS READ after the rows are in; a CLOB's text comes in Latin-1. A
 * short value, an empty one, a NULL, and 5000 bytes. */
static void check_lobs(void)
{
  const char *name = "CLOB / BLOB columns: short, empty, NULL, 5000 bytes";
  char m[512] = "";
  run_rows("DROP TABLE seer_lob8", NULL);
  run_rows("CREATE TABLE seer_lob8 (id NUMBER, c CLOB, b BLOB)", NULL);
  run_rows("INSERT INTO seer_lob8 VALUES (1, 'short caf\xc3\xa9', HEXTORAW('0102FF'))", NULL);
  run_rows("INSERT INTO seer_lob8 VALUES (2, EMPTY_CLOB(), EMPTY_BLOB())", NULL);
  run_rows("INSERT INTO seer_lob8 VALUES (3, NULL, NULL)", NULL);
  static char big[5001];
  memset(big, 'q', 5000);
  big[5000] = '\0';
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, "INSERT INTO seer_lob8 VALUES (4, :1, NULL)", &s) == SEER_OK) {
    seer_stmt_bind_text(s, 1, big, -1);
    seer_stmt_execute(s);
  }
  seer_stmt_close(s);
  s = NULL;
  int ok = 0, rows = 0;
  if (seer_stmt_prepare(C, "SELECT c, b FROM seer_lob8 ORDER BY id", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK) {
    ok = 1;
    while (seer_stmt_fetch(s) == SEER_OK) {
      const void *cd = NULL, *bd = NULL;
      size_t cl = 0, bl = 0;
      int cn = 0, bn = 0, x = 0;
      seer_stmt_get_data(s, 0, &cd, &cl, &cn, &x);
      seer_stmt_get_data(s, 1, &bd, &bl, &bn, &x);
      rows++;
      bool row_ok = false;
      if (rows == 1)
        row_ok = !cn && cl == 11 && memcmp(cd, "short caf\xc3\xa9", 11) == 0 && !bn && bl == 3 &&
                 memcmp(bd, "\x01\x02\xff", 3) == 0;
      else if (rows == 2)
        row_ok = !cn && cl == 0 && !bn && bl == 0;
      else if (rows == 3)
        row_ok = cn && bn;
      else if (rows == 4)
        row_ok = !cn && cl == 5000 && ((const char *)cd)[4999] == 'q' && bn;
      if (!row_ok && ok) {
        snprintf(m, sizeof m, "row %d: clob null=%d len=%zu, blob null=%d len=%zu", rows, cn, cl,
                 bn, bl);
        ok = 0;
      }
    }
  } else
    snprintf(m, sizeof m, "%s", seer_last_error(C) ? seer_last_error(C) : "query failed");
  seer_stmt_close(s);
  run_rows("DROP TABLE seer_lob8", NULL);
  if (ok && rows == 4)
    pass(name);
  else {
    if (m[0] == '\0')
      snprintf(m, sizeof m, "%d rows", rows);
    fail(name, m);
  }
}

/* UROWID (seerdb PROTOCOL.md §19.10, #136): an index-organized table's
 * logical rowid in the '*'-prefixed form, which binds back as text to find
 * its row; a physical rowid held in a UROWID renders as the ROWID it is. */
static void check_urowid(void)
{
  const char *name = "UROWID: logical rowid round trip, physical as ROWID";
  char lr[128] = "", back[16] = "", u[64] = "", r[64] = "";
  run_rows("DROP TABLE seer_iot8", NULL);
  run_rows("CREATE TABLE seer_iot8 (id NUMBER PRIMARY KEY, v VARCHAR2(8)) ORGANIZATION INDEX",
           NULL);
  run_rows("INSERT INTO seer_iot8 VALUES (7, 'seven')", NULL);
  query("SELECT ROWID FROM seer_iot8 WHERE id = 7", 0, 0, lr, sizeof lr);
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, "SELECT v FROM seer_iot8 WHERE ROWID = :1", &s) == SEER_OK) {
    seer_stmt_bind_text(s, 1, lr, -1);
    bound_row(s, back, sizeof back);
  }
  seer_stmt_close(s);
  run_rows("DROP TABLE seer_iot8", NULL);
  run_rows("DROP TABLE seer_hp8", NULL);
  run_rows("CREATE TABLE seer_hp8 (id NUMBER)", NULL);
  run_rows("INSERT INTO seer_hp8 VALUES (1)", NULL);
  query("SELECT CAST(ROWID AS UROWID) FROM seer_hp8", 0, 0, u, sizeof u);
  query("SELECT ROWIDTOCHAR(ROWID) FROM seer_hp8", 0, 0, r, sizeof r);
  run_rows("DROP TABLE seer_hp8", NULL);
  if (lr[0] == '*' && strlen(lr) > 1 && strcmp(back, "seven") == 0 && u[0] != '\0' &&
      strcmp(u, r) == 0)
    pass(name);
  else {
    char m[320];
    snprintf(m, sizeof m, "logical '%s' -> '%s'; urowid '%s' rowid '%s'", lr, back, u, r);
    fail(name, m);
  }
}

/* The BFILE fixtures the beds have: a directory and a file whose content
 * starts with `head`. The 9i bed's BFDIR holds hello.bin (20 bytes); the 8i
 * bed's ZZ_SEERDB_BD is its bdump directory, whose alert log is always there;
 * the 11g container's SEERBFILE holds hello.txt. */
static const struct {
  const char *dir, *file, *head;
} BFILES[] = {
    {"BFDIR", "hello.bin", "BFILE-9i-content"},
    {"ZZ_SEERDB_BD", "ORCLALRT.LOG", "Dump file"},
    {"SEERBFILE", "hello.txt", "Hello, BFILE world!"},
};

/* The first fixture this account can read, its length into *len; -1 if none. */
static int bfile_fixture(long *len)
{
  for (size_t i = 0; i < sizeof BFILES / sizeof BFILES[0]; i++) {
    char sql[160], n[32] = "";
    snprintf(sql, sizeof sql, "SELECT DBMS_LOB.GETLENGTH(BFILENAME('%s', '%s')) FROM dual",
             BFILES[i].dir, BFILES[i].file);
    query(sql, 0, 0, n, sizeof n);
    if (n[0] != '\0' && atol(n) > 0) {
      *len = atol(n);
      return (int)i;
    }
  }
  return -1;
}

/* A BFILE column's content: on 8i FILE_OPEN, GETLEN, READ, FILE_CLOSE; on 9i
 * and 10g+ their own LOB calls. Checked against the server's own length (the
 * alert log only grows) and the file's first bytes. */
static void check_bfile(void)
{
  const char *name = "BFILE read";
  long want = 0;
  int f = bfile_fixture(&want);
  if (f < 0) {
    skip(name, "fixture: no BFILE directory this account can read on this bed");
    return;
  }
  char sql[128];
  snprintf(sql, sizeof sql, "SELECT BFILENAME('%s', '%s') FROM dual", BFILES[f].dir,
           BFILES[f].file);
  SeerStmt *s = NULL;
  size_t len = 0;
  bool head = false;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    const void *d = NULL;
    int isn = 0, isb = 0;
    seer_stmt_get_data(s, 0, &d, &len, &isn, &isb);
    size_t hl = strlen(BFILES[f].head);
    head = d != NULL && len >= hl && memcmp(d, BFILES[f].head, hl) == 0;
  }
  seer_stmt_close(s);
  if (len >= (size_t)want && head)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "%s/%s: len=%zu (server %ld) head=%d", BFILES[f].dir, BFILES[f].file, len,
             want, (int)head);
    fail(name, m);
  }
}

/* A BFILE whose file can't be opened, as Oracle reports it: fetching the row
 * succeeds - it carries only the locator - and reading the cell is the
 * server's error, ORA-22285 for a missing directory (#158). A column beside
 * it reads as usual, and the session goes on. */
static void check_bfile_missing(void)
{
  const char *name = "a BFILE in a missing directory is the server's error when read";
  SeerStmt *s = NULL;
  SeerStatus st = SEER_EPROTO, fs = SEER_EPROTO, gs = SEER_EPROTO;
  char err[128] = "", tail[16] = "";
  if (seer_stmt_prepare(C, "SELECT BFILENAME('NO_SUCH_DIR', 'x'), 'tail' FROM dual", &s) ==
      SEER_OK) {
    st = seer_stmt_execute(s);
    if (st == SEER_OK)
      fs = seer_stmt_fetch(s);
    if (fs == SEER_OK) {
      const void *d = NULL;
      size_t len = 0;
      int isn = 0, isb = 0;
      gs = seer_stmt_get_data(s, 0, &d, &len, &isn, &isb);
      if (seer_last_error(C) != NULL)
        snprintf(err, sizeof err, "%s", seer_last_error(C));
      const char *t = NULL;
      if (seer_stmt_get_string(s, 1, &t, &isn) == SEER_OK && t != NULL)
        snprintf(tail, sizeof tail, "%s", t);
    }
  }
  seer_stmt_close(s);
  char after[8];
  query("SELECT 1 FROM dual", 0, 0, after, sizeof after);
  if (st == SEER_OK && fs == SEER_OK && gs == SEER_EDB && strncmp(err, "ORA-22285", 9) == 0 &&
      strcmp(tail, "tail") == 0 && strcmp(after, "1") == 0)
    pass(name);
  else {
    char m[240];
    snprintf(m, sizeof m, "execute %d fetch %d read %d '%s', tail '%s', then '%s'", (int)st,
             (int)fs, (int)gs, err, tail, after);
    fail(name, m);
  }
}

static bool can_read_v_session(void)
{
  char n[16] = "";
  query("SELECT COUNT(*) FROM v$session WHERE ROWNUM = 1", 0, 0, n, sizeof n);
  return strcmp(n, "1") == 0;
}

/* NULLs read from a table: a VARCHAR2's comes as an empty value and the
 * trailer with the indicator -1, a NUMBER's or DATE's as the trailer alone;
 * read by its first byte, the VARCHAR2 came back an empty string (#153). */
static void check_table_nulls(void)
{
  const char *name = "NULL VARCHAR2 / NUMBER / DATE read from a table";
  run_rows("DROP TABLE seer_n8", NULL);
  run_rows("CREATE TABLE seer_n8 (id NUMBER, v VARCHAR2(10), n NUMBER, d DATE)", NULL);
  run_rows("INSERT INTO seer_n8 VALUES (1, NULL, NULL, NULL)", NULL);
  run_rows("INSERT INTO seer_n8 VALUES (2, 'x', 5, SYSDATE)", NULL);
  SeerStmt *s = NULL;
  int nulls[2][3] = {{-1, -1, -1}, {-1, -1, -1}}, rows = 0;
  if (seer_stmt_prepare(C, "SELECT v, n, d FROM seer_n8 ORDER BY id", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK)
    while (rows < 2 && seer_stmt_fetch(s) == SEER_OK) {
      for (int i = 0; i < 3; i++) {
        const char *v = NULL;
        int isn = 0;
        seer_stmt_get_string(s, i, &v, &isn);
        nulls[rows][i] = isn;
      }
      rows++;
    }
  seer_stmt_close(s);
  run_rows("DROP TABLE seer_n8", NULL);
  bool ok = rows == 2;
  for (int i = 0; i < 3; i++)
    ok = ok && nulls[0][i] == 1 && nulls[1][i] == 0;
  if (ok)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "rows=%d null flags %d%d%d / %d%d%d", rows, nulls[0][0], nulls[0][1],
             nulls[0][2], nulls[1][0], nulls[1][1], nulls[1][2]);
    fail(name, m);
  }
}

/* The same SQL re-prepared with binds of other types: the statement cache
 * reuses a parsed cursor only for binds of the types it was parsed with,
 * else parses afresh. Reused regardless, SELECT :1 parsed for a double came
 * back with a protocol error for an int or a text, and the next double wrong
 * (#162). */
static void check_cache_bind_types(void)
{
  const char *name = "a cached statement re-run with binds of other types";
  GATE(name);
  static const struct {
    int kind;
    const char *want;
  } runs[] = {{0, "1.5"}, {0, "1.5"}, {2, "7"}, {3, "txt"}, {0, "1.5"}, {2, "7"}};
  char m[160] = "";
  for (size_t i = 0; i < sizeof runs / sizeof runs[0] && m[0] == '\0'; i++) {
    SeerStmt *s = NULL;
    const char *v = NULL;
    int isn = 0;
    SeerStatus st = seer_stmt_prepare(C, "SELECT :1 FROM dual", &s);
    if (st == SEER_OK)
      st = runs[i].kind == 0   ? seer_stmt_bind_double(s, 1, 1.5)
           : runs[i].kind == 2 ? seer_stmt_bind_int64(s, 1, 7)
                               : seer_stmt_bind_text(s, 1, "txt", -1);
    if (st == SEER_OK)
      st = seer_stmt_execute(s);
    if (st == SEER_OK && seer_stmt_fetch(s) == SEER_OK)
      seer_stmt_get_string(s, 0, &v, &isn);
    /* A double reads back as the server prints it; compare it as a number. */
    bool ok =
        v != NULL && (runs[i].kind == 0 ? strtod(v, NULL) == 1.5 : strcmp(v, runs[i].want) == 0);
    if (st != SEER_OK || !ok)
      snprintf(m, sizeof m, "run %zu: status %d, '%s' (want %s)", i + 1, (int)st, v ? v : "",
               runs[i].want);
    seer_stmt_close(s);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A cached query after another session recreated its table with another
 * column type (#212): the server re-parses the cursor and describes it anew,
 * and the rows decode by the new type - not a protocol error. */
static void check_cache_redescribe(void)
{
  const char *name = "a cached query re-described after another session retypes the table";
  SeerConn *b = NULL;
  if (seer_connect(&P, &b) != SEER_OK) {
    skip(name, "second connection failed");
    return;
  }
  run("DROP TABLE seer_redesc_t");
  run("CREATE TABLE seer_redesc_t (n NUMBER)");
  run("INSERT INTO seer_redesc_t VALUES (1)");
  char first[32], again[32], m[200] = "";
  scalar("SELECT n FROM seer_redesc_t", first, sizeof first); /* cached on close */
  const char *ddl[] = {"DROP TABLE seer_redesc_t", "CREATE TABLE seer_redesc_t (n VARCHAR2(10))",
                       "INSERT INTO seer_redesc_t VALUES ('x')"};
  for (size_t k = 0; k < 3; k++) {
    SeerStmt *s = NULL;
    if (seer_stmt_prepare(b, ddl[k], &s) == SEER_OK)
      seer_stmt_execute(s);
    seer_stmt_close(s);
  }
  seer_disconnect(b);
  scalar("SELECT n FROM seer_redesc_t", again, sizeof again);
  if (strcmp(first, "1") != 0 || strcmp(again, "x") != 0)
    snprintf(m, sizeof m, "first '%s' (want 1), after the retype '%s' (want x) %s", first, again,
             seer_last_error(C) ? seer_last_error(C) : "");
  run("DROP TABLE seer_redesc_t");
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A cached statement that fails is not run again unless the error says its
 * cursor is stale (#210): a duplicate key on a cached INSERT executes once,
 * counted by the sequence NEXTVAL it advances even when the row is refused. */
static void check_cache_no_retry(void)
{
  const char *name = "a cached statement that fails runs once";
  run("DROP TABLE seer_retry_t");
  run("DROP SEQUENCE seer_retry_s");
  run("CREATE TABLE seer_retry_t (id NUMBER PRIMARY KEY, n NUMBER)");
  run("CREATE SEQUENCE seer_retry_s");
  const char *ins = "INSERT INTO seer_retry_t VALUES (1, seer_retry_s.NEXTVAL)";
  SeerStatus st[2];
  for (int k = 0; k < 2; k++) { /* the second runs from the cache, and fails */
    SeerStmt *s = NULL;
    st[k] = seer_stmt_prepare(C, ins, &s);
    if (st[k] == SEER_OK)
      st[k] = seer_stmt_execute(s);
    seer_stmt_close(s);
  }
  char cur[32];
  scalar("SELECT seer_retry_s.CURRVAL FROM dual", cur, sizeof cur);
  run("DROP TABLE seer_retry_t");
  run("DROP SEQUENCE seer_retry_s");
  if (st[0] == SEER_OK && st[1] == SEER_EDB && strcmp(cur, "2") == 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "insert %d then %d, NEXTVAL taken %s times (want 2)", (int)st[0],
             (int)st[1], cur);
    fail(name, m);
  }
}

/* Connect-time failover (#201): a HOST list whose first address is a closed
 * port reaches the server behind it; a malformed address is refused before
 * any connect (SEER_EPARAM). */
static void check_connect_failover(void)
{
  const char *name = "connect-time failover across a HOST list";
  char hosts[320], m[400] = "";
  snprintf(hosts, sizeof hosts, "127.0.0.1:1, %s:%u", P.host, (unsigned)P.port);
  SeerConnParams p = P;
  p.host = hosts;
  SeerConn *c = NULL;
  char why[256] = "";
  SeerStatus st = seer_connect_diag(&p, &c, why, sizeof why);
  if (st != SEER_OK) {
    snprintf(m, sizeof m, "HOST=%s: status %d %s", hosts, (int)st, why);
  } else {
    SeerStmt *s = NULL;
    int ok = seer_stmt_prepare(c, "SELECT 1 FROM dual", &s) == SEER_OK &&
             seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK;
    seer_stmt_close(s);
    seer_disconnect(c);
    if (!ok)
      snprintf(m, sizeof m, "HOST=%s: the query failed", hosts);
  }
  /* Every address failing names each, with its cause (#203). */
  p.host = "127.0.0.1:1,127.0.0.1:2";
  c = NULL;
  if (m[0] == '\0' &&
      ((st = seer_connect_diag(&p, &c, why, sizeof why)) != SEER_EIO ||
       strstr(why, "127.0.0.1:1 refused") == NULL || strstr(why, "127.0.0.1:2 refused") == NULL)) {
    snprintf(m, sizeof m, "HOST=%s: status %d '%s'", p.host, (int)st, why);
    seer_disconnect(c);
  }
  p.host = "127.0.0.1:port";
  c = NULL;
  if (m[0] == '\0' && (st = seer_connect_diag(&p, &c, why, sizeof why)) != SEER_EPARAM) {
    snprintf(m, sizeof m, "HOST=%s: status %d, want SEER_EPARAM", p.host, (int)st);
    seer_disconnect(c);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* The core-API suite against one server, as run-matrix.sh runs it per tier.
 * The target comes from the environment: SEER_TEST_HOST / _PORT, _SERVICE or
 * _SID, _USER and _PASS, and SEER_TEST_RELEASE, which gates.h uses to skip a
 * check a release lacks, with its reason. Without a host the suite is
 * skipped (exit 77, as meson counts a skip); an unreachable server is one
 * skip, not a failure. The checks share one connection, C. Each prints its
 * PASS / FAIL / SKIP line, which run-matrix.sh counts. The SUMMARY line and
 * the exit status (1 on any failure) are for meson and a direct run. */
int main(void)
{
  if (getenv("SEER_TEST_HOST") == NULL) {
    fprintf(stderr, "test_core: no target configured (set SEER_TEST_HOST, SEER_TEST_SERVICE or "
                    "SEER_TEST_SID, SEER_TEST_USER, SEER_TEST_PASS, SEER_TEST_RELEASE) - "
                    "skipping\n");
    return 77; /* meson/automake "skipped" */
  }
  /* The release decides the gates; without it no skip could be given. */
  if (gate_release_init() <= 0) {
    fprintf(stderr, "test_core: set SEER_TEST_RELEASE to the server's release (8, 9, 10, 11, 18, "
                    "21, 23, 26)\n");
    return 2;
  }
  const char *port = getenv("SEER_TEST_PORT");
  const char *sid = getenv("SEER_TEST_SID");
  P = (SeerConnParams){
      .host = getenv("SEER_TEST_HOST"),
      .port = (uint16_t)(port ? atoi(port) : 1521),
      .sid = (sid && sid[0]) ? sid : NULL,
      .service_name = getenv("SEER_TEST_SERVICE"),
      .username = getenv("SEER_TEST_USER"),
      .password = getenv("SEER_TEST_PASS"),
  };
  if (seer_connect(&P, &C) != SEER_OK) {
    printf("  SKIP core: server not reachable (%s)\n",
           seer_last_error(NULL) ? seer_last_error(NULL) : "connect failed");
    printf("SUMMARY pass=0 fail=0 skip=1\n");
    return 0;
  }

  /* Queries, describes and the statement cache. */
  check_select_scalar();
  check_connect_failover();
  check_cache_redescribe();
  check_cache_no_retry();
  check_zero_length_columns();
  check_zero_size_numbers();
  check_select_table();
  check_wide_select();
  check_nullability();
  check_null_fetch();
  /* Binds, DML, errors and transactions. */
  check_dml_binds();
  check_date_bind();
  check_raw_bind();
  check_rowid();
  check_multibatch_fetch();
  check_error_recovery();
  check_long_error_text();
  check_rollback();
  /* PL/SQL, LOBs, national and long data, array DML. */
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
  check_array_returning();
  check_array_long_batch_errors();
  check_array_query_refused();
  check_national_bind();
  check_long_text_bind();
  check_long_raw_bind();
  check_cursor_hygiene();
  check_session_identity();
  check_non_ascii_sql();
  check_fetch_error_text();
  /* Type, NULL and error round trips across the value forms. */
  check_scalar_types();
  check_nulls_and_empty();
  check_multibatch();
  check_wide_describe();
  check_errors();
  check_latin1();
  check_long_sql();
  check_rowid_column();
  check_binds();
  check_bind_refused();
  check_dml();
  check_transactions();
  check_alter_session_and_compile();
  check_refused_commit();
  check_blocks();
  check_wide_out();
  check_refcursor_rounds();
  check_cursor_column_rows();
  check_lobs();
  check_urowid();
  check_bfile_missing();
  check_table_nulls();
  check_cache_bind_types();
  /* A refused login, with its own connection. */
  check_wrong_password(&P);
  /* The feature suites in their own files (core_*.c): two-phase commit,
   * request boundaries, sessionless transactions, pipelining, object binds
   * and Advanced Queuing. */
  core_tpc();
  core_reqbound();
  core_sessionless();
  core_pipeline();
  core_objbind();
  core_aq();

  /* The totals, and the exit status, for meson and a direct run. */
  seer_disconnect(C);
  printf("SUMMARY pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
  return fail_n > 0 ? 1 : 0;
}
