/* seer_smoke - a short, portable ODBC smoke test of an installed SeerODBC,
 * through whatever Driver Manager the platform has: the Windows one (odbc32),
 * unixODBC or iODBC. Where the full live suite (test_integration) needs a
 * unixODBC-style odbc.ini to set up, this one only connects, so it is the check
 * to run on a Windows machine after registering the driver (packaging/windows/).
 *
 *   seer_smoke "DRIVER={SeerODBC};HOST=db;PORT=1521;SERVICE=svc;UID=u;PWD=p;"
 *   seer_smoke "DSN=MyDsn;UID=u;PWD=p;"
 *
 * Exit status: 0 all passed, 1 a check failed, 2 the connect failed, 77 no
 * target given (as the other live tests skip).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifdef _WIN32
#include <windows.h>
#endif
#include <sql.h>
#include <sqlext.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int n_pass, n_fail;

static void report(int ok, const char *name, const char *detail)
{
  printf("  %s %s%s%s\n", ok ? "PASS" : "FAIL", name, detail && detail[0] ? ": " : "",
         detail ? detail : "");
  if (ok)
    n_pass++;
  else
    n_fail++;
}

static void diag(SQLSMALLINT type, SQLHANDLE h, char *out, size_t n, SQLINTEGER *native)
{
  SQLCHAR state[6] = "", msg[512] = "";
  SQLINTEGER nat = 0;
  SQLSMALLINT len = 0;
  out[0] = '\0';
  if (SQL_SUCCEEDED(SQLGetDiagRec(type, h, 1, state, &nat, msg, sizeof msg, &len)))
    snprintf(out, n, "[%s] %s", (char *)state, (char *)msg);
  if (native != NULL)
    *native = nat;
}

/* Run a one-row query and return column 1 as text. */
static int scalar(SQLHDBC dbc, const char *sql, char *out, size_t n, char *err, size_t errn)
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLLEN ind = 0;
  int ok = SQL_SUCCEEDED(SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS)) &&
           SQL_SUCCEEDED(SQLFetch(st)) &&
           SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_CHAR, out, (SQLLEN)n, &ind));
  if (!ok)
    diag(SQL_HANDLE_STMT, st, err, errn, NULL);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  return ok;
}

static void check_types(SQLHDBC dbc)
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  char err[600] = "", m[700];
  SQLINTEGER num = 0;
  SQLCHAR text[64] = "", date[32] = "";
  SQLLEN i1 = 0, i2 = 0, i3 = 0;
  int ok = SQL_SUCCEEDED(SQLExecDirect(st,
                                       (SQLCHAR *)"SELECT 42, 'seer', TO_CHAR(DATE '2026-11-12', "
                                                  "'YYYY-MM-DD') FROM dual",
                                       SQL_NTS)) &&
           SQL_SUCCEEDED(SQLBindCol(st, 1, SQL_C_SLONG, &num, 0, &i1)) &&
           SQL_SUCCEEDED(SQLBindCol(st, 2, SQL_C_CHAR, text, sizeof text, &i2)) &&
           SQL_SUCCEEDED(SQLBindCol(st, 3, SQL_C_CHAR, date, sizeof date, &i3)) &&
           SQL_SUCCEEDED(SQLFetch(st));
  if (!ok)
    diag(SQL_HANDLE_STMT, st, err, sizeof err, NULL);
  ok = ok && num == 42 && strcmp((char *)text, "seer") == 0 &&
       strcmp((char *)date, "2026-11-12") == 0;
  snprintf(m, sizeof m, "%s", ok ? "" : err[0] ? err : "wrong values");
  report(ok, "SELECT NUMBER / VARCHAR2 / DATE, bound columns", m);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

static void check_param(SQLHDBC dbc)
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  char err[600] = "";
  SQLINTEGER in = 41, out = 0;
  SQLLEN ii = 0, oi = 0;
  int ok = SQL_SUCCEEDED(SQLPrepare(st, (SQLCHAR *)"SELECT ? + 1 FROM dual", SQL_NTS)) &&
           SQL_SUCCEEDED(SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0,
                                          &in, 0, &ii)) &&
           SQL_SUCCEEDED(SQLExecute(st)) && SQL_SUCCEEDED(SQLFetch(st)) &&
           SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_SLONG, &out, 0, &oi));
  if (!ok)
    diag(SQL_HANDLE_STMT, st, err, sizeof err, NULL);
  report(ok && out == 42, "a bound parameter (? + 1)", ok ? (out == 42 ? "" : "wrong value") : err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

/* The wide API, as Windows applications call it: UTF-16 SQL in, UTF-16 out. */
static void check_wide(SQLHDBC dbc)
{
  static const SQLWCHAR sql[] = {'S',  'E', 'L', 'E', 'C',  'T',  ' ', 'U', 'N', 'I',
                                 'S',  'T', 'R', '(', '\'', '\\', '0', '0', 'C', '4',
                                 '\\', '4', 'E', '2', 'D',  '\'', ')', ' ', 'F', 'R',
                                 'O',  'M', ' ', 'd', 'u',  'a',  'l', 0};
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLWCHAR out[16] = {0};
  SQLLEN ind = 0;
  char err[600] = "";
  int ok = SQL_SUCCEEDED(SQLExecDirectW(st, (SQLWCHAR *)sql, SQL_NTS)) &&
           SQL_SUCCEEDED(SQLFetch(st)) &&
           SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_WCHAR, out, sizeof out, &ind));
  if (!ok)
    diag(SQL_HANDLE_STMT, st, err, sizeof err, NULL);
  /* U+00C4 LATIN CAPITAL LETTER A WITH DIAERESIS, U+4E2D CJK "middle" */
  int right = ok && out[0] == 0x00C4 && out[1] == 0x4E2D && out[2] == 0;
  char m[700];
  if (ok && !right)
    snprintf(m, sizeof m, "got U+%04X U+%04X (%ld bytes)", (unsigned)out[0], (unsigned)out[1],
             (long)ind);
  else
    snprintf(m, sizeof m, "%s", err);
  report(right, "wide API: SQLExecDirectW, UTF-16 text back", m);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

static void check_error(SQLHDBC dbc)
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT * FROM seer_no_such_table", SQL_NTS);
  char err[600] = "";
  SQLINTEGER native = 0;
  diag(SQL_HANDLE_STMT, st, err, sizeof err, &native);
  report(!SQL_SUCCEEDED(rc) && native == 942, "a server error: ORA-00942, native 942", err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

int main(int argc, char **argv)
{
  const char *cs = argc > 1 ? argv[1] : getenv("SEER_SMOKE_CONNECT");
  if (cs == NULL || cs[0] == '\0') {
    if (argc > 1) /* an empty argument: nothing to connect to */
      return 2;
    fprintf(stderr,
            "usage: %s \"DRIVER={SeerODBC};HOST=...;PORT=...;SERVICE=...;UID=...;PWD=...;\"\n"
            "   or: %s \"DSN=name;UID=...;PWD=...;\"\n",
            argv[0], argv[0]);
    return 77; /* no target: skipped, as the other live tests do */
  }
  SQLHENV env;
  SQLHDBC dbc;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
  SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
  SQLCHAR outcs[1024];
  SQLSMALLINT outlen = 0;
  SQLRETURN rc = SQLDriverConnect(dbc, NULL, (SQLCHAR *)cs, SQL_NTS, outcs, sizeof outcs, &outlen,
                                  SQL_DRIVER_NOPROMPT);
  if (!SQL_SUCCEEDED(rc)) {
    char err[600];
    diag(SQL_HANDLE_DBC, dbc, err, sizeof err, NULL);
    printf("  FAIL connect: %s\n", err[0] ? err : "(no diagnostic)");
    printf("SUMMARY pass=0 fail=1\n");
    return 2;
  }
  char drvname[128] = "", drvver[64] = "", dbms[128] = "";
  SQLGetInfo(dbc, SQL_DRIVER_NAME, drvname, sizeof drvname, NULL);
  SQLGetInfo(dbc, SQL_DRIVER_ODBC_VER, drvver, sizeof drvver, NULL);
  SQLGetInfo(dbc, SQL_DBMS_VER, dbms, sizeof dbms, NULL);
  printf("connected: driver %s (ODBC %s), server %s\n", drvname, drvver, dbms);
  report(1, "connect", "");

  char one[16] = "", err[600] = "";
  int ok = scalar(dbc, "SELECT 1 FROM dual", one, sizeof one, err, sizeof err);
  report(ok && strcmp(one, "1") == 0, "SELECT 1 FROM dual", ok ? "" : err);
  check_types(dbc);
  check_param(dbc);
  check_wide(dbc);
  check_error(dbc);

  SQLDisconnect(dbc);
  SQLFreeHandle(SQL_HANDLE_DBC, dbc);
  SQLFreeHandle(SQL_HANDLE_ENV, env);
  printf("SUMMARY pass=%d fail=%d\n", n_pass, n_fail);
  return n_fail > 0 ? 1 : 0;
}
