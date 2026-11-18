/* Capability reporting: SQLGetInfo / SQLGetFunctions.
 *
 * SQLGetInfo answers the InfoTypes the Driver Manager and consumers query at
 * connect time, several with Oracle-specific answers (identifier quote = ",
 * catalogs absent, schemas present, transactional). Unknown InfoTypes get a
 * benign empty/zero answer so the DM does not abort. The Oracle answer table
 * is tracked in docs/ODBC_CONFORMANCE.md.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "odbc_internal.h"

static SQLRETURN info_string(const char *val, SQLPOINTER buf, SQLSMALLINT buflen,
                             SQLSMALLINT *strlen_ptr)
{
  size_t n = strlen(val);
  if (strlen_ptr != NULL)
    *strlen_ptr = (SQLSMALLINT)n;
  if (buf != NULL && buflen > 0) {
    SQLSMALLINT c = (SQLSMALLINT)(n < (size_t)buflen - 1 ? n : (size_t)buflen - 1);
    memcpy(buf, val, c);
    ((char *)buf)[c] = '\0';
    if ((size_t)c < n)
      return SQL_SUCCESS_WITH_INFO;
  }
  return SQL_SUCCESS;
}

static SQLRETURN info_u16(SQLUSMALLINT val, SQLPOINTER buf)
{
  if (buf != NULL)
    *(SQLUSMALLINT *)buf = val;
  return SQL_SUCCESS;
}

static SQLRETURN info_u32(SQLUINTEGER val, SQLPOINTER buf)
{
  if (buf != NULL)
    *(SQLUINTEGER *)buf = val;
  return SQL_SUCCESS;
}

/* The release fields as SQL_DBMS_VER's "##.##.####" (major, minor or update,
 * then the next two fields), followed - as the spec allows - by the full
 * dotted release: e.g. "23.26.0200 Oracle 23.26.2.0.0". */
static void format_dbms_ver(const int v[5], char *out, size_t n)
{
  snprintf(out, n, "%02d.%02d.%04d Oracle %d.%d.%d.%d.%d", v[0], v[1], v[2] * 100 + v[3], v[0],
           v[1], v[2], v[3], v[4]);
}

/* The connected server's release. 10g+ sends it at login; a 9i login does
 * not, so it is asked for once (product_component_version, readable by every
 * user). Cached on the connection; "00.00.0000" if it cannot be had. */
/* The longest identifier: what the server stated at login (128 from 12.2 on),
 * else 30, the limit of 8i to 12.1, which state none. */
static SQLUSMALLINT max_identifier_len(OdbcDbc *c)
{
  int n = c->conn != NULL ? seer_max_identifier_length(c->conn) : 0;
  return (SQLUSMALLINT)(n > 0 && n <= 0xFFFF ? n : 30);
}

static const char *dbms_ver(OdbcDbc *c)
{
  if (c == NULL || c->conn == NULL)
    return "00.00.0000";
  if (c->dbms_ver[0] != '\0')
    return c->dbms_ver;
  int v[5] = {0};
  if (seer_server_version(c->conn, v) == SEER_OK) {
    format_dbms_ver(v, c->dbms_ver, sizeof c->dbms_ver);
    return c->dbms_ver;
  }
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(c->conn,
                        "SELECT version FROM product_component_version "
                        "WHERE product LIKE 'Oracle%' AND ROWNUM = 1",
                        &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *txt = NULL;
    int isnull = 0;
    if (seer_stmt_get_string(s, 0, &txt, &isnull) == SEER_OK && txt != NULL &&
        sscanf(txt, "%d.%d.%d.%d.%d", &v[0], &v[1], &v[2], &v[3], &v[4]) >= 2)
      format_dbms_ver(v, c->dbms_ver, sizeof c->dbms_ver);
  }
  seer_stmt_close(s);
  return c->dbms_ver[0] != '\0' ? c->dbms_ver : "00.00.0000";
}

/* Whether the connection is to Oracle 8i (whose SQL has no ANSI joins). */
static bool legacy_8i(OdbcDbc *c)
{
  int v[5] = {0};
  return c != NULL && c->conn != NULL && seer_server_version(c->conn, v) == SEER_OK && v[0] == 8;
}

SQLRETURN SQL_API SQLGetInfo(SQLHDBC ConnectionHandle, SQLUSMALLINT InfoType,
                             SQLPOINTER InfoValuePtr, SQLSMALLINT BufferLength,
                             SQLSMALLINT *StringLengthPtr)
{
  OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
  if (c != NULL)
    seer_odbc_diag_clear(c);

  switch (InfoType) {
  /* --- identification --- */
  case SQL_DRIVER_NAME:
#if defined(_WIN32)
    return info_string("seerodbc.dll", InfoValuePtr, BufferLength, StringLengthPtr);
#elif defined(__APPLE__)
    return info_string("libseerodbc.dylib", InfoValuePtr, BufferLength, StringLengthPtr);
#else
    return info_string("libseerodbc.so", InfoValuePtr, BufferLength, StringLengthPtr);
#endif
  case SQL_DRIVER_VER:
    return info_string("00.00.0000", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_DRIVER_ODBC_VER:
    return info_string("03.80", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_DBMS_NAME:
    return info_string("Oracle", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_DBMS_VER:
    return info_string(dbms_ver(c), InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_ODBC_VER:
    return info_string("03.80.0000", InfoValuePtr, BufferLength, StringLengthPtr);

  /* --- SQL syntax / naming --- */
  case SQL_IDENTIFIER_QUOTE_CHAR:
    return info_string("\"", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_SEARCH_PATTERN_ESCAPE:
    return info_string("\\", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_CATALOG_NAME:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_CATALOG_NAME_SEPARATOR:
    return info_string(".", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_CATALOG_TERM:
    return info_string("", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_SCHEMA_TERM:
    return info_string("schema", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_TABLE_TERM:
    return info_string("table", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_PROCEDURE_TERM:
    return info_string("procedure", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_SPECIAL_CHARACTERS:
    return info_string("$#", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_IDENTIFIER_CASE:
    return info_u16(SQL_IC_UPPER, InfoValuePtr);
  case SQL_QUOTED_IDENTIFIER_CASE:
    return info_u16(SQL_IC_SENSITIVE, InfoValuePtr);

  /* --- capabilities the DM/apps gate on --- */
  case SQL_ACCESSIBLE_TABLES:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_ACCESSIBLE_PROCEDURES:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_DATA_SOURCE_READ_ONLY:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_NEED_LONG_DATA_LEN:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_MULTIPLE_ACTIVE_TXN:
    return info_string("Y", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_GETDATA_EXTENSIONS:
    return info_u32(SQL_GD_ANY_COLUMN | SQL_GD_ANY_ORDER | SQL_GD_BOUND, InfoValuePtr);
  case SQL_MAX_COLUMN_NAME_LEN:
  case SQL_MAX_IDENTIFIER_LEN:
  case SQL_MAX_TABLE_NAME_LEN:
  case SQL_MAX_SCHEMA_NAME_LEN:
    return info_u16(max_identifier_len(c), InfoValuePtr);
  case SQL_MAX_CURSOR_NAME_LEN: /* SQLSetCursorName (#288) */
    return info_u16(SEER_MAX_CURSOR_NAME_LEN, InfoValuePtr);
  case SQL_POSITIONED_STATEMENTS: /* WHERE CURRENT OF, rewritten to the ROWID */
    return info_u32(SQL_PS_POSITIONED_DELETE | SQL_PS_POSITIONED_UPDATE, InfoValuePtr);
  case SQL_CATALOG_LOCATION:
    return info_u16(0, InfoValuePtr);
  case SQL_CONCAT_NULL_BEHAVIOR:
    return info_u16(SQL_CB_NULL, InfoValuePtr);
  case SQL_CORRELATION_NAME:
    return info_u16(SQL_CN_ANY, InfoValuePtr);
  case SQL_NON_NULLABLE_COLUMNS:
    return info_u16(SQL_NNC_NON_NULL, InfoValuePtr);

  /* --- transactions --- */
  case SQL_TXN_CAPABLE:
    return info_u16(SQL_TC_ALL, InfoValuePtr);
  case SQL_DEFAULT_TXN_ISOLATION:
    return info_u32(SQL_TXN_READ_COMMITTED, InfoValuePtr);
  case SQL_TXN_ISOLATION_OPTION:
    return info_u32(SQL_TXN_READ_COMMITTED | SQL_TXN_SERIALIZABLE, InfoValuePtr);
  case SQL_CURSOR_COMMIT_BEHAVIOR:
    return info_u16(SQL_CB_PRESERVE, InfoValuePtr);
  case SQL_CURSOR_ROLLBACK_BEHAVIOR:
    return info_u16(SQL_CB_PRESERVE, InfoValuePtr);

  /* --- the connection (#234) --- */
  case SQL_DATA_SOURCE_NAME:
    return info_string(c && c->info_dsn ? c->info_dsn : "", InfoValuePtr, BufferLength,
                       StringLengthPtr);
  case SQL_USER_NAME:
    return info_string(c && c->info_user ? c->info_user : "", InfoValuePtr, BufferLength,
                       StringLengthPtr);
  case SQL_SERVER_NAME:
    return info_string(c && c->info_server ? c->info_server : "", InfoValuePtr, BufferLength,
                       StringLengthPtr);
  case SQL_DATABASE_NAME: /* the current catalog: Oracle has none */
    return info_string("", InfoValuePtr, BufferLength, StringLengthPtr);

  /* --- conformance and SQL support (#234) --- */
  case SQL_SQL_CONFORMANCE:
    return info_u32(SQL_SC_SQL92_ENTRY, InfoValuePtr);
  case SQL_ODBC_INTERFACE_CONFORMANCE:
    return info_u32(SQL_OIC_CORE, InfoValuePtr);
  case SQL_MULT_RESULT_SETS: /* implicit results, SQLMoreResults */
  case SQL_PROCEDURES:       /* {call ...} */
  case SQL_COLUMN_ALIAS:
  case SQL_LIKE_ESCAPE_CLAUSE: /* {escape ...} */
  case SQL_EXPRESSIONS_IN_ORDERBY:
    return info_string("Y", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_ORDER_BY_COLUMNS_IN_SELECT:
  case SQL_ROW_UPDATES:
  case SQL_DESCRIBE_PARAMETER: /* SQLDescribeParam answers a generic default */
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_OUTER_JOINS:
    /* {oj} becomes ANSI join syntax, which 8.1.7 hasn't. */
    return info_string(legacy_8i(c) ? "N" : "Y", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_OJ_CAPABILITIES:
    return info_u32(legacy_8i(c)
                        ? 0
                        : SQL_OJ_LEFT | SQL_OJ_RIGHT | SQL_OJ_FULL | SQL_OJ_NESTED |
                              SQL_OJ_NOT_ORDERED | SQL_OJ_INNER | SQL_OJ_ALL_COMPARISON_OPS,
                    InfoValuePtr);
  case SQL_GROUP_BY:
    return info_u16(SQL_GB_GROUP_BY_CONTAINS_SELECT, InfoValuePtr);
  case SQL_UNION:
    return info_u32(SQL_U_UNION | SQL_U_UNION_ALL, InfoValuePtr);
  case SQL_SUBQUERIES:
    return info_u32(SQL_SQ_COMPARISON | SQL_SQ_EXISTS | SQL_SQ_IN | SQL_SQ_QUANTIFIED |
                        SQL_SQ_CORRELATED_SUBQUERIES,
                    InfoValuePtr);
  case SQL_PARAM_ARRAY_ROW_COUNTS: /* one count for the whole array */
    return info_u32(SQL_PARC_NO_BATCH, InfoValuePtr);
  case SQL_PARAM_ARRAY_SELECTS:
    return info_u32(SQL_PAS_NO_SELECT, InfoValuePtr);

  /* --- cursors --- forward-only plus a buffered static (scrollable) cursor */
  case SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES1:
    return info_u32(SQL_CA1_NEXT | SQL_CA1_POSITIONED_UPDATE | SQL_CA1_POSITIONED_DELETE,
                    InfoValuePtr);
  case SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES2:
    return info_u32(SQL_CA2_READ_ONLY_CONCURRENCY, InfoValuePtr);
  case SQL_SCROLL_OPTIONS:
    return info_u32(SQL_SO_FORWARD_ONLY | SQL_SO_STATIC, InfoValuePtr);
  case SQL_STATIC_CURSOR_ATTRIBUTES1:
    return info_u32(SQL_CA1_NEXT | SQL_CA1_ABSOLUTE | SQL_CA1_RELATIVE | SQL_CA1_POSITIONED_UPDATE |
                        SQL_CA1_POSITIONED_DELETE,
                    InfoValuePtr);
  case SQL_STATIC_CURSOR_ATTRIBUTES2:
    return info_u32(SQL_CA2_READ_ONLY_CONCURRENCY, InfoValuePtr);

  default:
    /* Unknown InfoType: a benign empty/zero answer keeps the DM happy. */
    if (StringLengthPtr != NULL)
      *StringLengthPtr = 0;
    if (InfoValuePtr != NULL && BufferLength >= (SQLSMALLINT)sizeof(SQLUINTEGER))
      *(SQLUINTEGER *)InfoValuePtr = 0;
    else if (InfoValuePtr != NULL && BufferLength > 0)
      *(char *)InfoValuePtr = '\0';
    return SQL_SUCCESS;
  }
}

/* Functions we implement (ODBC 3.x). */
static int func_supported(SQLUSMALLINT id)
{
  switch (id) {
  case SQL_API_SQLALLOCHANDLE:
  case SQL_API_SQLFREEHANDLE:
  case SQL_API_SQLCONNECT:
  case SQL_API_SQLDRIVERCONNECT:
  case SQL_API_SQLBROWSECONNECT:
  case SQL_API_SQLDISCONNECT:
  case SQL_API_SQLGETINFO:
  case SQL_API_SQLGETFUNCTIONS:
  case SQL_API_SQLGETDIAGREC:
  case SQL_API_SQLGETDIAGFIELD:
  case SQL_API_SQLSETENVATTR:
  case SQL_API_SQLGETENVATTR:
  case SQL_API_SQLSETCONNECTATTR:
  case SQL_API_SQLGETCONNECTATTR:
  case SQL_API_SQLENDTRAN:
  case SQL_API_SQLSETSTMTATTR:
  case SQL_API_SQLGETSTMTATTR:
  case SQL_API_SQLNATIVESQL:
  case SQL_API_SQLEXECDIRECT:
  case SQL_API_SQLPREPARE:
  case SQL_API_SQLEXECUTE:
  case SQL_API_SQLNUMPARAMS:
  case SQL_API_SQLPARAMDATA:
  case SQL_API_SQLPUTDATA:
  case SQL_API_SQLBINDPARAMETER:
  case SQL_API_SQLDESCRIBEPARAM:
  case SQL_API_SQLNUMRESULTCOLS:
  case SQL_API_SQLGETDESCFIELD:
  case SQL_API_SQLGETDESCREC:
  case SQL_API_SQLSETDESCFIELD:
  case SQL_API_SQLSETDESCREC:
  case SQL_API_SQLDESCRIBECOL:
  case SQL_API_SQLCOLATTRIBUTE:
  case SQL_API_SQLFETCHSCROLL:
  case SQL_API_SQLSETPOS:
  case SQL_API_SQLBINDCOL:
  case SQL_API_SQLFETCH:
  case SQL_API_SQLGETDATA:
  case SQL_API_SQLROWCOUNT:
  case SQL_API_SQLMORERESULTS:
  case SQL_API_SQLCANCEL:
  case SQL_API_SQLFREESTMT:
  case SQL_API_SQLCLOSECURSOR:
  case SQL_API_SQLTABLES:
  case SQL_API_SQLCOLUMNS:
  case SQL_API_SQLGETTYPEINFO:
  case SQL_API_SQLPRIMARYKEYS:
  case SQL_API_SQLSTATISTICS:
  case SQL_API_SQLFOREIGNKEYS:
  case SQL_API_SQLPROCEDURES:
  case SQL_API_SQLPROCEDURECOLUMNS:
  case SQL_API_SQLSPECIALCOLUMNS:
  case SQL_API_SQLTABLEPRIVILEGES: /* #286 */
  case SQL_API_SQLCOLUMNPRIVILEGES:
  case SQL_API_SQLGETCURSORNAME: /* #288 */
  case SQL_API_SQLSETCURSORNAME:
  case SQL_API_SQLCOPYDESC: /* #289 */
    return 1;
  default:
    return 0;
  }
}

SQLRETURN SQL_API SQLGetFunctions(SQLHDBC ConnectionHandle, SQLUSMALLINT FunctionId,
                                  SQLUSMALLINT *SupportedPtr)
{
  (void)ConnectionHandle;
  if (SupportedPtr == NULL)
    return SQL_ERROR;

  if (FunctionId == SQL_API_ODBC3_ALL_FUNCTIONS) {
    memset(SupportedPtr, 0, sizeof(SQLUSMALLINT) * SQL_API_ODBC3_ALL_FUNCTIONS_SIZE);
    for (SQLUSMALLINT id = 0; id < 2000; id++)
      if (func_supported(id))
        SupportedPtr[id >> 4] |= (SQLUSMALLINT)(1 << (id & 0x0F));
    return SQL_SUCCESS;
  }
  if (FunctionId == SQL_API_ALL_FUNCTIONS) {
    for (int i = 0; i < 100; i++)
      SupportedPtr[i] = func_supported((SQLUSMALLINT)i) ? SQL_TRUE : SQL_FALSE;
    return SQL_SUCCESS;
  }
  *SupportedPtr = func_supported(FunctionId) ? SQL_TRUE : SQL_FALSE;
  return SQL_SUCCESS;
}
