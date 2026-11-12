/* Unicode (*W) ODBC entry points.
 *
 * Exporting these makes the unixODBC Driver Manager treat SeerODBC as a
 * Unicode driver: it routes wide application calls here and uses the ANSI
 * functions for ANSI apps. Microsoft's Driver Manager goes further: it calls
 * the W form of every function a Unicode driver supports and never falls back
 * to the ANSI one, so the W surface below must be complete. Each wrapper
 * converts its SQLWCHAR (UTF-16, host byte order) string arguments to/from the
 * UTF-8 the ANSI functions speak - which is also Oracle's AL32UTF8 - so there
 * is no lossy locale round-trip.
 *
 * Input-string functions convert their arguments and delegate to the matching
 * ANSI function; output-string functions call the ANSI function into a UTF-8
 * scratch buffer and convert the result back to UTF-16 in the caller's buffer.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "odbc_platform.h" /* <windows.h> before the ODBC headers on Windows */

#include <sql.h>
#include <sqlext.h>
#include <sqlucode.h>

#include <stdlib.h>
#include <string.h>

#include "charset.h"

/* Decode a SQLWCHAR string (length in characters, or SQL_NTS) to a malloc'd
 * NUL-terminated UTF-8 string. NULL in -> NULL out (a genuinely absent arg). */
static char *w_to_utf8(const SQLWCHAR *w, SQLLEN len_chars)
{
  if (w == NULL)
    return NULL;
  size_t bytes;
  if (len_chars == SQL_NTS) {
    size_t n = 0;
    while (w[n] != 0)
      n++;
    bytes = n * sizeof(SQLWCHAR);
  } else {
    bytes = (len_chars > 0) ? (size_t)len_chars * sizeof(SQLWCHAR) : 0;
  }
  char *out = NULL;
  size_t outlen = 0;
  if (seer_iconv(SEER_UTF16, "UTF-8", (const char *)w, bytes, &out, &outlen) != 0)
    return NULL;
  return out;
}

/* Encode a UTF-8 string into a SQLWCHAR buffer of `cap_chars` characters
 * (including the NUL). Sets *out_chars to the full length in characters (not
 * counting the NUL). Truncates on a code-unit boundary -> SQL_SUCCESS_WITH_INFO. */
static SQLRETURN emit_w(const char *u8, SQLWCHAR *buf, SQLLEN cap_chars, SQLLEN *out_chars)
{
  char *u16 = NULL;
  size_t u16len = 0;
  if (seer_iconv("UTF-8", SEER_UTF16, u8, strlen(u8), &u16, &u16len) != 0) {
    if (out_chars)
      *out_chars = 0;
    return SQL_ERROR;
  }
  size_t total = u16len / sizeof(SQLWCHAR);
  if (out_chars)
    *out_chars = (SQLLEN)total;

  SQLRETURN r = SQL_SUCCESS;
  if (buf != NULL && cap_chars > 0) {
    size_t cap = (size_t)cap_chars - 1;
    size_t cp = total < cap ? total : cap;
    memcpy(buf, u16, cp * sizeof(SQLWCHAR));
    buf[cp] = 0;
    if (cp < total)
      r = SQL_SUCCESS_WITH_INFO;
  }
  free(u16);
  return r;
}

/* Byte-unit variant for functions whose buffer length / returned length are in
 * bytes (SQLGetInfoW, SQLColAttributeW) rather than characters. */
static SQLRETURN emit_w_bytes(const char *u8, SQLPOINTER buf, SQLSMALLINT cap_bytes,
                              SQLSMALLINT *out_bytes)
{
  SQLLEN oc = 0;
  SQLRETURN r =
      emit_w(u8, (SQLWCHAR *)buf, (SQLLEN)(cap_bytes / (SQLSMALLINT)sizeof(SQLWCHAR)), &oc);
  if (out_bytes)
    *out_bytes = (SQLSMALLINT)(oc * (SQLLEN)sizeof(SQLWCHAR));
  return r;
}

/* ------------------------------------------------------------- connection */

SQLRETURN SQL_API SQLConnectW(SQLHDBC hdbc, SQLWCHAR *szDSN, SQLSMALLINT cbDSN, SQLWCHAR *szUID,
                              SQLSMALLINT cbUID, SQLWCHAR *szAuth, SQLSMALLINT cbAuth)
{
  char *dsn = w_to_utf8(szDSN, cbDSN);
  char *uid = w_to_utf8(szUID, cbUID);
  char *pwd = w_to_utf8(szAuth, cbAuth);
  SQLRETURN r = SQLConnect(hdbc, (SQLCHAR *)dsn, dsn ? SQL_NTS : 0, (SQLCHAR *)uid,
                           uid ? SQL_NTS : 0, (SQLCHAR *)pwd, pwd ? SQL_NTS : 0);
  free(dsn);
  free(uid);
  free(pwd);
  return r;
}

SQLRETURN SQL_API SQLDriverConnectW(SQLHDBC hdbc, SQLHWND hwnd, SQLWCHAR *szIn, SQLSMALLINT cbIn,
                                    SQLWCHAR *szOut, SQLSMALLINT cbOutMax, SQLSMALLINT *pcbOut,
                                    SQLUSMALLINT completion)
{
  char *in = w_to_utf8(szIn, cbIn);
  char outbuf[2048];
  outbuf[0] = '\0';
  SQLSMALLINT outlen_a = 0;
  SQLRETURN r = SQLDriverConnect(hdbc, hwnd, (SQLCHAR *)in, in ? SQL_NTS : 0, (SQLCHAR *)outbuf,
                                 (SQLSMALLINT)sizeof outbuf, &outlen_a, completion);
  free(in);
  if (SQL_SUCCEEDED(r)) {
    SQLLEN oc = 0;
    SQLRETURN r2 = emit_w(outbuf, szOut, cbOutMax, &oc);
    if (pcbOut)
      *pcbOut = (SQLSMALLINT)oc;
    if (r == SQL_SUCCESS && r2 == SQL_SUCCESS_WITH_INFO)
      r = r2;
  }
  return r;
}

/* ------------------------------------------------------------- statements */

SQLRETURN SQL_API SQLPrepareW(SQLHSTMT hstmt, SQLWCHAR *szSql, SQLINTEGER cbSql)
{
  char *sql = w_to_utf8(szSql, cbSql);
  if (sql == NULL)
    return SQLPrepare(hstmt, NULL, 0);
  SQLRETURN r = SQLPrepare(hstmt, (SQLCHAR *)sql, SQL_NTS);
  free(sql);
  return r;
}

SQLRETURN SQL_API SQLExecDirectW(SQLHSTMT hstmt, SQLWCHAR *szSql, SQLINTEGER cbSql)
{
  char *sql = w_to_utf8(szSql, cbSql);
  if (sql == NULL)
    return SQLExecDirect(hstmt, NULL, 0);
  SQLRETURN r = SQLExecDirect(hstmt, (SQLCHAR *)sql, SQL_NTS);
  free(sql);
  return r;
}

/* ------------------------------------------------------------- diagnostics */

SQLRETURN SQL_API SQLGetDiagRecW(SQLSMALLINT htype, SQLHANDLE handle, SQLSMALLINT rec,
                                 SQLWCHAR *szState, SQLINTEGER *native, SQLWCHAR *szMsg,
                                 SQLSMALLINT cbMsgMax, SQLSMALLINT *pcbMsg)
{
  SQLCHAR state[6] = {0};
  SQLCHAR msg[1024] = {0};
  SQLSMALLINT mlen = 0;
  SQLRETURN r =
      SQLGetDiagRec(htype, handle, rec, state, native, msg, (SQLSMALLINT)sizeof msg, &mlen);
  if (!SQL_SUCCEEDED(r))
    return r; /* SQL_NO_DATA / error pass through */

  if (szState != NULL) { /* 5 ASCII chars + NUL */
    int i = 0;
    for (; i < 5 && state[i] != '\0'; i++)
      szState[i] = (SQLWCHAR)state[i];
    szState[i] = 0;
  }
  SQLLEN oc = 0;
  SQLRETURN r2 = emit_w((char *)msg, szMsg, cbMsgMax, &oc);
  if (pcbMsg)
    *pcbMsg = (SQLSMALLINT)oc;
  return (r == SQL_SUCCESS && r2 == SQL_SUCCESS_WITH_INFO) ? r2 : r;
}

/* ---------------------------------------------------------------- get info */

/* The InfoTypes our SQLGetInfo answers with a string (so the W form must
 * widen them); everything else is numeric and passes through untouched. */
static int is_string_info(SQLUSMALLINT t)
{
  switch (t) {
  case SQL_DRIVER_NAME:
  case SQL_DRIVER_VER:
  case SQL_DRIVER_ODBC_VER:
  case SQL_DBMS_NAME:
  case SQL_DBMS_VER:
  case SQL_ODBC_VER:
  case SQL_IDENTIFIER_QUOTE_CHAR:
  case SQL_SEARCH_PATTERN_ESCAPE:
  case SQL_CATALOG_NAME:
  case SQL_CATALOG_NAME_SEPARATOR:
  case SQL_CATALOG_TERM:
  case SQL_SCHEMA_TERM:
  case SQL_TABLE_TERM:
  case SQL_PROCEDURE_TERM:
  case SQL_SPECIAL_CHARACTERS:
  case SQL_ACCESSIBLE_TABLES:
  case SQL_ACCESSIBLE_PROCEDURES:
  case SQL_DATA_SOURCE_READ_ONLY:
  case SQL_NEED_LONG_DATA_LEN:
  case SQL_MULTIPLE_ACTIVE_TXN:
    return 1;
  default:
    return 0;
  }
}

SQLRETURN SQL_API SQLGetInfoW(SQLHDBC hdbc, SQLUSMALLINT type, SQLPOINTER buf, SQLSMALLINT cbMax,
                              SQLSMALLINT *pcb)
{
  if (!is_string_info(type))
    return SQLGetInfo(hdbc, type, buf, cbMax, pcb); /* numeric: untouched */

  SQLCHAR tmp[1024] = {0};
  SQLSMALLINT alen = 0;
  SQLRETURN r = SQLGetInfo(hdbc, type, tmp, (SQLSMALLINT)sizeof tmp, &alen);
  if (!SQL_SUCCEEDED(r))
    return r;
  SQLSMALLINT ob = 0;
  SQLRETURN r2 = emit_w_bytes((char *)tmp, buf, cbMax, &ob);
  if (pcb)
    *pcb = ob;
  return (r == SQL_SUCCESS) ? r2 : r;
}

/* ------------------------------------------------------------ result metadata */

SQLRETURN SQL_API SQLDescribeColW(SQLHSTMT hstmt, SQLUSMALLINT col, SQLWCHAR *szName,
                                  SQLSMALLINT cbNameMax, SQLSMALLINT *pcbName, SQLSMALLINT *pType,
                                  SQLULEN *pColDef, SQLSMALLINT *pScale, SQLSMALLINT *pNullable)
{
  SQLCHAR name[256] = {0};
  SQLSMALLINT nlen = 0;
  SQLRETURN r = SQLDescribeCol(hstmt, col, name, (SQLSMALLINT)sizeof name, &nlen, pType, pColDef,
                               pScale, pNullable);
  if (!SQL_SUCCEEDED(r))
    return r;
  SQLLEN oc = 0;
  SQLRETURN r2 = emit_w((char *)name, szName, cbNameMax, &oc); /* length in chars */
  if (pcbName)
    *pcbName = (SQLSMALLINT)oc;
  return (r == SQL_SUCCESS && r2 == SQL_SUCCESS_WITH_INFO) ? r2 : r;
}

SQLRETURN SQL_API SQLColAttributeW(SQLHSTMT hstmt, SQLUSMALLINT col, SQLUSMALLINT field,
                                   SQLPOINTER pCharAttr, SQLSMALLINT cbCharMax,
                                   SQLSMALLINT *pcbChar, SEER_COLATTR_NUMERIC pNumAttr)
{
  SQLCHAR tmp[512] = {0};
  SQLSMALLINT slen = 0;
  /* Numeric fields fill pNumAttr and leave tmp empty; string fields fill tmp. */
  SQLRETURN r = SQLColAttribute(hstmt, col, field, tmp, (SQLSMALLINT)sizeof tmp, &slen, pNumAttr);
  if (!SQL_SUCCEEDED(r))
    return r;
  SQLSMALLINT ob = 0;
  SQLRETURN r2 = emit_w_bytes((char *)tmp, pCharAttr, cbCharMax, &ob);
  if (pcbChar)
    *pcbChar = ob;
  return (r == SQL_SUCCESS) ? r2 : r;
}

/* ----------------------------------------------------------------- catalog */

SQLRETURN SQL_API SQLTablesW(SQLHSTMT hstmt, SQLWCHAR *cat, SQLSMALLINT lcat, SQLWCHAR *sch,
                             SQLSMALLINT lsch, SQLWCHAR *tab, SQLSMALLINT ltab, SQLWCHAR *typ,
                             SQLSMALLINT ltyp)
{
  char *c = w_to_utf8(cat, lcat), *s = w_to_utf8(sch, lsch);
  char *t = w_to_utf8(tab, ltab), *y = w_to_utf8(typ, ltyp);
  SQLRETURN r = SQLTables(hstmt, (SQLCHAR *)c, c ? SQL_NTS : 0, (SQLCHAR *)s, s ? SQL_NTS : 0,
                          (SQLCHAR *)t, t ? SQL_NTS : 0, (SQLCHAR *)y, y ? SQL_NTS : 0);
  free(c);
  free(s);
  free(t);
  free(y);
  return r;
}

SQLRETURN SQL_API SQLColumnsW(SQLHSTMT hstmt, SQLWCHAR *cat, SQLSMALLINT lcat, SQLWCHAR *sch,
                              SQLSMALLINT lsch, SQLWCHAR *tab, SQLSMALLINT ltab, SQLWCHAR *col,
                              SQLSMALLINT lcol)
{
  char *c = w_to_utf8(cat, lcat), *s = w_to_utf8(sch, lsch);
  char *t = w_to_utf8(tab, ltab), *o = w_to_utf8(col, lcol);
  SQLRETURN r = SQLColumns(hstmt, (SQLCHAR *)c, c ? SQL_NTS : 0, (SQLCHAR *)s, s ? SQL_NTS : 0,
                           (SQLCHAR *)t, t ? SQL_NTS : 0, (SQLCHAR *)o, o ? SQL_NTS : 0);
  free(c);
  free(s);
  free(t);
  free(o);
  return r;
}

SQLRETURN SQL_API SQLGetTypeInfoW(SQLHSTMT hstmt, SQLSMALLINT DataType)
{
  return SQLGetTypeInfo(hstmt, DataType); /* no string arguments */
}

/* --------------------------------------------- the rest of the W surface
 *
 * Microsoft's Driver Manager treats a driver exporting SQLConnectW as Unicode
 * and then calls the *W form of EVERY function that has one, without falling
 * back to the ANSI export: a missing SQLSetStmtAttrW is a NULL call inside
 * odbc32.dll. So every function SQLGetFunctions reports, if ODBC defines a W
 * form for it, has one here. */

/* (SQLCHAR *)s, length: the ANSI argument pair for a converted string. */
#define U8ARG(s) (SQLCHAR *)(s), (SQLSMALLINT)((s) ? SQL_NTS : 0)

SQLRETURN SQL_API SQLBrowseConnectW(SQLHDBC hdbc, SQLWCHAR *szIn, SQLSMALLINT cbIn, SQLWCHAR *szOut,
                                    SQLSMALLINT cbOutMax, SQLSMALLINT *pcbOut)
{
  char *in = w_to_utf8(szIn, cbIn);
  char outbuf[2048];
  outbuf[0] = '\0';
  SQLSMALLINT alen = 0;
  SQLRETURN r =
      SQLBrowseConnect(hdbc, U8ARG(in), (SQLCHAR *)outbuf, (SQLSMALLINT)sizeof outbuf, &alen);
  free(in);
  if (SQL_SUCCEEDED(r) || r == SQL_NEED_DATA) {
    SQLLEN oc = 0;
    SQLRETURN r2 = emit_w(outbuf, szOut, cbOutMax, &oc);
    if (pcbOut)
      *pcbOut = (SQLSMALLINT)oc;
    if (r == SQL_SUCCESS && r2 == SQL_SUCCESS_WITH_INFO)
      r = r2;
  }
  return r;
}

SQLRETURN SQL_API SQLNativeSqlW(SQLHDBC hdbc, SQLWCHAR *szIn, SQLINTEGER cbIn, SQLWCHAR *szOut,
                                SQLINTEGER cbOutMax, SQLINTEGER *pcbOut)
{
  char *in = w_to_utf8(szIn, cbIn);
  if (in == NULL)
    return SQLNativeSql(hdbc, NULL, 0, NULL, 0, NULL); /* reports HY009 */
  SQLINTEGER alen = 0;
  SQLRETURN r = SQLNativeSql(hdbc, (SQLCHAR *)in, SQL_NTS, NULL, 0, &alen);
  char *out = SQL_SUCCEEDED(r) ? malloc((size_t)alen + 1) : NULL;
  if (out != NULL)
    r = SQLNativeSql(hdbc, (SQLCHAR *)in, SQL_NTS, (SQLCHAR *)out, alen + 1, &alen);
  free(in);
  if (SQL_SUCCEEDED(r) && out != NULL) {
    SQLLEN oc = 0;
    SQLRETURN r2 = emit_w(out, szOut, cbOutMax, &oc);
    if (pcbOut)
      *pcbOut = (SQLINTEGER)oc;
    r = (r == SQL_SUCCESS) ? r2 : r;
  }
  free(out);
  return r;
}

/* Attributes: none of the connection or statement attributes we keep is a
 * string (the string-valued ones are accepted and ignored, or read back as 0,
 * which is also an empty wide string), so these pass straight through. */
SQLRETURN SQL_API SQLSetConnectAttrW(SQLHDBC hdbc, SQLINTEGER attr, SQLPOINTER val, SQLINTEGER len)
{
  return SQLSetConnectAttr(hdbc, attr, val, len);
}

SQLRETURN SQL_API SQLGetConnectAttrW(SQLHDBC hdbc, SQLINTEGER attr, SQLPOINTER val, SQLINTEGER cap,
                                     SQLINTEGER *len)
{
  return SQLGetConnectAttr(hdbc, attr, val, cap, len);
}

SQLRETURN SQL_API SQLSetStmtAttrW(SQLHSTMT hstmt, SQLINTEGER attr, SQLPOINTER val, SQLINTEGER len)
{
  return SQLSetStmtAttr(hstmt, attr, val, len);
}

SQLRETURN SQL_API SQLGetStmtAttrW(SQLHSTMT hstmt, SQLINTEGER attr, SQLPOINTER val, SQLINTEGER cap,
                                  SQLINTEGER *len)
{
  return SQLGetStmtAttr(hstmt, attr, val, cap, len);
}

/* Descriptors. SQLSetDescField ignores the string fields, so its W form needs
 * no conversion; the read side widens the ones SQLGetDescField answers. */
SQLRETURN SQL_API SQLSetDescFieldW(SQLHDESC hdesc, SQLSMALLINT rec, SQLSMALLINT field,
                                   SQLPOINTER val, SQLINTEGER len)
{
  return SQLSetDescField(hdesc, rec, field, val, len);
}

static int is_string_desc_field(SQLSMALLINT f)
{
  switch (f) {
  case SQL_DESC_NAME:
  case SQL_DESC_LABEL:
  case SQL_DESC_BASE_COLUMN_NAME:
  case SQL_DESC_BASE_TABLE_NAME:
  case SQL_DESC_CATALOG_NAME:
  case SQL_DESC_SCHEMA_NAME:
  case SQL_DESC_TABLE_NAME:
  case SQL_DESC_TYPE_NAME:
  case SQL_DESC_LOCAL_TYPE_NAME:
  case SQL_DESC_LITERAL_PREFIX:
  case SQL_DESC_LITERAL_SUFFIX:
    return 1;
  default:
    return 0;
  }
}

SQLRETURN SQL_API SQLGetDescFieldW(SQLHDESC hdesc, SQLSMALLINT rec, SQLSMALLINT field,
                                   SQLPOINTER val, SQLINTEGER cap, SQLINTEGER *len)
{
  if (!is_string_desc_field(field))
    return SQLGetDescField(hdesc, rec, field, val, cap, len);
  SQLCHAR tmp[512] = {0};
  SQLINTEGER alen = 0;
  SQLRETURN r = SQLGetDescField(hdesc, rec, field, tmp, (SQLINTEGER)sizeof tmp, &alen);
  if (!SQL_SUCCEEDED(r))
    return r;
  SQLLEN oc = 0;
  SQLRETURN r2 = emit_w((char *)tmp, (SQLWCHAR *)val, cap / (SQLINTEGER)sizeof(SQLWCHAR), &oc);
  if (len)
    *len = (SQLINTEGER)(oc * (SQLLEN)sizeof(SQLWCHAR)); /* bytes */
  return (r == SQL_SUCCESS) ? r2 : r;
}

SQLRETURN SQL_API SQLGetDescRecW(SQLHDESC hdesc, SQLSMALLINT rec, SQLWCHAR *szName,
                                 SQLSMALLINT cbNameMax, SQLSMALLINT *pcbName, SQLSMALLINT *pType,
                                 SQLSMALLINT *pSubType, SQLLEN *pLength, SQLSMALLINT *pPrecision,
                                 SQLSMALLINT *pScale, SQLSMALLINT *pNullable)
{
  SQLCHAR name[256] = {0};
  SQLSMALLINT nlen = 0;
  SQLRETURN r = SQLGetDescRec(hdesc, rec, name, (SQLSMALLINT)sizeof name, &nlen, pType, pSubType,
                              pLength, pPrecision, pScale, pNullable);
  if (!SQL_SUCCEEDED(r))
    return r;
  SQLLEN oc = 0;
  SQLRETURN r2 = emit_w((char *)name, szName, cbNameMax, &oc); /* length in chars */
  if (pcbName)
    *pcbName = (SQLSMALLINT)oc;
  return (r == SQL_SUCCESS && r2 == SQL_SUCCESS_WITH_INFO) ? r2 : r;
}

SQLRETURN SQL_API SQLGetDiagFieldW(SQLSMALLINT htype, SQLHANDLE handle, SQLSMALLINT rec,
                                   SQLSMALLINT field, SQLPOINTER val, SQLSMALLINT cap,
                                   SQLSMALLINT *len)
{
  if (field != SQL_DIAG_SQLSTATE && field != SQL_DIAG_MESSAGE_TEXT)
    return SQLGetDiagField(htype, handle, rec, field, val, cap, len);
  SQLCHAR tmp[1024] = {0};
  SQLSMALLINT alen = 0;
  SQLRETURN r = SQLGetDiagField(htype, handle, rec, field, tmp, (SQLSMALLINT)sizeof tmp, &alen);
  if (!SQL_SUCCEEDED(r))
    return r;
  SQLSMALLINT ob = 0;
  SQLRETURN r2 = emit_w_bytes((char *)tmp, val, cap, &ob);
  if (len)
    *len = ob;
  return (r == SQL_SUCCESS) ? r2 : r;
}

/* Catalog functions: identifier and pattern arguments in, a result set out. */
SQLRETURN SQL_API SQLPrimaryKeysW(SQLHSTMT hstmt, SQLWCHAR *cat, SQLSMALLINT lcat, SQLWCHAR *sch,
                                  SQLSMALLINT lsch, SQLWCHAR *tab, SQLSMALLINT ltab)
{
  char *c = w_to_utf8(cat, lcat), *s = w_to_utf8(sch, lsch), *t = w_to_utf8(tab, ltab);
  SQLRETURN r = SQLPrimaryKeys(hstmt, U8ARG(c), U8ARG(s), U8ARG(t));
  free(c);
  free(s);
  free(t);
  return r;
}

SQLRETURN SQL_API SQLStatisticsW(SQLHSTMT hstmt, SQLWCHAR *cat, SQLSMALLINT lcat, SQLWCHAR *sch,
                                 SQLSMALLINT lsch, SQLWCHAR *tab, SQLSMALLINT ltab,
                                 SQLUSMALLINT unique, SQLUSMALLINT reserved)
{
  char *c = w_to_utf8(cat, lcat), *s = w_to_utf8(sch, lsch), *t = w_to_utf8(tab, ltab);
  SQLRETURN r = SQLStatistics(hstmt, U8ARG(c), U8ARG(s), U8ARG(t), unique, reserved);
  free(c);
  free(s);
  free(t);
  return r;
}

SQLRETURN SQL_API SQLSpecialColumnsW(SQLHSTMT hstmt, SQLUSMALLINT idtype, SQLWCHAR *cat,
                                     SQLSMALLINT lcat, SQLWCHAR *sch, SQLSMALLINT lsch,
                                     SQLWCHAR *tab, SQLSMALLINT ltab, SQLUSMALLINT scope,
                                     SQLUSMALLINT nullable)
{
  char *c = w_to_utf8(cat, lcat), *s = w_to_utf8(sch, lsch), *t = w_to_utf8(tab, ltab);
  SQLRETURN r = SQLSpecialColumns(hstmt, idtype, U8ARG(c), U8ARG(s), U8ARG(t), scope, nullable);
  free(c);
  free(s);
  free(t);
  return r;
}

SQLRETURN SQL_API SQLForeignKeysW(SQLHSTMT hstmt, SQLWCHAR *pkcat, SQLSMALLINT lpkcat,
                                  SQLWCHAR *pksch, SQLSMALLINT lpksch, SQLWCHAR *pktab,
                                  SQLSMALLINT lpktab, SQLWCHAR *fkcat, SQLSMALLINT lfkcat,
                                  SQLWCHAR *fksch, SQLSMALLINT lfksch, SQLWCHAR *fktab,
                                  SQLSMALLINT lfktab)
{
  char *pc = w_to_utf8(pkcat, lpkcat), *ps = w_to_utf8(pksch, lpksch);
  char *pt = w_to_utf8(pktab, lpktab), *fc = w_to_utf8(fkcat, lfkcat);
  char *fs = w_to_utf8(fksch, lfksch), *ft = w_to_utf8(fktab, lfktab);
  SQLRETURN r =
      SQLForeignKeys(hstmt, U8ARG(pc), U8ARG(ps), U8ARG(pt), U8ARG(fc), U8ARG(fs), U8ARG(ft));
  free(pc);
  free(ps);
  free(pt);
  free(fc);
  free(fs);
  free(ft);
  return r;
}

SQLRETURN SQL_API SQLProceduresW(SQLHSTMT hstmt, SQLWCHAR *cat, SQLSMALLINT lcat, SQLWCHAR *sch,
                                 SQLSMALLINT lsch, SQLWCHAR *proc, SQLSMALLINT lproc)
{
  char *c = w_to_utf8(cat, lcat), *s = w_to_utf8(sch, lsch), *p = w_to_utf8(proc, lproc);
  SQLRETURN r = SQLProcedures(hstmt, U8ARG(c), U8ARG(s), U8ARG(p));
  free(c);
  free(s);
  free(p);
  return r;
}

SQLRETURN SQL_API SQLProcedureColumnsW(SQLHSTMT hstmt, SQLWCHAR *cat, SQLSMALLINT lcat,
                                       SQLWCHAR *sch, SQLSMALLINT lsch, SQLWCHAR *proc,
                                       SQLSMALLINT lproc, SQLWCHAR *col, SQLSMALLINT lcol)
{
  char *c = w_to_utf8(cat, lcat), *s = w_to_utf8(sch, lsch);
  char *p = w_to_utf8(proc, lproc), *o = w_to_utf8(col, lcol);
  SQLRETURN r = SQLProcedureColumns(hstmt, U8ARG(c), U8ARG(s), U8ARG(p), U8ARG(o));
  free(c);
  free(s);
  free(p);
  free(o);
  return r;
}
