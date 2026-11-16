/* Diagnostics: the per-handle diagnostic record plus SQLGetDiagRec /
 * SQLGetDiagField. Applications read every error and warning through these.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp, as exec.c */

#include "odbc_internal.h"

const char *seer_odbc_sqlstate(SeerStatus st)
{
  switch (st) {
  case SEER_OK:
    return "00000";
  case SEER_EIO:
    return "08S01"; /* communication link failure */
  case SEER_EPROTO:
    return "08S01";
  case SEER_EAUTH:
    return "28000"; /* invalid authorization      */
  case SEER_ENOMEM:
    return "HY001"; /* memory allocation error    */
  case SEER_EPARAM:
    return "HY009"; /* invalid argument           */
  case SEER_EDB:
    return "HY000"; /* general error (ORA-NNNNN)   */
  case SEER_ENODATA:
    return "02000"; /* no data                    */
  case SEER_ENOTIMPL:
    return "HYC00"; /* optional feature not impl. */
  }
  return "HY000";
}

void seer_odbc_diag_clear(SQLHANDLE handle)
{
  if (handle == NULL)
    return;
  OdbcHeader *h = (OdbcHeader *)handle;
  h->diag.count = 0; /* keep the buffer; just drop the records */
}

void seer_odbc_diag_free(SQLHANDLE handle)
{
  if (handle == NULL)
    return;
  OdbcHeader *h = (OdbcHeader *)handle;
  free(h->diag.recs);
  h->diag.recs = NULL;
  h->diag.count = 0;
  h->diag.cap = 0;
}

/* The SQLSTATE of a server error, by what the ORA code means; NULL for one
 * with no closer state than HY000 (#207). */
static const char *ora_sqlstate(SQLINTEGER code)
{
  switch (code) {
  case 1013: /* user requested cancel of current operation */
    return "HY008";
  case 1:    /* unique constraint violated */
  case 1400: /* cannot insert NULL */
  case 1407: /* cannot update to NULL */
  case 2290: /* check constraint violated */
  case 2291: /* parent key not found */
  case 2292: /* child record found */
    return "23000";
  case 942: /* table or view does not exist */
    return "42S02";
  case 955: /* name is already used by an existing object */
    return "42S01";
  case 904: /* invalid identifier */
    return "42S22";
  case 900:  /* invalid SQL statement */
  case 905:  /* missing keyword */
  case 906:  /* missing left parenthesis */
  case 907:  /* missing right parenthesis */
  case 917:  /* missing comma */
  case 921:  /* unexpected end of SQL command */
  case 923:  /* FROM keyword not found where expected */
  case 933:  /* SQL command not properly ended */
  case 936:  /* missing expression */
  case 1031: /* insufficient privileges */
    return "42000";
  case 60:   /* deadlock detected */
  case 8177: /* can't serialize access for this transaction */
    return "40001";
  case 1476: /* divisor is equal to zero */
    return "22012";
  case 1722: /* invalid number */
    return "22018";
  case 1438: /* value larger than specified precision */
    return "22003";
  case 1401:  /* inserted value too large for column (before 10g) */
  case 12899: /* value too large for column */
    return "22001";
  case 1830: /* date format picture ends before converting entire input */
  case 1840: /* input value not long enough for date format */
  case 1841: /* (full) year must be between -4713 and +9999 */
  case 1858: /* a non-numeric character was found where a numeric was expected */
  case 1861: /* literal does not match format string */
    return "22007";
  case 1843: /* not a valid month */
  case 1847: /* day of month must be between 1 and last day of month */
    return "22008";
  default:
    return NULL;
  }
}

/* Append a record, growing the queue. Returns the new record or NULL on OOM.
 * A server error's text gives its native error when the caller passed none,
 * and a general error (HY000) takes the ORA code's own SQLSTATE (#207). */
static OdbcDiagRec *diag_push(OdbcHeader *h, const char *state, SQLINTEGER native, const char *msg,
                              SQLLEN row)
{
  if (native == 0 && msg != NULL && strncmp(msg, "ORA-", 4) == 0)
    native = (SQLINTEGER)atoi(msg + 4);
  if (native > 0 && (state == NULL || strcmp(state, "HY000") == 0)) {
    const char *mapped = ora_sqlstate(native);
    if (mapped != NULL)
      state = mapped;
  }
  if (h->diag.count == h->diag.cap) {
    int cap = h->diag.cap ? h->diag.cap * 2 : 4;
    OdbcDiagRec *r = realloc(h->diag.recs, (size_t)cap * sizeof *r);
    if (r == NULL)
      return NULL;
    h->diag.recs = r;
    h->diag.cap = cap;
  }
  OdbcDiagRec *rec = &h->diag.recs[h->diag.count++];
  snprintf(rec->state, sizeof rec->state, "%.5s", state ? state : "HY000");
  rec->native = native;
  snprintf(rec->message, sizeof rec->message, "%s", msg ? msg : "");
  rec->row_number = row;
  rec->error_offset = 0;
  return rec;
}

SQLRETURN seer_odbc_diag(SQLHANDLE handle, const char *state, SQLINTEGER native, const char *msg,
                         SQLRETURN ret)
{
  if (handle == NULL)
    return ret;
  OdbcHeader *h = (OdbcHeader *)handle;
  h->diag.count = 0; /* replace any existing records */
  diag_push(h, state, native, msg, SQL_NO_ROW_NUMBER);
  return ret;
}

static void arm_seconds(SeerConn *conn, SQLULEN sec)
{
  seer_set_call_timeout(conn, sec > 2000000 ? 2000000000 : (int)sec * 1000);
}

/* A statement's calls: its SQL_ATTR_QUERY_TIMEOUT, or without one the
 * connection's SQL_ATTR_CONNECTION_TIMEOUT (#209, #228). */
void seer_odbc_arm_timeout(OdbcStmt *s)
{
  if (s == NULL || s->dbc == NULL || s->dbc->conn == NULL)
    return;
  arm_seconds(s->dbc->conn, s->query_timeout ? s->query_timeout : s->dbc->conn_timeout);
}

void seer_odbc_arm_conn_timeout(OdbcDbc *c)
{
  if (c != NULL && c->conn != NULL)
    arm_seconds(c->conn, c->conn_timeout);
}

SQLRETURN seer_odbc_exec_error(OdbcStmt *s, SeerStatus st)
{
  SeerConn *c = s->dbc != NULL ? s->dbc->conn : NULL;
  /* The server's text belongs to a database error, and the call timeout's
   * own text to the connection it closed; any other failure is described by
   * its own status, not by whatever ORA text came last. */
  const char *ora =
      st == SEER_EDB || (st == SEER_EIO && seer_call_timed_out(c)) ? seer_last_error(c) : NULL;
  /* The native error is the ORA number, as SQLGetDiagRec callers expect. */
  SQLINTEGER native = (ora != NULL && strncmp(ora, "ORA-", 4) == 0) ? (SQLINTEGER)atoi(ora + 4) : 0;
  /* Stopped by SQL_ATTR_QUERY_TIMEOUT: HYT00, the timeout's state, where
   * SQLCancel's ORA-01013 is HY008 (#209). */
  const char *state = (st == SEER_EDB || st == SEER_EIO) && seer_call_timed_out(c)
                          ? "HYT00"
                          : seer_odbc_sqlstate(st);
  SQLRETURN r = seer_odbc_diag(s, state, native, ora ? ora : seer_strerror(st), SQL_ERROR);
  OdbcHeader *h = (OdbcHeader *)s;
  if (h->diag.count > 0)
    h->diag.recs[h->diag.count - 1].error_offset = (SQLINTEGER)seer_last_error_offset(c);
  return r;
}

void seer_odbc_diag_add(SQLHANDLE handle, const char *state, SQLINTEGER native, const char *msg,
                        SQLLEN row_number)
{
  if (handle == NULL)
    return;
  diag_push((OdbcHeader *)handle, state, native, msg, row_number);
}

SQLRETURN SQL_API SQLGetDiagRec(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT RecNumber,
                                SQLCHAR *SQLState, SQLINTEGER *NativeErrorPtr, SQLCHAR *MessageText,
                                SQLSMALLINT BufferLength, SQLSMALLINT *TextLengthPtr)
{
  (void)HandleType;
  if (Handle == NULL || RecNumber < 1)
    return SQL_NO_DATA;

  OdbcHeader *h = (OdbcHeader *)Handle;
  if (RecNumber > h->diag.count)
    return SQL_NO_DATA;
  const OdbcDiagRec *rec = &h->diag.recs[RecNumber - 1];

  if (SQLState != NULL)
    memcpy(SQLState, rec->state, 6);
  if (NativeErrorPtr != NULL)
    *NativeErrorPtr = rec->native;

  size_t mlen = strlen(rec->message);
  if (TextLengthPtr != NULL)
    *TextLengthPtr = (SQLSMALLINT)mlen;
  if (MessageText != NULL && BufferLength > 0) {
    SQLSMALLINT n =
        (SQLSMALLINT)(mlen < (size_t)BufferLength - 1 ? mlen : (size_t)BufferLength - 1);
    memcpy(MessageText, rec->message, n);
    MessageText[n] = '\0';
    if ((size_t)n < mlen)
      return SQL_SUCCESS_WITH_INFO;
  }
  return SQL_SUCCESS;
}

/* A string diag field into the application's buffer: SQL_SUCCESS_WITH_INFO
 * when cut short, the full length reported either way (#257). */
static SQLRETURN diag_string(const char *v, SQLPOINTER buf, SQLSMALLINT cap, SQLSMALLINT *len)
{
  size_t n = strlen(v);
  if (len != NULL)
    *len = (SQLSMALLINT)n;
  if (buf == NULL || cap <= 0)
    return SQL_SUCCESS;
  size_t k = n < (size_t)cap - 1 ? n : (size_t)cap - 1;
  memcpy(buf, v, k);
  ((char *)buf)[k] = '\0';
  return k < n ? SQL_SUCCESS_WITH_INFO : SQL_SUCCESS;
}

/* Whether an SQLSTATE's subclass is ODBC's own rather than ISO SQL's / X/Open
 * CLI's (SQL_DIAG_SUBCLASS_ORIGIN, #257). */
static int odbc_subclass(const char *st)
{
  static const char *const odbc[] = {"01S00", "01S01", "01S02", "01S06", "01S07", "07S01", "08S01",
                                     "21S01", "21S02", "25S01", "25S02", "25S03", "42S01", "42S02",
                                     "42S11", "42S12", "42S21", "42S22", "HY095", "HY097", "HY098",
                                     "HY099", "HY100", "HY101", "HY105", "HY107", "HY109", "HY110",
                                     "HY111", "HYT00", "HYT01"};
  if (strncmp(st, "IM", 2) == 0)
    return 1;
  for (size_t i = 0; i < sizeof odbc / sizeof odbc[0]; i++)
    if (strcmp(st, odbc[i]) == 0)
      return 1;
  return 0;
}

/* The executed statement's kind by ODBC's names (SQL_DIAG_DYNAMIC_FUNCTION and
 * its code, #257), from its first words; "" / unknown for the rest. */
static void dynamic_function(const char *sql, const char **name, SQLINTEGER *code)
{
  *name = "";
  *code = SQL_DIAG_UNKNOWN_STATEMENT;
  if (sql == NULL)
    return;
  const char *w[6];
  size_t wl[6];
  int nw = 0;
  for (const char *p = sql; *p != '\0' && nw < 6;) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '(')
      p++;
    const char *b = p;
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' && *p != '(')
      p++;
    if (p > b) {
      w[nw] = b;
      wl[nw++] = (size_t)(p - b);
    }
  }
#define IS(i, kw) (nw > (i) && wl[i] == sizeof(kw) - 1 && strncasecmp(w[i], kw, wl[i]) == 0)
  if (nw == 0)
    return;
  if (IS(0, "INSERT")) {
    *name = "INSERT", *code = SQL_DIAG_INSERT;
  } else if (IS(0, "UPDATE")) {
    *name = "UPDATE WHERE", *code = SQL_DIAG_UPDATE_WHERE;
  } else if (IS(0, "DELETE")) {
    *name = "DELETE WHERE", *code = SQL_DIAG_DELETE_WHERE;
  } else if (IS(0, "SELECT") || IS(0, "WITH")) {
    *name = "SELECT CURSOR", *code = SQL_DIAG_SELECT_CURSOR;
  } else if (IS(0, "CALL") || IS(0, "BEGIN") || IS(0, "DECLARE")) {
    *name = "CALL", *code = SQL_DIAG_CALL; /* {call} runs as a block */
  } else if (IS(0, "GRANT")) {
    *name = "GRANT", *code = SQL_DIAG_GRANT;
  } else if (IS(0, "REVOKE")) {
    *name = "REVOKE", *code = SQL_DIAG_REVOKE;
  } else if (IS(0, "CREATE") || IS(0, "DROP") || IS(0, "ALTER")) {
    int create = IS(0, "CREATE"), drop = IS(0, "DROP");
    for (int i = 1; i < nw; i++) { /* past OR REPLACE, GLOBAL TEMPORARY, UNIQUE, ... */
      if (IS(i, "TABLE")) {
        *name = create ? "CREATE TABLE" : drop ? "DROP TABLE" : "ALTER TABLE";
        *code = create ? SQL_DIAG_CREATE_TABLE : drop ? SQL_DIAG_DROP_TABLE : SQL_DIAG_ALTER_TABLE;
        break;
      }
      if (IS(i, "VIEW") && (create || drop)) {
        *name = create ? "CREATE VIEW" : "DROP VIEW";
        *code = create ? SQL_DIAG_CREATE_VIEW : SQL_DIAG_DROP_VIEW;
        break;
      }
      if (IS(i, "INDEX") && (create || drop)) {
        *name = create ? "CREATE INDEX" : "DROP INDEX";
        *code = create ? SQL_DIAG_CREATE_INDEX : SQL_DIAG_DROP_INDEX;
        break;
      }
    }
  }
#undef IS
}

/* The connection a handle belongs to, NULL for an environment. */
static OdbcDbc *handle_dbc(OdbcHeader *h)
{
  switch (h->type) {
  case SQL_HANDLE_DBC:
    return (OdbcDbc *)h;
  case SQL_HANDLE_STMT:
    return ((OdbcStmt *)h)->dbc;
  case SQL_HANDLE_DESC: {
    OdbcStmt *s = (OdbcStmt *)((OdbcDesc *)h)->stmt;
    return s != NULL ? s->dbc : NULL;
  }
  default:
    return NULL;
  }
}

SQLRETURN SQL_API SQLGetDiagField(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT RecNumber,
                                  SQLSMALLINT DiagIdentifier, SQLPOINTER DiagInfoPtr,
                                  SQLSMALLINT BufferLength, SQLSMALLINT *StringLengthPtr)
{
  (void)HandleType;
  if (Handle == NULL)
    return SQL_NO_DATA;
  OdbcHeader *h = (OdbcHeader *)Handle;

  /* Header (record-independent) fields use RecNumber 0. */
  if (DiagIdentifier == SQL_DIAG_NUMBER) {
    if (DiagInfoPtr != NULL)
      *(SQLINTEGER *)DiagInfoPtr = h->diag.count;
    return SQL_SUCCESS;
  }
  /* The statement's header fields (#257): the rows its DML affected, as
   * SQLRowCount, and the kind of statement it ran. */
  if (DiagIdentifier == SQL_DIAG_ROW_COUNT || DiagIdentifier == SQL_DIAG_DYNAMIC_FUNCTION ||
      DiagIdentifier == SQL_DIAG_DYNAMIC_FUNCTION_CODE) {
    if (h->type != SQL_HANDLE_STMT)
      return SQL_ERROR; /* a statement's field only */
    OdbcStmt *s = (OdbcStmt *)h;
    if (DiagIdentifier == SQL_DIAG_ROW_COUNT) {
      if (DiagInfoPtr != NULL)
        *(SQLLEN *)DiagInfoPtr = s->core ? (SQLLEN)seer_stmt_row_count(s->core) : 0;
      return SQL_SUCCESS;
    }
    const char *fn;
    SQLINTEGER code;
    dynamic_function(s->core != NULL ? s->sql : NULL, &fn, &code);
    if (DiagIdentifier == SQL_DIAG_DYNAMIC_FUNCTION_CODE) {
      if (DiagInfoPtr != NULL)
        *(SQLINTEGER *)DiagInfoPtr = code;
      return SQL_SUCCESS;
    }
    return diag_string(fn, DiagInfoPtr, BufferLength, StringLengthPtr);
  }

  if (RecNumber < 1 || RecNumber > h->diag.count)
    return SQL_NO_DATA;
  const OdbcDiagRec *rec = &h->diag.recs[RecNumber - 1];

  switch (DiagIdentifier) {
  case SQL_DIAG_SQLSTATE:
    if (DiagInfoPtr != NULL && BufferLength >= 6)
      memcpy(DiagInfoPtr, rec->state, 6);
    if (StringLengthPtr != NULL)
      *StringLengthPtr = 5;
    return SQL_SUCCESS;
  case SQL_DIAG_NATIVE:
    if (DiagInfoPtr != NULL)
      *(SQLINTEGER *)DiagInfoPtr = rec->native;
    return SQL_SUCCESS;
  case SQL_DIAG_MESSAGE_TEXT:
    return diag_string(rec->message, DiagInfoPtr, BufferLength, StringLengthPtr);
  /* The record's origins, source and column (#257). */
  case SQL_DIAG_CLASS_ORIGIN:
    return diag_string(strncmp(rec->state, "IM", 2) == 0 ? "ODBC 3.0" : "ISO 9075", DiagInfoPtr,
                       BufferLength, StringLengthPtr);
  case SQL_DIAG_SUBCLASS_ORIGIN:
    return diag_string(odbc_subclass(rec->state) ? "ODBC 3.0" : "ISO 9075", DiagInfoPtr,
                       BufferLength, StringLengthPtr);
  case SQL_DIAG_SERVER_NAME: { /* as SQL_DATA_SOURCE_NAME */
    OdbcDbc *c = handle_dbc(h);
    return diag_string(c != NULL && c->info_dsn != NULL ? c->info_dsn : "", DiagInfoPtr,
                       BufferLength, StringLengthPtr);
  }
  case SQL_DIAG_CONNECTION_NAME:
    return diag_string("", DiagInfoPtr, BufferLength, StringLengthPtr);
  case SQL_DIAG_COLUMN_NUMBER:
    if (DiagInfoPtr != NULL)
      *(SQLINTEGER *)DiagInfoPtr =
          rec->row_number == SQL_NO_ROW_NUMBER ? SQL_NO_COLUMN_NUMBER : SQL_COLUMN_NUMBER_UNKNOWN;
    return SQL_SUCCESS;
  case SQL_DIAG_ROW_NUMBER:
    if (DiagInfoPtr != NULL)
      *(SQLLEN *)DiagInfoPtr = rec->row_number;
    return SQL_SUCCESS;
  case SQL_DIAG_SEER_ERROR_OFFSET:
    if (DiagInfoPtr != NULL)
      *(SQLINTEGER *)DiagInfoPtr = rec->error_offset;
    return SQL_SUCCESS;
  default:
    return SQL_NO_DATA;
  }
}
