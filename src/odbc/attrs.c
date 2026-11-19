/* Attribute getters/setters: environment, connection, statement.
 *
 * The Driver Manager sets SQL_ATTR_ODBC_VERSION on the environment during
 * setup and reads/writes a handful of connection and statement attributes.
 * We accept the common ones and report sane defaults; the rest succeed as
 * no-ops so the DM does not abort the session.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "odbc_internal.h"

#include <stdlib.h>
#include <string.h>

SQLRETURN SQL_API SQLSetEnvAttr(SQLHENV EnvironmentHandle, SQLINTEGER Attribute,
                                SQLPOINTER ValuePtr, SQLINTEGER StringLength)
{
  (void)StringLength;
  OdbcEnv *e = (OdbcEnv *)EnvironmentHandle;
  if (e == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(e);

  if (Attribute == SQL_ATTR_ODBC_VERSION) {
    e->odbc_version = (SQLINTEGER)(SQLLEN)ValuePtr;
    return SQL_SUCCESS;
  }
  /* SQL_ATTR_CONNECTION_POOLING, SQL_ATTR_OUTPUT_NTS, ...: accept silently. */
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLGetEnvAttr(SQLHENV EnvironmentHandle, SQLINTEGER Attribute,
                                SQLPOINTER ValuePtr, SQLINTEGER BufferLength,
                                SQLINTEGER *StringLengthPtr)
{
  (void)BufferLength;
  (void)StringLengthPtr;
  OdbcEnv *e = (OdbcEnv *)EnvironmentHandle;
  if (e == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(e);

  if (ValuePtr == NULL)
    return SQL_SUCCESS;
  switch (Attribute) {
  case SQL_ATTR_ODBC_VERSION:
    *(SQLINTEGER *)ValuePtr = e->odbc_version ? e->odbc_version : (SQLINTEGER)SQL_OV_ODBC3;
    return SQL_SUCCESS;
  case SQL_ATTR_OUTPUT_NTS:
    *(SQLINTEGER *)ValuePtr = SQL_TRUE;
    return SQL_SUCCESS;
  default:
    *(SQLINTEGER *)ValuePtr = 0;
    return SQL_SUCCESS;
  }
}

/* SQL_ATTR_TXN_ISOLATION (#220): the two levels Oracle has - and SQLGetInfo
 * advertises - set for the session's next transactions with ALTER SESSION;
 * the others, which it hasn't, refused (HYC00). Not yet connected, the level
 * is kept and applied once logged in. */
SQLRETURN seer_odbc_apply_isolation(OdbcDbc *c, SQLUINTEGER level)
{
  const char *sql = NULL;
  if (level == SQL_TXN_SERIALIZABLE)
    sql = "ALTER SESSION SET ISOLATION_LEVEL = SERIALIZABLE";
  else if (level == SQL_TXN_READ_COMMITTED)
    sql = "ALTER SESSION SET ISOLATION_LEVEL = READ COMMITTED";
  else
    return seer_odbc_diag(c, "HYC00", 0,
                          "Oracle has only the READ COMMITTED and SERIALIZABLE isolation levels",
                          SQL_ERROR);
  if (c->connected && c->conn != NULL) {
    SeerStmt *s = NULL;
    SeerStatus st = seer_stmt_prepare(c->conn, sql, &s);
    if (st == SEER_OK)
      st = seer_stmt_execute(s);
    seer_stmt_close(s);
    if (st != SEER_OK) {
      const char *ora = st == SEER_EDB ? seer_last_error(c->conn) : NULL;
      return seer_odbc_diag(c, seer_odbc_sqlstate(st), 0, ora ? ora : seer_strerror(st), SQL_ERROR);
    }
  }
  c->txn_isolation = level;
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLSetConnectAttr(SQLHDBC ConnectionHandle, SQLINTEGER Attribute,
                                    SQLPOINTER ValuePtr, SQLINTEGER StringLength)
{
  (void)StringLength;
  OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
  if (c == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(c);

  if (Attribute == SQL_ATTR_AUTOCOMMIT) {
    SQLUINTEGER on = (SQLUINTEGER)(SQLULEN)ValuePtr;
    /* Back to autocommit from manual: ODBC has the driver commit the open
     * transaction. If the commit fails, its error stands and the mode stays
     * manual (#342). */
    if (on == SQL_AUTOCOMMIT_ON && c->autocommit == SQL_AUTOCOMMIT_OFF && c->connected &&
        c->conn != NULL) {
      SeerStatus st = seer_commit(c->conn);
      if (st != SEER_OK) {
        const char *ora = st == SEER_EDB ? seer_last_error(c->conn) : NULL;
        return seer_odbc_diag(c, seer_odbc_sqlstate(st), 0, ora ? ora : seer_strerror(st),
                              SQL_ERROR);
      }
    }
    c->autocommit = on;
    if (c->connected && c->conn != NULL)
      seer_set_autocommit(c->conn, c->autocommit == SQL_AUTOCOMMIT_ON);
  }
  if (Attribute == SQL_ATTR_LOGIN_TIMEOUT) /* seconds; takes effect at the next connect */
    c->login_timeout = (long)(SQLULEN)ValuePtr;
  if (Attribute == SQL_ATTR_CONNECTION_TIMEOUT) /* seconds any call may wait (#228) */
    c->conn_timeout = (SQLUINTEGER)(SQLULEN)ValuePtr;
  if (Attribute == SQL_ATTR_METADATA_ID) /* the statements allocated after take it (#278) */
    c->metadata_id = (SQLULEN)ValuePtr == SQL_TRUE ? SQL_TRUE : SQL_FALSE;
  if (Attribute == SQL_ATTR_TXN_ISOLATION)
    return seer_odbc_apply_isolation(c, (SQLUINTEGER)(SQLULEN)ValuePtr);
  /* Connection timeout, tracing, etc.: accept as no-ops. */
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLEndTran(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT CompletionType)
{
  if (Handle == NULL)
    return SQL_INVALID_HANDLE;

  /* The DM maps the 2.x SQLTransact onto this. We only carry connection-level
   * transactions; an ENV handle would mean "all its connections" - with one
   * connection per DBC that is the same call. */
  OdbcDbc *c = NULL;
  if (HandleType == SQL_HANDLE_DBC)
    c = (OdbcDbc *)Handle;
  else
    return SQL_SUCCESS; /* ENV: nothing else to coordinate */

  seer_odbc_diag_clear(c);
  if (!c->connected || c->conn == NULL)
    return seer_odbc_diag(c, "08003", 0, "Connection not open", SQL_ERROR);

  seer_odbc_arm_conn_timeout(c);
  SeerStatus st = (CompletionType == SQL_ROLLBACK) ? seer_rollback(c->conn) : seer_commit(c->conn);
  if (st == SEER_OK)
    return SQL_SUCCESS;
  /* A database error carries the server's text and ORA number. A commit the
   * server rolled back (ORA-02091, a deferred constraint) is ODBC's 40002,
   * "integrity constraint violation" (#184). */
  const char *ora = st == SEER_EDB ? seer_last_error(c->conn) : NULL;
  SQLINTEGER native = (ora != NULL && strncmp(ora, "ORA-", 4) == 0) ? (SQLINTEGER)atoi(ora + 4) : 0;
  const char *state =
      (CompletionType == SQL_COMMIT && native == 2091) ? "40002" : seer_odbc_sqlstate(st);
  return seer_odbc_diag(c, state, native, ora ? ora : seer_strerror(st), SQL_ERROR);
}

SQLRETURN SQL_API SQLGetConnectAttr(SQLHDBC ConnectionHandle, SQLINTEGER Attribute,
                                    SQLPOINTER ValuePtr, SQLINTEGER BufferLength,
                                    SQLINTEGER *StringLengthPtr)
{
  OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
  if (c == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(c);

  if (ValuePtr == NULL)
    return SQL_SUCCESS;
  switch (Attribute) {
  case SQL_ATTR_AUTOCOMMIT:
    *(SQLUINTEGER *)ValuePtr = c->autocommit;
    return SQL_SUCCESS;
  case SQL_ATTR_CONNECTION_DEAD:
    *(SQLUINTEGER *)ValuePtr =
        c->connected && !c->session_dead && !seer_conn_lost(c->conn) ? SQL_CD_FALSE : SQL_CD_TRUE;
    return SQL_SUCCESS;
  case SQL_ATTR_CONNECTION_TIMEOUT:
    *(SQLUINTEGER *)ValuePtr = c->conn_timeout;
    return SQL_SUCCESS;
  case SQL_ATTR_TXN_ISOLATION: /* unset: the server's default, READ COMMITTED */
    *(SQLUINTEGER *)ValuePtr = c->txn_isolation ? c->txn_isolation : SQL_TXN_READ_COMMITTED;
    return SQL_SUCCESS;
  case SQL_ATTR_LOGIN_TIMEOUT: /* unset: the 30 s default */
    *(SQLUINTEGER *)ValuePtr = (SQLUINTEGER)(c->login_timeout < 0 ? 30 : c->login_timeout);
    return SQL_SUCCESS;
  /* #250: a string and the pointer-wide ones, which the catch-all wrote as
   * four zero bytes. Oracle has no catalogs: the current one is empty. */
  case SQL_ATTR_CURRENT_CATALOG:
    if (BufferLength > 0)
      *(SQLCHAR *)ValuePtr = '\0';
    if (StringLengthPtr != NULL)
      *StringLengthPtr = 0;
    return SQL_SUCCESS;
  case SQL_ATTR_ASYNC_ENABLE:
    *(SQLULEN *)ValuePtr = SQL_ASYNC_ENABLE_OFF;
    return SQL_SUCCESS;
  case SQL_ATTR_QUIET_MODE:
    *(SQLPOINTER *)ValuePtr = NULL;
    return SQL_SUCCESS;
  case SQL_ATTR_METADATA_ID:
    *(SQLUINTEGER *)ValuePtr = c->metadata_id;
    return SQL_SUCCESS;
  default: /* the 32-bit ones: ACCESS_MODE read-write, AUTO_IPD false, ... */
    *(SQLUINTEGER *)ValuePtr = 0;
    return SQL_SUCCESS;
  }
}

SQLRETURN SQL_API SQLSetStmtAttr(SQLHSTMT StatementHandle, SQLINTEGER Attribute,
                                 SQLPOINTER ValuePtr, SQLINTEGER StringLength)
{
  (void)StringLength;
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);

  switch (Attribute) {
  case SQL_ATTR_APP_ROW_DESC: /* an explicit descriptor, or back to the implicit one (#291) */
  case SQL_ATTR_APP_PARAM_DESC: {
    int row = Attribute == SQL_ATTR_APP_ROW_DESC;
    OdbcDesc *d = (OdbcDesc *)ValuePtr;
    if (d == NULL || d == (row ? &s->ard : &s->apd)) {
      d = NULL;
    } else if (!d->is_explicit) {
      return seer_odbc_diag(
          s, "HY017", 0, "Invalid use of an automatically allocated descriptor handle", SQL_ERROR);
    } else if (d->dbc != s->dbc) {
      return seer_odbc_diag(s, "HY024", 0,
                            "Invalid attribute value: the descriptor is another connection's",
                            SQL_ERROR);
    }
    if (row) {
      s->ard_ext = d;
      s->ab = d != NULL ? &d->recs : &s->own_binds;
    } else {
      s->apd_ext = d;
    }
    return SQL_SUCCESS;
  }
  case SQL_ATTR_IMP_ROW_DESC: /* the implementation descriptors are the statement's */
  case SQL_ATTR_IMP_PARAM_DESC:
    return seer_odbc_diag(s, "HY017", 0,
                          "Invalid use of an automatically allocated descriptor handle", SQL_ERROR);
  case SQL_ATTR_PARAMSET_SIZE: /* rows per array-bind execute */
    s->paramset_size = (SQLULEN)(uintptr_t)ValuePtr;
    if (s->paramset_size == 0)
      s->paramset_size = 1;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAM_BIND_TYPE:
    s->param_bind_type = (SQLULEN)(uintptr_t)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAMS_PROCESSED_PTR:
    s->params_processed = (SQLULEN *)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAM_STATUS_PTR:
    s->param_status = (SQLUSMALLINT *)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_SEER_DML_ROW_COUNTS: /* SeerODBC ext: per-iteration counts */
    s->dml_row_counts = (SQLLEN *)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_ROW_ARRAY_SIZE: /* rows per block fetch */
    s->row_array_size = (SQLULEN)(uintptr_t)ValuePtr;
    if (s->row_array_size == 0)
      s->row_array_size = 1;
    return SQL_SUCCESS;
  case SQL_ATTR_ROW_BIND_TYPE:
    s->row_bind_type = (SQLULEN)(uintptr_t)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_ROWS_FETCHED_PTR:
    s->rows_fetched = (SQLULEN *)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_ROW_STATUS_PTR:
    s->row_status = (SQLUSMALLINT *)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_CONCURRENCY: { /* updatable cursor opt-in */
    SQLULEN v = (SQLULEN)(uintptr_t)ValuePtr;
    if (v == SQL_CONCUR_READ_ONLY || v == SQL_CONCUR_LOCK) {
      s->concurrency = v;
      return SQL_SUCCESS;
    }
    if (v != SQL_CONCUR_ROWVER && v != SQL_CONCUR_VALUES)
      return seer_odbc_diag(s, "HY024", 0, "Invalid attribute value", SQL_ERROR);
    /* Optimistic concurrency (#294): SQLSetPos would have to refuse a row
     * changed since the fetch, and updates by ROWID unchecked. The one it has
     * that keeps the promise is locking the rows, as ODBC has a driver
     * substitute what it lacks. */
    s->concurrency = SQL_CONCUR_LOCK;
    return seer_odbc_diag(s, "01S02", 0, "Concurrency changed to SQL_CONCUR_LOCK",
                          SQL_SUCCESS_WITH_INFO);
  }
  case SQL_ATTR_QUERY_TIMEOUT: /* seconds a call may wait for the server */
    s->query_timeout = (SQLULEN)(uintptr_t)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_MAX_ROWS: /* rows a query returns at most, from the next execute */
    s->max_rows = (SQLULEN)(uintptr_t)ValuePtr;
    return SQL_SUCCESS;
  /* Where bound data lives and which parameter sets run (#243). */
  case SQL_ATTR_PARAM_BIND_OFFSET_PTR:
    s->param_bind_offset = (SQLLEN *)ValuePtr;
    return SQL_SUCCESS;
  /* #250: the rows a bulk SQLSetPos skips, whether a fetch fills the
   * buffers, and the bookmark pointer (kept; SeerODBC has no bookmarks). */
  case SQL_ATTR_ROW_OPERATION_PTR:
    s->row_operation = (SQLUSMALLINT *)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_RETRIEVE_DATA:
    s->retrieve_data = (SQLULEN)(uintptr_t)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_FETCH_BOOKMARK_PTR:
    s->fetch_bookmark = (SQLLEN *)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_METADATA_ID: /* catalog arguments as identifiers (#278) */
    s->metadata_id = (SQLULEN)(uintptr_t)ValuePtr == SQL_TRUE ? SQL_TRUE : SQL_FALSE;
    return SQL_SUCCESS;
  case SQL_ATTR_MAX_LENGTH: /* bytes of a char / binary value returned (#248) */
    s->max_length = (SQLULEN)(uintptr_t)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_NOSCAN: /* escapes left as written (#248) */
    s->noscan = (SQLULEN)(uintptr_t)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_ROW_BIND_OFFSET_PTR:
    s->row_bind_offset = (SQLLEN *)ValuePtr;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAM_OPERATION_PTR:
    s->param_operation = (SQLUSMALLINT *)ValuePtr;
    return SQL_SUCCESS;
  /* What SeerODBC doesn't do is refused, so the application can fall back:
   * every call is synchronous, and there are no bookmarks (#243). */
  case SQL_ATTR_ASYNC_ENABLE:
    if ((SQLULEN)(uintptr_t)ValuePtr != SQL_ASYNC_ENABLE_OFF)
      return seer_odbc_diag(s, "HYC00", 0, "Asynchronous execution is not supported", SQL_ERROR);
    return SQL_SUCCESS;
  case SQL_ATTR_USE_BOOKMARKS:
    if ((SQLULEN)(uintptr_t)ValuePtr != SQL_UB_OFF)
      return seer_odbc_diag(s, "HYC00", 0, "Bookmarks are not supported", SQL_ERROR);
    return SQL_SUCCESS;
  /* The cursor (#226): forward-only, or the buffered static one SQLFetchScroll
   * scrolls - what SQL_SCROLL_OPTIONS advertises. A keyset-driven or dynamic
   * one becomes static, a sensitive one insensitive, with 01S02 (option value
   * changed), as ODBC has a driver substitute what it lacks. */
  case SQL_ATTR_CURSOR_TYPE: {
    SQLULEN v = (SQLULEN)(uintptr_t)ValuePtr;
    if (v == SQL_CURSOR_FORWARD_ONLY || v == SQL_CURSOR_STATIC) {
      s->cursor_type = v;
      return SQL_SUCCESS;
    }
    s->cursor_type = SQL_CURSOR_STATIC;
    return seer_odbc_diag(s, "01S02", 0, "Cursor type changed to SQL_CURSOR_STATIC",
                          SQL_SUCCESS_WITH_INFO);
  }
  case SQL_ATTR_CURSOR_SCROLLABLE:
    s->cursor_type = (SQLULEN)(uintptr_t)ValuePtr == SQL_SCROLLABLE ? SQL_CURSOR_STATIC
                                                                    : SQL_CURSOR_FORWARD_ONLY;
    return SQL_SUCCESS;
  case SQL_ATTR_CURSOR_SENSITIVITY: {
    SQLULEN v = (SQLULEN)(uintptr_t)ValuePtr;
    if (v == SQL_UNSPECIFIED || v == SQL_INSENSITIVE) {
      s->sensitivity = v;
      return SQL_SUCCESS;
    }
    s->sensitivity = SQL_INSENSITIVE;
    return seer_odbc_diag(s, "01S02", 0, "Cursor sensitivity changed to SQL_INSENSITIVE",
                          SQL_SUCCESS_WITH_INFO);
  }
  default:
    /* Cursor type, etc.: accept as no-ops. */
    return SQL_SUCCESS;
  }
}

SQLRETURN SQL_API SQLGetStmtAttr(SQLHSTMT StatementHandle, SQLINTEGER Attribute,
                                 SQLPOINTER ValuePtr, SQLINTEGER BufferLength,
                                 SQLINTEGER *StringLengthPtr)
{
  (void)BufferLength;
  (void)StringLengthPtr;
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);

  if (ValuePtr == NULL)
    return SQL_SUCCESS;
  switch (Attribute) {
  case SQL_ATTR_APP_ROW_DESC: /* the one in use: an explicit one if set (#291) */
    *(SQLHANDLE *)ValuePtr = s->ard_ext != NULL ? (SQLHANDLE)s->ard_ext : (SQLHANDLE)&s->ard;
    return SQL_SUCCESS;
  case SQL_ATTR_APP_PARAM_DESC:
    *(SQLHANDLE *)ValuePtr = s->apd_ext != NULL ? (SQLHANDLE)s->apd_ext : (SQLHANDLE)&s->apd;
    return SQL_SUCCESS;
  case SQL_ATTR_IMP_ROW_DESC:
    *(SQLHANDLE *)ValuePtr = &s->ird;
    return SQL_SUCCESS;
  case SQL_ATTR_IMP_PARAM_DESC:
    *(SQLHANDLE *)ValuePtr = &s->ipd;
    return SQL_SUCCESS;
  case SQL_ATTR_ROW_ARRAY_SIZE:
    *(SQLULEN *)ValuePtr = s->row_array_size ? s->row_array_size : 1;
    return SQL_SUCCESS;
  case SQL_ATTR_ROW_BIND_TYPE:
    *(SQLULEN *)ValuePtr = s->row_bind_type;
    return SQL_SUCCESS;
  case SQL_ATTR_ROWS_FETCHED_PTR:
    *(SQLULEN **)ValuePtr = s->rows_fetched;
    return SQL_SUCCESS;
  case SQL_ATTR_ROW_STATUS_PTR:
    *(SQLUSMALLINT **)ValuePtr = s->row_status;
    return SQL_SUCCESS;
  case SQL_ATTR_CONCURRENCY:
    *(SQLULEN *)ValuePtr = s->concurrency ? s->concurrency : SQL_CONCUR_READ_ONLY;
    return SQL_SUCCESS;
  case SQL_ATTR_QUERY_TIMEOUT:
    *(SQLULEN *)ValuePtr = s->query_timeout;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAM_BIND_OFFSET_PTR:
    *(SQLLEN **)ValuePtr = s->param_bind_offset;
    return SQL_SUCCESS;
  case SQL_ATTR_MAX_LENGTH:
    *(SQLULEN *)ValuePtr = s->max_length;
    return SQL_SUCCESS;
  /* The rest of the standard attributes, each at its own width and default
   * (#250): the catch-all below wrote a 4-byte zero, half of a SQLULEN. */
  case SQL_ATTR_ROW_OPERATION_PTR:
    *(SQLUSMALLINT **)ValuePtr = s->row_operation;
    return SQL_SUCCESS;
  case SQL_ATTR_FETCH_BOOKMARK_PTR:
    *(SQLLEN **)ValuePtr = s->fetch_bookmark;
    return SQL_SUCCESS;
  case SQL_ATTR_RETRIEVE_DATA:
    *(SQLULEN *)ValuePtr = s->retrieve_data == SQL_RD_OFF ? SQL_RD_OFF : SQL_RD_ON;
    return SQL_SUCCESS;
  case SQL_ATTR_ROW_NUMBER: /* the current row, 1-based; 0 with none */
    *(SQLULEN *)ValuePtr = s->rowset_start >= 0 ? (SQLULEN)s->rowset_start + 1 : 0;
    return SQL_SUCCESS;
  case SQL_ATTR_KEYSET_SIZE:
  case SQL_ATTR_USE_BOOKMARKS: /* SQL_UB_OFF */
  case SQL_ATTR_ENABLE_AUTO_IPD:
    *(SQLULEN *)ValuePtr = 0;
    return SQL_SUCCESS;
  case SQL_ATTR_METADATA_ID:
    *(SQLULEN *)ValuePtr = s->metadata_id;
    return SQL_SUCCESS;
  case SQL_ATTR_SIMULATE_CURSOR: /* positioned DML by ROWID: one row each */
    *(SQLULEN *)ValuePtr = SQL_SC_UNIQUE;
    return SQL_SUCCESS;
  case SQL_ATTR_NOSCAN:
    *(SQLULEN *)ValuePtr = s->noscan;
    return SQL_SUCCESS;
  case SQL_ATTR_ROW_BIND_OFFSET_PTR:
    *(SQLLEN **)ValuePtr = s->row_bind_offset;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAM_OPERATION_PTR:
    *(SQLUSMALLINT **)ValuePtr = s->param_operation;
    return SQL_SUCCESS;
  case SQL_ATTR_ASYNC_ENABLE:
    *(SQLULEN *)ValuePtr = SQL_ASYNC_ENABLE_OFF;
    return SQL_SUCCESS;
  case SQL_ATTR_MAX_ROWS:
    *(SQLULEN *)ValuePtr = s->max_rows;
    return SQL_SUCCESS;
  case SQL_ATTR_CURSOR_TYPE:
    *(SQLULEN *)ValuePtr = s->cursor_type;
    return SQL_SUCCESS;
  case SQL_ATTR_CURSOR_SCROLLABLE:
    *(SQLULEN *)ValuePtr = s->cursor_type == SQL_CURSOR_STATIC ? SQL_SCROLLABLE : SQL_NONSCROLLABLE;
    return SQL_SUCCESS;
  case SQL_ATTR_CURSOR_SENSITIVITY:
    *(SQLULEN *)ValuePtr = s->sensitivity;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAMSET_SIZE:
    *(SQLULEN *)ValuePtr = s->paramset_size ? s->paramset_size : 1;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAM_BIND_TYPE:
    *(SQLULEN *)ValuePtr = s->param_bind_type;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAMS_PROCESSED_PTR:
    *(SQLULEN **)ValuePtr = s->params_processed;
    return SQL_SUCCESS;
  case SQL_ATTR_PARAM_STATUS_PTR:
    *(SQLUSMALLINT **)ValuePtr = s->param_status;
    return SQL_SUCCESS;
  default:
    *(SQLINTEGER *)ValuePtr = 0;
    return SQL_SUCCESS;
  }
}
