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

SQLRETURN SQL_API SQLSetEnvAttr(SQLHENV     EnvironmentHandle,
                                SQLINTEGER  Attribute,
                                SQLPOINTER  ValuePtr,
                                SQLINTEGER  StringLength)
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

SQLRETURN SQL_API SQLGetEnvAttr(SQLHENV     EnvironmentHandle,
                                SQLINTEGER  Attribute,
                                SQLPOINTER  ValuePtr,
                                SQLINTEGER  BufferLength,
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

SQLRETURN SQL_API SQLSetConnectAttr(SQLHDBC    ConnectionHandle,
                                    SQLINTEGER Attribute,
                                    SQLPOINTER ValuePtr,
                                    SQLINTEGER StringLength)
{
    (void)StringLength;
    OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
    if (c == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(c);

    if (Attribute == SQL_ATTR_AUTOCOMMIT) {
        c->autocommit = (SQLUINTEGER)(SQLULEN)ValuePtr;
        if (c->connected && c->conn != NULL)
            seer_set_autocommit(c->conn, c->autocommit == SQL_AUTOCOMMIT_ON);
    }
    /* Login/connection timeouts, tracing, etc.: accept as no-ops. */
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLEndTran(SQLSMALLINT HandleType, SQLHANDLE Handle,
                             SQLSMALLINT CompletionType)
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
        return SQL_SUCCESS;        /* ENV: nothing else to coordinate */

    seer_odbc_diag_clear(c);
    if (!c->connected || c->conn == NULL)
        return seer_odbc_diag(c, "08003", 0, "Connection not open", SQL_ERROR);

    SeerStatus st = (CompletionType == SQL_ROLLBACK)
                  ? seer_rollback(c->conn)
                  : seer_commit(c->conn);
    if (st != SEER_OK)
        return seer_odbc_diag(c, seer_odbc_sqlstate(st), 0, seer_strerror(st), SQL_ERROR);
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLGetConnectAttr(SQLHDBC     ConnectionHandle,
                                    SQLINTEGER  Attribute,
                                    SQLPOINTER  ValuePtr,
                                    SQLINTEGER  BufferLength,
                                    SQLINTEGER *StringLengthPtr)
{
    (void)BufferLength;
    (void)StringLengthPtr;
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
        *(SQLUINTEGER *)ValuePtr = c->connected ? SQL_CD_FALSE : SQL_CD_TRUE;
        return SQL_SUCCESS;
    default:
        *(SQLINTEGER *)ValuePtr = 0;
        return SQL_SUCCESS;
    }
}

SQLRETURN SQL_API SQLSetStmtAttr(SQLHSTMT   StatementHandle,
                                 SQLINTEGER Attribute,
                                 SQLPOINTER ValuePtr,
                                 SQLINTEGER StringLength)
{
    (void)StringLength;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);

    switch (Attribute) {
    case SQL_ATTR_PARAMSET_SIZE:            /* rows per array-bind execute */
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
    case SQL_ATTR_SEER_DML_ROW_COUNTS:     /* SeerODBC ext: per-iteration counts */
        s->dml_row_counts = (SQLLEN *)ValuePtr;
        return SQL_SUCCESS;
    case SQL_ATTR_ROW_ARRAY_SIZE:           /* rows per block fetch */
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
    case SQL_ATTR_CONCURRENCY:          /* updatable cursor opt-in */
        s->concurrency = (SQLULEN)(uintptr_t)ValuePtr;
        return SQL_SUCCESS;
    default:
        /* Cursor type, etc.: accept as no-ops. */
        return SQL_SUCCESS;
    }
}

SQLRETURN SQL_API SQLGetStmtAttr(SQLHSTMT    StatementHandle,
                                 SQLINTEGER  Attribute,
                                 SQLPOINTER  ValuePtr,
                                 SQLINTEGER  BufferLength,
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
    case SQL_ATTR_APP_ROW_DESC:   *(SQLHANDLE *)ValuePtr = &s->ard; return SQL_SUCCESS;
    case SQL_ATTR_APP_PARAM_DESC: *(SQLHANDLE *)ValuePtr = &s->apd; return SQL_SUCCESS;
    case SQL_ATTR_IMP_ROW_DESC:   *(SQLHANDLE *)ValuePtr = &s->ird; return SQL_SUCCESS;
    case SQL_ATTR_IMP_PARAM_DESC: *(SQLHANDLE *)ValuePtr = &s->ipd; return SQL_SUCCESS;
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
