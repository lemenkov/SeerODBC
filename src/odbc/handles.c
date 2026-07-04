/* Handle allocation/deallocation: SQLAllocHandle / SQLFreeHandle.
 *
 * In ODBC 3.x these subsume the deprecated SQLAllocEnv/Connect/Stmt and
 * SQLFreeEnv/Connect/Stmt; the Driver Manager maps the old 2.x calls onto
 * these for us, so we implement only the 3.x form.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>

#include "odbc_internal.h"

SQLRETURN SQL_API SQLAllocHandle(SQLSMALLINT HandleType,
                                 SQLHANDLE   InputHandle,
                                 SQLHANDLE  *OutputHandle)
{
    if (OutputHandle == NULL)
        return SQL_ERROR;
    *OutputHandle = SQL_NULL_HANDLE;

    switch (HandleType) {
    case SQL_HANDLE_ENV: {
        OdbcEnv *e = calloc(1, sizeof *e);
        if (e == NULL)
            return SQL_ERROR;
        e->h.type = SQL_HANDLE_ENV;
        *OutputHandle = (SQLHANDLE)e;
        return SQL_SUCCESS;
    }
    case SQL_HANDLE_DBC: {
        if (InputHandle == NULL)
            return SQL_INVALID_HANDLE;
        OdbcDbc *c = calloc(1, sizeof *c);
        if (c == NULL)
            return SQL_ERROR;
        c->h.type     = SQL_HANDLE_DBC;
        c->env        = (OdbcEnv *)InputHandle;
        c->autocommit = SQL_AUTOCOMMIT_ON;
        *OutputHandle = (SQLHANDLE)c;
        return SQL_SUCCESS;
    }
    case SQL_HANDLE_STMT: {
        if (InputHandle == NULL)
            return SQL_INVALID_HANDLE;
        OdbcDbc *c = (OdbcDbc *)InputHandle;
        if (!c->connected)
            return seer_odbc_diag(c, "08003", 0, "Connection not open", SQL_ERROR);
        OdbcStmt *s = calloc(1, sizeof *s);
        if (s == NULL)
            return SQL_ERROR;
        s->h.type         = SQL_HANDLE_STMT;
        s->dbc            = c;
        s->getdata_col    = -1;
        s->paramset_size  = 1;
        s->row_array_size = 1;
        s->rowset_start   = -1;
        s->concurrency    = SQL_CONCUR_READ_ONLY;
        s->rowid_col      = -1;
        /* The implicit descriptors share the statement's lifetime. */
        s->ard.h.type = s->apd.h.type = s->ird.h.type = s->ipd.h.type = SQL_HANDLE_DESC;
        s->ard.stmt = s->apd.stmt = s->ird.stmt = s->ipd.stmt = s;
        s->ard.kind = SEER_DESC_ARD;  s->apd.kind = SEER_DESC_APD;
        s->ird.kind = SEER_DESC_IRD;  s->ipd.kind = SEER_DESC_IPD;
        *OutputHandle     = (SQLHANDLE)s;
        return SQL_SUCCESS;
    }
    default:
        return SQL_ERROR;
    }
}

SQLRETURN SQL_API SQLFreeHandle(SQLSMALLINT HandleType, SQLHANDLE Handle)
{
    if (Handle == NULL)
        return SQL_INVALID_HANDLE;

    switch (HandleType) {
    case SQL_HANDLE_STMT: {
        OdbcStmt *s = (OdbcStmt *)Handle;
        if (s->core != NULL)
            seer_stmt_close(s->core);
        seer_odbc_free_updatable(s);
        seer_odbc_diag_free(s);
        seer_odbc_diag_free(&s->ard); seer_odbc_diag_free(&s->apd);
        seer_odbc_diag_free(&s->ird); seer_odbc_diag_free(&s->ipd);
        free(s->binds);
        for (int i = 0; i < s->num_params; i++)
            free(s->params[i].dae_buf);
        free(s->params);
        free(s->sql);
        free(s);
        return SQL_SUCCESS;
    }
    case SQL_HANDLE_DESC:
        /* Implicit descriptors are owned by their statement; the app cannot
         * free them (no explicit descriptor allocation is supported). */
        return seer_odbc_diag(Handle, "HY017", 0,
                              "Invalid use of an automatically allocated "
                              "descriptor handle", SQL_ERROR);
    case SQL_HANDLE_DBC: {
        OdbcDbc *c = (OdbcDbc *)Handle;
        if (c->connected && c->conn != NULL)
            seer_disconnect(c->conn);
        free(c->browse_cs);
        seer_odbc_diag_free(c);
        free(c);
        return SQL_SUCCESS;
    }
    case SQL_HANDLE_ENV:
        seer_odbc_diag_free(Handle);
        free(Handle);
        return SQL_SUCCESS;
    default:
        return SQL_ERROR;
    }
}
