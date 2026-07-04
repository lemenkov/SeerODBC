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

SQLRETURN SQL_API SQLGetInfo(SQLHDBC      ConnectionHandle,
                             SQLUSMALLINT InfoType,
                             SQLPOINTER   InfoValuePtr,
                             SQLSMALLINT  BufferLength,
                             SQLSMALLINT *StringLengthPtr)
{
    OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
    if (c != NULL)
        seer_odbc_diag_clear(c);

    switch (InfoType) {
    /* --- identification --- */
    case SQL_DRIVER_NAME:            return info_string("libseerodbc.so", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_DRIVER_VER:             return info_string("00.00.0000", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_DRIVER_ODBC_VER:        return info_string("03.80", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_DBMS_NAME:              return info_string("Oracle", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_DBMS_VER:               return info_string("11.02.0000", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_ODBC_VER:               return info_string("03.80.0000", InfoValuePtr, BufferLength, StringLengthPtr);

    /* --- SQL syntax / naming --- */
    case SQL_IDENTIFIER_QUOTE_CHAR:  return info_string("\"", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_SEARCH_PATTERN_ESCAPE:  return info_string("\\", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_CATALOG_NAME:           return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_CATALOG_NAME_SEPARATOR: return info_string(".", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_CATALOG_TERM:           return info_string("", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_SCHEMA_TERM:            return info_string("schema", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_TABLE_TERM:             return info_string("table", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_PROCEDURE_TERM:         return info_string("procedure", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_SPECIAL_CHARACTERS:     return info_string("$#", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_IDENTIFIER_CASE:        return info_u16(SQL_IC_UPPER, InfoValuePtr);
    case SQL_QUOTED_IDENTIFIER_CASE: return info_u16(SQL_IC_SENSITIVE, InfoValuePtr);

    /* --- capabilities the DM/apps gate on --- */
    case SQL_ACCESSIBLE_TABLES:      return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_ACCESSIBLE_PROCEDURES:  return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_DATA_SOURCE_READ_ONLY:  return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_NEED_LONG_DATA_LEN:     return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_MULTIPLE_ACTIVE_TXN:    return info_string("Y", InfoValuePtr, BufferLength, StringLengthPtr);
    case SQL_GETDATA_EXTENSIONS:     return info_u32(SQL_GD_ANY_COLUMN | SQL_GD_ANY_ORDER | SQL_GD_BOUND, InfoValuePtr);
    case SQL_MAX_COLUMN_NAME_LEN:    return info_u16(30, InfoValuePtr);
    case SQL_MAX_IDENTIFIER_LEN:     return info_u16(30, InfoValuePtr);
    case SQL_MAX_TABLE_NAME_LEN:     return info_u16(30, InfoValuePtr);
    case SQL_MAX_SCHEMA_NAME_LEN:    return info_u16(30, InfoValuePtr);
    case SQL_CATALOG_LOCATION:       return info_u16(0, InfoValuePtr);
    case SQL_CONCAT_NULL_BEHAVIOR:   return info_u16(SQL_CB_NULL, InfoValuePtr);
    case SQL_CORRELATION_NAME:       return info_u16(SQL_CN_ANY, InfoValuePtr);
    case SQL_NON_NULLABLE_COLUMNS:   return info_u16(SQL_NNC_NON_NULL, InfoValuePtr);

    /* --- transactions --- */
    case SQL_TXN_CAPABLE:            return info_u16(SQL_TC_ALL, InfoValuePtr);
    case SQL_DEFAULT_TXN_ISOLATION:  return info_u32(SQL_TXN_READ_COMMITTED, InfoValuePtr);
    case SQL_TXN_ISOLATION_OPTION:   return info_u32(SQL_TXN_READ_COMMITTED | SQL_TXN_SERIALIZABLE, InfoValuePtr);
    case SQL_CURSOR_COMMIT_BEHAVIOR:    return info_u16(SQL_CB_PRESERVE, InfoValuePtr);
    case SQL_CURSOR_ROLLBACK_BEHAVIOR:  return info_u16(SQL_CB_PRESERVE, InfoValuePtr);

    /* --- cursors --- forward-only plus a buffered static (scrollable) cursor */
    case SQL_SCROLL_OPTIONS:         return info_u32(SQL_SO_FORWARD_ONLY | SQL_SO_STATIC, InfoValuePtr);
    case SQL_STATIC_CURSOR_ATTRIBUTES1:
        return info_u32(SQL_CA1_NEXT | SQL_CA1_ABSOLUTE | SQL_CA1_RELATIVE, InfoValuePtr);
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
    case SQL_API_SQLALLOCHANDLE: case SQL_API_SQLFREEHANDLE:
    case SQL_API_SQLCONNECT:     case SQL_API_SQLDRIVERCONNECT:
    case SQL_API_SQLBROWSECONNECT:
    case SQL_API_SQLDISCONNECT:
    case SQL_API_SQLGETINFO:     case SQL_API_SQLGETFUNCTIONS:
    case SQL_API_SQLGETDIAGREC:  case SQL_API_SQLGETDIAGFIELD:
    case SQL_API_SQLSETENVATTR:  case SQL_API_SQLGETENVATTR:
    case SQL_API_SQLSETCONNECTATTR: case SQL_API_SQLGETCONNECTATTR:
    case SQL_API_SQLENDTRAN:
    case SQL_API_SQLSETSTMTATTR: case SQL_API_SQLGETSTMTATTR:
    case SQL_API_SQLNATIVESQL:
    case SQL_API_SQLEXECDIRECT:  case SQL_API_SQLPREPARE:
    case SQL_API_SQLEXECUTE:     case SQL_API_SQLNUMPARAMS:
    case SQL_API_SQLPARAMDATA:   case SQL_API_SQLPUTDATA:
    case SQL_API_SQLBINDPARAMETER: case SQL_API_SQLDESCRIBEPARAM:
    case SQL_API_SQLNUMRESULTCOLS:
    case SQL_API_SQLGETDESCFIELD: case SQL_API_SQLGETDESCREC:
    case SQL_API_SQLSETDESCFIELD: case SQL_API_SQLSETDESCREC:
    case SQL_API_SQLDESCRIBECOL: case SQL_API_SQLCOLATTRIBUTE:
    case SQL_API_SQLFETCHSCROLL: case SQL_API_SQLSETPOS:
    case SQL_API_SQLBINDCOL:     case SQL_API_SQLFETCH:
    case SQL_API_SQLGETDATA:     case SQL_API_SQLROWCOUNT:
    case SQL_API_SQLMORERESULTS: case SQL_API_SQLCANCEL:
    case SQL_API_SQLFREESTMT:    case SQL_API_SQLCLOSECURSOR:
    case SQL_API_SQLTABLES:      case SQL_API_SQLCOLUMNS:
    case SQL_API_SQLGETTYPEINFO: case SQL_API_SQLPRIMARYKEYS:
    case SQL_API_SQLSTATISTICS:  case SQL_API_SQLFOREIGNKEYS:
    case SQL_API_SQLPROCEDURES:  case SQL_API_SQLPROCEDURECOLUMNS:
    case SQL_API_SQLSPECIALCOLUMNS:
        return 1;
    default:
        return 0;
    }
}

SQLRETURN SQL_API SQLGetFunctions(SQLHDBC       ConnectionHandle,
                                  SQLUSMALLINT  FunctionId,
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
