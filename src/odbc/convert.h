/* The SQL_C_* conversion seam (docs/ARCHITECTURE.md rule 3).
 *
 * The protocol core renders every value to a canonical form - text for
 * NUMBER/DATE/strings, raw bytes for binary. This is the one place that turns
 * that into whatever ODBC C type the application asked for.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEERODBC_CONVERT_H
#define SEERODBC_CONVERT_H

#include <stddef.h>

#include "odbc_platform.h" /* <windows.h> before the ODBC headers on Windows */

#include <sql.h>

/* Convert a column value (val/vallen; binary if is_binary) to the C type
 * `target`, into `buf`/`buflen`, setting *ind (StrLen_or_Ind). `offset` (may
 * be NULL) tracks partial SQL_C_CHAR/BINARY retrieval across SQLGetData calls,
 * in source-byte units. Returns SQL_SUCCESS, SQL_SUCCESS_WITH_INFO or
 * SQL_ERROR; for the latter two `*sqlstate` (may be NULL) names why:
 *   01004 text or binary truncated; 01S07 an interval's trailing part cut;
 *   22002 NULL with no indicator; 22015 an interval's leading field too big;
 *   22018 a value that doesn't parse as the target; 07006 a target no Oracle
 *   value converts to (SQL_C_GUID, a year-month into a day-time interval). */
SQLRETURN seer_odbc_convert(const void *val, size_t vallen, int is_null, int is_binary,
                            SQLSMALLINT target, SQLPOINTER buf, SQLLEN buflen, SQLLEN *ind,
                            SQLLEN *offset, const char **sqlstate);

/* The diagnostic text for a state seer_odbc_convert reported (NULL: 01004). */
const char *seer_odbc_convert_text(const char *sqlstate);

/* What SQL_C_DEFAULT means for a value of SQL type `sql_type` (#316): the
 * ODBC default C type (Appendix D), SQL_C_CHAR for character, decimal and
 * driver-specific types. */
SQLSMALLINT seer_odbc_default_c_type(SQLSMALLINT sql_type);

/* The size of a fixed-length C type's value (SQL_C_NUMERIC's struct, the
 * interval structs, ...), 0 for the variable-length ones (#314). */
size_t seer_odbc_c_fixed_size(SQLSMALLINT t);

#endif /* SEERODBC_CONVERT_H */
