/* Oracle wire-type decoders (PROTOCOL.md §11). For the first SQL milestone we
 * render values to text in the core; typed access and the SQL_C_* conversion
 * matrix live in the ODBC shim (convert.c) later.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_TYPES_H
#define SEER_TNS_TYPES_H

#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"

/* Oracle TNS data-type numbers we recognise (subset). */
#define ORA_TYPE_VARCHAR       1
#define ORA_TYPE_NUMBER        2
#define ORA_TYPE_VARNUM        6   /* NUMBER return/define request (9i fv2) */
#define ORA_TYPE_LONG          8
#define ORA_TYPE_RID          11   /* physical ROWID (column wire type)   */
#define ORA_TYPE_DATE         12
#define ORA_TYPE_RAW          23
#define ORA_TYPE_LONGRAW      24
#define ORA_TYPE_CHAR         96
#define ORA_TYPE_BFLOAT      100
#define ORA_TYPE_BDOUBLE     101
#define ORA_TYPE_REFCURSOR   102
#define ORA_TYPE_ROWID       104   /* extended ROWID descriptor (-> RID)  */
#define ORA_TYPE_ADT         109   /* SQL OBJECT / collection (ADT)       */
#define ORA_TYPE_REF         111   /* REF (opaque object reference)       */
#define ORA_TYPE_CLOB        112
#define ORA_TYPE_BLOB        113
#define ORA_TYPE_BFILE       114
#define ORA_TYPE_JSON        119
#define ORA_TYPE_VECTOR      127
#define ORA_TYPE_TIMESTAMP   180
#define ORA_TYPE_TIMESTAMPTZ 181
#define ORA_TYPE_INTERVAL_YM 182
#define ORA_TYPE_INTERVAL_DS 183
#define ORA_TYPE_UROWID      208
#define ORA_TYPE_TIMESTAMPLTZ 231
#define ORA_TYPE_BOOLEAN     252

/* Decode an Oracle NUMBER (§11.1) to a decimal string in `out` (a buffer of
 * `outsz` bytes; 192 is ample for the full NUMBER range). */
SeerStatus seer_decode_number(const uint8_t *data, size_t len, char *out, size_t outsz);

/* Decode an Oracle DATE/TIMESTAMP (§11.2-11.3) to "YYYY-MM-DD HH:MM:SS" (with
 * a fractional-second suffix when present). */
SeerStatus seer_decode_date(const uint8_t *data, size_t len, char *out, size_t outsz);

/* Encode a 64-bit integer as an Oracle NUMBER (§11.1) into `out` (>= 24
 * bytes). Returns the number of bytes written. */
size_t seer_encode_number_int(int64_t v, uint8_t *out);

/* Encode a decimal string ("[-]ddd[.ddd]") as Oracle NUMBER bytes (base-100,
 * exact - no float). Returns the byte length (<= 22) in `out`, or 0 if `s` is
 * not a valid number. Handles integers and decimals alike. */
size_t seer_encode_number_str(const char *s, uint8_t *out);

/* Encode a double as a BINARY_DOUBLE (order-preserving IEEE-754, §11.7) into
 * `out` (8 bytes). */
void seer_encode_bdouble(double v, uint8_t out[8]);

/* Encode a float as a BINARY_FLOAT (order-preserving IEEE-754, §11.7) into
 * `out` (4 bytes). */
void seer_encode_bfloat(float v, uint8_t out[4]);

/* Decode BINARY_FLOAT (4 bytes) / BINARY_DOUBLE (8 bytes), order-preserving
 * IEEE-754 (§11.7), to a string. */
SeerStatus seer_decode_bfloat(const uint8_t *data, size_t len, char *out, size_t outsz);
SeerStatus seer_decode_bdouble(const uint8_t *data, size_t len, char *out, size_t outsz);

/* Decode INTERVAL YEAR TO MONTH (5 bytes, §11) to "[+|-]Y-MM", and INTERVAL DAY
 * TO SECOND (11 bytes) to "[+|-]D HH:MM:SS.fffffffff". */
SeerStatus seer_decode_interval_ym(const uint8_t *data, size_t len, char *out, size_t outsz);
SeerStatus seer_decode_interval_ds(const uint8_t *data, size_t len, char *out, size_t outsz);

#endif /* SEER_TNS_TYPES_H */
