/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "convert.h"

#include <sqlext.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "charset.h"

/* Parse a "YYYY-MM-DD HH:MM:SS[.fffffffff]" value (as the core renders DATE /
 * TIMESTAMP). Fraction is nanoseconds. Returns 0 on success. */
static int parse_datetime(const char *s, int *Y, int *Mo, int *D,
                          int *h, int *mi, int *se, unsigned long *frac)
{
    *Y = *Mo = *D = *h = *mi = *se = 0;
    *frac = 0;
    int n = sscanf(s, "%d-%d-%d %d:%d:%d", Y, Mo, D, h, mi, se);
    if (n < 3)
        return -1;
    const char *dot = strchr(s, '.');
    if (dot != NULL)
        *frac = strtoul(dot + 1, NULL, 10);   /* 9-digit nanoseconds */
    return 0;
}

/* Fill an SQL_NUMERIC_STRUCT from a decimal string (sign, 128-bit LE mantissa,
 * scale = fractional digit count). */
static void to_numeric(const char *s, SQL_NUMERIC_STRUCT *ns)
{
    memset(ns, 0, sizeof *ns);
    ns->sign = 1;
    const char *p = s;
    if (*p == '-') { ns->sign = 0; p++; }
    else if (*p == '+') { p++; }

    unsigned char val[SQL_MAX_NUMERIC_LEN] = { 0 };
    int scale = 0, prec = 0;
    bool seen_dot = false;
    for (; *p != '\0'; p++) {
        if (*p == '.') { seen_dot = true; continue; }
        if (*p < '0' || *p > '9') break;
        int carry = *p - '0';
        for (size_t i = 0; i < sizeof val; i++) {
            int x = val[i] * 10 + carry;
            val[i] = (unsigned char)(x & 0xFF);
            carry = x >> 8;
        }
        prec++;
        if (seen_dot) scale++;
    }
    ns->precision = (SQLCHAR)(prec ? prec : 1);
    ns->scale     = (SQLSCHAR)scale;
    memcpy(ns->val, val, sizeof val);
}

/* Copy `n` source bytes / hex / text into buf with offset tracking. Helper for
 * the variable-length targets. Returns SQL_SUCCESS[_WITH_INFO]. */
static SQLRETURN copy_var(const unsigned char *src, size_t total, int as_hex,
                          SQLPOINTER buf, SQLLEN buflen, SQLLEN *ind, SQLLEN *offset)
{
    size_t off = offset ? (size_t)*offset : 0;
    if (off > total) off = total;
    size_t remain = total - off;

    if (ind)
        *ind = (SQLLEN)(as_hex ? remain * 2 : remain);
    if (buf == NULL || buflen <= 0)
        return SQL_SUCCESS;

    if (as_hex) {
        static const char H[] = "0123456789ABCDEF";
        if (buflen < 2)
            return SQL_SUCCESS_WITH_INFO;
        size_t cap_bytes = ((size_t)buflen - 1) / 2;
        size_t cp = remain < cap_bytes ? remain : cap_bytes;
        char *out = (char *)buf;
        for (size_t i = 0; i < cp; i++) {
            out[2 * i]     = H[src[off + i] >> 4];
            out[2 * i + 1] = H[src[off + i] & 0x0F];
        }
        out[2 * cp] = '\0';
        if (offset) *offset = (SQLLEN)(off + cp);
        return cp < remain ? SQL_SUCCESS_WITH_INFO : SQL_SUCCESS;
    }

    size_t cap = (size_t)buflen - 1;
    size_t cp  = remain < cap ? remain : cap;
    memcpy(buf, src + off, cp);
    ((char *)buf)[cp] = '\0';
    if (offset) *offset = (SQLLEN)(off + cp);
    return cp < remain ? SQL_SUCCESS_WITH_INFO : SQL_SUCCESS;
}

/* Copy UTF-16 bytes `src` (total bytes) into a wide buffer with offset tracking
 * and a 2-byte NUL terminator. buflen and the indicator are in BYTES; copies
 * whole 16-bit code units only. */
static SQLRETURN copy_wide(const unsigned char *src, size_t total,
                           SQLPOINTER buf, SQLLEN buflen, SQLLEN *ind, SQLLEN *offset)
{
    size_t off = offset ? (size_t)*offset : 0;
    off &= ~(size_t)1;                 /* align to a 16-bit unit */
    if (off > total) off = total;
    size_t remain = total - off;

    if (ind)
        *ind = (SQLLEN)remain;         /* bytes of UTF-16, excluding terminator */
    if (buf == NULL || buflen < 2)
        return remain > 0 ? SQL_SUCCESS_WITH_INFO : SQL_SUCCESS;

    size_t cap = ((size_t)buflen - 2) & ~(size_t)1;   /* leave room for the NUL */
    size_t cp  = remain < cap ? remain : cap;
    memcpy(buf, src + off, cp);
    ((unsigned char *)buf)[cp]     = 0;
    ((unsigned char *)buf)[cp + 1] = 0;
    if (offset) *offset = (SQLLEN)(off + cp);
    return cp < remain ? SQL_SUCCESS_WITH_INFO : SQL_SUCCESS;
}

SQLRETURN seer_odbc_convert(const void *val, size_t vallen, int is_null,
                            int is_binary, SQLSMALLINT target,
                            SQLPOINTER buf, SQLLEN buflen, SQLLEN *ind,
                            SQLLEN *offset)
{
    if (is_null) {
        if (ind == NULL)
            return SQL_ERROR;          /* 22002 */
        *ind = SQL_NULL_DATA;
        return SQL_SUCCESS;
    }

    const char *s = (const char *)val;   /* NUL-terminated for numeric/date parse */

    switch (target) {
    /* ---- integer family ---- */
    case SQL_C_STINYINT: case SQL_C_TINYINT:
        if (buf) *(SQLSCHAR *)buf = (SQLSCHAR)strtoll(s, NULL, 10);
        if (ind) *ind = (SQLLEN)sizeof(SQLSCHAR);
        return SQL_SUCCESS;
    case SQL_C_UTINYINT:
        if (buf) *(SQLCHAR *)buf = (SQLCHAR)strtoull(s, NULL, 10);
        if (ind) *ind = (SQLLEN)sizeof(SQLCHAR);
        return SQL_SUCCESS;
    case SQL_C_SSHORT: case SQL_C_SHORT:
        if (buf) *(SQLSMALLINT *)buf = (SQLSMALLINT)strtoll(s, NULL, 10);
        if (ind) *ind = (SQLLEN)sizeof(SQLSMALLINT);
        return SQL_SUCCESS;
    case SQL_C_USHORT:
        if (buf) *(SQLUSMALLINT *)buf = (SQLUSMALLINT)strtoull(s, NULL, 10);
        if (ind) *ind = (SQLLEN)sizeof(SQLUSMALLINT);
        return SQL_SUCCESS;
    case SQL_C_SLONG: case SQL_C_LONG:
        if (buf) *(SQLINTEGER *)buf = (SQLINTEGER)strtoll(s, NULL, 10);
        if (ind) *ind = (SQLLEN)sizeof(SQLINTEGER);
        return SQL_SUCCESS;
    case SQL_C_ULONG:
        if (buf) *(SQLUINTEGER *)buf = (SQLUINTEGER)strtoull(s, NULL, 10);
        if (ind) *ind = (SQLLEN)sizeof(SQLUINTEGER);
        return SQL_SUCCESS;
    case SQL_C_SBIGINT:
        if (buf) *(SQLBIGINT *)buf = (SQLBIGINT)strtoll(s, NULL, 10);
        if (ind) *ind = (SQLLEN)sizeof(SQLBIGINT);
        return SQL_SUCCESS;
    case SQL_C_UBIGINT:
        if (buf) *(SQLUBIGINT *)buf = (SQLUBIGINT)strtoull(s, NULL, 10);
        if (ind) *ind = (SQLLEN)sizeof(SQLUBIGINT);
        return SQL_SUCCESS;
    case SQL_C_BIT:
        if (buf) *(SQLCHAR *)buf = (strtoll(s, NULL, 10) != 0) ? 1 : 0;
        if (ind) *ind = (SQLLEN)sizeof(SQLCHAR);
        return SQL_SUCCESS;

    /* ---- floating point ---- */
    case SQL_C_FLOAT:
        if (buf) *(SQLREAL *)buf = (SQLREAL)strtod(s, NULL);
        if (ind) *ind = (SQLLEN)sizeof(SQLREAL);
        return SQL_SUCCESS;
    case SQL_C_DOUBLE:
        if (buf) *(SQLDOUBLE *)buf = strtod(s, NULL);
        if (ind) *ind = (SQLLEN)sizeof(SQLDOUBLE);
        return SQL_SUCCESS;

    case SQL_C_NUMERIC:
        if (buf) to_numeric(s, (SQL_NUMERIC_STRUCT *)buf);
        if (ind) *ind = (SQLLEN)sizeof(SQL_NUMERIC_STRUCT);
        return SQL_SUCCESS;

    /* ---- date / time ---- */
    case SQL_C_TYPE_TIMESTAMP: case SQL_C_TIMESTAMP: {
        int Y, Mo, D, h, mi, se; unsigned long fr;
        if (parse_datetime(s, &Y, &Mo, &D, &h, &mi, &se, &fr) != 0)
            return SQL_ERROR;
        if (buf) {
            SQL_TIMESTAMP_STRUCT *t = buf;
            t->year = (SQLSMALLINT)Y; t->month = (SQLUSMALLINT)Mo; t->day = (SQLUSMALLINT)D;
            t->hour = (SQLUSMALLINT)h; t->minute = (SQLUSMALLINT)mi; t->second = (SQLUSMALLINT)se;
            t->fraction = (SQLUINTEGER)fr;
        }
        if (ind) *ind = (SQLLEN)sizeof(SQL_TIMESTAMP_STRUCT);
        return SQL_SUCCESS;
    }
    case SQL_C_TYPE_DATE: case SQL_C_DATE: {
        int Y, Mo, D, h, mi, se; unsigned long fr;
        if (parse_datetime(s, &Y, &Mo, &D, &h, &mi, &se, &fr) != 0)
            return SQL_ERROR;
        if (buf) {
            SQL_DATE_STRUCT *t = buf;
            t->year = (SQLSMALLINT)Y; t->month = (SQLUSMALLINT)Mo; t->day = (SQLUSMALLINT)D;
        }
        if (ind) *ind = (SQLLEN)sizeof(SQL_DATE_STRUCT);
        return SQL_SUCCESS;
    }
    case SQL_C_TYPE_TIME: case SQL_C_TIME: {
        int Y, Mo, D, h, mi, se; unsigned long fr;
        if (parse_datetime(s, &Y, &Mo, &D, &h, &mi, &se, &fr) != 0)
            return SQL_ERROR;
        if (buf) {
            SQL_TIME_STRUCT *t = buf;
            t->hour = (SQLUSMALLINT)h; t->minute = (SQLUSMALLINT)mi; t->second = (SQLUSMALLINT)se;
        }
        if (ind) *ind = (SQLLEN)sizeof(SQL_TIME_STRUCT);
        return SQL_SUCCESS;
    }

    /* ---- wide text ---- */
    case SQL_C_WCHAR: {
        char  *u16 = NULL;
        size_t u16len = 0;
        if (seer_iconv("UTF-8", SEER_UTF16, (const char *)val, vallen,
                       &u16, &u16len) != 0)
            return SQL_ERROR;
        SQLRETURN r = copy_wide((const unsigned char *)u16, u16len,
                                buf, buflen, ind, offset);
        free(u16);
        return r;
    }

    /* ---- raw / text ---- */
    case SQL_C_BINARY:
        return copy_var((const unsigned char *)val, vallen, 0, buf, buflen, ind, offset);
    case SQL_C_CHAR:
    case SQL_C_DEFAULT:
    default:
        return copy_var((const unsigned char *)val, vallen, is_binary, buf, buflen, ind, offset);
    }
}
