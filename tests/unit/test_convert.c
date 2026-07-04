/* Offline unit tests for the SQL_C_* conversion matrix (src/odbc/convert.c).
 * The core renders values to canonical text/bytes; this turns them into the
 * requested ODBC C type. No connection required.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#include "convert.h"

#include <assert.h>
#include <sqlext.h>
#include <stdio.h>
#include <string.h>

#define CV(val, vlen, isnull, isbin, target, buf, buflen, ind) \
    seer_odbc_convert((val), (vlen), (isnull), (isbin), (target), (buf), (buflen), (ind), NULL)

int main(void)
{
    SQLLEN ind;

    /* --- integers --- */
    {
        SQLINTEGER v = 0;
        assert(CV("42", 2, 0, 0, SQL_C_SLONG, &v, 0, &ind) == SQL_SUCCESS);
        assert(v == 42 && ind == (SQLLEN)sizeof(SQLINTEGER));
        SQLSMALLINT s = 0;
        CV("-7", 2, 0, 0, SQL_C_SSHORT, &s, 0, &ind);
        assert(s == -7);
        SQLBIGINT b = 0;
        CV("9000000000", 10, 0, 0, SQL_C_SBIGINT, &b, 0, &ind);
        assert(b == 9000000000LL);
    }

    /* --- floating point + bit --- */
    {
        SQLDOUBLE d = 0;
        CV("3.5", 3, 0, 0, SQL_C_DOUBLE, &d, 0, &ind);
        assert(d == 3.5);
        SQLREAL f = 0;
        CV("1.25", 4, 0, 0, SQL_C_FLOAT, &f, 0, &ind);
        assert(f == 1.25f);
        unsigned char bit = 9;
        CV("0", 1, 0, 0, SQL_C_BIT, &bit, 0, &ind);
        assert(bit == 0);
        CV("5", 1, 0, 0, SQL_C_BIT, &bit, 0, &ind);
        assert(bit == 1);                       /* nonzero -> 1 */
    }

    /* --- NUMERIC struct (sign, scale, mantissa) --- */
    {
        SQL_NUMERIC_STRUCT ns;
        CV("-123.45", 7, 0, 0, SQL_C_NUMERIC, &ns, 0, &ind);
        assert(ns.sign == 0 && ns.scale == 2);  /* sign 0 = negative */
        assert(ns.val[0] == (12345 & 0xFF) && ns.val[1] == ((12345 >> 8) & 0xFF));
    }

    /* --- char, truncation, hex(binary) --- */
    {
        char buf[16];
        assert(CV("hello", 5, 0, 0, SQL_C_CHAR, buf, sizeof buf, &ind) == SQL_SUCCESS);
        assert(strcmp(buf, "hello") == 0 && ind == 5);

        char small[4];                          /* 3 chars + NUL */
        SQLRETURN r = CV("hello", 5, 0, 0, SQL_C_CHAR, small, sizeof small, &ind);
        assert(r == SQL_SUCCESS_WITH_INFO && strcmp(small, "hel") == 0 && ind == 5);

        char hex[16];
        unsigned char raw[2] = { 0xDE, 0xAD };
        CV(raw, 2, 0, 1, SQL_C_CHAR, hex, sizeof hex, &ind);   /* binary -> hex text */
        assert(strcmp(hex, "DEAD") == 0 && ind == 4);

        unsigned char bin[4];
        CV(raw, 2, 0, 1, SQL_C_BINARY, bin, sizeof bin, &ind);
        assert(ind == 2 && bin[0] == 0xDE && bin[1] == 0xAD);
    }

    /* --- timestamp / date --- */
    {
        SQL_TIMESTAMP_STRUCT ts;
        CV("2026-06-18 14:30:45", 19, 0, 0, SQL_C_TYPE_TIMESTAMP, &ts, 0, &ind);
        assert(ts.year == 2026 && ts.month == 6 && ts.day == 18 &&
               ts.hour == 14 && ts.minute == 30 && ts.second == 45);
        SQL_DATE_STRUCT dt;
        CV("2026-06-18 00:00:00", 19, 0, 0, SQL_C_TYPE_DATE, &dt, 0, &ind);
        assert(dt.year == 2026 && dt.month == 6 && dt.day == 18);
    }

    /* --- wide (UTF-16) --- */
    {
        SQLWCHAR w[16];
        CV("Hi", 2, 0, 0, SQL_C_WCHAR, w, sizeof w, &ind);
        assert(ind == 4 && w[0] == 'H' && w[1] == 'i' && w[2] == 0);   /* 2 chars = 4 bytes */
        /* a 2-byte (1-char) buffer truncates cleanly with a NUL */
        SQLWCHAR one[1];
        SQLRETURN r = CV("AB", 2, 0, 0, SQL_C_WCHAR, one, sizeof one, &ind);
        assert(r == SQL_SUCCESS_WITH_INFO && ind == 4 && one[0] == 0);
    }

    /* --- NULL --- */
    {
        SQLINTEGER v = 1;
        assert(CV(NULL, 0, 1, 0, SQL_C_SLONG, &v, 0, &ind) == SQL_SUCCESS);
        assert(ind == SQL_NULL_DATA);
        assert(CV(NULL, 0, 1, 0, SQL_C_SLONG, &v, 0, NULL) == SQL_ERROR);  /* 22002 */
    }

    printf("test_convert: all assertions passed\n");
    return 0;
}
