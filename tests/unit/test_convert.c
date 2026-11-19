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

static const char *cv_state; /* the SQLSTATE of the last CV() */
#define ST(want) (cv_state != NULL && strcmp(cv_state, (want)) == 0)

/* An interval conversion of NUL-terminated `txt`. */
#define IV(txt, target, out) CV((txt), strlen(txt), 0, 0, (target), (out), 0, &ind)

#define CV(val, vlen, isnull, isbin, target, buf, buflen, ind)                                     \
  seer_odbc_convert((val), (vlen), (isnull), (isbin), (target), (buf), (buflen), (ind), NULL,      \
                    &cv_state)

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
    assert(bit == 1); /* nonzero -> 1 */
  }

  /* --- NUMERIC struct (sign, scale, mantissa) --- */
  {
    SQL_NUMERIC_STRUCT ns;
    CV("-123.45", 7, 0, 0, SQL_C_NUMERIC, &ns, 0, &ind);
    assert(ns.sign == 0 && ns.scale == 2); /* sign 0 = negative */
    assert(ns.val[0] == (12345 & 0xFF) && ns.val[1] == ((12345 >> 8) & 0xFF));
  }

  /* --- char, truncation, hex(binary) --- */
  {
    char buf[16];
    assert(CV("hello", 5, 0, 0, SQL_C_CHAR, buf, sizeof buf, &ind) == SQL_SUCCESS);
    assert(strcmp(buf, "hello") == 0 && ind == 5);

    char small[4]; /* 3 chars + NUL */
    SQLRETURN r = CV("hello", 5, 0, 0, SQL_C_CHAR, small, sizeof small, &ind);
    assert(r == SQL_SUCCESS_WITH_INFO && strcmp(small, "hel") == 0 && ind == 5);

    char hex[16];
    unsigned char raw[2] = {0xDE, 0xAD};
    CV(raw, 2, 0, 1, SQL_C_CHAR, hex, sizeof hex, &ind); /* binary -> hex text */
    assert(strcmp(hex, "DEAD") == 0 && ind == 4);

    unsigned char bin[4];
    CV(raw, 2, 0, 1, SQL_C_BINARY, bin, sizeof bin, &ind);
    assert(ind == 2 && bin[0] == 0xDE && bin[1] == 0xAD);
  }

  /* --- timestamp / date --- */
  {
    SQL_TIMESTAMP_STRUCT ts;
    CV("2026-06-18 14:30:45", 19, 0, 0, SQL_C_TYPE_TIMESTAMP, &ts, 0, &ind);
    assert(ts.year == 2026 && ts.month == 6 && ts.day == 18 && ts.hour == 14 && ts.minute == 30 &&
           ts.second == 45);
    SQL_DATE_STRUCT dt;
    CV("2026-06-18 00:00:00", 19, 0, 0, SQL_C_TYPE_DATE, &dt, 0, &ind);
    assert(dt.year == 2026 && dt.month == 6 && dt.day == 18);
  }

  /* --- wide (UTF-16) --- */
  {
    SQLWCHAR w[16];
    CV("Hi", 2, 0, 0, SQL_C_WCHAR, w, sizeof w, &ind);
    assert(ind == 4 && w[0] == 'H' && w[1] == 'i' && w[2] == 0); /* 2 chars = 4 bytes */
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
    assert(CV(NULL, 0, 1, 0, SQL_C_SLONG, &v, 0, NULL) == SQL_ERROR && ST("22002"));
  }

  /* --- intervals from Oracle's text (#314) --- */
  {
    SQL_INTERVAL_STRUCT iv;
    const char *ds = "+1 02:03:04.500000000";
    assert(IV(ds, SQL_C_INTERVAL_DAY_TO_SECOND, &iv) == SQL_SUCCESS);
    assert(ind == (SQLLEN)sizeof iv && iv.interval_type == SQL_IS_DAY_TO_SECOND &&
           iv.interval_sign == SQL_FALSE && iv.intval.day_second.day == 1 &&
           iv.intval.day_second.hour == 2 && iv.intval.day_second.minute == 3 &&
           iv.intval.day_second.second == 4 && iv.intval.day_second.fraction == 500000);
    /* The leading field takes in the larger ones; what has no field is cut. */
    assert(IV(ds, SQL_C_INTERVAL_HOUR, &iv) == SQL_SUCCESS_WITH_INFO && ST("01S07"));
    assert(iv.interval_type == SQL_IS_HOUR && iv.intval.day_second.hour == 26 &&
           iv.intval.day_second.minute == 0);
    assert(IV(ds, SQL_C_INTERVAL_MINUTE_TO_SECOND, &iv) == SQL_SUCCESS);
    assert(iv.intval.day_second.minute == 26 * 60 + 3 && iv.intval.day_second.second == 4 &&
           iv.intval.day_second.fraction == 500000 && iv.intval.day_second.hour == 0);
    assert(IV(ds, SQL_C_INTERVAL_SECOND, &iv) == SQL_SUCCESS);
    assert(iv.intval.day_second.second == ((26 * 60) + 3) * 60 + 4);
    assert(IV(ds, SQL_C_INTERVAL_DAY_TO_HOUR, &iv) == SQL_SUCCESS_WITH_INFO && ST("01S07"));
    assert(iv.intval.day_second.day == 1 && iv.intval.day_second.hour == 2);
    assert(IV("+1 02:03:00.000000000", SQL_C_INTERVAL_DAY_TO_MINUTE, &iv) == SQL_SUCCESS);
    assert(IV("+1 02:03:00.000000000", SQL_C_INTERVAL_HOUR_TO_MINUTE, &iv) == SQL_SUCCESS);
    assert(iv.intval.day_second.hour == 26 && iv.intval.day_second.minute == 3);
    assert(IV("-0 10:00:00.000000000", SQL_C_INTERVAL_HOUR_TO_SECOND, &iv) == SQL_SUCCESS);
    assert(iv.interval_sign == SQL_TRUE && iv.intval.day_second.hour == 10);
    assert(IV("+5 00:00:00.000000000", SQL_C_INTERVAL_DAY, &iv) == SQL_SUCCESS);
    assert(iv.interval_type == SQL_IS_DAY && iv.intval.day_second.day == 5);
    /* Nanoseconds past the default seconds precision (6) are cut. */
    assert(IV("+0 00:00:01.123456789", SQL_C_INTERVAL_SECOND, &iv) == SQL_SUCCESS_WITH_INFO &&
           ST("01S07") && iv.intval.day_second.fraction == 123456);
    assert(IV("+000000001 02:03:04", SQL_C_INTERVAL_DAY_TO_SECOND, &iv) == SQL_SUCCESS);
    assert(iv.intval.day_second.day == 1 && iv.intval.day_second.fraction == 0);

    const char *ym = "-3-04";
    assert(IV(ym, SQL_C_INTERVAL_YEAR_TO_MONTH, &iv) == SQL_SUCCESS);
    assert(iv.interval_type == SQL_IS_YEAR_TO_MONTH && iv.interval_sign == SQL_TRUE &&
           iv.intval.year_month.year == 3 && iv.intval.year_month.month == 4);
    assert(IV(ym, SQL_C_INTERVAL_MONTH, &iv) == SQL_SUCCESS && iv.intval.year_month.month == 40);
    assert(IV(ym, SQL_C_INTERVAL_YEAR, &iv) == SQL_SUCCESS_WITH_INFO && ST("01S07"));
    assert(iv.intval.year_month.year == 3);

    /* A plain count is one field; year-month and day-time don't mix; text
     * that isn't an interval is 22018; a leading field past 32 bits 22015. */
    assert(IV("42", SQL_C_INTERVAL_DAY, &iv) == SQL_SUCCESS && iv.intval.day_second.day == 42);
    assert(IV("-7", SQL_C_INTERVAL_MONTH, &iv) == SQL_SUCCESS && iv.interval_sign == SQL_TRUE &&
           iv.intval.year_month.month == 7);
    assert(IV("42", SQL_C_INTERVAL_DAY_TO_SECOND, &iv) == SQL_ERROR && ST("22018"));
    assert(IV(ym, SQL_C_INTERVAL_DAY_TO_SECOND, &iv) == SQL_ERROR && ST("07006"));
    assert(IV(ds, SQL_C_INTERVAL_YEAR_TO_MONTH, &iv) == SQL_ERROR && ST("07006"));
    assert(IV("abc", SQL_C_INTERVAL_DAY, &iv) == SQL_ERROR && ST("22018"));
    assert(IV("+1 25:00:00", SQL_C_INTERVAL_DAY_TO_SECOND, &iv) == SQL_ERROR && ST("22018"));
    assert(IV("+999999999 23:59:59.000000000", SQL_C_INTERVAL_SECOND, &iv) == SQL_ERROR &&
           ST("22015"));
  }

  /* --- no Oracle value converts to a GUID; a bad date is 22018 --- */
  {
    SQLGUID g;
    memset(&g, 0x5A, sizeof g);
    assert(CV("abc", 3, 0, 0, SQL_C_GUID, &g, sizeof g, &ind) == SQL_ERROR && ST("07006"));
    assert(((unsigned char *)&g)[0] == 0x5A); /* nothing written */
    SQL_TIMESTAMP_STRUCT ts;
    assert(CV("x", 1, 0, 0, SQL_C_TYPE_TIMESTAMP, &ts, 0, &ind) == SQL_ERROR && ST("22018"));
    char small[4];
    assert(CV("hello", 5, 0, 0, SQL_C_CHAR, small, sizeof small, &ind) == SQL_SUCCESS_WITH_INFO &&
           ST("01004"));
  }

  /* --- SQL_C_DEFAULT is the SQL type's ODBC default C type (#316) --- */
  {
    static const struct {
      SQLSMALLINT sql, c;
    } D[] = {
        {SQL_CHAR, SQL_C_CHAR},
        {SQL_VARCHAR, SQL_C_CHAR},
        {SQL_LONGVARCHAR, SQL_C_CHAR},
        {SQL_DECIMAL, SQL_C_CHAR},
        {SQL_NUMERIC, SQL_C_CHAR},
        {SQL_WVARCHAR, SQL_C_WCHAR},
        {SQL_BIT, SQL_C_BIT},
        {SQL_TINYINT, SQL_C_STINYINT},
        {SQL_SMALLINT, SQL_C_SSHORT},
        {SQL_INTEGER, SQL_C_SLONG},
        {SQL_BIGINT, SQL_C_SBIGINT},
        {SQL_REAL, SQL_C_FLOAT},
        {SQL_FLOAT, SQL_C_DOUBLE},
        {SQL_DOUBLE, SQL_C_DOUBLE},
        {SQL_VARBINARY, SQL_C_BINARY},
        {SQL_LONGVARBINARY, SQL_C_BINARY},
        {SQL_TYPE_DATE, SQL_C_TYPE_DATE},
        {SQL_TYPE_TIME, SQL_C_TYPE_TIME},
        {SQL_TYPE_TIMESTAMP, SQL_C_TYPE_TIMESTAMP},
        {SQL_TIMESTAMP, SQL_C_TIMESTAMP},
        {SQL_GUID, SQL_C_GUID},
        {SQL_INTERVAL_YEAR, SQL_C_INTERVAL_YEAR},
        {SQL_INTERVAL_DAY_TO_SECOND, SQL_C_INTERVAL_DAY_TO_SECOND},
        {SQL_INTERVAL_MINUTE_TO_SECOND, SQL_C_INTERVAL_MINUTE_TO_SECOND},
        {-9998, SQL_C_CHAR}, /* a driver-specific type (SQL_SEER_CLOB) */
    };
    for (size_t i = 0; i < sizeof D / sizeof D[0]; i++)
      assert(seer_odbc_default_c_type(D[i].sql) == D[i].c);
  }

  /* --- fixed-length C types have their own size (array strides) --- */
  {
    assert(seer_odbc_c_fixed_size(SQL_C_NUMERIC) == sizeof(SQL_NUMERIC_STRUCT));
    assert(seer_odbc_c_fixed_size(SQL_C_INTERVAL_DAY_TO_SECOND) == sizeof(SQL_INTERVAL_STRUCT));
    assert(seer_odbc_c_fixed_size(SQL_C_INTERVAL_YEAR) == sizeof(SQL_INTERVAL_STRUCT));
    assert(seer_odbc_c_fixed_size(SQL_C_GUID) == sizeof(SQLGUID));
    assert(seer_odbc_c_fixed_size(SQL_C_SLONG) == sizeof(SQLINTEGER));
    assert(seer_odbc_c_fixed_size(SQL_C_CHAR) == 0 && seer_odbc_c_fixed_size(SQL_C_BINARY) == 0);
  }

  printf("test_convert: all assertions passed\n");
  return 0;
}
