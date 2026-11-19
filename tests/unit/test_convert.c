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
                    &cv_state, 0)
/* The same with the source's SQL type (#336). */
#define CVS(val, src, target, buf, buflen, ind)                                                    \
  seer_odbc_convert((val), strlen(val), 0, 0, (target), (buf), (buflen), (ind), NULL, &cv_state,   \
                    (src))

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
    /* a bit is 0 or 1: 5 is 22003, the buffer untouched (#329) */
    assert(CV("5", 1, 0, 0, SQL_C_BIT, &bit, 0, &ind) == SQL_ERROR && ST("22003") && bit == 0);
    assert(CV("1.5", 3, 0, 0, SQL_C_BIT, &bit, 0, &ind) == SQL_SUCCESS_WITH_INFO && ST("01S07") &&
           bit == 1);
    assert(CV("-1", 2, 0, 0, SQL_C_BIT, &bit, 0, &ind) == SQL_ERROR && ST("22003"));
    assert(CV("-0.5", 4, 0, 0, SQL_C_BIT, &bit, 0, &ind) == SQL_ERROR && ST("22003"));
    /* 23ai BOOLEAN text */
    assert(CV("TRUE", 4, 0, 0, SQL_C_BIT, &bit, 0, &ind) == SQL_SUCCESS && bit == 1);
    assert(CV("false", 5, 0, 0, SQL_C_BIT, &bit, 0, &ind) == SQL_SUCCESS && bit == 0);
  }

  /* --- a number / date cut short in a character buffer (#336) --- */
  {
    char c[32];
    SQLWCHAR w[8];
    SQL_DATE_STRUCT dt;
    /* whole digits don't fit: 22003; only fraction digits lost: 01004 */
    assert(CVS("12345", SQL_DECIMAL, SQL_C_CHAR, c, 4, &ind) == SQL_ERROR && ST("22003"));
    assert(CVS("123.456", SQL_DECIMAL, SQL_C_CHAR, c, 3, &ind) == SQL_ERROR && ST("22003"));
    assert(CVS("123.456", SQL_DECIMAL, SQL_C_CHAR, c, 4, &ind) == SQL_SUCCESS_WITH_INFO &&
           ST("01004") && strcmp(c, "123") == 0);
    assert(CVS("123.456", SQL_DECIMAL, SQL_C_CHAR, c, 5, &ind) == SQL_SUCCESS_WITH_INFO &&
           strcmp(c, "123.") == 0);
    assert(CVS("-12", SQL_INTEGER, SQL_C_CHAR, c, 3, &ind) == SQL_ERROR && ST("22003"));
    assert(CVS("12345", SQL_DECIMAL, SQL_C_CHAR, c, 6, &ind) == SQL_SUCCESS);
    assert(CVS("12345", SQL_DOUBLE, SQL_C_WCHAR, w, 8, &ind) == SQL_ERROR && ST("22003"));
    assert(CVS("123", SQL_DOUBLE, SQL_C_WCHAR, w, 8, &ind) == SQL_SUCCESS);
    /* a length probe is not an overflow */
    assert(CVS("12345", SQL_DECIMAL, SQL_C_CHAR, NULL, 0, &ind) == SQL_SUCCESS && ind == 5);
    /* a timestamp may lose its fraction, not its date or time */
    assert(CVS("2026-11-19 13:14:15", SQL_TYPE_TIMESTAMP, SQL_C_CHAR, c, 11, &ind) == SQL_ERROR &&
           ST("22003"));
    assert(CVS("2026-11-19 13:14:15.5", SQL_TYPE_TIMESTAMP, SQL_C_CHAR, c, 20, &ind) ==
               SQL_SUCCESS_WITH_INFO &&
           ST("01004"));
    /* text still truncates with 01004; an unknown source keeps the old rule */
    assert(CVS("hello", SQL_VARCHAR, SQL_C_CHAR, c, 4, &ind) == SQL_SUCCESS_WITH_INFO &&
           ST("01004"));
    assert(CVS("12345", 0, SQL_C_CHAR, c, 4, &ind) == SQL_SUCCESS_WITH_INFO);
    /* a number into a date struct: 07006 */
    assert(CVS("5", SQL_DECIMAL, SQL_C_TYPE_DATE, &dt, 0, &ind) == SQL_ERROR && ST("07006"));
  }

  /* --- date / time targets: fields, truncation, fractions (#334) --- */
  {
    SQL_DATE_STRUCT dt;
    SQL_TIME_STRUCT tm;
    SQL_TIMESTAMP_STRUCT ts;
#define DTV(txt, target, out) CV((txt), strlen(txt), 0, 0, (target), (out), 0, &ind)
    /* a DATE with a time into a date struct: 01S07 */
    assert(DTV("2026-11-19 13:14:15", SQL_C_TYPE_DATE, &dt) == SQL_SUCCESS_WITH_INFO &&
           ST("01S07") && dt.year == 2026 && dt.month == 11 && dt.day == 19);
    assert(DTV("2026-11-19 00:00:00", SQL_C_TYPE_DATE, &dt) == SQL_SUCCESS);
    assert(DTV("2026-11-19", SQL_C_TYPE_DATE, &dt) == SQL_SUCCESS);
    /* a fraction into a time struct: 01S07; the date part is ignored */
    assert(DTV("2026-11-19 13:14:15.500000000", SQL_C_TYPE_TIME, &tm) == SQL_SUCCESS_WITH_INFO &&
           ST("01S07") && tm.hour == 13 && tm.minute == 14 && tm.second == 15);
    assert(DTV("2026-11-19 13:14:15", SQL_C_TYPE_TIME, &tm) == SQL_SUCCESS);
    assert(DTV("13:14:15", SQL_C_TYPE_TIME, &tm) == SQL_SUCCESS && tm.hour == 13);
    assert(DTV("{t '07:08:09'}", SQL_C_TYPE_TIME, &tm) == SQL_SUCCESS && tm.second == 9);
    /* text fractions scale by digit count */
    assert(DTV("2026-11-19 13:14:15.5", SQL_C_TYPE_TIMESTAMP, &ts) == SQL_SUCCESS &&
           ts.fraction == 500000000);
    assert(DTV("2026-11-19 13:14:15.123456789", SQL_C_TYPE_TIMESTAMP, &ts) == SQL_SUCCESS &&
           ts.fraction == 123456789);
    assert(DTV("2026-11-19 13:14:15.1234567891", SQL_C_TYPE_TIMESTAMP, &ts) ==
               SQL_SUCCESS_WITH_INFO &&
           ST("01S07") && ts.fraction == 123456789);
    assert(DTV("2026-11-19", SQL_C_TYPE_TIMESTAMP, &ts) == SQL_SUCCESS && ts.hour == 0);
    assert(DTV(" {ts '2026-11-19 01:02:03'} ", SQL_C_TYPE_TIMESTAMP, &ts) == SQL_SUCCESS &&
           ts.minute == 2);
    assert(DTV("{d '2024-02-29'}", SQL_C_TYPE_DATE, &dt) == SQL_SUCCESS && dt.day == 29);
    assert(DTV("-044-03-15 00:00:00", SQL_C_TYPE_DATE, &dt) == SQL_SUCCESS && dt.year == -44);
    assert(DTV("1500-02-29", SQL_C_TYPE_DATE, &dt) == SQL_SUCCESS); /* Julian leap year */
    /* invalid fields and forms: 22018 */
    assert(DTV("2026-13-45", SQL_C_TYPE_DATE, &dt) == SQL_ERROR && ST("22018"));
    assert(DTV("2026-02-29", SQL_C_TYPE_DATE, &dt) == SQL_ERROR && ST("22018"));
    assert(DTV("1900-02-29", SQL_C_TYPE_DATE, &dt) == SQL_ERROR && ST("22018"));
    assert(DTV("25:00:00", SQL_C_TYPE_TIME, &tm) == SQL_ERROR && ST("22018"));
    assert(DTV("12:60:00", SQL_C_TYPE_TIME, &tm) == SQL_ERROR && ST("22018"));
    assert(DTV("13:14:15", SQL_C_TYPE_TIMESTAMP, &ts) == SQL_ERROR && ST("22018"));
    assert(DTV("13:14:15", SQL_C_TYPE_DATE, &dt) == SQL_ERROR && ST("22018"));
    assert(DTV("2026-11-19 junk", SQL_C_TYPE_TIMESTAMP, &ts) == SQL_ERROR && ST("22018"));
    assert(DTV("garbage", SQL_C_TYPE_TIMESTAMP, &ts) == SQL_ERROR && ST("22018"));
    assert(DTV("5", SQL_C_TYPE_DATE, &dt) == SQL_ERROR && ST("22018"));
    assert(DTV("2026-11-19 13:14:15.", SQL_C_TYPE_TIMESTAMP, &ts) == SQL_ERROR);
#undef DTV
  }

  /* --- SQL_C_NUMERIC: exact, past 128 bits, text (#332) --- */
  {
    SQL_NUMERIC_STRUCT n;
    char t[300];
    assert(CV("-123.45", 7, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_SUCCESS);
    assert(n.sign == 0 && n.scale == 2 && n.precision == 5);
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "-123.45") == 0);
    /* 1e39: past 2^128 as written; exact as mantissa 1, scale -39 */
    assert(CV("1e39", 4, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_SUCCESS);
    assert(n.sign == 1 && n.scale == -39 && n.precision == 1 && n.val[0] == 1);
    assert(CV("1000000000000000000000000000000000000000", 40, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) ==
               SQL_SUCCESS &&
           n.scale == -1);
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "1000000000000000000000000000000000000000") == 0);
    /* 2^128 - 1 fits; 40 significant integer digits don't */
    assert(CV("340282366920938463463374607431768211455", 39, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) ==
           SQL_SUCCESS);
    assert(n.scale == 0 && n.precision == 39 && n.val[15] == 0xFF);
    assert(CV("1234567890123456789012345678901234567891", 40, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) ==
               SQL_ERROR &&
           ST("22003"));
    /* too many fraction digits: the tail is dropped with 01S07 */
    assert(CV("1.2345678901234567890123456789012345678901", 42, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) ==
               SQL_SUCCESS_WITH_INFO &&
           ST("01S07"));
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "1.23456789012345678901234567890123456789") == 0);
    assert(CV("'1.5e3'", 0, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_ERROR && ST("22018"));
    assert(CV("1.5e3", 5, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_SUCCESS);
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "1500") == 0);
    assert(CV("abc", 3, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_ERROR && ST("22018"));
    assert(CV("1e-20", 5, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_SUCCESS && n.scale == 20 &&
           n.val[0] == 1);
    assert(CV("1e-200", 6, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_SUCCESS_WITH_INFO &&
           ST("01S07") && n.val[0] == 0); /* below SQLSCHAR scale: truncates to zero */
    assert(CV("1e200", 5, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_ERROR && ST("22003"));
    assert(CV("0.000", 5, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_SUCCESS && n.val[0] == 0 &&
           n.sign == 1);
    assert(CV("TRUE", 4, 0, 0, SQL_C_NUMERIC, &n, 0, &ind) == SQL_SUCCESS && n.val[0] == 1);
    unsigned char raw[1] = {1};
    assert(CV(raw, 1, 0, 1, SQL_C_NUMERIC, &n, 0, &ind) == SQL_ERROR && ST("07006"));
  }

  /* --- integer ranges, truncation, non-numeric text (#329) --- */
  {
    SQLSMALLINT sh = 7;
    assert(CV("70000", 5, 0, 0, SQL_C_SSHORT, &sh, 0, &ind) == SQL_ERROR && ST("22003") && sh == 7);
    assert(CV("-32768", 6, 0, 0, SQL_C_SSHORT, &sh, 0, &ind) == SQL_SUCCESS && sh == -32768);
    assert(CV("32768", 5, 0, 0, SQL_C_SSHORT, &sh, 0, &ind) == SQL_ERROR && ST("22003"));
    SQLUSMALLINT us = 0;
    assert(CV("65535", 5, 0, 0, SQL_C_USHORT, &us, 0, &ind) == SQL_SUCCESS && us == 65535);
    SQLINTEGER l = 0;
    assert(CV("3.7", 3, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_SUCCESS_WITH_INFO && ST("01S07") &&
           l == 3);
    assert(CV("-3.7", 4, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_SUCCESS_WITH_INFO && l == -3);
    assert(CV("12.000", 6, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_SUCCESS && l == 12);
    assert(CV(".5", 2, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_SUCCESS_WITH_INFO && l == 0);
    assert(CV("  42  ", 6, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_SUCCESS && l == 42);
    assert(CV("1.5E+3", 6, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_SUCCESS && l == 1500);
    assert(CV("abc", 3, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_ERROR && ST("22018"));
    assert(CV("", 0, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_ERROR && ST("22018"));
    assert(CV("1e", 2, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_ERROR && ST("22018"));
    assert(CV("TRUE", 4, 0, 0, SQL_C_SLONG, &l, 0, &ind) == SQL_SUCCESS && l == 1);
    SQLUINTEGER ul = 9;
    assert(CV("-1", 2, 0, 0, SQL_C_ULONG, &ul, 0, &ind) == SQL_ERROR && ST("22003") && ul == 9);
    assert(CV("-0.4", 4, 0, 0, SQL_C_ULONG, &ul, 0, &ind) == SQL_SUCCESS_WITH_INFO && ul == 0);
    SQLBIGINT b = 0;
    assert(CV("-9223372036854775808", 20, 0, 0, SQL_C_SBIGINT, &b, 0, &ind) == SQL_SUCCESS &&
           b == (-9223372036854775807LL - 1));
    assert(CV("9223372036854775808", 19, 0, 0, SQL_C_SBIGINT, &b, 0, &ind) == SQL_ERROR &&
           ST("22003"));
    assert(CV("1e20", 4, 0, 0, SQL_C_SBIGINT, &b, 0, &ind) == SQL_ERROR && ST("22003"));
    SQLUBIGINT ub = 0;
    assert(CV("18446744073709551615", 20, 0, 0, SQL_C_UBIGINT, &ub, 0, &ind) == SQL_SUCCESS &&
           ub == 18446744073709551615ULL);
    assert(CV("18446744073709551616", 20, 0, 0, SQL_C_UBIGINT, &ub, 0, &ind) == SQL_ERROR &&
           ST("22003"));
    SQLSCHAR t = 0;
    assert(CV("-128", 4, 0, 0, SQL_C_STINYINT, &t, 0, &ind) == SQL_SUCCESS && t == -128);
    assert(CV("128", 3, 0, 0, SQL_C_STINYINT, &t, 0, &ind) == SQL_ERROR && ST("22003"));
    unsigned char raw[2] = {0x01, 0x02}; /* binary -> numeric: 07006 */
    assert(CV(raw, 2, 0, 1, SQL_C_SLONG, &l, 0, &ind) == SQL_ERROR && ST("07006"));
    SQLDOUBLE d = 0;
    assert(CV("1e400", 5, 0, 0, SQL_C_DOUBLE, &d, 0, &ind) == SQL_ERROR && ST("22003"));
    assert(CV("x1", 2, 0, 0, SQL_C_DOUBLE, &d, 0, &ind) == SQL_ERROR && ST("22018"));
    SQLREAL f = 0;
    assert(CV("1e39", 4, 0, 0, SQL_C_FLOAT, &f, 0, &ind) == SQL_ERROR && ST("22003"));
    /* exactly representable: msvcrt's strtod is not correctly rounded (MinGW 32-bit) */
    assert(CV("-1.25E+2", 8, 0, 0, SQL_C_DOUBLE, &d, 0, &ind) == SQL_SUCCESS && d == -125.0);
    assert(CV("2.5e-1", 6, 0, 0, SQL_C_DOUBLE, &d, 0, &ind) == SQL_SUCCESS && d == 0.25);
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

  /* --- parameter side (#322): SQL_NUMERIC_STRUCT -> exact decimal text --- */
  {
    char t[300];
    SQL_NUMERIC_STRUCT n;
    memset(&n, 0, sizeof n);
    n.sign = 1;
    n.scale = 2;
    n.val[0] = 12345 & 0xFF;
    n.val[1] = 12345 >> 8;
    assert(seer_odbc_numeric_to_text(&n, t, sizeof t) == 6 && strcmp(t, "123.45") == 0);
    n.sign = 0; /* negative */
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "-123.45") == 0);
    n.scale = 7; /* more scale than digits */
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "-0.0012345") == 0);
    n.scale = -3; /* negative scale: trailing zeros */
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "-12345000") == 0);
    memset(n.val, 0, sizeof n.val); /* zero: no sign, no padding */
    n.scale = -3;
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "0") == 0);
    n.scale = 2;
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "0.00") == 0);
    memset(n.val, 0xFF, sizeof n.val); /* 2^128 - 1 */
    n.sign = 1;
    n.scale = 0;
    seer_odbc_numeric_to_text(&n, t, sizeof t);
    assert(strcmp(t, "340282366920938463463374607431768211455") == 0);
    assert(seer_odbc_numeric_to_text(&n, t, 10) == 0); /* too small: refused */
  }

  /* --- GUID -> canonical text --- */
  {
    SQLGUID g = {0x12345678, 0x9abc, 0xdef0, {1, 2, 3, 4, 5, 6, 7, 8}};
    char t[37];
    seer_odbc_guid_to_text(&g, t);
    assert(strcmp(t, "12345678-9ABC-DEF0-0102-030405060708") == 0);
  }

  /* --- interval C struct -> the Oracle form, only the type's own fields --- */
  {
    SQL_INTERVAL_STRUCT iv;
    SeerOdbcInterval v;
    memset(&iv, 0, sizeof iv);
    iv.intval.day_second.day = 7; /* not a field of HOUR: ignored */
    iv.intval.day_second.hour = 30;
    assert(seer_odbc_interval_from_c(SQL_C_INTERVAL_HOUR, &iv, &v) == 0);
    assert(!v.year_month && v.days == 1 && v.hours == 6 && v.mins == 0 && !v.negative);

    memset(&iv, 0, sizeof iv);
    iv.interval_sign = SQL_TRUE;
    iv.intval.year_month.year = 3; /* not a field of MONTH: ignored */
    iv.intval.year_month.month = 14;
    assert(seer_odbc_interval_from_c(SQL_C_INTERVAL_MONTH, &iv, &v) == 0);
    assert(v.year_month && v.negative && v.years == 1 && v.months == 2);

    memset(&iv, 0, sizeof iv);
    iv.intval.day_second.minute = 2;
    iv.intval.day_second.second = 59;
    iv.intval.day_second.fraction = 1500000; /* 1.5 s in microseconds */
    assert(seer_odbc_interval_from_c(SQL_C_INTERVAL_MINUTE_TO_SECOND, &iv, &v) == 0);
    assert(v.days == 0 && v.hours == 0 && v.mins == 3 && v.secs == 0 && v.nanos == 500000000);

    memset(&iv, 0, sizeof iv);
    iv.intval.day_second.day = 1000000000; /* past INTERVAL DAY(9) */
    assert(seer_odbc_interval_from_c(SQL_C_INTERVAL_DAY, &iv, &v) == -2);
    assert(seer_odbc_interval_from_c(SQL_C_SLONG, &iv, &v) == -1);
  }

  printf("test_convert: all assertions passed\n");
  return 0;
}
