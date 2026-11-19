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
static int parse_datetime(const char *s, int *Y, int *Mo, int *D, int *h, int *mi, int *se,
                          unsigned long *frac)
{
  *Y = *Mo = *D = *h = *mi = *se = 0;
  *frac = 0;
  int n = sscanf(s, "%d-%d-%d %d:%d:%d", Y, Mo, D, h, mi, se);
  if (n < 3)
    return -1;
  const char *dot = strchr(s, '.');
  if (dot != NULL)
    *frac = strtoul(dot + 1, NULL, 10); /* 9-digit nanoseconds */
  return 0;
}

/* Fill an SQL_NUMERIC_STRUCT from a decimal string (sign, 128-bit LE mantissa,
 * scale = fractional digit count). */
static void to_numeric(const char *s, SQL_NUMERIC_STRUCT *ns)
{
  memset(ns, 0, sizeof *ns);
  ns->sign = 1;
  const char *p = s;
  if (*p == '-') {
    ns->sign = 0;
    p++;
  } else if (*p == '+') {
    p++;
  }

  unsigned char val[SQL_MAX_NUMERIC_LEN] = {0};
  int scale = 0, prec = 0;
  bool seen_dot = false;
  for (; *p != '\0'; p++) {
    if (*p == '.') {
      seen_dot = true;
      continue;
    }
    if (*p < '0' || *p > '9')
      break;
    int carry = *p - '0';
    for (size_t i = 0; i < sizeof val; i++) {
      int x = val[i] * 10 + carry;
      val[i] = (unsigned char)(x & 0xFF);
      carry = x >> 8;
    }
    prec++;
    if (seen_dot)
      scale++;
  }
  ns->precision = (SQLCHAR)(prec ? prec : 1);
  ns->scale = (SQLSCHAR)scale;
  memcpy(ns->val, val, sizeof val);
}

/* An interval value from its text (#314): Oracle renders INTERVAL DAY TO
 * SECOND as "[+-]D HH:MI:SS[.fffffffff]" and YEAR TO MONTH as "[+-]Y-MM"; a
 * plain integer is one field's count (an exact numeric source). */
enum { IV_BAD, IV_YM, IV_DS, IV_INT };
typedef struct {
  int kind;
  int neg;
  unsigned long long y, mo, d, h, mi, se, ns; /* ns: nanoseconds */
} Interval;

static unsigned long long digits(const char **p, int *n)
{
  unsigned long long v = 0;
  *n = 0;
  while (**p >= '0' && **p <= '9' && *n < 19) {
    v = v * 10 + (unsigned long long)(**p - '0');
    (*p)++;
    (*n)++;
  }
  return v;
}

static void parse_interval(const char *s, size_t len, Interval *iv)
{
  memset(iv, 0, sizeof *iv);
  char tmp[64];
  if (len >= sizeof tmp)
    return; /* IV_BAD */
  memcpy(tmp, s, len);
  tmp[len] = '\0';
  const char *p = tmp;
  int n;
  while (*p == ' ')
    p++;
  if (*p == '-' || *p == '+')
    iv->neg = *p++ == '-';
  unsigned long long lead = digits(&p, &n);
  if (n == 0)
    return;
  if (*p == '\0') {
    iv->kind = IV_INT;
    iv->d = lead;
    return;
  }
  if (*p == '-') { /* Y-MM */
    p++;
    iv->y = lead;
    iv->mo = digits(&p, &n);
    if (n == 0 || *p != '\0' || iv->mo > 11)
      return;
    iv->kind = IV_YM;
    return;
  }
  if (*p != ' ') /* D HH:MI:SS[.f] */
    return;
  p++;
  iv->d = lead;
  iv->h = digits(&p, &n);
  if (n == 0 || *p++ != ':')
    return;
  iv->mi = digits(&p, &n);
  if (n == 0 || *p++ != ':')
    return;
  iv->se = digits(&p, &n);
  if (n == 0)
    return;
  if (*p == '.') {
    p++;
    const char *f = p;
    iv->ns = digits(&p, &n);
    for (int k = (int)(p - f); k < 9; k++)
      iv->ns *= 10;
    for (int k = (int)(p - f); k > 9; k--)
      iv->ns /= 10;
  }
  if (*p != '\0' || iv->h > 23 || iv->mi > 59 || iv->se > 59)
    return;
  iv->kind = IV_DS;
}

/* Fill an SQL_INTERVAL_STRUCT of C type `target` from `iv`. The leading field
 * takes in the larger ones (SQL_C_INTERVAL_HOUR of 1 day 2 hours is 26);
 * dropping non-zero trailing fields, or fraction digits past the default
 * seconds precision of 6, is 01S07. Returns SQL_SUCCESS, SQL_SUCCESS_WITH_INFO
 * or SQL_ERROR, with the SQLSTATE in *state. */
static SQLRETURN to_interval(const Interval *iv, SQLSMALLINT target, SQL_INTERVAL_STRUCT *out,
                             const char **state)
{
  const bool ym_target = target == SQL_C_INTERVAL_YEAR || target == SQL_C_INTERVAL_MONTH ||
                         target == SQL_C_INTERVAL_YEAR_TO_MONTH;
  const bool single = target == SQL_C_INTERVAL_YEAR || target == SQL_C_INTERVAL_MONTH ||
                      target == SQL_C_INTERVAL_DAY || target == SQL_C_INTERVAL_HOUR ||
                      target == SQL_C_INTERVAL_MINUTE || target == SQL_C_INTERVAL_SECOND;
  Interval v = *iv;
  if (v.kind == IV_BAD || (v.kind == IV_INT && !single)) {
    *state = "22018";
    return SQL_ERROR;
  }
  if (v.kind == IV_INT) { /* the count is the target's one field */
    unsigned long long c = v.d;
    v.d = 0;
    switch (target) {
    case SQL_C_INTERVAL_YEAR:
      v.y = c;
      break;
    case SQL_C_INTERVAL_MONTH:
      v.mo = c;
      break;
    case SQL_C_INTERVAL_DAY:
      v.d = c;
      break;
    case SQL_C_INTERVAL_HOUR:
      v.h = c;
      break;
    case SQL_C_INTERVAL_MINUTE:
      v.mi = c;
      break;
    default:
      v.se = c;
      break;
    }
    v.kind = ym_target ? IV_YM : IV_DS;
  }
  if ((v.kind == IV_YM) != ym_target) {
    *state = "07006"; /* year-month and day-time don't convert */
    return SQL_ERROR;
  }

  memset(out, 0, sizeof *out);
  out->interval_type = (SQLINTERVAL)(target - SQL_C_INTERVAL_YEAR + SQL_IS_YEAR);
  out->interval_sign = v.neg ? SQL_TRUE : SQL_FALSE;
  const unsigned long long hours = v.d * 24 + v.h, mins = hours * 60 + v.mi,
                           secs = mins * 60 + v.se;
  /* The leading field, in 64 bits so an overflow shows; the trailing fields
   * are as they are; `trunc` when a non-zero part has no field. */
  unsigned long long lead;
  bool trunc = false;
  SQLUINTEGER *lead_at;
  switch (target) {
  case SQL_C_INTERVAL_YEAR:
    lead = v.y, lead_at = &out->intval.year_month.year, trunc = v.mo != 0;
    break;
  case SQL_C_INTERVAL_MONTH:
    lead = v.y * 12 + v.mo, lead_at = &out->intval.year_month.month, trunc = false;
    break;
  case SQL_C_INTERVAL_YEAR_TO_MONTH:
    lead = v.y, lead_at = &out->intval.year_month.year, trunc = false;
    out->intval.year_month.month = (SQLUINTEGER)v.mo;
    break;
  case SQL_C_INTERVAL_DAY:
  case SQL_C_INTERVAL_DAY_TO_HOUR:
  case SQL_C_INTERVAL_DAY_TO_MINUTE:
  case SQL_C_INTERVAL_DAY_TO_SECOND:
    lead = v.d, lead_at = &out->intval.day_second.day;
    break;
  case SQL_C_INTERVAL_HOUR:
  case SQL_C_INTERVAL_HOUR_TO_MINUTE:
  case SQL_C_INTERVAL_HOUR_TO_SECOND:
    lead = hours, lead_at = &out->intval.day_second.hour;
    break;
  case SQL_C_INTERVAL_MINUTE:
  case SQL_C_INTERVAL_MINUTE_TO_SECOND:
    lead = mins, lead_at = &out->intval.day_second.minute;
    break;
  default: /* SQL_C_INTERVAL_SECOND */
    lead = secs, lead_at = &out->intval.day_second.second;
    break;
  }
  if (!ym_target) {
    /* The last field the target has: the hour, minute and second below the
     * leading one are filled down to it; what lies past it is cut. */
    const int last = target == SQL_C_INTERVAL_DAY                                            ? 0
                     : target == SQL_C_INTERVAL_HOUR || target == SQL_C_INTERVAL_DAY_TO_HOUR ? 1
                     : target == SQL_C_INTERVAL_MINUTE || target == SQL_C_INTERVAL_DAY_TO_MINUTE ||
                             target == SQL_C_INTERVAL_HOUR_TO_MINUTE
                         ? 2
                         : 3;
    const int first = lead_at == &out->intval.day_second.day      ? 0
                      : lead_at == &out->intval.day_second.hour   ? 1
                      : lead_at == &out->intval.day_second.minute ? 2
                                                                  : 3;
    if (first < 1 && last >= 1)
      out->intval.day_second.hour = (SQLUINTEGER)v.h;
    if (first < 2 && last >= 2)
      out->intval.day_second.minute = (SQLUINTEGER)v.mi;
    if (first < 3 && last >= 3)
      out->intval.day_second.second = (SQLUINTEGER)v.se;
    if (last == 3)
      out->intval.day_second.fraction = (SQLUINTEGER)(v.ns / 1000);
    trunc = (last < 1 && v.h) || (last < 2 && v.mi) || (last < 3 && v.se) ||
            (last < 3 ? v.ns != 0 : v.ns % 1000 != 0);
  }
  if (lead > 0xFFFFFFFFULL) {
    *state = "22015"; /* the leading field doesn't fit */
    return SQL_ERROR;
  }
  *lead_at = (SQLUINTEGER)lead;
  if (trunc) {
    *state = "01S07";
    return SQL_SUCCESS_WITH_INFO;
  }
  return SQL_SUCCESS;
}

const char *seer_odbc_convert_text(const char *sqlstate)
{
  static const struct {
    const char *state, *text;
  } T[] = {
      {"01S07", "Fractional truncation: an interval part the target type has no field for"},
      {"22002", "Indicator variable required but not supplied"},
      {"22015", "Interval field overflow: the leading field doesn't fit the target"},
      {"22018", "Invalid character value for cast specification"},
      {"07006", "Restricted data type attribute violation: the value can't convert to that "
                "C type"},
  };
  for (size_t i = 0; sqlstate != NULL && i < sizeof T / sizeof T[0]; i++)
    if (strcmp(T[i].state, sqlstate) == 0)
      return T[i].text;
  return "String data, right truncated";
}

SQLSMALLINT seer_odbc_default_c_type(SQLSMALLINT sql_type)
{
  switch (sql_type) {
  case SQL_WCHAR:
  case SQL_WVARCHAR:
  case SQL_WLONGVARCHAR:
    return SQL_C_WCHAR;
  case SQL_BIT:
    return SQL_C_BIT;
  case SQL_TINYINT:
    return SQL_C_STINYINT;
  case SQL_SMALLINT:
    return SQL_C_SSHORT;
  case SQL_INTEGER:
    return SQL_C_SLONG;
  case SQL_BIGINT:
    return SQL_C_SBIGINT;
  case SQL_REAL:
    return SQL_C_FLOAT;
  case SQL_FLOAT:
  case SQL_DOUBLE:
    return SQL_C_DOUBLE;
  case SQL_BINARY:
  case SQL_VARBINARY:
  case SQL_LONGVARBINARY:
    return SQL_C_BINARY;
  case SQL_TYPE_DATE:
    return SQL_C_TYPE_DATE;
  case SQL_TYPE_TIME:
    return SQL_C_TYPE_TIME;
  case SQL_TYPE_TIMESTAMP:
    return SQL_C_TYPE_TIMESTAMP;
  case SQL_DATE: /* the ODBC 2 names */
    return SQL_C_DATE;
  case SQL_TIME:
    return SQL_C_TIME;
  case SQL_TIMESTAMP:
    return SQL_C_TIMESTAMP;
  case SQL_GUID:
    return SQL_C_GUID;
  case SQL_INTERVAL_YEAR:
  case SQL_INTERVAL_MONTH:
  case SQL_INTERVAL_DAY:
  case SQL_INTERVAL_HOUR:
  case SQL_INTERVAL_MINUTE:
  case SQL_INTERVAL_SECOND:
  case SQL_INTERVAL_YEAR_TO_MONTH:
  case SQL_INTERVAL_DAY_TO_HOUR:
  case SQL_INTERVAL_DAY_TO_MINUTE:
  case SQL_INTERVAL_DAY_TO_SECOND:
  case SQL_INTERVAL_HOUR_TO_MINUTE:
  case SQL_INTERVAL_HOUR_TO_SECOND:
  case SQL_INTERVAL_MINUTE_TO_SECOND:
    /* SQL_INTERVAL_x is 100 + SQL_CODE_x, as is its C type. */
    return sql_type;
  default: /* character, DECIMAL / NUMERIC, and the driver's own types */
    return SQL_C_CHAR;
  }
}

size_t seer_odbc_c_fixed_size(SQLSMALLINT t)
{
  switch (t) {
  case SQL_C_SLONG:
  case SQL_C_LONG:
  case SQL_C_ULONG:
    return sizeof(SQLINTEGER);
  case SQL_C_SSHORT:
  case SQL_C_SHORT:
  case SQL_C_USHORT:
    return sizeof(SQLSMALLINT);
  case SQL_C_SBIGINT:
  case SQL_C_UBIGINT:
    return sizeof(SQLBIGINT);
  case SQL_C_STINYINT:
  case SQL_C_TINYINT:
  case SQL_C_UTINYINT:
  case SQL_C_BIT:
    return 1;
  case SQL_C_FLOAT:
    return sizeof(SQLREAL);
  case SQL_C_DOUBLE:
    return sizeof(SQLDOUBLE);
  case SQL_C_NUMERIC:
    return sizeof(SQL_NUMERIC_STRUCT);
  case SQL_C_TYPE_TIMESTAMP:
  case SQL_C_TIMESTAMP:
    return sizeof(SQL_TIMESTAMP_STRUCT);
  case SQL_C_TYPE_DATE:
  case SQL_C_DATE:
    return sizeof(SQL_DATE_STRUCT);
  case SQL_C_TYPE_TIME:
  case SQL_C_TIME:
    return sizeof(SQL_TIME_STRUCT);
  case SQL_C_GUID:
    return sizeof(SQLGUID);
  case SQL_C_INTERVAL_YEAR:
  case SQL_C_INTERVAL_MONTH:
  case SQL_C_INTERVAL_DAY:
  case SQL_C_INTERVAL_HOUR:
  case SQL_C_INTERVAL_MINUTE:
  case SQL_C_INTERVAL_SECOND:
  case SQL_C_INTERVAL_YEAR_TO_MONTH:
  case SQL_C_INTERVAL_DAY_TO_HOUR:
  case SQL_C_INTERVAL_DAY_TO_MINUTE:
  case SQL_C_INTERVAL_DAY_TO_SECOND:
  case SQL_C_INTERVAL_HOUR_TO_MINUTE:
  case SQL_C_INTERVAL_HOUR_TO_SECOND:
  case SQL_C_INTERVAL_MINUTE_TO_SECOND:
    return sizeof(SQL_INTERVAL_STRUCT);
  default:
    return 0;
  }
}

/* Copy `n` source bytes / hex / text into buf with offset tracking. Helper for
 * the variable-length targets. Returns SQL_SUCCESS[_WITH_INFO]. */
static SQLRETURN copy_var(const unsigned char *src, size_t total, int as_hex, SQLPOINTER buf,
                          SQLLEN buflen, SQLLEN *ind, SQLLEN *offset)
{
  size_t off = offset ? (size_t)*offset : 0;
  if (off > total)
    off = total;
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
      out[2 * i] = H[src[off + i] >> 4];
      out[2 * i + 1] = H[src[off + i] & 0x0F];
    }
    out[2 * cp] = '\0';
    if (offset)
      *offset = (SQLLEN)(off + cp);
    return cp < remain ? SQL_SUCCESS_WITH_INFO : SQL_SUCCESS;
  }

  size_t cap = (size_t)buflen - 1;
  size_t cp = remain < cap ? remain : cap;
  memcpy(buf, src + off, cp);
  ((char *)buf)[cp] = '\0';
  if (offset)
    *offset = (SQLLEN)(off + cp);
  return cp < remain ? SQL_SUCCESS_WITH_INFO : SQL_SUCCESS;
}

/* Copy UTF-16 bytes `src` (total bytes) into a wide buffer with offset tracking
 * and a 2-byte NUL terminator. buflen and the indicator are in BYTES; copies
 * whole 16-bit code units only. */
static SQLRETURN copy_wide(const unsigned char *src, size_t total, SQLPOINTER buf, SQLLEN buflen,
                           SQLLEN *ind, SQLLEN *offset)
{
  size_t off = offset ? (size_t)*offset : 0;
  off &= ~(size_t)1; /* align to a 16-bit unit */
  if (off > total)
    off = total;
  size_t remain = total - off;

  if (ind)
    *ind = (SQLLEN)remain; /* bytes of UTF-16, excluding terminator */
  if (buf == NULL || buflen < 2)
    return remain > 0 ? SQL_SUCCESS_WITH_INFO : SQL_SUCCESS;

  size_t cap = ((size_t)buflen - 2) & ~(size_t)1; /* leave room for the NUL */
  size_t cp = remain < cap ? remain : cap;
  memcpy(buf, src + off, cp);
  ((unsigned char *)buf)[cp] = 0;
  ((unsigned char *)buf)[cp + 1] = 0;
  if (offset)
    *offset = (SQLLEN)(off + cp);
  return cp < remain ? SQL_SUCCESS_WITH_INFO : SQL_SUCCESS;
}

SQLRETURN seer_odbc_convert(const void *val, size_t vallen, int is_null, int is_binary,
                            SQLSMALLINT target, SQLPOINTER buf, SQLLEN buflen, SQLLEN *ind,
                            SQLLEN *offset, const char **sqlstate)
{
  const char *unused;
  const char **state = sqlstate != NULL ? sqlstate : &unused;
  *state = NULL;
  if (is_null) {
    if (ind == NULL) {
      *state = "22002";
      return SQL_ERROR;
    }
    *ind = SQL_NULL_DATA;
    return SQL_SUCCESS;
  }

  const char *s = (const char *)val; /* NUL-terminated for numeric/date parse */

  switch (target) {
  /* ---- integer family ---- */
  case SQL_C_STINYINT:
  case SQL_C_TINYINT:
    if (buf)
      *(SQLSCHAR *)buf = (SQLSCHAR)strtoll(s, NULL, 10);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLSCHAR);
    return SQL_SUCCESS;
  case SQL_C_UTINYINT:
    if (buf)
      *(SQLCHAR *)buf = (SQLCHAR)strtoull(s, NULL, 10);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLCHAR);
    return SQL_SUCCESS;
  case SQL_C_SSHORT:
  case SQL_C_SHORT:
    if (buf)
      *(SQLSMALLINT *)buf = (SQLSMALLINT)strtoll(s, NULL, 10);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLSMALLINT);
    return SQL_SUCCESS;
  case SQL_C_USHORT:
    if (buf)
      *(SQLUSMALLINT *)buf = (SQLUSMALLINT)strtoull(s, NULL, 10);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLUSMALLINT);
    return SQL_SUCCESS;
  case SQL_C_SLONG:
  case SQL_C_LONG:
    if (buf)
      *(SQLINTEGER *)buf = (SQLINTEGER)strtoll(s, NULL, 10);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLINTEGER);
    return SQL_SUCCESS;
  case SQL_C_ULONG:
    if (buf)
      *(SQLUINTEGER *)buf = (SQLUINTEGER)strtoull(s, NULL, 10);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLUINTEGER);
    return SQL_SUCCESS;
  case SQL_C_SBIGINT:
    if (buf)
      *(SQLBIGINT *)buf = (SQLBIGINT)strtoll(s, NULL, 10);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLBIGINT);
    return SQL_SUCCESS;
  case SQL_C_UBIGINT:
    if (buf)
      *(SQLUBIGINT *)buf = (SQLUBIGINT)strtoull(s, NULL, 10);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLUBIGINT);
    return SQL_SUCCESS;
  case SQL_C_BIT:
    if (buf)
      *(SQLCHAR *)buf = (strtoll(s, NULL, 10) != 0) ? 1 : 0;
    if (ind)
      *ind = (SQLLEN)sizeof(SQLCHAR);
    return SQL_SUCCESS;

  /* ---- floating point ---- */
  case SQL_C_FLOAT:
    if (buf)
      *(SQLREAL *)buf = (SQLREAL)strtod(s, NULL);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLREAL);
    return SQL_SUCCESS;
  case SQL_C_DOUBLE:
    if (buf)
      *(SQLDOUBLE *)buf = strtod(s, NULL);
    if (ind)
      *ind = (SQLLEN)sizeof(SQLDOUBLE);
    return SQL_SUCCESS;

  case SQL_C_NUMERIC:
    if (buf)
      to_numeric(s, (SQL_NUMERIC_STRUCT *)buf);
    if (ind)
      *ind = (SQLLEN)sizeof(SQL_NUMERIC_STRUCT);
    return SQL_SUCCESS;

  /* ---- date / time ---- */
  case SQL_C_TYPE_TIMESTAMP:
  case SQL_C_TIMESTAMP: {
    int Y, Mo, D, h, mi, se;
    unsigned long fr;
    if (parse_datetime(s, &Y, &Mo, &D, &h, &mi, &se, &fr) != 0) {
      *state = "22018";
      return SQL_ERROR;
    }
    if (buf) {
      SQL_TIMESTAMP_STRUCT *t = buf;
      t->year = (SQLSMALLINT)Y;
      t->month = (SQLUSMALLINT)Mo;
      t->day = (SQLUSMALLINT)D;
      t->hour = (SQLUSMALLINT)h;
      t->minute = (SQLUSMALLINT)mi;
      t->second = (SQLUSMALLINT)se;
      t->fraction = (SQLUINTEGER)fr;
    }
    if (ind)
      *ind = (SQLLEN)sizeof(SQL_TIMESTAMP_STRUCT);
    return SQL_SUCCESS;
  }
  case SQL_C_TYPE_DATE:
  case SQL_C_DATE: {
    int Y, Mo, D, h, mi, se;
    unsigned long fr;
    if (parse_datetime(s, &Y, &Mo, &D, &h, &mi, &se, &fr) != 0) {
      *state = "22018";
      return SQL_ERROR;
    }
    if (buf) {
      SQL_DATE_STRUCT *t = buf;
      t->year = (SQLSMALLINT)Y;
      t->month = (SQLUSMALLINT)Mo;
      t->day = (SQLUSMALLINT)D;
    }
    if (ind)
      *ind = (SQLLEN)sizeof(SQL_DATE_STRUCT);
    return SQL_SUCCESS;
  }
  case SQL_C_TYPE_TIME:
  case SQL_C_TIME: {
    int Y, Mo, D, h, mi, se;
    unsigned long fr;
    if (parse_datetime(s, &Y, &Mo, &D, &h, &mi, &se, &fr) != 0) {
      *state = "22018";
      return SQL_ERROR;
    }
    if (buf) {
      SQL_TIME_STRUCT *t = buf;
      t->hour = (SQLUSMALLINT)h;
      t->minute = (SQLUSMALLINT)mi;
      t->second = (SQLUSMALLINT)se;
    }
    if (ind)
      *ind = (SQLLEN)sizeof(SQL_TIME_STRUCT);
    return SQL_SUCCESS;
  }

  /* ---- wide text ---- */
  case SQL_C_WCHAR: {
    char *u16 = NULL;
    size_t u16len = 0;
    if (seer_iconv("UTF-8", SEER_UTF16, (const char *)val, vallen, &u16, &u16len) != 0) {
      *state = "22018";
      return SQL_ERROR;
    }
    SQLRETURN r = copy_wide((const unsigned char *)u16, u16len, buf, buflen, ind, offset);
    free(u16);
    if (r == SQL_SUCCESS_WITH_INFO)
      *state = "01004";
    return r;
  }

  /* ---- intervals (#314) ---- */
  case SQL_C_INTERVAL_YEAR:
  case SQL_C_INTERVAL_MONTH:
  case SQL_C_INTERVAL_DAY:
  case SQL_C_INTERVAL_HOUR:
  case SQL_C_INTERVAL_MINUTE:
  case SQL_C_INTERVAL_SECOND:
  case SQL_C_INTERVAL_YEAR_TO_MONTH:
  case SQL_C_INTERVAL_DAY_TO_HOUR:
  case SQL_C_INTERVAL_DAY_TO_MINUTE:
  case SQL_C_INTERVAL_DAY_TO_SECOND:
  case SQL_C_INTERVAL_HOUR_TO_MINUTE:
  case SQL_C_INTERVAL_HOUR_TO_SECOND:
  case SQL_C_INTERVAL_MINUTE_TO_SECOND: {
    if (is_binary) {
      *state = "07006";
      return SQL_ERROR;
    }
    Interval iv;
    SQL_INTERVAL_STRUCT tmp;
    parse_interval(s, vallen, &iv);
    SQLRETURN r = to_interval(&iv, target, &tmp, state);
    if (r == SQL_ERROR)
      return r;
    if (buf)
      memcpy(buf, &tmp, sizeof tmp);
    if (ind)
      *ind = (SQLLEN)sizeof(SQL_INTERVAL_STRUCT);
    return r;
  }

  /* ---- raw / text ---- */
  case SQL_C_BINARY: {
    SQLRETURN r = copy_var((const unsigned char *)val, vallen, 0, buf, buflen, ind, offset);
    if (r == SQL_SUCCESS_WITH_INFO)
      *state = "01004";
    return r;
  }
  case SQL_C_CHAR:
  case SQL_C_DEFAULT: {
    SQLRETURN r = copy_var((const unsigned char *)val, vallen, is_binary, buf, buflen, ind, offset);
    if (r == SQL_SUCCESS_WITH_INFO)
      *state = "01004";
    return r;
  }
  default:
    /* SQL_C_GUID (Oracle has no GUID type) and anything else no Oracle value
     * converts to: the restricted data type attribute violation, not the
     * value's text in a buffer of another type. */
    *state = "07006";
    return SQL_ERROR;
  }
}

size_t seer_odbc_numeric_to_text(const SQL_NUMERIC_STRUCT *ns, char *out, size_t cap)
{
  /* The mantissa's decimal digits, least significant first, by repeated
   * division of the 16-byte little-endian value by 10. */
  unsigned char m[SQL_MAX_NUMERIC_LEN];
  memcpy(m, ns->val, sizeof m);
  char rev[48];
  size_t nd = 0;
  for (;;) {
    unsigned rem = 0;
    bool nonzero = false;
    for (int i = SQL_MAX_NUMERIC_LEN - 1; i >= 0; i--) {
      unsigned cur = (rem << 8) | m[i];
      m[i] = (unsigned char)(cur / 10);
      rem = cur % 10;
      nonzero = nonzero || m[i] != 0;
    }
    rev[nd++] = (char)('0' + rem);
    if (!nonzero)
      break;
  }
  bool zero = nd == 1 && rev[0] == '0';
  int scale = ns->scale;
  /* sign + "0." + leading zeros + digits + trailing zeros + NUL */
  size_t need = 1 + 2 + nd + (size_t)(scale > 0 ? scale : -scale) + 1;
  if (cap < need)
    return 0;
  size_t k = 0;
  if (ns->sign == 0 && !zero) /* 0 = negative */
    out[k++] = '-';
  if (scale <= 0) {
    for (size_t i = nd; i > 0; i--)
      out[k++] = rev[i - 1];
    if (!zero)
      for (int i = 0; i < -scale; i++)
        out[k++] = '0';
  } else if ((size_t)scale >= nd) {
    out[k++] = '0';
    out[k++] = '.';
    for (size_t i = nd; i < (size_t)scale; i++)
      out[k++] = '0';
    for (size_t i = nd; i > 0; i--)
      out[k++] = rev[i - 1];
  } else {
    for (size_t i = nd; i > 0; i--) {
      out[k++] = rev[i - 1];
      if (i - 1 == (size_t)scale)
        out[k++] = '.';
    }
  }
  out[k] = '\0';
  return k;
}

void seer_odbc_guid_to_text(const SQLGUID *g, char out[37])
{
  snprintf(out, 37, "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", (unsigned long)g->Data1,
           (unsigned)g->Data2, (unsigned)g->Data3, g->Data4[0], g->Data4[1], g->Data4[2],
           g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

/* Oracle's largest leading field: INTERVAL ... (9). */
#define IVL_LEAD_MAX 999999999UL

int seer_odbc_interval_from_c(SQLSMALLINT c_type, const SQL_INTERVAL_STRUCT *iv,
                              SeerOdbcInterval *out)
{
  memset(out, 0, sizeof *out);
  out->negative = iv->interval_sign == SQL_TRUE;
  const SQL_YEAR_MONTH_STRUCT *ym = &iv->intval.year_month;
  const SQL_DAY_SECOND_STRUCT *ds = &iv->intval.day_second;
  unsigned long long y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0, frac = 0;
  switch (c_type) {
  case SQL_C_INTERVAL_YEAR:
    y = ym->year;
    break;
  case SQL_C_INTERVAL_MONTH:
    mo = ym->month;
    break;
  case SQL_C_INTERVAL_YEAR_TO_MONTH:
    y = ym->year;
    mo = ym->month;
    break;
  case SQL_C_INTERVAL_DAY:
    d = ds->day;
    break;
  case SQL_C_INTERVAL_HOUR:
    h = ds->hour;
    break;
  case SQL_C_INTERVAL_MINUTE:
    mi = ds->minute;
    break;
  case SQL_C_INTERVAL_SECOND:
    s = ds->second;
    frac = ds->fraction;
    break;
  case SQL_C_INTERVAL_DAY_TO_HOUR:
    d = ds->day;
    h = ds->hour;
    break;
  case SQL_C_INTERVAL_DAY_TO_MINUTE:
    d = ds->day;
    h = ds->hour;
    mi = ds->minute;
    break;
  case SQL_C_INTERVAL_DAY_TO_SECOND:
    d = ds->day;
    h = ds->hour;
    mi = ds->minute;
    s = ds->second;
    frac = ds->fraction;
    break;
  case SQL_C_INTERVAL_HOUR_TO_MINUTE:
    h = ds->hour;
    mi = ds->minute;
    break;
  case SQL_C_INTERVAL_HOUR_TO_SECOND:
    h = ds->hour;
    mi = ds->minute;
    s = ds->second;
    frac = ds->fraction;
    break;
  case SQL_C_INTERVAL_MINUTE_TO_SECOND:
    mi = ds->minute;
    s = ds->second;
    frac = ds->fraction;
    break;
  default:
    return -1;
  }
  switch (c_type) {
  case SQL_C_INTERVAL_YEAR:
  case SQL_C_INTERVAL_MONTH:
  case SQL_C_INTERVAL_YEAR_TO_MONTH: {
    unsigned long long tm = y * 12 + mo;
    if (tm / 12 > IVL_LEAD_MAX)
      return -2;
    out->year_month = 1;
    out->years = (long)(tm / 12);
    out->months = (long)(tm % 12);
    return 0;
  }
  default:
    break;
  }
  /* fraction is in microseconds (precision 6); a whole second carries over. */
  unsigned long long ts = ((d * 24 + h) * 60 + mi) * 60 + s + frac / 1000000;
  if (ts / 86400 > IVL_LEAD_MAX)
    return -2;
  out->days = (long)(ts / 86400);
  out->hours = (int)(ts / 3600 % 24);
  out->mins = (int)(ts / 60 % 60);
  out->secs = (int)(ts % 60);
  out->nanos = (unsigned long)(frac % 1000000 * 1000);
  return 0;
}
