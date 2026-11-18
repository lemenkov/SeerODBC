/* SQL statement preprocessing - see sqlprep.h. Pure string transforms.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#include "sqlprep.h"

#include "compat.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Find the '}' that closes the '{' at `p` (quote- and nesting-aware). */
static const char *find_close_brace(const char *p)
{
  int depth = 0;
  char quote = 0;
  for (const char *s = p; *s != '\0'; s++) {
    if (quote) {
      if (*s == quote)
        quote = 0;
    } else if (*s == '\'' || *s == '"') {
      quote = *s;
    } else if (*s == '{') {
      depth++;
    } else if (*s == '}') {
      if (--depth == 0)
        return s;
    }
  }
  return NULL;
}

/* A small growable string. */
typedef struct {
  char *b;
  size_t len, cap;
} Buf;
static int buf_put(Buf *x, const char *s, size_t n)
{
  if (x->len + n + 1 > x->cap) {
    size_t nc = x->cap ? x->cap : 64;
    while (nc < x->len + n + 1)
      nc *= 2;
    char *p = realloc(x->b, nc);
    if (p == NULL)
      return -1;
    x->b = p;
    x->cap = nc;
  }
  memcpy(x->b + x->len, s, n);
  x->len += n;
  x->b[x->len] = '\0';
  return 0;
}

/* What a translation needs to know: the server's major release (0 when it is
 * not known, read as the newest) and, on a refusal, why. */
typedef struct {
  int major;
  const char *err;
} Ctx;

/* The ODBC scalar functions (Appendix E) and their Oracle forms (#301). A form
 * starting with '=' renames the function and keeps its argument list as
 * written; any other is a template whose $1..$9 are the arguments. `kw` is the
 * keyword argument of TIMESTAMPADD / TIMESTAMPDIFF (the first; SQL_TSI_
 * dropped) or CONVERT (the last), which is not counted in `nargs` nor numbered.
 * `lo` / `hi` bound the releases a form is for (0: unbounded). A function, or an
 * argument count, the table lacks goes to the server as written: most of
 * Oracle's own names match (ABS, MOD, ROUND, CONCAT, REPLACE, EXTRACT...). */
static const struct {
  const char *name, *kw;
  int nargs, lo, hi;
  const char *form;
} FN[] = {
    /* string */
    {"BIT_LENGTH", NULL, 1, 0, 0, "(LENGTHB($1) * 8)"},
    {"CHAR", NULL, 1, 0, 0, "=CHR"},
    {"CHAR_LENGTH", NULL, 1, 0, 0, "=LENGTH"},
    {"CHARACTER_LENGTH", NULL, 1, 0, 0, "=LENGTH"},
    {"INSERT", NULL, 4, 0, 0, "(SUBSTR($1, 1, ($2) - 1) || $4 || SUBSTR($1, ($2) + ($3)))"},
    {"LCASE", NULL, 1, 0, 0, "=LOWER"},
    {"LEFT", NULL, 2, 0, 0, "SUBSTR($1, 1, $2)"},
    {"LENGTH", NULL, 1, 0, 0, "LENGTH(RTRIM($1))"}, /* ODBC's drops trailing blanks */
    {"LOCATE", NULL, 2, 0, 0, "INSTR($2, $1)"},
    {"LOCATE", NULL, 3, 0, 0, "INSTR($2, $1, $3)"},
    {"OCTET_LENGTH", NULL, 1, 0, 0, "=LENGTHB"},
    {"POSITION", NULL, 2, 0, 0, "INSTR($2, $1)"}, /* POSITION(a IN b), split at IN */
    {"REPEAT", NULL, 2, 0, 0, "RPAD($1, LENGTH($1) * ($2), $1)"},
    {"RIGHT", NULL, 2, 0, 0, "SUBSTR($1, GREATEST(LENGTH($1) - ($2) + 1, 1))"},
    {"SPACE", NULL, 1, 0, 0, "RPAD(' ', $1)"},
    {"SUBSTRING", NULL, -1, 0, 0, "=SUBSTR"},
    {"UCASE", NULL, 1, 0, 0, "=UPPER"},
    /* numeric */
    {"CEILING", NULL, 1, 0, 0, "=CEIL"},
    {"COT", NULL, 1, 0, 0, "(1 / TAN($1))"},
    {"DEGREES", NULL, 1, 0, 0, "(($1) * 180 / ACOS(-1))"},
    {"LOG", NULL, 1, 0, 0, "=LN"},
    {"LOG10", NULL, 1, 0, 0, "LOG(10, $1)"},
    {"PI", NULL, 0, 0, 0, "ACOS(-1)"},
    {"RADIANS", NULL, 1, 0, 0, "(($1) * ACOS(-1) / 180)"},
    {"RAND", NULL, 0, 0, 0, "DBMS_RANDOM.VALUE"}, /* no seeded form in SQL */
    {"TRUNCATE", NULL, -1, 0, 0, "=TRUNC"},
    /* date and time: 8i has no LOCALTIMESTAMP or CURRENT_DATE, and no time
     * type anywhere, so a time is a DATE */
    {"CURDATE", NULL, 0, 9, 0, "TRUNC(CURRENT_DATE)"},
    {"CURDATE", NULL, 0, 0, 8, "TRUNC(SYSDATE)"},
    {"CURRENT_DATE", NULL, 0, 9, 0, "TRUNC(CURRENT_DATE)"},
    {"CURRENT_DATE", NULL, 0, 0, 8, "TRUNC(SYSDATE)"},
    {"CURTIME", NULL, 0, 9, 0, "CURRENT_DATE"},
    {"CURTIME", NULL, 0, 0, 8, "SYSDATE"},
    {"CURRENT_TIME", NULL, 0, 9, 0, "CURRENT_DATE"},
    {"CURRENT_TIME", NULL, 1, 9, 0, "LOCALTIMESTAMP($1)"},
    {"CURRENT_TIME", NULL, 0, 0, 8, "SYSDATE"},
    {"CURRENT_TIMESTAMP", NULL, 0, 9, 0, "LOCALTIMESTAMP"},
    {"CURRENT_TIMESTAMP", NULL, 1, 9, 0, "LOCALTIMESTAMP($1)"},
    {"CURRENT_TIMESTAMP", NULL, 0, 0, 8, "SYSDATE"},
    {"NOW", NULL, 0, 9, 0, "LOCALTIMESTAMP"},
    {"NOW", NULL, 0, 0, 8, "SYSDATE"},
    {"DAYNAME", NULL, 1, 0, 0, "RTRIM(TO_CHAR($1, 'Day'))"},
    {"DAYOFMONTH", NULL, 1, 0, 0, "TO_NUMBER(TO_CHAR($1, 'DD'))"},
    /* 1 = Sunday whatever NLS_TERRITORY says: Julian day 0 was a Monday */
    {"DAYOFWEEK", NULL, 1, 0, 0, "(MOD(TO_NUMBER(TO_CHAR($1, 'J')) + 1, 7) + 1)"},
    {"DAYOFYEAR", NULL, 1, 0, 0, "TO_NUMBER(TO_CHAR($1, 'DDD'))"},
    {"HOUR", NULL, 1, 0, 0, "TO_NUMBER(TO_CHAR($1, 'HH24'))"},
    {"MINUTE", NULL, 1, 0, 0, "TO_NUMBER(TO_CHAR($1, 'MI'))"},
    {"MONTH", NULL, 1, 0, 0, "TO_NUMBER(TO_CHAR($1, 'MM'))"},
    {"MONTHNAME", NULL, 1, 0, 0, "RTRIM(TO_CHAR($1, 'Month'))"},
    {"QUARTER", NULL, 1, 0, 0, "TO_NUMBER(TO_CHAR($1, 'Q'))"},
    {"SECOND", NULL, 1, 0, 0, "TO_NUMBER(TO_CHAR($1, 'SS'))"},
    /* weeks start on Sunday, and week 1 holds January 1 */
    {"WEEK", NULL, 1, 0, 0,
     "(TRUNC((TO_NUMBER(TO_CHAR($1, 'DDD')) + MOD(TO_NUMBER(TO_CHAR(TRUNC($1, 'YYYY'), 'J')) + 1, "
     "7) - 1) / 7) + 1)"},
    {"YEAR", NULL, 1, 0, 0, "TO_NUMBER(TO_CHAR($1, 'YYYY'))"},
    /* TIMESTAMPADD(interval, n, ts): from 9i an INTERVAL keeps a TIMESTAMP's
     * type and fraction; 8i adds days to a DATE */
    {"TIMESTAMPADD", "FRAC_SECOND", 2, 9, 0, "(NUMTODSINTERVAL(($1) / 1000000000, 'SECOND') + $2)"},
    {"TIMESTAMPADD", "SECOND", 2, 9, 0, "(NUMTODSINTERVAL($1, 'SECOND') + $2)"},
    {"TIMESTAMPADD", "MINUTE", 2, 9, 0, "(NUMTODSINTERVAL($1, 'MINUTE') + $2)"},
    {"TIMESTAMPADD", "HOUR", 2, 9, 0, "(NUMTODSINTERVAL($1, 'HOUR') + $2)"},
    {"TIMESTAMPADD", "DAY", 2, 9, 0, "(NUMTODSINTERVAL($1, 'DAY') + $2)"},
    {"TIMESTAMPADD", "WEEK", 2, 9, 0, "(NUMTODSINTERVAL(($1) * 7, 'DAY') + $2)"},
    {"TIMESTAMPADD", "SECOND", 2, 0, 8, "(($1) / 86400 + $2)"},
    {"TIMESTAMPADD", "MINUTE", 2, 0, 8, "(($1) / 1440 + $2)"},
    {"TIMESTAMPADD", "HOUR", 2, 0, 8, "(($1) / 24 + $2)"},
    {"TIMESTAMPADD", "DAY", 2, 0, 8, "(($1) + $2)"},
    {"TIMESTAMPADD", "WEEK", 2, 0, 8, "(($1) * 7 + $2)"},
    {"TIMESTAMPADD", "MONTH", 2, 0, 0, "ADD_MONTHS($2, $1)"},
    {"TIMESTAMPADD", "QUARTER", 2, 0, 0, "ADD_MONTHS($2, ($1) * 3)"},
    {"TIMESTAMPADD", "YEAR", 2, 0, 0, "ADD_MONTHS($2, ($1) * 12)"},
    /* TIMESTAMPDIFF(interval, t1, t2): whole intervals from t1 to t2, toward
     * zero. Whole seconds first, as a day's fraction is not exact */
    {"TIMESTAMPDIFF", "SECOND", 2, 0, 0, "ROUND((CAST($1 AS DATE) - CAST($2 AS DATE)) * -86400)"},
    {"TIMESTAMPDIFF", "MINUTE", 2, 0, 0,
     "TRUNC(ROUND((CAST($1 AS DATE) - CAST($2 AS DATE)) * -86400) / 60)"},
    {"TIMESTAMPDIFF", "HOUR", 2, 0, 0,
     "TRUNC(ROUND((CAST($1 AS DATE) - CAST($2 AS DATE)) * -86400) / 3600)"},
    {"TIMESTAMPDIFF", "DAY", 2, 0, 0,
     "TRUNC(ROUND((CAST($1 AS DATE) - CAST($2 AS DATE)) * -86400) / 86400)"},
    {"TIMESTAMPDIFF", "WEEK", 2, 0, 0,
     "TRUNC(ROUND((CAST($1 AS DATE) - CAST($2 AS DATE)) * -86400) / 604800)"},
    {"TIMESTAMPDIFF", "MONTH", 2, 0, 0, "TRUNC(-MONTHS_BETWEEN($1, $2))"},
    {"TIMESTAMPDIFF", "QUARTER", 2, 0, 0, "TRUNC(-MONTHS_BETWEEN($1, $2) / 3)"},
    {"TIMESTAMPDIFF", "YEAR", 2, 0, 0, "TRUNC(-MONTHS_BETWEEN($1, $2) / 12)"},
    /* system */
    {"IFNULL", NULL, 2, 0, 0, "=NVL"},
    {"USER", NULL, 0, 0, 0, "USER"},
    /* CONVERT(value, SQL_type) */
    {"CONVERT", "SQL_CHAR", 1, 0, 0, "TO_CHAR($1)"},
    {"CONVERT", "SQL_VARCHAR", 1, 0, 0, "TO_CHAR($1)"},
    {"CONVERT", "SQL_WCHAR", 1, 0, 0, "TO_NCHAR($1)"},
    {"CONVERT", "SQL_WVARCHAR", 1, 0, 0, "TO_NCHAR($1)"},
    {"CONVERT", "SQL_LONGVARCHAR", 1, 9, 0, "TO_CLOB($1)"},
    {"CONVERT", "SQL_WLONGVARCHAR", 1, 9, 0, "TO_NCLOB($1)"},
    {"CONVERT", "SQL_NUMERIC", 1, 0, 0, "CAST($1 AS NUMBER)"},
    {"CONVERT", "SQL_DECIMAL", 1, 0, 0, "CAST($1 AS NUMBER)"},
    {"CONVERT", "SQL_TINYINT", 1, 0, 0, "TRUNC(CAST($1 AS NUMBER))"},
    {"CONVERT", "SQL_SMALLINT", 1, 0, 0, "TRUNC(CAST($1 AS NUMBER))"},
    {"CONVERT", "SQL_INTEGER", 1, 0, 0, "TRUNC(CAST($1 AS NUMBER))"},
    {"CONVERT", "SQL_BIGINT", 1, 0, 0, "TRUNC(CAST($1 AS NUMBER))"},
    {"CONVERT", "SQL_REAL", 1, 10, 0, "CAST($1 AS BINARY_FLOAT)"},
    {"CONVERT", "SQL_FLOAT", 1, 10, 0, "CAST($1 AS BINARY_DOUBLE)"},
    {"CONVERT", "SQL_DOUBLE", 1, 10, 0, "CAST($1 AS BINARY_DOUBLE)"},
    {"CONVERT", "SQL_REAL", 1, 0, 9, "CAST($1 AS NUMBER)"},
    {"CONVERT", "SQL_FLOAT", 1, 0, 9, "CAST($1 AS NUMBER)"},
    {"CONVERT", "SQL_DOUBLE", 1, 0, 9, "CAST($1 AS NUMBER)"},
    {"CONVERT", "SQL_DATE", 1, 0, 0, "TRUNC(CAST($1 AS DATE))"},
    {"CONVERT", "SQL_TYPE_DATE", 1, 0, 0, "TRUNC(CAST($1 AS DATE))"},
    {"CONVERT", "SQL_TIMESTAMP", 1, 9, 0, "CAST($1 AS TIMESTAMP)"},
    {"CONVERT", "SQL_TYPE_TIMESTAMP", 1, 9, 0, "CAST($1 AS TIMESTAMP)"},
    {"CONVERT", "SQL_TIMESTAMP", 1, 0, 8, "CAST($1 AS DATE)"},
    {"CONVERT", "SQL_TYPE_TIMESTAMP", 1, 0, 8, "CAST($1 AS DATE)"},
};

/* Whether `s` holds a bind placeholder (":1", ":name") outside quotes. */
static bool has_marker(const char *s, size_t n)
{
  char quote = 0;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (quote) {
      if (c == quote)
        quote = 0;
    } else if (c == '\'' || c == '"') {
      quote = c;
    } else if (c == ':' && i + 1 < n &&
               (isalnum((unsigned char)s[i + 1]) || s[i + 1] == '_' || s[i + 1] == '"')) {
      return true;
    }
  }
  return false;
}

#define FN_MAX_ARGS 9

typedef struct {
  const char *p;
  size_t n;
} Span;

static Span trim_span(const char *p, size_t n)
{
  while (n > 0 && isspace((unsigned char)*p)) {
    p++;
    n--;
  }
  while (n > 0 && isspace((unsigned char)p[n - 1]))
    n--;
  return (Span){p, n};
}

/* Split an argument list (the text between the parentheses) at its top-level
 * commas; POSITION's "a IN b" splits at the IN. Returns the count, or -1 when
 * there are more than FN_MAX_ARGS. */
static int split_args(const char *p, size_t n, bool at_in, Span *out)
{
  Span all = trim_span(p, n);
  if (all.n == 0)
    return 0;
  int k = 0, depth = 0;
  char quote = 0;
  size_t start = 0;
  for (size_t i = 0; i < all.n; i++) {
    char c = all.p[i];
    if (quote) {
      if (c == quote)
        quote = 0;
      continue;
    }
    if (c == '\'' || c == '"') {
      quote = c;
      continue;
    }
    if (c == '(' || c == ')') {
      depth += c == '(' ? 1 : -1;
      continue;
    }
    size_t cut = 0; /* the separator's length */
    if (depth == 0 && !at_in && c == ',')
      cut = 1;
    else if (depth == 0 && at_in && i > 0 && i + 2 < all.n &&
             isspace((unsigned char)all.p[i - 1]) && strncasecmp(all.p + i, "IN", 2) == 0 &&
             isspace((unsigned char)all.p[i + 2]))
      cut = 2;
    if (cut == 0)
      continue;
    if (k == FN_MAX_ARGS)
      return -1;
    out[k++] = trim_span(all.p + start, i - start);
    start = i + cut;
    i += cut - 1;
    at_in = false; /* POSITION has one IN */
  }
  if (k == FN_MAX_ARGS)
    return -1;
  out[k++] = trim_span(all.p + start, all.n - start);
  return k;
}

/* Expand template `t` with `args`. Bind N is the N-th distinct placeholder
 * by first appearance, so an argument holding one may repeat (":1" twice is
 * one bind; the core sends it for each occurrence, #302), but those arguments
 * must first appear in their own order, and none may be dropped: otherwise
 * the values would land in the wrong places, and the form is refused. */
static int expand(Buf *out, const char *t, const Span *args, int nargs, Ctx *ctx)
{
  int seen[FN_MAX_ARGS] = {0}, last = 0;
  for (const char *q = t; *q != '\0'; q++)
    if (q[0] == '$' && q[1] >= '1' && q[1] <= '9') {
      int a = q[1] - '1';
      if (a < nargs && !seen[a] && has_marker(args[a].p, args[a].n)) {
        if (a + 1 < last) {
          ctx->err = "this {fn} escape reorders arguments that hold parameter markers, so their "
                     "values would bind to the wrong arguments";
          return -1;
        }
        last = a + 1;
      }
      if (a < nargs)
        seen[a] = 1;
    }
  for (int a = 0; a < nargs; a++)
    if (!seen[a] && has_marker(args[a].p, args[a].n)) {
      ctx->err = "this {fn} escape drops an argument that holds a parameter marker";
      return -1;
    }
  for (const char *q = t; *q != '\0'; q++) {
    if (q[0] == '$' && q[1] >= '1' && q[1] <= '9' && q[1] - '1' < nargs) {
      const Span *a = &args[q[1] - '1'];
      if (buf_put(out, a->p, a->n))
        return -1;
      q++;
    } else if (buf_put(out, q, 1)) {
      return -1;
    }
  }
  return 0;
}

/* Translate one {fn ...} body (its inner escapes already expanded). 1 when it
 * was written to `out`, 0 when the table has no form for it (the caller writes
 * it as it is), -1 on a refusal (ctx->err) or no memory. */
static int translate_fn(Buf *out, const char *body, Ctx *ctx)
{
  size_t id = 0;
  while (body[id] && (isalnum((unsigned char)body[id]) || body[id] == '_'))
    id++;
  const char *after = body + id;
  while (isspace((unsigned char)*after))
    after++;
  const char *open = NULL, *close = NULL;
  if (*after == '(') {
    open = after;
    int depth = 0;
    char quote = 0;
    for (const char *q = open; *q != '\0'; q++) {
      if (quote) {
        if (*q == quote)
          quote = 0;
      } else if (*q == '\'' || *q == '"') {
        quote = *q;
      } else if (*q == '(') {
        depth++;
      } else if (*q == ')' && --depth == 0) {
        close = q;
        break;
      }
    }
    if (close == NULL)
      return 0;
    for (const char *q = close + 1; *q != '\0'; q++)
      if (!isspace((unsigned char)*q))
        return 0; /* something after the call: not ours to rewrite */
  } else if (*after != '\0') {
    return 0; /* schema.function, or anything else */
  }
  if (id == 0)
    return 0;

  Span args[FN_MAX_ARGS];
  int nargs = 0;
  bool at_in = id == 8 && strncasecmp(body, "POSITION", 8) == 0;
  if (open != NULL) {
    nargs = split_args(open + 1, (size_t)(close - open - 1), at_in, args);
    if (nargs < 0)
      return 0;
  }
  int major = ctx->major > 0 ? ctx->major : 99;
  for (size_t i = 0; i < sizeof FN / sizeof FN[0]; i++) {
    if (strlen(FN[i].name) != id || strncasecmp(body, FN[i].name, id) != 0)
      continue;
    if ((FN[i].lo && major < FN[i].lo) || (FN[i].hi && major > FN[i].hi))
      continue;
    const Span *a = args;
    int n = nargs;
    if (FN[i].kw != NULL) { /* the keyword argument, matched and set aside */
      if (n < 1)
        continue;
      bool first = strcasecmp(FN[i].name, "CONVERT") != 0;
      Span k = first ? args[0] : args[n - 1];
      if (first && k.n > 8 && strncasecmp(k.p, "SQL_TSI_", 8) == 0) {
        k.p += 8;
        k.n -= 8;
      }
      if (strlen(FN[i].kw) != k.n || strncasecmp(k.p, FN[i].kw, k.n) != 0)
        continue;
      if (first)
        a++;
      n--;
    }
    if (FN[i].nargs >= 0 && FN[i].nargs != n)
      continue;
    if (FN[i].form[0] == '=') { /* a rename: the argument list as written */
      const char *rest = open != NULL ? open : "()";
      return buf_put(out, FN[i].form + 1, strlen(FN[i].form + 1)) ||
                     buf_put(out, rest, strlen(rest))
                 ? -1
                 : 1;
    }
    return expand(out, FN[i].form, a, n, ctx) ? -1 : 1;
  }
  return 0;
}

static char *inline_escapes(const char *in, Ctx *ctx); /* recursion */

/* Append the translation of one escape body (content between { and }, with the
 * leading keyword already identified) to `out`. */
static int emit_escape(Buf *out, const char *kw, size_t kwlen, const char *rest, size_t restlen,
                       Ctx *ctx)
{
  /* Trim surrounding whitespace of the remainder. */
  while (restlen > 0 && isspace((unsigned char)*rest)) {
    rest++;
    restlen--;
  }
  while (restlen > 0 && isspace((unsigned char)rest[restlen - 1]))
    restlen--;

  if (kwlen == 2 && strncasecmp(kw, "ts", 2) == 0)
    return buf_put(out, "TIMESTAMP ", 10) || buf_put(out, rest, restlen);
  if (kwlen == 1 && (kw[0] == 'd' || kw[0] == 'D'))
    return buf_put(out, "DATE ", 5) || buf_put(out, rest, restlen);
  if (kwlen == 1 && (kw[0] == 't' || kw[0] == 'T')) /* time -> dummy-dated */
    return buf_put(out, "TO_DATE(", 8) || buf_put(out, rest, restlen) ||
           buf_put(out, ",'HH24:MI:SS')", 14);
  if (kwlen == 6 && strncasecmp(kw, "escape", 6) == 0)
    return buf_put(out, "ESCAPE ", 7) || buf_put(out, rest, restlen);
  /* {INTERVAL [+|-] 'value' qualifier}: Oracle's own INTERVAL literal (9i+)
   * takes every ODBC qualifier. Oracle has no unary minus for an interval
   * (ORA-00932), so a sign outside the quotes moves inside them; a minus on a
   * value that already starts with one cancels it. 8i has no INTERVAL: the
   * escape stays as written. */
  if (kwlen == 8 && strncasecmp(kw, "interval", 8) == 0 && (ctx->major <= 0 || ctx->major >= 9)) {
    char sign = 0;
    if (restlen > 0 && (*rest == '+' || *rest == '-')) {
      sign = *rest;
      rest++;
      restlen--;
      while (restlen > 0 && isspace((unsigned char)*rest)) {
        rest++;
        restlen--;
      }
    }
    if (sign != '-' || restlen < 2 || *rest != '\'')
      return buf_put(out, "INTERVAL ", 9) || buf_put(out, rest, restlen);
    rest++; /* past the opening quote */
    restlen--;
    bool neg = true;
    if (*rest == '-' || *rest == '+') {
      neg = *rest == '+';
      rest++;
      restlen--;
    }
    return buf_put(out, neg ? "INTERVAL '-" : "INTERVAL '", neg ? 11 : 10) ||
           buf_put(out, rest, restlen);
  }
  if ((kwlen == 2 && strncasecmp(kw, "fn", 2) == 0) ||
      (kwlen == 2 && strncasecmp(kw, "oj", 2) == 0)) {
    char *tmp = seer_strndup(rest, restlen);
    if (tmp == NULL)
      return -1;
    char *inner = inline_escapes(tmp, ctx); /* recurse (nested escapes) */
    free(tmp);
    if (inner == NULL)
      return -1;
    int rc = 0;
    if (kwlen == 2 && strncasecmp(kw, "fn", 2) == 0) {
      rc = translate_fn(out, inner, ctx);
      rc = rc == 0 ? buf_put(out, inner, strlen(inner)) : rc < 0 ? -1 : 0;
    } else {
      rc = buf_put(out, inner, strlen(inner));
    }
    free(inner);
    return rc;
  }
  /* Unknown escape: emit the original braces verbatim. */
  return buf_put(out, "{", 1) || buf_put(out, kw, kwlen) ||
         (restlen ? (buf_put(out, " ", 1) || buf_put(out, rest, restlen)) : 0) ||
         buf_put(out, "}", 1);
}

/* Translate inline ODBC escapes ({ts}/{d}/{t}/{fn}/{oj}/{escape}) anywhere in
 * the text, quote- and nesting-aware. NULL on a refusal (ctx->err) or no
 * memory. */
static char *inline_escapes(const char *in, Ctx *ctx)
{
  Buf out = {0};
  char quote = 0;
  for (const char *p = in; *p != '\0';) {
    char c = *p;
    if (quote) {
      buf_put(&out, p, 1);
      if (c == quote)
        quote = 0;
      p++;
    } else if (c == '\'' || c == '"') {
      quote = c;
      buf_put(&out, p, 1);
      p++;
    } else if (c == '{') {
      const char *close = find_close_brace(p);
      if (close == NULL) {
        buf_put(&out, p, 1);
        p++;
        continue;
      }
      const char *k = p + 1;
      while (isspace((unsigned char)*k))
        k++;
      const char *kend = k;
      while (kend < close && (isalpha((unsigned char)*kend)))
        kend++;
      size_t kwlen = (size_t)(kend - k);
      int rc;
      if (kwlen > 0 && strncasecmp(k, "call", 4) != 0)
        rc = emit_escape(&out, k, kwlen, kend, (size_t)(close - kend), ctx);
      else
        rc = buf_put(&out, p, (size_t)(close - p + 1)); /* leave {call}/unknown */
      if (rc) {
        free(out.b);
        return NULL;
      }
      p = close + 1;
    } else {
      buf_put(&out, p, 1);
      p++;
    }
  }
  if (out.b == NULL)
    return strdup(in);
  return out.b;
}

/* Translate the ODBC {call ...} / {?=call ...} statement escape into an Oracle
 * PL/SQL block, then any inline escapes. Non-call text just gets inline
 * translation. */
static char *translate_escapes(const char *in, Ctx *ctx)
{
  const char *p = in;
  while (*p != '\0' && isspace((unsigned char)*p))
    p++;
  if (*p != '{')
    return inline_escapes(in, ctx);

  const char *close = find_close_brace(p);
  if (close == NULL)
    return inline_escapes(in, ctx);

  const char *q = p + 1;
  while (isspace((unsigned char)*q))
    q++;
  /* {? = call func(...)}: the markers are already :1, :2... */
  const char *ret = NULL;
  size_t retlen = 0;
  if (*q == ':' && isdigit((unsigned char)q[1])) {
    ret = q++;
    while (isdigit((unsigned char)*q))
      q++;
    retlen = (size_t)(q - ret);
    while (isspace((unsigned char)*q))
      q++;
    if (*q == '=')
      q++;
    while (isspace((unsigned char)*q))
      q++;
  }
  if (strncasecmp(q, "call", 4) != 0 ||
      !(q[4] == '\0' || isspace((unsigned char)q[4]) || q[4] == '('))
    return inline_escapes(in, ctx); /* not a call escape */

  q += 4;
  while (isspace((unsigned char)*q))
    q++;
  size_t blen = (size_t)(close - q);
  while (blen > 0 && isspace((unsigned char)q[blen - 1]))
    blen--;

  char *res = malloc(blen + retlen + 32);
  if (res == NULL)
    return NULL;
  int o = sprintf(res, "BEGIN ");
  if (ret != NULL) {
    memcpy(res + o, ret, retlen);
    o += (int)retlen;
    o += sprintf(res + o, " := ");
  }
  memcpy(res + o, q, blen);
  o += (int)blen;
  sprintf(res + o, "; END;");

  char *full = inline_escapes(res, ctx); /* handle {ts}/{d}/... inside the call */
  free(res);
  return full;
}

/* Rewrite ODBC '?' parameter markers to Oracle positional binds :1, :2, ...
 * (Oracle rejects '?'). Markers inside string/quoted-identifier literals are
 * left alone. */
static char *rewrite_params(const char *in)
{
  size_t n = strlen(in);
  char *out = malloc(n * 6 + 1); /* worst case '?' -> ':NNNNN' */
  if (out == NULL)
    return NULL;
  size_t o = 0;
  int pnum = 0;
  char quote = 0;
  for (size_t i = 0; i < n; i++) {
    char c = in[i];
    if (quote) {
      out[o++] = c;
      if (c == quote)
        quote = 0;
    } else if (c == '\'' || c == '"') {
      quote = c;
      out[o++] = c;
    } else if (c == '?') {
      o += (size_t)sprintf(out + o, ":%d", ++pnum);
    } else {
      out[o++] = c;
    }
  }
  out[o] = '\0';
  return out;
}

char *seer_sql_prepare(const char *raw)
{
  return seer_sql_prepare_scan(raw, 1);
}

char *seer_sql_prepare_scan(const char *raw, int scan)
{
  return seer_sql_prepare_for(raw, scan, 0, NULL);
}

/* The markers first, so the {fn} translations see which arguments hold one. */
char *seer_sql_prepare_for(const char *raw, int scan, int major, const char **err)
{
  if (err != NULL)
    *err = NULL;
  char *marked = rewrite_params(raw);
  if (!scan || marked == NULL)
    return marked;
  Ctx ctx = {major, NULL};
  char *out = translate_escapes(marked, &ctx);
  free(marked);
  if (out == NULL && err != NULL)
    *err = ctx.err;
  return out;
}

/* Word match: `kw` at `p`, case-insensitive, followed by a non-identifier. */
static int kw_at(const char *p, const char *kw)
{
  size_t n = strlen(kw);
  if (strncasecmp(p, kw, n) != 0)
    return 0;
  char c = p[n];
  return !(isalnum((unsigned char)c) || c == '_' || c == '$' || c == '#');
}

/* Skip a dotted identifier (a[.b], each part a word or "quoted"); return the
 * end, and the start of the LAST part in *last (the unqualified name). */
static const char *skip_dotted_ident(const char *p, const char **last)
{
  *last = p;
  for (;;) {
    if (*p == '"') {
      p++;
      while (*p && *p != '"')
        p++;
      if (*p == '"')
        p++;
    } else if (isalpha((unsigned char)*p) || *p == '_') {
      while (isalnum((unsigned char)*p) || *p == '_' || *p == '$' || *p == '#')
        p++;
    } else
      break;
    if (*p == '.') {
      p++;
      *last = p;
    } else
      break;
  }
  return p;
}

/* True if `s` carries a top-level (depth 0, outside literals) FOR UPDATE. */
static int has_for_update(const char *s)
{
  int depth = 0;
  char q = 0;
  for (const char *c = s; *c; c++) {
    if (q) {
      if (*c == q)
        q = 0;
      continue;
    }
    if (*c == '\'' || *c == '"') {
      q = *c;
      continue;
    }
    if (*c == '(')
      depth++;
    else if (*c == ')')
      depth--;
    else if (depth == 0 && (c == s || !isalnum((unsigned char)c[-1])) && kw_at(c, "FOR")) {
      const char *u = c + 3;
      while (isspace((unsigned char)*u))
        u++;
      if (kw_at(u, "UPDATE"))
        return 1;
    }
  }
  return 0;
}

char *seer_sql_make_updatable(const char *sql, char **table, int lock)
{
  *table = NULL;
  const char *p = sql;
  while (isspace((unsigned char)*p))
    p++;
  if (!kw_at(p, "SELECT"))
    return NULL;
  p += 6;
  while (isspace((unsigned char)*p))
    p++;
  if (kw_at(p, "DISTINCT") || kw_at(p, "UNIQUE"))
    return NULL;

  const char *sel_start = p;
  /* Find the top-level FROM (depth 0, outside string/identifier literals). */
  const char *from = NULL;
  int depth = 0;
  char q = 0;
  for (const char *c = p; *c; c++) {
    if (q) {
      if (*c == q)
        q = 0;
      continue;
    }
    if (*c == '\'' || *c == '"') {
      q = *c;
      continue;
    }
    if (*c == '(')
      depth++;
    else if (*c == ')')
      depth--;
    else if (depth == 0 && (*c == ' ' || *c == '\t' || *c == '\n' || *c == '(') &&
             kw_at(c + 1, "FROM")) {
      from = c + 1;
      break;
    }
  }
  if (from == NULL)
    return NULL;
  const char *sel_end = from; /* select list is [sel_start, sel_end) */

  /* Reject set operators anywhere at depth 0 (UNION/MINUS/INTERSECT). */
  q = 0;
  depth = 0;
  for (const char *c = sql; *c; c++) {
    if (q) {
      if (*c == q)
        q = 0;
      continue;
    }
    if (*c == '\'' || *c == '"') {
      q = *c;
      continue;
    }
    if (*c == '(')
      depth++;
    else if (*c == ')')
      depth--;
    else if (depth == 0 && (c == sql || !isalnum((unsigned char)c[-1])) &&
             (kw_at(c, "UNION") || kw_at(c, "MINUS") || kw_at(c, "INTERSECT")))
      return NULL;
  }

  /* Parse the single table reference after FROM. */
  const char *t = from + 4;
  while (isspace((unsigned char)*t))
    t++;
  if (*t == '(') /* subquery / derived table */
    return NULL;
  const char *tbl_last = NULL;
  const char *tbl_start = t;
  const char *tbl_end = skip_dotted_ident(t, &tbl_last);
  if (tbl_end == t)
    return NULL; /* no identifier */
  char *base = seer_strndup(tbl_start, (size_t)(tbl_end - tbl_start));

  /* Optional alias, then the next token must end the single-table FROM. */
  const char *a = tbl_end;
  while (isspace((unsigned char)*a))
    a++;
  const char *ref_start = tbl_last; /* unqualified table for *-qualify */
  const char *ref_end = tbl_end;
  if (*a != '\0' && *a != ',' && !kw_at(a, "WHERE") && !kw_at(a, "ORDER") && !kw_at(a, "GROUP") &&
      !kw_at(a, "HAVING") && !kw_at(a, "CONNECT") && !kw_at(a, "START") && !kw_at(a, "FOR") &&
      !kw_at(a, "JOIN") && (isalpha((unsigned char)*a) || *a == '"')) {
    const char *al_last;
    const char *al_end = skip_dotted_ident(a, &al_last);
    ref_start = a;
    ref_end = al_end; /* alias qualifies '*' / nothing */
    a = al_end;
    while (isspace((unsigned char)*a))
      a++;
  }
  /* After table[+alias] only a clause keyword or end may follow. */
  if (!(*a == '\0' || kw_at(a, "WHERE") || kw_at(a, "ORDER") || kw_at(a, "CONNECT") ||
        kw_at(a, "START") || kw_at(a, "FOR"))) {
    free(base);
    return NULL; /* comma/join/group/having/... */
  }

  /* Build: SELECT <sel'> , ROWIDTOCHAR(ROWID) <from...>. A bare '*' select
   * list is qualified with the table/alias so '*,' stays valid. */
  int star = 0;
  const char *ss = sel_start;
  while (isspace((unsigned char)*ss))
    ss++;
  if (*ss == '*') {
    const char *after = ss + 1;
    while (isspace((unsigned char)*after))
      after++;
    if (after == sel_end)
      star = 1;
  }
  size_t cap = strlen(sql) + (size_t)(ref_end - ref_start) + 64;
  char *out = malloc(cap);
  if (out == NULL) {
    free(base);
    return NULL;
  }
  int o = snprintf(out, cap, "SELECT ");
  if (star) {
    o += snprintf(out + o, cap - o, "%.*s.*", (int)(ref_end - ref_start), ref_start);
  } else {
    o += snprintf(out + o, cap - o, "%.*s", (int)(sel_end - sel_start), sel_start);
  }
  o += snprintf(out + o, cap - o, ", ROWIDTOCHAR(ROWID) %s", from);
  /* Pessimistic concurrency (SQL_CONCUR_LOCK): lock the fetched rows unless
   * the caller already asked for it. The single-table-SELECT shape we accept
   * above is exactly what FOR UPDATE allows. */
  if (lock && !has_for_update(out))
    o += snprintf(out + o, cap - o, " FOR UPDATE");
  *table = base;
  return out;
}

int seer_sql_count_params(const char *sql)
{
  if (sql == NULL)
    return 0;
  char seen[256][64];
  int nseen = 0;
  char quote = 0;
  for (const char *p = sql; *p != '\0';) {
    char c = *p;
    if (quote) {
      if (c == quote)
        quote = 0;
      p++;
    } else if (c == '\'' || c == '"') {
      quote = c;
      p++;
    } else if (c == '-' && p[1] == '-') {
      while (*p != '\0' && *p != '\n')
        p++;
    } else if (c == '/' && p[1] == '*') {
      p += 2;
      while (*p != '\0' && !(*p == '*' && p[1] == '/'))
        p++;
      if (*p != '\0')
        p += 2;
    } else if (c == ':' && p[1] != ':' && p[1] != '=') {
      p++; /* consume ':' */
      char tok[64];
      int tl = 0;
      if (*p == '"') { /* :"Quoted Name" */
        p++;
        while (*p != '\0' && *p != '"' && tl < 63)
          tok[tl++] = *p++;
        if (*p == '"')
          p++;
      } else if (isdigit((unsigned char)*p)) {
        while (isdigit((unsigned char)*p) && tl < 63)
          tok[tl++] = *p++;
      } else if (isalpha((unsigned char)*p) || *p == '_') {
        while ((isalnum((unsigned char)*p) || *p == '_' || *p == '$' || *p == '#') && tl < 63)
          tok[tl++] = *p++;
      }
      tok[tl] = '\0';
      if (tl > 0) {
        int found = 0;
        for (int i = 0; i < nseen; i++)
          if (strcasecmp(seen[i], tok) == 0) {
            found = 1;
            break;
          }
        if (!found && nseen < 256) {
          memcpy(seen[nseen], tok, (size_t)tl + 1);
          nseen++;
        }
      }
    } else {
      p++;
    }
  }
  return nseen;
}

static int ident_char(char c)
{
  return isalnum((unsigned char)c) || c == '_' || c == '$' || c == '#';
}

/* Whether `p` begins `WHERE CURRENT OF name` ending the statement; if so,
 * fill the offsets (from `sql`) and the name. */
static int current_of_at(const char *sql, const char *p, size_t *start, size_t *end, char *name,
                         size_t namelen)
{
  p += 5; /* WHERE */
  while (isspace((unsigned char)*p))
    p++;
  if (!kw_at(p, "CURRENT"))
    return 0;
  const char *cur = p;
  p += 7;
  if (!isspace((unsigned char)*p))
    return 0;
  while (isspace((unsigned char)*p))
    p++;
  if (!kw_at(p, "OF"))
    return 0;
  p += 2;
  if (!isspace((unsigned char)*p))
    return 0;
  while (isspace((unsigned char)*p))
    p++;
  const char *n0, *n1;
  if (*p == '"') {
    n0 = ++p;
    while (*p != '\0' && *p != '"')
      p++;
    if (*p != '"' || p == n0)
      return 0;
    n1 = p++;
  } else {
    if (!isalpha((unsigned char)*p))
      return 0;
    n0 = p;
    while (ident_char(*p))
      p++;
    n1 = p;
  }
  const char *after = p;
  while (isspace((unsigned char)*p))
    p++;
  if (*p == ';')
    p++;
  while (isspace((unsigned char)*p))
    p++;
  if (*p != '\0')
    return 0;
  size_t len = (size_t)(n1 - n0);
  if (namelen == 0)
    return 0;
  if (len >= namelen)
    len = namelen - 1;
  memcpy(name, n0, len);
  name[len] = '\0';
  *start = (size_t)(cur - sql);
  *end = (size_t)(after - sql);
  return 1;
}

int seer_sql_current_of(const char *sql, size_t *start, size_t *end, char *name, size_t namelen)
{
  if (sql == NULL)
    return 0;
  const char *p = sql;
  while (isspace((unsigned char)*p))
    p++;
  if (!kw_at(p, "UPDATE") && !kw_at(p, "DELETE"))
    return 0;
  while (*p != '\0') {
    if (*p == '\'' || *p == '"') { /* a literal or quoted identifier ('' / "" inside) */
      char q = *p++;
      while (*p != '\0' && !(*p == q && p[1] != q))
        p += (*p == q) ? 2 : 1;
      if (*p != '\0')
        p++;
    } else if (p[0] == '-' && p[1] == '-') {
      while (*p != '\0' && *p != '\n')
        p++;
    } else if (p[0] == '/' && p[1] == '*') {
      const char *e = strstr(p + 2, "*/");
      p = e != NULL ? e + 2 : p + strlen(p);
    } else if ((p == sql || !ident_char(p[-1])) && kw_at(p, "WHERE")) {
      if (current_of_at(sql, p, start, end, name, namelen))
        return 1;
      p += 5;
    } else {
      p++;
    }
  }
  return 0;
}
