/* The bind placeholders of a statement's text - see placeholders.h.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "placeholders.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* The character that closes a q'X...X' literal opened by X. */
static char q_close(char open)
{
  switch (open) {
  case '[':
    return ']';
  case '{':
    return '}';
  case '(':
    return ')';
  case '<':
    return '>';
  default:
    return open;
  }
}

static int ident_char(char c)
{
  return isalnum((unsigned char)c) || c == '_' || c == '$' || c == '#';
}

int seer_sql_placeholders(const char *sql, int **occ, int *nocc, int *ndistinct)
{
  *occ = NULL;
  *nocc = 0;
  *ndistinct = 0;
  if (sql == NULL)
    return 0;
  const char **names = NULL; /* each distinct name: its start in sql */
  size_t *lens = NULL;
  int *o = NULL, n = 0, nd = 0, cap = 0;
  const char *p = sql;
  while (*p != '\0') {
    char c = *p;
    if ((c == 'q' || c == 'Q') && p[1] == '\'' && p[2] != '\0' &&
        (p == sql || !ident_char(p[-1]))) { /* q'X...X' */
      char close = q_close(p[2]);
      p += 3;
      while (*p != '\0' && !(*p == close && p[1] == '\''))
        p++;
      if (*p != '\0')
        p += 2;
    } else if (c == '\'' || c == '"') { /* '' inside text reads as two literals */
      p++;
      while (*p != '\0' && *p != c)
        p++;
      if (*p != '\0')
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
    } else if (c == ':' && (ident_char(p[1]) || p[1] == '"') && (p == sql || p[-1] != ':')) {
      const char *name = ++p;
      size_t len;
      if (*p == '"') {
        p++;
        while (*p != '\0' && *p != '"')
          p++;
        if (*p != '\0')
          p++;
      } else {
        while (ident_char(*p))
          p++;
      }
      len = (size_t)(p - name);
      int k = 0;
      while (k < nd && !(lens[k] == len && strncasecmp(names[k], name, len) == 0))
        k++;
      if (k == nd) {
        const char **nn = realloc(names, (size_t)(nd + 1) * sizeof *nn);
        size_t *nl = nn != NULL ? realloc(lens, (size_t)(nd + 1) * sizeof *nl) : NULL;
        if (nn != NULL)
          names = nn;
        if (nl == NULL)
          goto oom;
        lens = nl;
        names[nd] = name;
        lens[nd] = len;
        nd++;
      }
      if (n == cap) {
        cap = cap ? cap * 2 : 8;
        int *no = realloc(o, (size_t)cap * sizeof *no);
        if (no == NULL)
          goto oom;
        o = no;
      }
      o[n++] = k;
    } else {
      p++;
    }
  }
  free(names);
  free(lens);
  *occ = o;
  *nocc = n;
  *ndistinct = nd;
  return 0;
oom:
  free(names);
  free(lens);
  free(o);
  return -1;
}
