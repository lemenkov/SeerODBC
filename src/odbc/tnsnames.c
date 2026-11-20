/* tnsnames.ora lookup (#374). An entry is `name[, name...] = (DESCRIPTION =
 * ...)`, a tree of (KEY = value) and (KEY = (child)(child)...) groups; '#'
 * starts a comment, keywords are case-insensitive, IFILE = path includes
 * another file. Of the descriptor this takes what SeerODBC connects with: every
 * TCP / TCPS ADDRESS (HOST, PORT), in order, as a failover list, and the first
 * CONNECT_DATA's SERVICE_NAME or SID. The rest (LOAD_BALANCE, SERVER,
 * SECURITY, ...) has no SeerODBC counterpart and is not read.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#include "tnsnames.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TNS_MAX_DEPTH 32 /* nesting of ( ) groups */
#define TNS_MAX_IFILE 4  /* IFILE includes followed */
#define TNS_MAX_FILE 1048576

typedef struct TnsNode {
  char *key;
  char *atom; /* a value; NULL for a group of children */
  struct TnsNode **kids;
  int nkids;
} TnsNode;

static void node_free(TnsNode *n)
{
  if (n == NULL)
    return;
  for (int i = 0; i < n->nkids; i++)
    node_free(n->kids[i]);
  free(n->kids);
  free(n->key);
  free(n->atom);
  free(n);
}

static int ieq(const char *a, const char *b)
{
  for (; *a && *b; a++, b++)
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
      return 0;
  return *a == *b;
}

static char *dup_trim(const char *s, size_t n)
{
  while (n > 0 && isspace((unsigned char)*s))
    s++, n--;
  while (n > 0 && isspace((unsigned char)s[n - 1]))
    n--;
  if (n >= 2 && s[0] == '"' && s[n - 1] == '"') /* a quoted value */
    s++, n -= 2;
  char *d = malloc(n + 1);
  if (d != NULL) {
    memcpy(d, s, n);
    d[n] = '\0';
  }
  return d;
}

static void skip_ws(const char **p)
{
  while (**p && isspace((unsigned char)**p))
    (*p)++;
}

/* (KEY = atom) or (KEY = (child)...), at *p; NULL if malformed. */
static TnsNode *parse_node(const char **p, int depth)
{
  skip_ws(p);
  if (**p != '(' || depth > TNS_MAX_DEPTH)
    return NULL;
  (*p)++;
  const char *k = *p;
  while (**p && **p != '=' && **p != '(' && **p != ')')
    (*p)++;
  if (**p != '=')
    return NULL;
  TnsNode *n = calloc(1, sizeof *n);
  if (n == NULL)
    return NULL;
  n->key = dup_trim(k, (size_t)(*p - k));
  (*p)++;
  skip_ws(p);
  if (**p == '(') {
    for (;;) {
      skip_ws(p);
      if (**p == ')')
        break;
      TnsNode *c = parse_node(p, depth + 1);
      if (c == NULL) {
        node_free(n);
        return NULL;
      }
      TnsNode **nk = realloc(n->kids, (size_t)(n->nkids + 1) * sizeof *nk);
      if (nk == NULL) {
        node_free(c);
        node_free(n);
        return NULL;
      }
      n->kids = nk;
      n->kids[n->nkids++] = c;
    }
  } else {
    const char *a = *p;
    while (**p && **p != ')')
      (*p)++;
    n->atom = dup_trim(a, (size_t)(*p - a));
  }
  if (**p != ')' || n->key == NULL) {
    node_free(n);
    return NULL;
  }
  (*p)++;
  return n;
}

static const char *kid_atom(const TnsNode *n, const char *key)
{
  for (int i = 0; i < n->nkids; i++)
    if (n->kids[i]->atom != NULL && ieq(n->kids[i]->key, key))
      return n->kids[i]->atom;
  return NULL;
}

static void collect(const TnsNode *n, SeerTnsEntry *out)
{
  if (ieq(n->key, "ADDRESS")) {
    const char *proto = kid_atom(n, "PROTOCOL"), *host = kid_atom(n, "HOST");
    const char *port = kid_atom(n, "PORT");
    if (proto != NULL && host != NULL && host[0] && (ieq(proto, "TCP") || ieq(proto, "TCPS"))) {
      if (ieq(proto, "TCPS"))
        out->tcps = 1;
      size_t len = strlen(out->hosts);
      int v6 = strchr(host, ':') != NULL;
      snprintf(out->hosts + len, sizeof out->hosts - len, "%s%s%s%s:%s", len ? "," : "",
               v6 ? "[" : "", host, v6 ? "]" : "", port && port[0] ? port : "1521");
    }
    return;
  }
  if (ieq(n->key, "CONNECT_DATA")) {
    if (out->service[0] == '\0') {
      const char *svc = kid_atom(n, "SERVICE_NAME");
      const char *sid = kid_atom(n, "SID");
      if (svc != NULL && svc[0])
        snprintf(out->service, sizeof out->service, "%s", svc);
      else if (sid != NULL && sid[0]) {
        snprintf(out->service, sizeof out->service, "%s", sid);
        out->is_sid = 1;
      }
    }
    return;
  }
  for (int i = 0; i < n->nkids; i++)
    collect(n->kids[i], out);
}

/* The text with comments ('#' to the end of its line) blanked. */
static char *strip_comments(const char *text)
{
  char *t = strdup(text);
  if (t == NULL)
    return NULL;
  /* a comment on the last line, with no newline after it, ends at the
   * terminator: the scan must stop there, not step past it */
  int in_comment = 0;
  for (char *c = t; *c; c++) {
    if (*c == '#')
      in_comment = 1;
    else if (*c == '\n')
      in_comment = 0;
    if (in_comment)
      *c = ' ';
  }
  return t;
}

static char *read_file(const char *path)
{
  FILE *f = fopen(path, "rb");
  if (f == NULL)
    return NULL;
  char *buf = malloc(TNS_MAX_FILE + 1);
  size_t n = buf ? fread(buf, 1, TNS_MAX_FILE, f) : 0;
  fclose(f);
  if (buf != NULL)
    buf[n] = '\0';
  return buf;
}

static int lookup_text(const char *text, const char *alias, const char *dir, SeerTnsEntry *out,
                       int ifiles);

static int lookup_ifile(const char *path, const char *alias, const char *dir, SeerTnsEntry *out,
                        int ifiles)
{
  if (ifiles >= TNS_MAX_IFILE || dir == NULL)
    return -1;
  char full[1024];
  int abs = path[0] == '/' || path[0] == '\\' || (path[0] && path[1] == ':');
  snprintf(full, sizeof full, "%s%s%s", abs ? "" : dir, abs ? "" : "/", path);
  char *text = read_file(full);
  if (text == NULL)
    return -1;
  /* a relative IFILE in the included file is relative to that file's dir */
  char sub[1024];
  snprintf(sub, sizeof sub, "%s", full);
  char *slash = strrchr(sub, '/');
  if (slash != NULL)
    *slash = '\0';
  int r = lookup_text(text, alias, slash ? sub : dir, out, ifiles + 1);
  free(text);
  return r;
}

static int lookup_text(const char *text, const char *alias, const char *dir, SeerTnsEntry *out,
                       int ifiles)
{
  char *t = strip_comments(text);
  if (t == NULL)
    return -1;
  const char *p = t;
  int result = -1;
  while (result == -1) {
    skip_ws(&p);
    if (*p == '\0')
      break;
    /* the entry's names, comma-separated, up to '=' */
    int match = 0, is_ifile = 0, names = 0;
    for (;;) {
      skip_ws(&p);
      const char *s = p;
      while (*p && !isspace((unsigned char)*p) && *p != '=' && *p != ',' && *p != '(' && *p != ')')
        p++;
      if (p > s) {
        char *name = dup_trim(s, (size_t)(p - s));
        if (name != NULL) {
          match |= ieq(name, alias);
          is_ifile |= names == 0 && ieq(name, "IFILE");
          free(name);
        }
        names++;
      }
      skip_ws(&p);
      if (*p == ',') {
        p++;
        continue;
      }
      break;
    }
    if (*p != '=') { /* not an entry: skip to the next line */
      while (*p && *p != '\n')
        p++;
      continue;
    }
    p++;
    skip_ws(&p);
    if (*p != '(') { /* a bare value: IFILE = path, or another setting */
      const char *s = p;
      while (*p && *p != '\n')
        p++;
      if (is_ifile) {
        char *path = dup_trim(s, (size_t)(p - s));
        if (path != NULL) {
          result = lookup_ifile(path, alias, dir, out, ifiles);
          free(path);
        }
      }
      continue;
    }
    /* the descriptor: one or more ( ) groups */
    SeerTnsEntry e;
    memset(&e, 0, sizeof e);
    int ok = 1;
    const char *value = p; /* where to resynchronise from if it is malformed */
    while (*p == '(') {
      TnsNode *n = parse_node(&p, 0);
      if (n == NULL) {
        ok = 0;
        break;
      }
      if (match)
        collect(n, &e);
      node_free(n);
      skip_ws(&p);
    }
    if (!ok) {
      /* malformed: resynchronise at the line after the one its value
       * starts on - where the parse stopped may already be the next
       * entry's line */
      p = value;
      while (*p && *p != '\n')
        p++;
      continue;
    }
    if (match) {
      *out = e;
      result = (e.hosts[0] && e.service[0]) ? 0 : -2;
    }
  }
  free(t);
  return result;
}

int seer_tns_lookup_text(const char *text, const char *alias, const char *dir, SeerTnsEntry *out)
{
  memset(out, 0, sizeof *out);
  if (text == NULL || alias == NULL || alias[0] == '\0')
    return -1;
  return lookup_text(text, alias, dir, out, 0);
}

int seer_tns_lookup(const char *alias, SeerTnsEntry *out, char *searched, size_t searched_len)
{
  memset(out, 0, sizeof *out);
  if (searched != NULL && searched_len > 0)
    searched[0] = '\0';
  char dirs[3][768];
  int nd = 0;
  const char *ta = getenv("TNS_ADMIN"), *oh = getenv("ORACLE_HOME");
  if (ta != NULL && ta[0])
    snprintf(dirs[nd++], sizeof dirs[0], "%s", ta);
  if (oh != NULL && oh[0])
    snprintf(dirs[nd++], sizeof dirs[0], "%s/network/admin", oh);
#ifndef _WIN32
  snprintf(dirs[nd++], sizeof dirs[0], "%s", "/etc");
#endif
  for (int i = 0; i < nd; i++) {
    char path[1024];
    snprintf(path, sizeof path, "%s/tnsnames.ora", dirs[i]);
    if (searched != NULL && searched_len > 0) {
      size_t l = strlen(searched);
      snprintf(searched + l, searched_len - l, "%s%s", l ? ", " : "", path);
    }
    char *text = read_file(path);
    if (text == NULL)
      continue;
    int r = lookup_text(text, alias, dirs[i], out, 0);
    free(text);
    if (r != -1)
      return r;
  }
  return -1;
}
