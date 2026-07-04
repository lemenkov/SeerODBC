/* JSON text -> OSON (native binary JSON) encoder. See json.h.
 *
 * Two stages: a recursive-descent parser builds a small value tree, then the
 * OSON encoder serialises it in the server's compact small-document form
 * (header flags 0x2106: ub1 field-name count, ub2 value-offsets) - exactly the
 * shape seer_decode_oson reads back. Mirrors python-oracledb's encode_oson.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "json.h"

#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "writer.h"

/* ---- value tree --------------------------------------------------------- */

typedef enum { JN_NULL, JN_TRUE, JN_FALSE, JN_NUM, JN_STR, JN_ARR, JN_OBJ } JsonKind;

typedef struct JsonNode {
    JsonKind          kind;
    char             *str;      /* JN_STR: decoded UTF-8; JN_NUM: number text  */
    size_t            slen;     /* JN_STR byte length                          */
    struct JsonNode **kids;     /* JN_ARR / JN_OBJ element values              */
    char            **keys;     /* JN_OBJ keys (NUL-terminated UTF-8)          */
    size_t           *keylens;  /* JN_OBJ key byte lengths                     */
    size_t            n;        /* element / member count                      */
} JsonNode;

static void json_free(JsonNode *j)
{
    if (j == NULL)
        return;
    for (size_t i = 0; i < j->n; i++) {
        json_free(j->kids ? j->kids[i] : NULL);
        if (j->keys) free(j->keys[i]);
    }
    free(j->kids);
    free(j->keys);
    free(j->keylens);
    free(j->str);
    free(j);
}

/* ---- parser ------------------------------------------------------------- */

typedef struct { const char *p; int ok; } Parser;

static void skip_ws(Parser *ps)
{
    while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')
        ps->p++;
}

/* Append the UTF-8 encoding of a code point to a growable buffer. */
static int utf8_append(char **buf, size_t *len, size_t *cap, unsigned cp)
{
    char enc[4];
    size_t n;
    if (cp < 0x80) { enc[0] = (char)cp; n = 1; }
    else if (cp < 0x800) {
        enc[0] = (char)(0xC0 | (cp >> 6)); enc[1] = (char)(0x80 | (cp & 0x3F)); n = 2;
    } else if (cp < 0x10000) {
        enc[0] = (char)(0xE0 | (cp >> 12)); enc[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        enc[2] = (char)(0x80 | (cp & 0x3F)); n = 3;
    } else {
        enc[0] = (char)(0xF0 | (cp >> 18)); enc[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        enc[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); enc[3] = (char)(0x80 | (cp & 0x3F)); n = 4;
    }
    if (*len + n > *cap) {
        size_t nc = (*cap ? *cap * 2 : 16);
        while (nc < *len + n) nc *= 2;
        char *t = realloc(*buf, nc);
        if (t == NULL) return 0;
        *buf = t; *cap = nc;
    }
    memcpy(*buf + *len, enc, n);
    *len += n;
    return 1;
}

static int hex4(const char *p, unsigned *out)
{
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return 0;
    }
    *out = v;
    return 1;
}

/* Parse a JSON string (cursor at the opening quote); returns malloc'd UTF-8. */
static char *parse_string(Parser *ps, size_t *outlen)
{
    if (*ps->p != '"') { ps->ok = 0; return NULL; }
    ps->p++;
    char  *buf = NULL;
    size_t len = 0, cap = 0;
    while (*ps->p != '"') {
        unsigned c = (unsigned char)*ps->p;
        if (c == 0) { ps->ok = 0; free(buf); return NULL; }
        if (c == '\\') {
            ps->p++;
            char e = *ps->p;
            unsigned cp = 0;
            switch (e) {
            case '"':  cp = '"';  break;
            case '\\': cp = '\\'; break;
            case '/':  cp = '/';  break;
            case 'b':  cp = '\b'; break;
            case 'f':  cp = '\f'; break;
            case 'n':  cp = '\n'; break;
            case 'r':  cp = '\r'; break;
            case 't':  cp = '\t'; break;
            case 'u': {
                unsigned u;
                if (!hex4(ps->p + 1, &u)) { ps->ok = 0; free(buf); return NULL; }
                ps->p += 4;
                if (u >= 0xD800 && u <= 0xDBFF) {        /* high surrogate */
                    if (ps->p[1] != '\\' || ps->p[2] != 'u') { ps->ok = 0; free(buf); return NULL; }
                    unsigned lo;
                    if (!hex4(ps->p + 3, &lo) || lo < 0xDC00 || lo > 0xDFFF) {
                        ps->ok = 0; free(buf); return NULL;
                    }
                    ps->p += 6;
                    cp = 0x10000u + ((u - 0xD800u) << 10) + (lo - 0xDC00u);
                } else {
                    cp = u;
                }
                break;
            }
            default: ps->ok = 0; free(buf); return NULL;
            }
            if (!utf8_append(&buf, &len, &cap, cp)) { ps->ok = 0; free(buf); return NULL; }
            ps->p++;
        } else {
            if (!utf8_append(&buf, &len, &cap, c)) { ps->ok = 0; free(buf); return NULL; }
            ps->p++;
        }
    }
    ps->p++;                                             /* closing quote */
    /* NUL-terminate (keys need it; values use slen). */
    if (len + 1 > cap) {
        char *t = realloc(buf, len + 1);
        if (t == NULL) { ps->ok = 0; free(buf); return NULL; }
        buf = t;
    }
    if (buf == NULL) buf = calloc(1, 1);                 /* empty string */
    else buf[len] = '\0';
    *outlen = len;
    return buf;
}

static JsonNode *parse_value(Parser *ps);

static JsonNode *parse_array(Parser *ps)
{
    JsonNode *j = calloc(1, sizeof *j);
    if (j == NULL) { ps->ok = 0; return NULL; }
    j->kind = JN_ARR;
    ps->p++;                                             /* '[' */
    skip_ws(ps);
    if (*ps->p == ']') { ps->p++; return j; }
    for (;;) {
        JsonNode *v = parse_value(ps);
        if (!ps->ok) { json_free(v); json_free(j); return NULL; }
        JsonNode **k = realloc(j->kids, (j->n + 1) * sizeof *k);
        if (k == NULL) { ps->ok = 0; json_free(v); json_free(j); return NULL; }
        j->kids = k;
        j->kids[j->n++] = v;
        skip_ws(ps);
        if (*ps->p == ',') { ps->p++; skip_ws(ps); continue; }
        if (*ps->p == ']') { ps->p++; break; }
        ps->ok = 0; json_free(j); return NULL;
    }
    return j;
}

static JsonNode *parse_object(Parser *ps)
{
    JsonNode *j = calloc(1, sizeof *j);
    if (j == NULL) { ps->ok = 0; return NULL; }
    j->kind = JN_OBJ;
    ps->p++;                                             /* '{' */
    skip_ws(ps);
    if (*ps->p == '}') { ps->p++; return j; }
    for (;;) {
        skip_ws(ps);
        size_t klen = 0;
        char  *key = parse_string(ps, &klen);
        if (!ps->ok) { free(key); json_free(j); return NULL; }
        skip_ws(ps);
        if (*ps->p != ':') { ps->ok = 0; free(key); json_free(j); return NULL; }
        ps->p++;
        JsonNode *v = parse_value(ps);
        if (!ps->ok) { free(key); json_free(v); json_free(j); return NULL; }
        char  **nk = realloc(j->keys, (j->n + 1) * sizeof *nk);
        size_t *nl = realloc(j->keylens, (j->n + 1) * sizeof *nl);
        JsonNode **nv = realloc(j->kids, (j->n + 1) * sizeof *nv);
        if (nk) j->keys = nk;
        if (nl) j->keylens = nl;
        if (nv) j->kids = nv;
        if (!nk || !nl || !nv) { ps->ok = 0; free(key); json_free(v); json_free(j); return NULL; }
        j->keys[j->n] = key;
        j->keylens[j->n] = klen;
        j->kids[j->n] = v;
        j->n++;
        skip_ws(ps);
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == '}') { ps->p++; break; }
        ps->ok = 0; json_free(j); return NULL;
    }
    return j;
}

static JsonNode *parse_number(Parser *ps)
{
    const char *start = ps->p;
    if (*ps->p == '-') ps->p++;
    while ((*ps->p >= '0' && *ps->p <= '9') || *ps->p == '.'
           || *ps->p == '+' || *ps->p == '-' || *ps->p == 'e' || *ps->p == 'E')
        ps->p++;
    size_t len = (size_t)(ps->p - start);
    if (len == 0) { ps->ok = 0; return NULL; }
    JsonNode *j = calloc(1, sizeof *j);
    if (j == NULL) { ps->ok = 0; return NULL; }
    j->kind = JN_NUM;
    j->str  = malloc(len + 1);
    if (j->str == NULL) { ps->ok = 0; free(j); return NULL; }
    memcpy(j->str, start, len);
    j->str[len] = '\0';
    return j;
}

static JsonNode *lit(Parser *ps, const char *word, JsonKind kind)
{
    size_t n = strlen(word);
    if (strncmp(ps->p, word, n) != 0) { ps->ok = 0; return NULL; }
    ps->p += n;
    JsonNode *j = calloc(1, sizeof *j);
    if (j == NULL) { ps->ok = 0; return NULL; }
    j->kind = kind;
    return j;
}

static JsonNode *parse_value(Parser *ps)
{
    skip_ws(ps);
    char c = *ps->p;
    if (c == '{') return parse_object(ps);
    if (c == '[') return parse_array(ps);
    if (c == '"') {
        JsonNode *j = calloc(1, sizeof *j);
        if (j == NULL) { ps->ok = 0; return NULL; }
        j->kind = JN_STR;
        j->str  = parse_string(ps, &j->slen);
        if (!ps->ok) { json_free(j); return NULL; }
        return j;
    }
    if (c == 't') return lit(ps, "true", JN_TRUE);
    if (c == 'f') return lit(ps, "false", JN_FALSE);
    if (c == 'n') return lit(ps, "null", JN_NULL);
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number(ps);
    ps->ok = 0;
    return NULL;
}

/* ---- field-name table --------------------------------------------------- */

typedef struct { char **names; size_t *lens; int count, cap; int ok; } Fnames;

/* Return the 1-based field id for a key, assigning a new one in first-seen order. */
static int fid(Fnames *f, const char *name, size_t len)
{
    for (int i = 0; i < f->count; i++)
        if (f->lens[i] == len && memcmp(f->names[i], name, len) == 0)
            return i + 1;
    if (f->count >= 0xFF) { f->ok = 0; return 1; }      /* subset limit */
    if (f->count >= f->cap) {
        int nc = f->cap ? f->cap * 2 : 8;
        char  **nn = realloc(f->names, (size_t)nc * sizeof *nn);
        size_t *nl = realloc(f->lens, (size_t)nc * sizeof *nl);
        if (nn) f->names = nn;
        if (nl) f->lens = nl;
        if (!nn || !nl) { f->ok = 0; return 1; }
        f->cap = nc;
    }
    f->names[f->count] = (char *)name;
    f->lens[f->count]  = len;
    f->count++;
    return f->count;
}

/* Walk the tree assigning field ids in document order (mirrors encode_oson). */
static void collect_fnames(const JsonNode *j, Fnames *f)
{
    if (j->kind == JN_OBJ) {
        for (size_t i = 0; i < j->n; i++) {
            fid(f, j->keys[i], j->keylens[i]);
            collect_fnames(j->kids[i], f);
        }
    } else if (j->kind == JN_ARR) {
        for (size_t i = 0; i < j->n; i++)
            collect_fnames(j->kids[i], f);
    }
}

/* ---- OSON encoder ------------------------------------------------------- */

typedef struct { SeerWriter *w; Fnames *f; int ok; } Enc;

static void emit_scalar(Enc *e, const JsonNode *j)
{
    switch (j->kind) {
    case JN_NULL:  seer_writer_u8(e->w, 0x30); break;
    case JN_TRUE:  seer_writer_u8(e->w, 0x31); break;
    case JN_FALSE: seer_writer_u8(e->w, 0x32); break;
    case JN_STR:
        if (j->slen <= 0x1F) {
            seer_writer_u8(e->w, (uint8_t)j->slen);
        } else if (j->slen <= 0xFF) {
            seer_writer_u8(e->w, 0x33);
            seer_writer_u8(e->w, (uint8_t)j->slen);
        } else {
            e->ok = 0; return;                          /* string too long */
        }
        if (j->slen > 0) seer_writer_bytes(e->w, j->str, j->slen);
        break;
    case JN_NUM: {
        uint8_t nb[24];
        size_t  nl = seer_encode_number_str(j->str, nb);
        if (nl == 0 || nl > sizeof nb) { e->ok = 0; return; }
        seer_writer_u8(e->w, 0x34);
        seer_writer_u8(e->w, (uint8_t)nl);
        seer_writer_bytes(e->w, nb, nl);
        break;
    }
    default: e->ok = 0; break;
    }
}

/* Emit a node into the tree buffer; return its start offset (tree-relative). */
static size_t emit_node(Enc *e, const JsonNode *j)
{
    size_t start = e->w->len;
    if (j->kind == JN_OBJ || j->kind == JN_ARR) {
        if (j->n > 0xFF) { e->ok = 0; return start; }
        seer_writer_u8(e->w, j->kind == JN_OBJ ? 0x84 : 0xC4);
        seer_writer_u8(e->w, (uint8_t)j->n);
        if (j->kind == JN_OBJ)
            for (size_t i = 0; i < j->n; i++)
                seer_writer_u8(e->w, (uint8_t)fid(e->f, j->keys[i], j->keylens[i]));
        size_t off_pos = e->w->len;
        for (size_t i = 0; i < j->n; i++) { seer_writer_u8(e->w, 0); seer_writer_u8(e->w, 0); }
        for (size_t i = 0; i < j->n; i++) {
            size_t coff = emit_node(e, j->kids[i]);
            if (!e->ok) return start;
            e->w->buf[off_pos + 2 * i]     = (uint8_t)(coff >> 8);
            e->w->buf[off_pos + 2 * i + 1] = (uint8_t)(coff & 0xFF);
        }
        return start;
    }
    emit_scalar(e, j);
    return start;
}

SeerStatus seer_json_to_oson(const char *json_text, uint8_t **out, size_t *outlen)
{
    if (json_text == NULL || out == NULL || outlen == NULL)
        return SEER_EPARAM;
    *out = NULL;
    *outlen = 0;

    Parser ps = { .p = json_text, .ok = 1 };
    JsonNode *root = parse_value(&ps);
    if (!ps.ok || root == NULL) { json_free(root); return SEER_EPARAM; }
    skip_ws(&ps);
    if (*ps.p != '\0') { json_free(root); return SEER_EPARAM; }   /* trailing junk */

    SeerStatus rc = SEER_ENOMEM;

    /* Scalar root: FF 4A 5A 01 | 00 16 00 | ub1 node-len | node. */
    if (root->kind != JN_OBJ && root->kind != JN_ARR) {
        SeerWriter node;
        if (!seer_writer_init(&node, 32)) { json_free(root); return SEER_ENOMEM; }
        Enc e = { .w = &node, .f = NULL, .ok = 1 };
        emit_scalar(&e, root);
        if (!e.ok || !seer_writer_ok(&node) || node.len > 0xFF) {
            seer_writer_free(&node); json_free(root);
            return e.ok ? SEER_EPARAM : SEER_EPARAM;
        }
        SeerWriter w;
        if (!seer_writer_init(&w, 16 + node.len)) {
            seer_writer_free(&node); json_free(root); return SEER_ENOMEM;
        }
        static const uint8_t hdr[7] = { 0xFF, 0x4A, 0x5A, 0x01, 0x00, 0x16, 0x00 };
        seer_writer_bytes(&w, hdr, sizeof hdr);
        seer_writer_u8(&w, (uint8_t)node.len);
        seer_writer_bytes(&w, node.buf, node.len);
        seer_writer_free(&node);
        if (seer_writer_ok(&w)) { *out = w.buf; *outlen = w.len; rc = SEER_OK; }
        else { seer_writer_free(&w); rc = SEER_ENOMEM; }
        json_free(root);
        return rc;
    }

    /* Container root: collect field names, then header + segments + tree. */
    Fnames f = { .ok = 1 };
    collect_fnames(root, &f);
    if (!f.ok) { free(f.names); free(f.lens); json_free(root); return SEER_EPARAM; }

    SeerWriter tree;
    if (!seer_writer_init(&tree, 128)) {
        free(f.names); free(f.lens); json_free(root); return SEER_ENOMEM;
    }
    Enc e = { .w = &tree, .f = &f, .ok = 1 };
    emit_node(&e, root);

    /* field-name segment: <len><utf8> each; offset array: ub2 into the segment. */
    SeerWriter fseg;
    if (!seer_writer_init(&fseg, 64)) {
        seer_writer_free(&tree); free(f.names); free(f.lens); json_free(root);
        return SEER_ENOMEM;
    }
    uint16_t *offs = f.count ? calloc((size_t)f.count, sizeof *offs) : NULL;
    if (f.count && offs == NULL) {
        seer_writer_free(&tree); seer_writer_free(&fseg);
        free(f.names); free(f.lens); json_free(root); return SEER_ENOMEM;
    }
    for (int i = 0; i < f.count; i++) {
        offs[i] = (uint16_t)fseg.len;
        seer_writer_u8(&fseg, (uint8_t)f.lens[i]);       /* key <= 0xFF (subset) */
        seer_writer_bytes(&fseg, f.names[i], f.lens[i]);
    }

    if (!e.ok || !seer_writer_ok(&tree) || !seer_writer_ok(&fseg)
        || fseg.len > 0xFFFF || tree.len > 0xFFFF) {
        rc = e.ok ? SEER_EPARAM : SEER_EPARAM;
        goto done;
    }

    SeerWriter w;
    if (!seer_writer_init(&w, 16 + (size_t)f.count * 3 + fseg.len + tree.len)) {
        rc = SEER_ENOMEM;
        goto done;
    }
    {
        static const uint8_t magic[6] = { 0xFF, 0x4A, 0x5A, 0x01, 0x21, 0x06 };
        seer_writer_bytes(&w, magic, sizeof magic);
        seer_writer_u8(&w, (uint8_t)f.count);
        seer_writer_u8(&w, (uint8_t)(fseg.len >> 8));  seer_writer_u8(&w, (uint8_t)(fseg.len & 0xFF));
        seer_writer_u8(&w, (uint8_t)(tree.len >> 8));  seer_writer_u8(&w, (uint8_t)(tree.len & 0xFF));
        seer_writer_u8(&w, 0); seer_writer_u8(&w, 0);  /* reserved */
        for (int i = 0; i < f.count; i++) seer_writer_u8(&w, 0);          /* hash array */
        for (int i = 0; i < f.count; i++) {
            seer_writer_u8(&w, (uint8_t)(offs[i] >> 8)); seer_writer_u8(&w, (uint8_t)(offs[i] & 0xFF));
        }
        seer_writer_bytes(&w, fseg.buf, fseg.len);
        seer_writer_bytes(&w, tree.buf, tree.len);
    }
    if (seer_writer_ok(&w)) { *out = w.buf; *outlen = w.len; rc = SEER_OK; }
    else { seer_writer_free(&w); rc = SEER_ENOMEM; }

done:
    free(offs);
    seer_writer_free(&tree);
    seer_writer_free(&fseg);
    free(f.names);
    free(f.lens);
    json_free(root);
    return rc;
}
