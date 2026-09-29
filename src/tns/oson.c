/* OSON decoder: Oracle's binary JSON image (the wire form of a native JSON
 * column, 21c+) to JSON text. Ported from pyoracle/oracle/oson.py; layout per
 * PROTOCOL.md. We walk the image tree and emit JSON text directly (objects,
 * arrays, strings, numbers, true/false/null), reusing the column-type decoders
 * for extended scalars (native NUMBER, DATE, TIMESTAMP, BINARY_FLOAT/DOUBLE,
 * INTERVAL nodes).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "oson.h"

#include "types.h"
#include "writer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Image flags (header ub2). */
#define OSON_FLAG_REL_OFFSETS                                                                      \
  0x0001                      /* child offsets relative to their container (compressed column) */
#define OSON_FLAG_TREE 0x2000 /* container image vs bare scalar      */
#define OSON_FLAG_UB2_OFFSETS 0x0004 /* container value-offsets are ub2     */
#define OSON_FLAG_UB2_FNAMES 0x0400  /* num_fnames is ub2 (> 255 fields)    */
#define OSON_FLAG_UB4_TREE 0x1000    /* tree-segment size is ub4 (> 64 KiB) */

/* Container node tag bits. */
#define OSON_TAG_WIDE_COUNT 0x08  /* count + field-ids are ub2           */
#define OSON_TAG_UB4_COUNT 0x10   /* count + field-ids are ub4           */
#define OSON_TAG_UB4_OFFSETS 0x20 /* this container's offsets are ub4    */
/* On an OBJECT tag, both count-width bits set mean "shared field ids": the
 * object stores no id array but an (absolute) offset to a donor object whose
 * count and ids it uses (compressed columns, seerdb PROTOCOL.md §17.0c). */
#define OSON_TAG_SHARED_IDS 0x18

#define OSON_MAX_DEPTH 64

typedef struct {
  const uint8_t *tree; /* tree segment (nodes live here)        */
  size_t tree_len;
  const uint8_t *fnames; /* field-name segment                    */
  size_t fnames_len;
  const uint8_t *foff; /* field-name offset table (ub2 each)    */
  size_t nfnames;
  /* Version 3: a second segment for names over 255 bytes, sharing the id
   * space (ids above nfnames index it); <ub2 len><bytes> names. */
  const uint8_t *lfnames;
  size_t lfnames_len;
  const uint8_t *lfoff; /* its offset table (lfoff_size bytes each) */
  int lfoff_size;
  size_t nlfnames;
  bool rel;     /* container child offsets are relative to the container */
  int off_size; /* container value-offset width (2 or 4) */
  SeerWriter *w;
  bool ok;
} OsonCtx;

/* Big-endian read of `size` (1..4) bytes; bounds-checked against `end`. */
static uint32_t rd_uint(OsonCtx *c, const uint8_t *p, int size, const uint8_t *end)
{
  if (p + size > end) {
    c->ok = false;
    return 0;
  }
  uint32_t v = 0;
  for (int i = 0; i < size; i++)
    v = (v << 8) | p[i];
  return v;
}

/* Emit a JSON string literal for `n` UTF-8 bytes, escaping per RFC 8259. */
static void emit_json_string(OsonCtx *c, const uint8_t *s, size_t n)
{
  SeerWriter *w = c->w;
  seer_writer_u8(w, '"');
  for (size_t i = 0; i < n; i++) {
    uint8_t ch = s[i];
    switch (ch) {
    case '"':
      seer_writer_bytes(w, "\\\"", 2);
      break;
    case '\\':
      seer_writer_bytes(w, "\\\\", 2);
      break;
    case '\b':
      seer_writer_bytes(w, "\\b", 2);
      break;
    case '\f':
      seer_writer_bytes(w, "\\f", 2);
      break;
    case '\n':
      seer_writer_bytes(w, "\\n", 2);
      break;
    case '\r':
      seer_writer_bytes(w, "\\r", 2);
      break;
    case '\t':
      seer_writer_bytes(w, "\\t", 2);
      break;
    default:
      if (ch < 0x20) {
        char u[7];
        snprintf(u, sizeof u, "\\u%04x", ch);
        seer_writer_bytes(w, u, 6);
      } else {
        seer_writer_u8(w, ch); /* pass UTF-8 through */
      }
    }
  }
  seer_writer_u8(w, '"');
}

/* Emit an Oracle NUMBER (n bytes) as a bare JSON number; "null" if undecodable. */
static void emit_number(OsonCtx *c, const uint8_t *p, size_t n, const uint8_t *end)
{
  if (p + n > end) {
    c->ok = false;
    return;
  }
  char buf[192];
  if (seer_decode_number(p, n, buf, sizeof buf) == SEER_OK && buf[0] != '\0')
    seer_writer_bytes(c->w, buf, strlen(buf));
  else
    seer_writer_bytes(c->w, "null", 4);
}

/* The `id`-th field name (1-based) as a quoted JSON key. */
static void emit_field_key(OsonCtx *c, uint32_t id)
{
  if (id > c->nfnames && id - c->nfnames <= c->nlfnames) { /* long-name segment */
    size_t k = id - c->nfnames - 1;
    const uint8_t *op = c->lfoff + (size_t)c->lfoff_size * k;
    uint32_t off = 0;
    for (int i = 0; i < c->lfoff_size; i++)
      off = off << 8 | op[i];
    if ((size_t)off + 2 > c->lfnames_len) {
      c->ok = false;
      return;
    }
    size_t len = (size_t)c->lfnames[off] << 8 | c->lfnames[off + 1];
    if ((size_t)off + 2 + len > c->lfnames_len) {
      c->ok = false;
      return;
    }
    emit_json_string(c, c->lfnames + off + 2, len);
    return;
  }
  if (id == 0 || id > c->nfnames) {
    c->ok = false;
    return;
  }
  const uint8_t *op = c->foff + 2 * (size_t)(id - 1);
  uint32_t off = ((uint32_t)op[0] << 8) | op[1];
  if (off >= c->fnames_len) {
    c->ok = false;
    return;
  }
  uint8_t len = c->fnames[off];
  if (off + 1 + len > c->fnames_len) {
    c->ok = false;
    return;
  }
  emit_json_string(c, c->fnames + off + 1, len);
}

/* An extended scalar node (#69): a tag byte then a fixed-width native value
 * decoded by the column codecs. Returns false if `tag` isn't an ext scalar. */
static bool emit_ext_scalar(OsonCtx *c, uint8_t tag, const uint8_t *val, const uint8_t *end)
{
  int width;
  char buf[64];
  bool quoted; /* dates/intervals -> JSON string */
  SeerStatus (*dec)(const uint8_t *, size_t, char *, size_t);
  switch (tag) {
  case 0x36:
    width = 8;
    dec = seer_decode_bdouble;
    quoted = false;
    break;
  case 0x7F:
    width = 4;
    dec = seer_decode_bfloat;
    quoted = false;
    break;
  case 0x3C:
  case 0x7D:
    width = 7;
    dec = seer_decode_date;
    quoted = true;
    break;
  case 0x39:
    width = 11;
    dec = seer_decode_date;
    quoted = true;
    break;
  case 0x7C:
    width = 13;
    dec = seer_decode_date;
    quoted = true;
    break;
  case 0x3D:
    width = 5;
    dec = seer_decode_interval_ym;
    quoted = true;
    break;
  case 0x3E:
    width = 11;
    dec = seer_decode_interval_ds;
    quoted = true;
    break;
  default:
    return false;
  }
  if (val + width > end) {
    c->ok = false;
    return true;
  }
  if (dec(val, (size_t)width, buf, sizeof buf) != SEER_OK || buf[0] == '\0') {
    seer_writer_bytes(c->w, "null", 4);
    return true;
  }
  if (quoted)
    emit_json_string(c, (const uint8_t *)buf, strlen(buf));
  else
    seer_writer_bytes(c->w, buf, strlen(buf));
  return true;
}

/* Emit the node at `off` within the tree segment as JSON text. */
static void emit_node(OsonCtx *c, size_t off, int depth)
{
  if (!c->ok || depth > OSON_MAX_DEPTH) {
    c->ok = false;
    return;
  }
  const uint8_t *tree = c->tree, *end = tree + c->tree_len;
  if (off >= c->tree_len) {
    c->ok = false;
    return;
  }
  uint8_t tag = tree[off];

  if (tag <= 0x1F) { /* inline short string */
    if (off + 1 + tag > c->tree_len) {
      c->ok = false;
      return;
    }
    emit_json_string(c, tree + off + 1, tag);
    return;
  }
  if (tag >= 0x20 && tag <= 0x2F) { /* number, length packed in tag */
    emit_number(c, tree + off + 1, (size_t)(tag - 0x1F), end);
    return;
  }
  switch (tag) {
  case 0x30:
    seer_writer_bytes(c->w, "null", 4);
    return;
  case 0x31:
    seer_writer_bytes(c->w, "true", 4);
    return;
  case 0x32:
    seer_writer_bytes(c->w, "false", 5);
    return;
  case 0x33: { /* string, ub1 length */
    if (off + 2 > c->tree_len) {
      c->ok = false;
      return;
    }
    uint8_t len = tree[off + 1];
    if (off + 2 + len > c->tree_len) {
      c->ok = false;
      return;
    }
    emit_json_string(c, tree + off + 2, len);
    return;
  }
  case 0x34: { /* number, ub1 length */
    if (off + 2 > c->tree_len) {
      c->ok = false;
      return;
    }
    uint8_t len = tree[off + 1];
    emit_number(c, tree + off + 2, len, end);
    return;
  }
  case 0x37: { /* string, ub2 length */
    uint32_t len = rd_uint(c, tree + off + 1, 2, end);
    if (!c->ok || off + 3 + len > c->tree_len) {
      c->ok = false;
      return;
    }
    emit_json_string(c, tree + off + 3, len);
    return;
  }
  case 0x38: { /* string, ub4 length */
    uint32_t len = rd_uint(c, tree + off + 1, 4, end);
    if (!c->ok || off + 5 + len > c->tree_len) {
      c->ok = false;
      return;
    }
    emit_json_string(c, tree + off + 5, len);
    return;
  }
  }

  if ((tag & 0xC0) == 0xC0 || (tag & 0xC0) == 0x80) { /* container */
    int csz = (tag & OSON_TAG_UB4_COUNT) ? 4 : (tag & OSON_TAG_WIDE_COUNT) ? 2 : 1;
    int osz = (tag & OSON_TAG_UB4_OFFSETS) ? 4 : c->off_size;
    /* Relative mode: a container's child offsets count from its own offset
     * (the donor pointer below stays absolute). */
    size_t rbase = c->rel ? off : 0;
    uint32_t count;
    size_t p;
    const uint8_t *ids = NULL;
    int idsz = csz;
    if ((tag & 0xC0) == 0x80 && (tag & OSON_TAG_SHARED_IDS) == OSON_TAG_SHARED_IDS) {
      uint32_t donor = rd_uint(c, tree + off + 1, osz, end);
      if (!c->ok || donor >= c->tree_len || (tree[donor] & 0xC0) != 0x80 ||
          (tree[donor] & OSON_TAG_SHARED_IDS) == OSON_TAG_SHARED_IDS) {
        c->ok = false;
        return;
      }
      uint8_t dtag = tree[donor];
      idsz = (dtag & OSON_TAG_UB4_COUNT) ? 4 : (dtag & OSON_TAG_WIDE_COUNT) ? 2 : 1;
      count = rd_uint(c, tree + donor + 1, idsz, end);
      ids = tree + donor + 1 + idsz;
      p = off + 1 + (size_t)osz; /* this node's value offsets follow the pointer */
    } else {
      count = rd_uint(c, tree + off + 1, csz, end);
      p = off + 1 + csz;
    }
    if (!c->ok)
      return;
    if ((tag & 0xC0) == 0xC0) { /* array */
      seer_writer_u8(c->w, '[');
      for (uint32_t i = 0; i < count && c->ok; i++) {
        if (i)
          seer_writer_u8(c->w, ',');
        uint32_t coff = rd_uint(c, tree + p + (size_t)osz * i, osz, end);
        emit_node(c, rbase + coff, depth + 1);
      }
      seer_writer_u8(c->w, ']');
    } else { /* object */
      size_t vbase = p;
      if (ids == NULL) { /* own id array, then the value offsets */
        ids = tree + p;
        vbase = p + (size_t)csz * count;
      }
      seer_writer_u8(c->w, '{');
      for (uint32_t i = 0; i < count && c->ok; i++) {
        if (i)
          seer_writer_u8(c->w, ',');
        uint32_t id = rd_uint(c, ids + (size_t)idsz * i, idsz, end);
        uint32_t voff = rd_uint(c, tree + vbase + (size_t)osz * i, osz, end);
        emit_field_key(c, id);
        seer_writer_u8(c->w, ':');
        emit_node(c, rbase + voff, depth + 1);
      }
      seer_writer_u8(c->w, '}');
    }
    return;
  }

  if (!emit_ext_scalar(c, tag, tree + off + 1, end))
    c->ok = false; /* unknown tag */
}

SeerStatus seer_decode_oson(const uint8_t *d, size_t n, char **out)
{
  *out = NULL;
  if (n < 8 || d[0] != 0xFF || d[1] != 0x4A || d[2] != 0x5A)
    return SEER_EPROTO;
  /* d[3] is the image version: 1, or 3 when names over 255 bytes sit in a
   * second segment (seerdb PROTOCOL.md §17.0b). Parsing a version-3 header as
   * version 1 lands 8 bytes out, so refuse anything else. */
  uint8_t version = d[3];
  if (version != 1 && version != 3)
    return SEER_EPROTO;
  uint16_t flags = (uint16_t)((uint16_t)d[4] << 8 | d[5]);
  size_t pos = 6;

  OsonCtx c = {0};
  c.off_size = (flags & OSON_FLAG_UB2_OFFSETS) ? 2 : 4;
  c.rel = (flags & OSON_FLAG_REL_OFFSETS) != 0;
  c.ok = true;
  SeerWriter w;
  if (!seer_writer_init(&w, 128))
    return SEER_ENOMEM;
  c.w = &w;

  if (!(flags & OSON_FLAG_TREE)) { /* bare scalar image */
    if (pos + 2 > n)
      goto bad;
    uint8_t size = d[pos + 1]; /* reserved(ub1), value_size(ub1) */
    c.tree = d + pos + 2;
    c.tree_len = (pos + 2 + size <= n) ? size : 0;
    emit_node(&c, 0, 0);
  } else { /* container image */
    size_t num_fnames;
    if (flags & OSON_FLAG_UB2_FNAMES) {
      if (pos + 2 > n)
        goto bad;
      num_fnames = (size_t)d[pos] << 8 | d[pos + 1];
      pos += 2;
    } else {
      if (pos + 1 > n)
        goto bad;
      num_fnames = d[pos];
      pos += 1;
    }
    if (pos + 4 > n)
      goto bad; /* fnames_size(2) + ub2 tree_size(2) */
    uint16_t fnames_size = (uint16_t)((uint16_t)d[pos] << 8 | d[pos + 1]);
    /* Version 3: secondary_flags(2) | num_long_fnames(4) | long_fnames_size(4)
     * sit between fnames_size and tree_size. */
    uint16_t sec_flags = 0;
    size_t nlong = 0, long_size = 0;
    if (version == 3) {
      if (pos + 2 + 10 + 4 > n)
        goto bad;
      sec_flags = (uint16_t)((uint16_t)d[pos + 2] << 8 | d[pos + 3]);
      nlong = (size_t)d[pos + 4] << 24 | (size_t)d[pos + 5] << 16 | (size_t)d[pos + 6] << 8 |
              d[pos + 7];
      long_size = (size_t)d[pos + 8] << 24 | (size_t)d[pos + 9] << 16 | (size_t)d[pos + 10] << 8 |
                  d[pos + 11];
      pos += 10; /* now at tree_size, as in version 1 (after fnames_size) */
    }
    size_t tree_size;
    if (flags & OSON_FLAG_UB4_TREE) {
      if (pos + 6 > n)
        goto bad; /* ub4 tree_size reads pos+2..pos+5 */
      tree_size = (size_t)d[pos + 2] << 24 | (size_t)d[pos + 3] << 16 | (size_t)d[pos + 4] << 8 |
                  d[pos + 5];
      pos += 8; /* fnames_size(2)+tree_size(4)+reserved(2) */
    } else {
      tree_size = (size_t)d[pos + 2] << 8 | d[pos + 3];
      pos += 6; /* fnames_size(2)+tree_size(2)+reserved(2) */
    }
    pos += num_fnames; /* hash array (1 byte / field) */
    c.foff = d + pos;  /* field-name offset table (ub2) */
    pos += 2 * num_fnames;
    if (pos + fnames_size > n)
      goto bad;
    c.fnames = d + pos;
    c.fnames_len = fnames_size;
    c.nfnames = num_fnames;
    pos += fnames_size;
    if (version == 3 && nlong > 0) {
      /* long hash array (ub2 each), long offsets (ub2 when sec_flags 0x0100,
       * else ub4), then the long names */
      c.lfoff_size = (sec_flags & 0x0100) ? 2 : 4;
      if (nlong > n || pos + 2 * nlong + (size_t)c.lfoff_size * nlong + long_size > n)
        goto bad;
      pos += 2 * nlong;
      c.lfoff = d + pos;
      pos += (size_t)c.lfoff_size * nlong;
      c.lfnames = d + pos;
      c.lfnames_len = long_size;
      c.nlfnames = nlong;
      pos += long_size;
    }
    if (pos + tree_size > n)
      goto bad;
    c.tree = d + pos;
    c.tree_len = tree_size;
    emit_node(&c, 0, 0);
  }

  if (!c.ok || !seer_writer_ok(&w))
    goto bad;
  char *s = malloc(w.len + 1);
  if (s == NULL) {
    seer_writer_free(&w);
    return SEER_ENOMEM;
  }
  memcpy(s, w.buf, w.len);
  s[w.len] = '\0';
  seer_writer_free(&w);
  *out = s;
  return SEER_OK;
bad:
  seer_writer_free(&w);
  return SEER_EPROTO;
}
