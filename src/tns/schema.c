/* Wire schemas (#395 spike); see schema.h.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "schema.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "marshal.h"

void seer_bytes_free(SeerBytes *b)
{
  if (b->owned)
    free((void *)b->p);
  b->p = NULL;
  b->n = 0;
  b->owned = 0;
}

static int64_t *num(void *msg, uint16_t off)
{
  return (int64_t *)((char *)msg + off);
}

static const int64_t *cnum(const void *msg, uint16_t off)
{
  return (const int64_t *)((const char *)msg + off);
}

/* Whether `f` is on the wire for this codec, version and message. */
static bool present(const SeerField *f, const SeerSchemaCtx *cx, const void *msg)
{
  /* A thin context must say its field version: 0 would read as 9i's (2) and
   * below, and pick the pre-10g fields - a context built by hand without it
   * did, twice. */
  assert(cx->codec != SEER_CODEC_THIN || cx->fv != 0);
  if (f->codecs != 0 && (f->codecs & cx->codec) == 0)
    return false;
  if (cx->codec == SEER_CODEC_THIN) { /* 8i has no field version */
    if (f->fv_min != 0 && cx->fv < f->fv_min)
      return false;
    if (f->fv_max != 0 && cx->fv >= f->fv_max)
      return false;
    if (f->sfv_min != 0 && cx->server_fv < f->sfv_min)
      return false;
  }
  if ((f->flags & SG_IF_SET) && *cnum(msg, f->if_off) == 0)
    return false;
  if ((f->flags & SG_IF_CLEAR) && *cnum(msg, f->if_off) != 0)
    return false;
  return true;
}

/* ---- encode ------------------------------------------------------------ */

static void put_le(SeerWriter *w, uint64_t v, int width)
{
  for (int i = 0; i < width; i++)
    seer_writer_u8(w, (uint8_t)(v >> (8 * i)));
}

static void put_num(SeerWriter *w, const SeerSchemaCtx *cx, uint8_t kind, int64_t v)
{
  if (cx->codec == SEER_CODEC_THIN) {
    seer_enc_sb4(w, (uint32_t)v);
    return;
  }
  put_le(w, (uint64_t)v, kind == SF_N1 ? 1 : kind == SF_N2 ? 2 : 4);
}

static void put_value(SeerWriter *w, const SeerSchemaCtx *cx, const SeerBytes *b)
{
  if (b->n == 0) {
    seer_writer_u8(w, 0);
    return;
  }
  if (b->n <= 252) {
    seer_writer_u8(w, (uint8_t)b->n);
    seer_writer_bytes(w, b->p, b->n);
    return;
  }
  seer_writer_u8(w, 0xFE);
  for (size_t i = 0; i < b->n; i += 252) {
    size_t c = b->n - i < 252 ? b->n - i : 252;
    if (cx->codec == SEER_CODEC_THIN && cx->wide_chunks)
      seer_enc_sb4(w, (uint32_t)c);
    else
      seer_writer_u8(w, (uint8_t)c);
    seer_writer_bytes(w, b->p + i, c);
  }
  seer_writer_u8(w, 0);
}

void seer_schema_encode(const SeerField *schema, const SeerSchemaCtx *cx, const void *msg,
                        SeerWriter *w)
{
  for (const SeerField *f = schema; f->kind != SF_END; f++) {
    if (!present(f, cx, msg))
      continue;
    switch (f->kind) {
    case SF_U8:
      seer_writer_u8(w, (uint8_t)*cnum(msg, f->off));
      break;
    case SF_N1:
    case SF_N2:
    case SF_N4:
      put_num(w, cx, f->kind, *cnum(msg, f->off));
      break;
    case SF_BE2:
      seer_writer_u16(w, (uint16_t)*cnum(msg, f->off));
      break;
    case SF_PAD:
      for (uint16_t i = 0; i < f->arg; i++)
        seer_writer_u8(w, 0);
      break;
    case SF_VALUE:
      put_value(w, cx, (const SeerBytes *)((const char *)msg + f->off));
      break;
    case SF_U8L:
      if (cx->codec == SEER_CODEC_THIN)
        seer_writer_u8(w, 1);
      seer_writer_u8(w, (uint8_t)*cnum(msg, f->off));
      break;
    case SF_INTS: {
      const int *v = *(const int *const *)((const char *)msg + f->off);
      int64_t n = *cnum(msg, f->arg);
      put_num(w, cx, SF_N4, n);
      for (int64_t i = 0; i < n; i++)
        put_num(w, cx, SF_N4, v[i]);
      break;
    }
    case SF_RAW: {
      const SeerBytes *b = (const SeerBytes *)((const char *)msg + f->off);
      seer_writer_bytes(w, b->p,
                        (size_t)*cnum(msg, f->arg) < b->n ? (size_t)*cnum(msg, f->arg) : b->n);
      break;
    }
    case SF_COUNTED: {
      const SeerBytes *b = (const SeerBytes *)((const char *)msg + f->off);
      put_num(w, cx, f->arg ? (uint8_t)f->arg : SF_N4, (int64_t)b->n);
      if (b->n > 0)
        put_value(w, cx, b);
      break;
    }
    default:
      break;
    }
  }
}

/* ---- decode ------------------------------------------------------------ */

static int64_t get_le(SeerReader *r, int width)
{
  const uint8_t *p = seer_reader_bytes(r, (size_t)width);
  if (p == NULL)
    return 0;
  uint64_t v = 0;
  for (int i = width - 1; i >= 0; i--)
    v = v << 8 | p[i];
  return (int64_t)v;
}

static int64_t get_num(SeerReader *r, const SeerSchemaCtx *cx, uint8_t kind)
{
  if (cx->codec == SEER_CODEC_THIN)
    return seer_dec_sb4(r);
  return get_le(r, kind == SF_N1 ? 1 : kind == SF_N2 ? 2 : 4);
}

/* A value: a ub1 length (0 and 0xFF are empty / NULL) and the bytes, pointed
 * into; or 0xFE then chunks to a zero length - each a ub1, or on thin from
 * 12.1 an sb4 - assembled into an owned buffer. */
static bool get_value(SeerReader *r, const SeerSchemaCtx *cx, SeerBytes *b, bool *bad)
{
  b->p = NULL;
  b->n = 0;
  b->owned = 0;
  uint8_t lb = seer_reader_u8(r);
  if (!seer_reader_ok(r))
    return false;
  if (lb == 0xFF && cx->codec == SEER_CODEC_O8I) {
    r->pos--; /* 8i: a NULL cell is its trailer alone, whose indicator starts ff */
    return true;
  }
  if (lb == 0 || lb == 0xFF)
    return true;
  if (lb != 0xFE) {
    b->p = seer_reader_bytes(r, lb);
    b->n = b->p != NULL ? lb : 0;
    return b->p != NULL;
  }
  SeerWriter acc;
  if (!seer_writer_init(&acc, 256))
    return false;
  bool wide = cx->codec == SEER_CODEC_THIN && cx->wide_chunks;
  for (;;) {
    int64_t cl = wide ? seer_dec_sb4(r) : seer_reader_u8(r);
    if (cl < 0) { /* a negative chunk length: no value */
      seer_writer_free(&acc);
      *bad = true;
      return false;
    }
    if (!seer_reader_ok(r) || cl == 0)
      break;
    const uint8_t *p = seer_reader_bytes(r, (size_t)cl);
    if (p == NULL)
      break;
    seer_writer_bytes(&acc, p, (size_t)cl);
  }
  if (!seer_reader_ok(r) || !seer_writer_ok(&acc)) {
    seer_writer_free(&acc);
    return false;
  }
  b->p = acc.buf;
  b->n = acc.len;
  b->owned = 1;
  return true;
}

SeerSchemaResult seer_schema_decode_ex(const SeerField *schema, const SeerSchemaCtx *cx,
                                       SeerReader *r, void *msg)
{
  bool bad = false;
  for (const SeerField *f = schema; f->kind != SF_END && seer_reader_ok(r) && !bad; f++) {
    if (!present(f, cx, msg))
      continue;
    if ((f->flags & SG_IF_MORE) && cx->codec == SEER_CODEC_THIN && seer_reader_remaining(r) == 0)
      continue; /* thin only: an 8i reply may simply not have it yet */
    switch (f->kind) {
    case SF_U8: {
      uint8_t v = seer_reader_u8(r);
      *num(msg, f->off) = (f->flags & SG_FF_NULL) && v == 0xFF ? 0 : v;
      break;
    }
    case SF_N1:
    case SF_N2:
    case SF_N4:
      *num(msg, f->off) = get_num(r, cx, f->kind);
      break;
    case SF_BE2:
      *num(msg, f->off) = seer_reader_u16(r);
      break;
    case SF_PAD:
      (void)seer_reader_bytes(r, f->arg);
      break;
    case SF_VALUE:
      get_value(r, cx, (SeerBytes *)((char *)msg + f->off), &bad);
      break;
    case SF_U8L:
      *num(msg, f->off) = cx->codec == SEER_CODEC_THIN ? seer_dec_sb4(r) : seer_reader_u8(r);
      break;
    case SF_INTS: /* encode only: nothing the client reads has one */
      bad = true;
      break;
    case SF_RAW: {
      SeerBytes *b = (SeerBytes *)((char *)msg + f->off);
      size_t n = (size_t)*num(msg, f->arg);
      b->p = seer_reader_bytes(r, n);
      b->n = b->p != NULL ? n : 0;
      b->owned = 0;
      break;
    }
    case SF_COUNTED: {
      SeerBytes *b = (SeerBytes *)((char *)msg + f->off);
      b->p = NULL, b->n = 0, b->owned = 0;
      if (get_num(r, cx, f->arg ? (uint8_t)f->arg : SF_N4) > 0)
        get_value(r, cx, b, &bad);
      break;
    }
    default:
      break;
    }
  }
  if (bad)
    return SCH_BAD;
  return seer_reader_ok(r) ? SCH_OK : SCH_SHORT;
}

bool seer_schema_decode(const SeerField *schema, const SeerSchemaCtx *cx, SeerReader *r, void *msg)
{
  return seer_schema_decode_ex(schema, cx, r, msg) == SCH_OK;
}

void seer_schema_free(const SeerField *schema, void *msg)
{
  for (const SeerField *f = schema; f->kind != SF_END; f++)
    if (f->kind == SF_VALUE || f->kind == SF_RAW || f->kind == SF_COUNTED)
      seer_bytes_free((SeerBytes *)((char *)msg + f->off));
}
