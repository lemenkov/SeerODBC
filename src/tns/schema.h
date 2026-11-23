/* Wire schemas (#395 spike): what a TTC message carries, written once, and a
 * codec per serialisation that says how each primitive is packed - after
 * seerdb's wire_schema.py (seerdb#2064). SeerODBC speaks two codecs: thin
 * (TTC variable-width integers; 10g+ and 9i's O7 calls) and 8i (fixed-width
 * little-endian).
 *
 * A schema is an array of SeerField ending in SF_END. Each field names a
 * member of the message's struct by offset; numbers are int64_t members,
 * byte strings SeerBytes members. A field may be guarded: by codec, by a
 * field-version range (the negotiated version, or the server's), and by
 * another numeric member being non-zero.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_SCHEMA_H
#define SEER_TNS_SCHEMA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "reader.h"
#include "writer.h"

typedef enum { SEER_CODEC_THIN = 1, SEER_CODEC_O8I = 2 } SeerCodecId;

typedef enum {
  SF_END,
  SF_U8,      /* one byte, every codec */
  SF_N1,      /* a small integer: thin variable-width, 8i one byte */
  SF_N2,      /* thin variable-width, 8i a ub2 little-endian */
  SF_N4,      /* thin variable-width, 8i a ub4 little-endian */
  SF_BE2,     /* a big-endian ub2 whatever the codec */
  SF_PAD,     /* `arg` bytes nobody reads: zeros written, skipped read */
  SF_VALUE,   /* bytes with their length: thin ub1 / 0xFE chunks, 8i the same at ub1 */
  SF_RAW,     /* bytes as they are, as many as the member at `arg` (an int64_t) says */
  SF_COUNTED, /* a count, then (when > 0) a SF_VALUE: thin's bytes-with-length */
  SF_U8L,     /* a byte, written by thin with its length byte even when 0 (`01 00`,
               * as ojdbc14 writes it), one byte on 8i */
  SF_INTS,    /* an N4 count, then that many N4s: the member is a `const int *`,
               * `arg` the offsetof its int64_t count; encode only */
  SF_N4S,     /* N4s, as many as the int64_t member at `arg` says, from a
               * `const uint32_t *` member, no count written; encode only */
  SF_CONST,   /* `arg` literal bytes at `lit`, the same in every message: captured
               * ground truth whose fields aren't known; checked when read */
  SF_SQL,     /* a SeerBytes of SQL text as each dialect frames it: thin raw
               * below 12.1, from 12.1 a ub1 length or, past 252 bytes, 254,
               * an sb4 length, the bytes and an sb4 0; 8i ub1-length chunks
               * of 64 (0xFE first, a 0 last) past 64 bytes; encode only */
  SF_EACH,    /* the sub-schema `sub` as many times as the int64_t member at
               * `arg` says, each item read into a scratch message of `subsize`
               * bytes and dropped: what the client passes over; decode only */
  SF_CHR,     /* a SeerBytes as a bind value is written (oracledb
               * encode_chr, 8i's o8w_chr): a ub1 length and the bytes up to
               * 64 bytes - 252 on thin from 12.1 - else 0xFE, chunks of 64,
               * a 0; each chunk's length a ub1, on thin from 12.1 an sb4.
               * Read as SF_VALUE */
  SF_LE2,     /* a little-endian ub2 on every path: TTI_DTY's charsets */
  SF_LOB      /* a SeerBytes of LOB content as a LOB write sends it: a ub1
               * length and the bytes up to 252 bytes, else 0xFE, chunks to a
               * 0 - on thin from 10.2 of up to 0x7FFF bytes each with an sb4
               * length (PROTOCOL.md §14.2), before of 252 with a ub1. Read as
               * SF_VALUE */
} SeerFieldKind;

/* Guards: which codecs carry the field (0 = all); the field-version range it
 * has [fv_min, fv_max) (0 = unbounded) on the negotiated version, and with
 * sfv_min a minimum on the server's own - both on thin only, 8i having no
 * field version; with SG_IF_SET the member at `if_off` must be non-zero, and
 * with SG_IF_MORE bytes must remain (on thin; on 8i the field is read, and a
 * reply that hasn't brought it yet is short). */
#define SG_IF_SET 0x02
#define SG_IF_MORE 0x04
#define SG_IF_CLEAR 0x08 /* the member at `if_off` must be zero */
#define SG_FF_NULL 0x10  /* SF_U8: 0xFF reads as 0, a NULL marker */

typedef struct SeerField {
  uint8_t kind;
  uint8_t codecs;
  uint8_t fv_min, fv_max;
  uint8_t sfv_min;
  uint8_t flags;
  uint16_t off;                /* the member, offsetof the message struct */
  uint16_t arg;                /* SF_PAD: bytes; SF_RAW: offsetof its length member;
                                * SF_COUNTED: the count's kind (SF_N2 / SF_N4, 0 = N4) */
  uint16_t if_off;             /* SG_IF_SET: offsetof the member that must be non-zero */
  const struct SeerField *sub; /* SF_EACH: the item's schema */
  const void *lit;             /* SF_CONST: the bytes */
  uint16_t subsize;            /* SF_EACH: the item's message size */
} SeerField;

/* A byte string a decode points into the message for (owned = 0), or one it
 * had to assemble from chunks (owned = 1, free with seer_bytes_free). */
typedef struct {
  const uint8_t *p;
  size_t n;
  int owned;
} SeerBytes;

void seer_bytes_free(SeerBytes *b);

typedef struct {
  SeerCodecId codec;
  uint8_t fv;        /* the negotiated field version */
  uint8_t server_fv; /* the server's own */
  bool wide_chunks;  /* thin: chunk lengths are sb4 (12.1+), not ub1 */
} SeerSchemaCtx;

/* Write `msg` by `schema`. */
void seer_schema_encode(const SeerField *schema, const SeerSchemaCtx *cx, const void *msg,
                        SeerWriter *w);

/* How a decode ended: whole, short (the bytes ran out - a reply still
 * arriving), or bad (bytes no message has). */
typedef enum { SCH_OK, SCH_SHORT, SCH_BAD } SeerSchemaResult;

SeerSchemaResult seer_schema_decode_ex(const SeerField *schema, const SeerSchemaCtx *cx,
                                       SeerReader *r, void *msg);

/* Read `msg` by `schema`; false when it didn't decode whole. */
bool seer_schema_decode(const SeerField *schema, const SeerSchemaCtx *cx, SeerReader *r, void *msg);

/* Free the owned SeerBytes members a decode left in `msg`. */
void seer_schema_free(const SeerField *schema, void *msg);

/* Field constructors. */
#define SEER_F(kind_, type_, member_) {.kind = (kind_), .off = offsetof(type_, member_)}
#define SEER_FC(kind_, codecs_, type_, member_)                                                    \
  {.kind = (kind_), .codecs = (codecs_), .off = offsetof(type_, member_)}
#define SEER_FV(kind_, codecs_, min_, max_, type_, member_)                                        \
  {.kind = (kind_),                                                                                \
   .codecs = (codecs_),                                                                            \
   .fv_min = (min_),                                                                               \
   .fv_max = (max_),                                                                               \
   .off = offsetof(type_, member_)}
#define SEER_PAD(n_) {.kind = SF_PAD, .arg = (n_)}
#define SEER_END {.kind = SF_END}

#endif /* SEER_TNS_SCHEMA_H */
