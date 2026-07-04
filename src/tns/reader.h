/* Bounds-checked, big-endian byte cursor over a received TNS/TTC buffer.
 *
 * THE safety chokepoint. Every read of untrusted server bytes goes through
 * here; nothing else in src/tns/ is permitted to index a raw packet buffer.
 * This is the discipline that recovers, in C, most of what a memory-safe
 * language would have enforced for the parser.
 *
 * On any out-of-bounds read the cursor latches `overflow` to true, every
 * subsequent read returns 0 / NULL, and the position stops advancing. So a
 * decoder can read a whole structure optimistically and check
 * seer_reader_ok() once at the end, rather than after every field.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_READER_H
#define SEER_TNS_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
    bool           overflow;
    /* Width of the per-chunk length in a 0xFE-chunked DALC value: sb4 on 12c+,
     * a bare ub1 on 11g (set by the response parser from the field version).
     * Defaults to ub1; only matters for values >= 254 bytes. */
    bool           sb4_chunks;
} SeerReader;

static inline void seer_reader_init(SeerReader *r, const void *buf, size_t len)
{
    r->buf        = (const uint8_t *)buf;
    r->len        = len;
    r->pos        = 0;
    r->overflow   = false;
    r->sb4_chunks = false;
}

/* True while no over-read has occurred. */
static inline bool seer_reader_ok(const SeerReader *r)
{
    return !r->overflow;
}

/* Bytes left to read (0 once overflowed or exhausted). */
static inline size_t seer_reader_remaining(const SeerReader *r)
{
    return (!r->overflow && r->pos <= r->len) ? (r->len - r->pos) : 0;
}

uint8_t  seer_reader_u8(SeerReader *r);
uint16_t seer_reader_u16(SeerReader *r);  /* big-endian (network order) */
uint32_t seer_reader_u32(SeerReader *r);  /* big-endian (network order) */

/* Borrow `n` bytes at the cursor and advance. Returns a pointer into the
 * underlying buffer (not a copy), or NULL if fewer than `n` bytes remain. */
const uint8_t *seer_reader_bytes(SeerReader *r, size_t n);

#endif /* SEER_TNS_READER_H */
