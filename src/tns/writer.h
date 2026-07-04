/* Growable, big-endian byte builder for outgoing TNS/TTC buffers.
 *
 * The send-side mirror of reader.h. It owns a heap buffer that grows as
 * needed; on allocation failure it latches `error` (just as the reader
 * latches `overflow`), every subsequent append becomes a no-op, and the
 * caller checks seer_writer_ok() once at the end instead of after every
 * field. seer_writer_patch_u16() backfills a length field whose value is
 * only known after the body has been written.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_WRITER_H
#define SEER_TNS_WRITER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *buf;
    size_t   len;    /* bytes written so far */
    size_t   cap;    /* allocated capacity */
    bool     error;  /* latched on allocation failure */
} SeerWriter;

/* Initialise with an initial capacity hint (0 is allowed). Returns false and
 * latches error if the initial allocation fails. */
bool seer_writer_init(SeerWriter *w, size_t initial_cap);

/* Release the buffer. Safe to call on a zeroed or already-freed writer. */
void seer_writer_free(SeerWriter *w);

/* True while no allocation has failed. */
static inline bool seer_writer_ok(const SeerWriter *w)
{
    return !w->error;
}

void seer_writer_u8(SeerWriter *w, uint8_t v);
void seer_writer_u16(SeerWriter *w, uint16_t v);  /* big-endian */
void seer_writer_u32(SeerWriter *w, uint32_t v);  /* big-endian */
void seer_writer_bytes(SeerWriter *w, const void *p, size_t n);

/* Overwrite two bytes already written at `off` with a big-endian u16. Used to
 * backfill packet/segment lengths. No-op (and latches error) if the range is
 * out of bounds. */
void seer_writer_patch_u16(SeerWriter *w, size_t off, uint16_t v);

#endif /* SEER_TNS_WRITER_H */
