/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "reader.h"

/* Returns true if `n` bytes can be read; otherwise latches overflow. */
static bool ensure(SeerReader *r, size_t n)
{
    if (r->overflow)
        return false;
    if (r->pos > r->len || n > r->len - r->pos) {
        r->overflow = true;
        return false;
    }
    return true;
}

uint8_t seer_reader_u8(SeerReader *r)
{
    if (!ensure(r, 1))
        return 0;
    return r->buf[r->pos++];
}

uint16_t seer_reader_u16(SeerReader *r)
{
    if (!ensure(r, 2))
        return 0;
    uint16_t v = (uint16_t)(((uint16_t)r->buf[r->pos] << 8) | r->buf[r->pos + 1]);
    r->pos += 2;
    return v;
}

uint32_t seer_reader_u32(SeerReader *r)
{
    if (!ensure(r, 4))
        return 0;
    uint32_t v = ((uint32_t)r->buf[r->pos]     << 24) |
                 ((uint32_t)r->buf[r->pos + 1] << 16) |
                 ((uint32_t)r->buf[r->pos + 2] <<  8) |
                 ((uint32_t)r->buf[r->pos + 3]);
    r->pos += 4;
    return v;
}

const uint8_t *seer_reader_bytes(SeerReader *r, size_t n)
{
    if (!ensure(r, n))
        return NULL;
    const uint8_t *p = r->buf + r->pos;
    r->pos += n;
    return p;
}
