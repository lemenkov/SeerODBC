/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "writer.h"

#include <stdlib.h>
#include <string.h>

bool seer_writer_init(SeerWriter *w, size_t initial_cap)
{
    w->buf   = NULL;
    w->len   = 0;
    w->cap   = 0;
    w->error = false;
    if (initial_cap > 0) {
        w->buf = malloc(initial_cap);
        if (w->buf == NULL) {
            w->error = true;
            return false;
        }
        w->cap = initial_cap;
    }
    return true;
}

void seer_writer_free(SeerWriter *w)
{
    free(w->buf);
    w->buf   = NULL;
    w->len   = 0;
    w->cap   = 0;
    w->error = false;
}

/* Ensure room for `n` more bytes; latches error and returns false on OOM. */
static bool reserve(SeerWriter *w, size_t n)
{
    if (w->error)
        return false;
    if (n > w->cap - w->len) {
        size_t need = w->len + n;
        if (need < n) {            /* size_t overflow */
            w->error = true;
            return false;
        }
        size_t cap = w->cap ? w->cap : 64;
        while (cap < need) {
            size_t next = cap * 2;
            if (next < cap) {      /* doubling overflowed: clamp to need */
                cap = need;
                break;
            }
            cap = next;
        }
        uint8_t *nb = realloc(w->buf, cap);
        if (nb == NULL) {
            w->error = true;
            return false;
        }
        w->buf = nb;
        w->cap = cap;
    }
    return true;
}

void seer_writer_u8(SeerWriter *w, uint8_t v)
{
    if (!reserve(w, 1))
        return;
    w->buf[w->len++] = v;
}

void seer_writer_u16(SeerWriter *w, uint16_t v)
{
    if (!reserve(w, 2))
        return;
    w->buf[w->len++] = (uint8_t)(v >> 8);
    w->buf[w->len++] = (uint8_t)(v);
}

void seer_writer_u32(SeerWriter *w, uint32_t v)
{
    if (!reserve(w, 4))
        return;
    w->buf[w->len++] = (uint8_t)(v >> 24);
    w->buf[w->len++] = (uint8_t)(v >> 16);
    w->buf[w->len++] = (uint8_t)(v >>  8);
    w->buf[w->len++] = (uint8_t)(v);
}

void seer_writer_bytes(SeerWriter *w, const void *p, size_t n)
{
    if (n == 0)
        return;
    if (!reserve(w, n))
        return;
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}

void seer_writer_patch_u16(SeerWriter *w, size_t off, uint16_t v)
{
    if (w->error)
        return;
    if (off > w->len || w->len - off < 2) {
        w->error = true;
        return;
    }
    w->buf[off]     = (uint8_t)(v >> 8);
    w->buf[off + 1] = (uint8_t)(v);
}
