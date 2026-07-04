/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "marshal.h"

#include <stdlib.h>
#include <string.h>

void seer_enc_sb4(SeerWriter *w, uint32_t v)
{
    if (v == 0) {
        seer_writer_u8(w, 0);
        return;
    }
    int n;                       /* number of significant big-endian bytes */
    if      (v & 0xFF000000u) n = 4;
    else if (v & 0x00FF0000u) n = 3;
    else if (v & 0x0000FF00u) n = 2;
    else                      n = 1;

    seer_writer_u8(w, (uint8_t)n);
    for (int i = n - 1; i >= 0; i--)
        seer_writer_u8(w, (uint8_t)(v >> (8 * i)));
}

int64_t seer_dec_sb4(SeerReader *r)
{
    uint8_t lb = seer_reader_u8(r);
    bool    neg   = (lb & 0x80) != 0;
    uint8_t width = lb & 0x7f;

    /* A width of 5..0x7f is not a real 1..4-byte integer: it is a raw ub2 /
     * counter that some token decoders (notably the OER) read through this
     * function. Mirror the reference decoder - consume exactly one more byte
     * and return its negation (the value is discarded by those callers) -
     * rather than reading `width` bytes and running off the buffer. */
    if (width > 4)
        return -(int64_t)seer_reader_u8(r);

    uint64_t mag = 0;
    for (uint8_t i = 0; i < width; i++)
        mag = (mag << 8) | seer_reader_u8(r);

    return neg ? -(int64_t)mag : (int64_t)mag;
}

/* Encode one field (key or value): empty -> 0x00, else <sb4 len><ub1 len><data>. */
static void enc_field(SeerWriter *w, const void *d, size_t n)
{
    if (n == 0) {
        seer_writer_u8(w, 0);
        return;
    }
    seer_enc_sb4(w, (uint32_t)n);
    seer_writer_u8(w, (uint8_t)n);   /* ub1 length echo (callers keep n < 256) */
    seer_writer_bytes(w, d, n);
}

void seer_enc_kv(SeerWriter *w, const void *key, size_t klen,
                 const void *val, size_t vlen, uint32_t padding)
{
    enc_field(w, key, klen);
    enc_field(w, val, vlen);
    seer_enc_sb4(w, padding);
}

SeerStatus seer_dec_field(SeerReader *r, uint8_t **out, size_t *outlen)
{
    *out    = NULL;
    *outlen = 0;

    uint8_t lb = seer_reader_u8(r);
    if (!seer_reader_ok(r))
        return SEER_EPROTO;
    if (lb == 0)
        return SEER_OK;                 /* empty field */

    /* lb is the sb4 length byte; magnitude width in the low 7 bits. */
    uint8_t  width = lb & 0x7f;
    uint64_t size  = 0;
    for (uint8_t i = 0; i < width; i++)
        size = (size << 8) | seer_reader_u8(r);

    uint8_t echo = seer_reader_u8(r);
    if (!seer_reader_ok(r))
        return SEER_EPROTO;

    if (echo == 254) {
        /* Chunked: repeated <ub1 len><bytes> until a zero-length chunk. */
        SeerWriter acc;
        if (!seer_writer_init(&acc, 64))
            return SEER_ENOMEM;
        for (;;) {
            uint8_t clen = seer_reader_u8(r);
            if (!seer_reader_ok(r)) {
                seer_writer_free(&acc);
                return SEER_EPROTO;
            }
            if (clen == 0)
                break;
            const uint8_t *cp = seer_reader_bytes(r, clen);
            if (cp == NULL) {
                seer_writer_free(&acc);
                return SEER_EPROTO;
            }
            seer_writer_bytes(&acc, cp, clen);
        }
        if (!seer_writer_ok(&acc)) {
            seer_writer_free(&acc);
            return SEER_ENOMEM;
        }
        *out    = acc.buf;              /* hand ownership of the buffer */
        *outlen = acc.len;
        return SEER_OK;
    }

    if (size > 0xFF || echo != (uint8_t)size)
        return SEER_EPROTO;             /* length echo mismatch */

    const uint8_t *p = seer_reader_bytes(r, (size_t)size);
    if (p == NULL)
        return SEER_EPROTO;
    uint8_t *copy = malloc((size_t)size);
    if (copy == NULL)
        return SEER_ENOMEM;
    memcpy(copy, p, (size_t)size);
    *out    = copy;
    *outlen = (size_t)size;
    return SEER_OK;
}

SeerStatus seer_dec_dalc(SeerReader *r, uint8_t **out, size_t *outlen)
{
    *out    = NULL;
    *outlen = 0;

    uint8_t lb = seer_reader_u8(r);
    if (!seer_reader_ok(r))
        return SEER_EPROTO;
    if (lb == 0 || lb == 0xFF)
        return SEER_OK;                 /* empty / null */

    if (lb == 0xFE) {
        /* Chunked: repeated <len><bytes> until a zero-length chunk. The chunk
         * length is an sb4 on 12c+ and a bare ub1 on 11g (r->sb4_chunks) - the
         * same split as the LOB read and bind-value encode paths. (A ub1 read of
         * an sb4 length desyncs the value, SEER_EPROTO on large fetches.) */
        SeerWriter acc;
        if (!seer_writer_init(&acc, 64))
            return SEER_ENOMEM;
        for (;;) {
            int64_t clen = r->sb4_chunks ? seer_dec_sb4(r)
                                         : (int64_t)seer_reader_u8(r);
            if (!seer_reader_ok(r) || clen < 0) {
                seer_writer_free(&acc);
                return SEER_EPROTO;
            }
            if (clen == 0)
                break;
            const uint8_t *cp = seer_reader_bytes(r, (size_t)clen);
            if (cp == NULL) {
                seer_writer_free(&acc);
                return SEER_EPROTO;
            }
            seer_writer_bytes(&acc, cp, (size_t)clen);
        }
        if (!seer_writer_ok(&acc)) {
            seer_writer_free(&acc);
            return SEER_ENOMEM;
        }
        *out    = acc.buf;
        *outlen = acc.len;
        return SEER_OK;
    }

    const uint8_t *p = seer_reader_bytes(r, lb);
    if (p == NULL)
        return SEER_EPROTO;
    uint8_t *copy = malloc(lb);
    if (copy == NULL)
        return SEER_ENOMEM;
    memcpy(copy, p, lb);
    *out    = copy;
    *outlen = lb;
    return SEER_OK;
}

void seer_skip_chunked(SeerReader *r)
{
    uint8_t lb = seer_reader_u8(r);
    if (!seer_reader_ok(r))
        return;
    if (lb == 0xFE) {
        for (;;) {
            int64_t clen = seer_dec_sb4(r);
            if (!seer_reader_ok(r) || clen <= 0)
                break;
            seer_reader_bytes(r, (size_t)clen);
        }
    } else if (lb == 0xFF) {
        /* null: nothing follows */
    } else {
        seer_reader_bytes(r, lb);
    }
}

void seer_skip_bytes_with_length(SeerReader *r)
{
    int64_t n = seer_dec_sb4(r);
    if (n > 0)
        seer_skip_chunked(r);
}

SeerStatus seer_read_str(SeerReader *r, char **out)
{
    *out = NULL;
    int64_t n = seer_dec_sb4(r);
    if (!seer_reader_ok(r))
        return SEER_EPROTO;
    if (n <= 0) {
        char *empty = malloc(1);
        if (empty == NULL)
            return SEER_ENOMEM;
        empty[0] = '\0';
        *out = empty;
        return SEER_OK;
    }

    uint8_t *bytes = NULL;
    size_t   blen  = 0;
    SeerStatus st = seer_dec_dalc(r, &bytes, &blen);
    if (st != SEER_OK)
        return st;

    char *s = malloc(blen + 1);
    if (s == NULL) {
        free(bytes);
        return SEER_ENOMEM;
    }
    if (blen > 0)
        memcpy(s, bytes, blen);
    s[blen] = '\0';
    free(bytes);
    *out = s;
    return SEER_OK;
}
