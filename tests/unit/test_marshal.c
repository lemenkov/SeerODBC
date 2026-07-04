/* Unit test for the TTC wire-encoding primitives (marshal.c). Byte vectors are
 * taken from the reference client's test suite.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "marshal.h"
#include "reader.h"
#include "writer.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check_sb4(uint32_t v, const uint8_t *expect, size_t n)
{
    SeerWriter w;
    assert(seer_writer_init(&w, 8));
    seer_enc_sb4(&w, v);
    assert(seer_writer_ok(&w));
    assert(w.len == n);
    assert(memcmp(w.buf, expect, n) == 0);

    /* Round-trip back through the decoder. */
    SeerReader r;
    seer_reader_init(&r, w.buf, w.len);
    assert(seer_dec_sb4(&r) == (int64_t)v);
    assert(seer_reader_ok(&r));
    seer_writer_free(&w);
}

int main(void)
{
    /* §12.1 encode vectors. */
    check_sb4(0,          (const uint8_t[]){ 0x00 }, 1);
    check_sb4(0xAB,       (const uint8_t[]){ 0x01, 0xAB }, 2);
    check_sb4(0xABCD,     (const uint8_t[]){ 0x02, 0xAB, 0xCD }, 3);
    check_sb4(0xABCDEF,   (const uint8_t[]){ 0x03, 0xAB, 0xCD, 0xEF }, 4);
    check_sb4(0xABCDEF87, (const uint8_t[]){ 0x04, 0xAB, 0xCD, 0xEF, 0x87 }, 5);

    /* §12.1 decode of sign-magnitude negatives. */
    {
        SeerReader r;
        seer_reader_init(&r, (const uint8_t[]){ 0x81, 0x01 }, 2);
        assert(seer_dec_sb4(&r) == -1);
        seer_reader_init(&r, (const uint8_t[]){ 0x81, 0x7F }, 2);
        assert(seer_dec_sb4(&r) == -127);
        seer_reader_init(&r, (const uint8_t[]){ 0x82, 0x01, 0x00 }, 3);
        assert(seer_dec_sb4(&r) == -256);
    }

    /* §12.3 key/value pair: encode_kv("AUTH_MACHINE", "ExampleHost"). */
    {
        SeerWriter w;
        assert(seer_writer_init(&w, 64));
        seer_enc_kv(&w, "AUTH_MACHINE", 12, "ExampleHost", 11, 0);
        const uint8_t expect[] = {
            0x01, 0x0C, 0x0C, 'A','U','T','H','_','M','A','C','H','I','N','E',
            0x01, 0x0B, 0x0B, 'E','x','a','m','p','l','e','H','o','s','t',
            0x00,
        };
        assert(seer_writer_ok(&w));
        assert(w.len == sizeof expect);
        assert(memcmp(w.buf, expect, sizeof expect) == 0);
        seer_writer_free(&w);
    }

    /* dec_field round-trips the inline form, and an empty field. */
    {
        const uint8_t field[] = { 0x01, 0x03, 0x03, 'h','i','!' };
        SeerReader r;
        seer_reader_init(&r, field, sizeof field);
        uint8_t *out = NULL;
        size_t outlen = 0;
        assert(seer_dec_field(&r, &out, &outlen) == SEER_OK);
        assert(outlen == 3 && memcmp(out, "hi!", 3) == 0);
        free(out);

        const uint8_t empty[] = { 0x00 };
        seer_reader_init(&r, empty, sizeof empty);
        assert(seer_dec_field(&r, &out, &outlen) == SEER_OK);
        assert(out == NULL && outlen == 0);
    }

    /* dec_field handles the chunked (0xFE) form: sb4 len, 0xFE, [len][data]..0. */
    {
        const uint8_t chunked[] = {
            0x01, 0x05,             /* sb4 length (ignored for chunked) */
            0xFE,                   /* chunk marker */
            0x03, 'a','b','c',      /* chunk 1 */
            0x02, 'd','e',          /* chunk 2 */
            0x00,                   /* terminator */
        };
        SeerReader r;
        seer_reader_init(&r, chunked, sizeof chunked);
        uint8_t *out = NULL;
        size_t outlen = 0;
        assert(seer_dec_field(&r, &out, &outlen) == SEER_OK);
        assert(outlen == 5 && memcmp(out, "abcde", 5) == 0);
        free(out);
    }

    printf("test_marshal: all assertions passed\n");
    return 0;
}
