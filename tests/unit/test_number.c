/* Unit test for Oracle NUMBER/DATE decode (types.c), pinned to values verified
 * against the reference decoder.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "types.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void check_num(const uint8_t *b, size_t n, const char *expect)
{
    char out[192];
    assert(seer_decode_number(b, n, out, sizeof out) == SEER_OK);
    if (strcmp(out, expect) != 0) {
        fprintf(stderr, "NUMBER decode: got \"%s\", expected \"%s\"\n", out, expect);
        assert(0);
    }
}

int main(void)
{
    check_num((const uint8_t[]){ 0x80 }, 1, "0");
    check_num((const uint8_t[]){ 0xc1, 0x02 }, 2, "1");
    check_num((const uint8_t[]){ 0xc1, 0x03 }, 2, "2");
    check_num((const uint8_t[]){ 0xc1, 0x2a }, 2, "41");
    check_num((const uint8_t[]){ 0xc1, 0x0b }, 2, "10");
    check_num((const uint8_t[]){ 0xc1, 0x14, 0x64 }, 3, "19.99");
    check_num((const uint8_t[]){ 0xc2, 0x02, 0x01, 0x33 }, 4, "100.5");
    check_num((const uint8_t[]){ 0xc0, 0x02 }, 2, "0.01");
    check_num((const uint8_t[]){ 0x3e, 0x64, 0x66 }, 3, "-1");
    check_num((const uint8_t[]){ 0x3e, 0x63 }, 2, "-2");

    /* NUMBER encode vectors (reference client). */
    {
        struct { int64_t v; const uint8_t *b; size_t n; } enc[] = {
            { 0,     (const uint8_t[]){ 0x80 }, 1 },
            { 1,     (const uint8_t[]){ 0xC1, 0x02 }, 2 },
            { 41,    (const uint8_t[]){ 0xC1, 0x2A }, 2 },
            { 100,   (const uint8_t[]){ 0xC2, 0x02 }, 2 },
            { 12345, (const uint8_t[]){ 0xC3, 0x02, 0x18, 0x2E }, 4 },
            { -1,    (const uint8_t[]){ 0x3E, 0x64, 0x66 }, 3 },
            { -9900, (const uint8_t[]){ 0x3D, 0x02, 0x66 }, 3 },
        };
        for (size_t i = 0; i < sizeof enc / sizeof enc[0]; i++) {
            uint8_t out[24];
            size_t n = seer_encode_number_int(enc[i].v, out);
            assert(n == enc[i].n && memcmp(out, enc[i].b, n) == 0);
        }
    }

    /* Encode -> decode round-trip over a range of integers. */
    {
        int64_t vals[] = { 0, 1, -1, 7, -7, 255, 256, -256, 1000000,
                           -1000000, 9223372036854775807LL, -9223372036854775807LL };
        for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) {
            uint8_t enc[24];
            size_t n = seer_encode_number_int(vals[i], enc);
            char dec[64];
            char expect[32];
            assert(seer_decode_number(enc, n, dec, sizeof dec) == SEER_OK);
            snprintf(expect, sizeof expect, "%lld", (long long)vals[i]);
            if (strcmp(dec, expect) != 0) {
                fprintf(stderr, "roundtrip %s -> \"%s\"\n", expect, dec);
                assert(0);
            }
        }
    }

    /* DATE: 7-byte form. 2026-06-18 14:30:00 */
    {
        const uint8_t d[7] = { 120, 126, 6, 18, 15, 31, 1 };
        char out[40];
        assert(seer_decode_date(d, 7, out, sizeof out) == SEER_OK);
        assert(strcmp(out, "2026-06-18 14:30:00") == 0);
    }

    /* BINARY_FLOAT / BINARY_DOUBLE order-preserving decode (§11.7). */
    {
        char out[32];
        /* 1.5 -> IEEE 3fc00000 -> wire bfc00000 */
        assert(seer_decode_bfloat((const uint8_t[]){ 0xbf, 0xc0, 0x00, 0x00 }, 4,
                                  out, sizeof out) == SEER_OK);
        assert(strcmp(out, "1.5") == 0);
        /* -2.25 -> IEEE c0100000 -> wire 3fefffff */
        assert(seer_decode_bfloat((const uint8_t[]){ 0x3f, 0xef, 0xff, 0xff }, 4,
                                  out, sizeof out) == SEER_OK);
        assert(strcmp(out, "-2.25") == 0);
        /* double 1.5 -> IEEE 3ff8000000000000 -> wire bff8000000000000 */
        assert(seer_decode_bdouble((const uint8_t[]){ 0xbf, 0xf8, 0,0,0,0,0,0 }, 8,
                                   out, sizeof out) == SEER_OK);
        assert(strcmp(out, "1.5") == 0);
    }

    printf("test_number: all assertions passed\n");
    return 0;
}
