/* Unit test for the growable byte writer - the send-side mirror of the reader.
 * Round-trips through the reader to confirm big-endian framing and checks the
 * length-backfill (patch) and OOM-latch behaviour.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "reader.h"
#include "writer.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    SeerWriter w;
    assert(seer_writer_init(&w, 0));   /* zero initial capacity is allowed */

    seer_writer_u8(&w, 0x01);
    seer_writer_u16(&w, 0x0203);
    seer_writer_u32(&w, 0x04050607);
    const uint8_t blob[] = { 0xAA, 0xBB, 0xCC };
    seer_writer_bytes(&w, blob, sizeof blob);
    assert(seer_writer_ok(&w));
    assert(w.len == 1 + 2 + 4 + 3);

    /* Read it back: the bytes must round-trip big-endian. */
    SeerReader r;
    seer_reader_init(&r, w.buf, w.len);
    assert(seer_reader_u8(&r) == 0x01);
    assert(seer_reader_u16(&r) == 0x0203);
    assert(seer_reader_u32(&r) == 0x04050607);
    const uint8_t *p = seer_reader_bytes(&r, 3);
    assert(p != NULL && p[0] == 0xAA && p[1] == 0xBB && p[2] == 0xCC);
    assert(seer_reader_remaining(&r) == 0 && seer_reader_ok(&r));

    /* patch_u16 backfills a length field once the body size is known. */
    seer_writer_patch_u16(&w, 1, 0xBEEF);
    assert(seer_writer_ok(&w));
    assert(w.buf[1] == 0xBE && w.buf[2] == 0xEF);

    /* An out-of-range patch latches error rather than scribbling memory. */
    seer_writer_patch_u16(&w, w.len, 0x0000);
    assert(!seer_writer_ok(&w));

    seer_writer_free(&w);

    /* Growth across the initial capacity must preserve earlier bytes. */
    SeerWriter g;
    assert(seer_writer_init(&g, 4));
    for (int i = 0; i < 1000; i++)
        seer_writer_u8(&g, (uint8_t)i);
    assert(seer_writer_ok(&g) && g.len == 1000);
    assert(g.buf[0] == 0 && g.buf[255] == 255 && g.buf[999] == (uint8_t)999);
    seer_writer_free(&g);

    printf("test_writer: all assertions passed\n");
    return 0;
}
