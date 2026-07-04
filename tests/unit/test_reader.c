/* Unit test for the bounds-checked byte reader - the safety chokepoint.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#include "reader.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    SeerReader r;
    seer_reader_init(&r, data, sizeof data);

    /* In-bounds reads, big-endian. */
    assert(seer_reader_u8(&r) == 0x01);
    assert(seer_reader_u16(&r) == 0x0203);
    assert(seer_reader_remaining(&r) == 2);
    assert(seer_reader_ok(&r));

    /* Borrowing bytes hands back a pointer into the buffer. */
    const uint8_t *p = seer_reader_bytes(&r, 2);
    assert(p != NULL && p[0] == 0x04 && p[1] == 0x05);
    assert(seer_reader_remaining(&r) == 0);
    assert(seer_reader_ok(&r));

    /* Over-read past the end must latch overflow, not crash, and return 0. */
    assert(seer_reader_u32(&r) == 0);
    assert(!seer_reader_ok(&r));

    /* Once overflowed, the cursor stays latched. */
    assert(seer_reader_u8(&r) == 0);
    assert(seer_reader_bytes(&r, 1) == NULL);

    /* Empty / NULL buffer: any read latches overflow safely. */
    SeerReader e;
    seer_reader_init(&e, NULL, 0);
    assert(seer_reader_u8(&e) == 0);
    assert(!seer_reader_ok(&e));

    printf("test_reader: all assertions passed\n");
    return 0;
}
