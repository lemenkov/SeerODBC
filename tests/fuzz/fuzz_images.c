/* libFuzzer harness for the ADT image decoders (object / collection / vector),
 * which are static in stmt.c and reached here via seer_fuzz_image_decoders (only
 * defined under -DSEER_FUZZ). These walk server-controlled image bytes with a
 * caller-supplied attribute/element type layout, so they are a prime spot for
 * out-of-bounds reads. Build + run with clang + libFuzzer + ASan + UBSan via
 * tests/fuzz/build-fuzz.sh.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <stddef.h>

extern void seer_fuzz_image_decoders(const uint8_t *d, size_t n);

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    seer_fuzz_image_decoders(d, n);
    return 0;
}
