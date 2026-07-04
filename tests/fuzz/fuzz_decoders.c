/* libFuzzer harness for the response decoders. Feeds the fuzzer's input to every
 * decoder of server-controlled bytes, to shake out out-of-bounds reads / UB.
 * Coverage-guided; build + run with clang + libFuzzer + ASan + UBSan:
 *
 *   tests/fuzz/build-fuzz.sh
 *   build-fuzz/fuzz_decoders -max_len=512 build-fuzz/corpus
 *
 * The reader is bounds-checked (seer_reader_ok), so this is mainly a verification
 * that the decoders never over-read on malformed input - the chunked-DALC bug
 * (sb4 vs ub1) is the kind of thing this guards.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <stdlib.h>

#include <stdlib.h>
#include <string.h>

#include "seer/seertns.h"
#include "types.h"
#include "oson.h"
#include "json.h"
#include "marshal.h"
#include "reader.h"

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    char out[256];
    seer_decode_number(d, n, out, sizeof out);
    seer_decode_date(d, n, out, sizeof out);
    seer_decode_bfloat(d, n, out, sizeof out);
    seer_decode_bdouble(d, n, out, sizeof out);
    seer_decode_interval_ym(d, n, out, sizeof out);
    seer_decode_interval_ds(d, n, out, sizeof out);

    char *j = NULL;
    seer_decode_oson(d, n, &j);            /* sets *out=NULL unless it succeeds */
    free(j);

    /* JSON -> OSON encoder: feed the input as a NUL-terminated string. */
    char *jt = malloc(n + 1);
    if (jt != NULL) {
        memcpy(jt, d, n);
        jt[n] = '\0';
        uint8_t *o = NULL; size_t ol = 0;
        if (seer_json_to_oson(jt, &o, &ol) == SEER_OK) free(o);
        free(jt);
    }

    SeerReader r;
    uint8_t *o = NULL; size_t ol = 0;
    seer_reader_init(&r, d, n);            o = NULL; seer_dec_dalc(&r, &o, &ol); free(o);
    seer_reader_init(&r, d, n);            r.sb4_chunks = true;
    o = NULL; seer_dec_dalc(&r, &o, &ol);  free(o);          /* the sb4 chunk path */
    seer_reader_init(&r, d, n);            o = NULL; seer_dec_field(&r, &o, &ol); free(o);
    seer_reader_init(&r, d, n);            seer_skip_chunked(&r);
    seer_reader_init(&r, d, n);            (void)seer_dec_sb4(&r);
    return 0;
}
