/* Unit test for the JSON -> OSON encoder (json.c), verified by round-tripping
 * each document through seer_decode_oson and by rejecting malformed input.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#include "json.h"
#include "oson.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void rt(const char *in, const char *expect)
{
    uint8_t *oson = NULL; size_t n = 0;
    assert(seer_json_to_oson(in, &oson, &n) == SEER_OK);
    char *back = NULL;
    assert(seer_decode_oson(oson, n, &back) == SEER_OK);
    if (back == NULL || strcmp(back, expect) != 0) {
        fprintf(stderr, "JSON round-trip: in=%s got=%s want=%s\n",
                in, back ? back : "(null)", expect);
        assert(0);
    }
    free(oson);
    free(back);
}

static void bad(const char *in)
{
    uint8_t *oson = NULL; size_t n = 0;
    if (seer_json_to_oson(in, &oson, &n) == SEER_OK) {
        fprintf(stderr, "JSON: expected rejection of %s\n", in);
        assert(0);
    }
    free(oson);
}

int main(void)
{
    /* scalars */
    rt("42", "42");
    rt("-7", "-7");
    rt("3.14", "3.14");
    rt("\"hello\"", "\"hello\"");
    rt("true", "true");
    rt("false", "false");
    rt("null", "null");

    /* containers + nesting */
    rt("{\"id\":42,\"nm\":\"hello\"}", "{\"id\":42,\"nm\":\"hello\"}");
    rt("[1,2,3]", "[1,2,3]");
    rt("{\"a\":[1,{\"b\":\"x\"}],\"c\":true}", "{\"a\":[1,{\"b\":\"x\"}],\"c\":true}");
    rt("[]", "[]");
    rt("{}", "{}");

    /* whitespace tolerated; \u escape -> UTF-8 (e9 = c3 a9) */
    rt("  { \"x\" : 1 }  ", "{\"x\":1}");
    rt("\"caf\\u00e9\"", "\"caf\xc3\xa9\"");

    /* malformed input is rejected, not crashed */
    bad("");
    bad("{");
    bad("[1,2");
    bad("{\"a\":}");
    bad("nul");
    bad("42 43");
    bad("{\"a\" 1}");

    printf("json encoder: all round-trips OK\n");
    return 0;
}
