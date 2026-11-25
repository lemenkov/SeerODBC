/* Unit test for the TTC wire-encoding primitives (marshal.c). Byte vectors are
 * taken from the reference client's test suite.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "marshal.h"
#include "msg.h"
#include "reader.h"
#include "tns_consts.h"
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
  check_sb4(0, (const uint8_t[]){0x00}, 1);
  check_sb4(0xAB, (const uint8_t[]){0x01, 0xAB}, 2);
  check_sb4(0xABCD, (const uint8_t[]){0x02, 0xAB, 0xCD}, 3);
  check_sb4(0xABCDEF, (const uint8_t[]){0x03, 0xAB, 0xCD, 0xEF}, 4);
  check_sb4(0xABCDEF87, (const uint8_t[]){0x04, 0xAB, 0xCD, 0xEF, 0x87}, 5);

  /* §12.1 decode of sign-magnitude negatives. */
  {
    SeerReader r;
    seer_reader_init(&r, (const uint8_t[]){0x81, 0x01}, 2);
    assert(seer_dec_sb4(&r) == -1);
    seer_reader_init(&r, (const uint8_t[]){0x81, 0x7F}, 2);
    assert(seer_dec_sb4(&r) == -127);
    seer_reader_init(&r, (const uint8_t[]){0x82, 0x01, 0x00}, 3);
    assert(seer_dec_sb4(&r) == -256);
  }

  /* §12.3 key/value pair: encode_kv("AUTH_MACHINE", "ExampleHost"), by
   * SEER_AUTH_PAIR_SCHEMA (#398). */
  {
    SeerWriter w;
    assert(seer_writer_init(&w, 64));
    SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_12_1, TTC_FIELD_VERSION_12_1);
    SeerAuthPairMsg m = {.key = {.p = (const uint8_t *)"AUTH_MACHINE", .n = 12},
                         .value = {.p = (const uint8_t *)"ExampleHost", .n = 11}};
    seer_schema_encode(SEER_AUTH_PAIR_SCHEMA, &cx, &m, &w);
    const uint8_t expect[] = {
        0x01, 0x0C, 0x0C, 'A', 'U', 'T', 'H', '_', 'M', 'A', 'C', 'H', 'I', 'N', 'E',
        0x01, 0x0B, 0x0B, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 'H', 'o', 's', 't', 0x00,
    };
    assert(seer_writer_ok(&w));
    assert(w.len == sizeof expect);
    assert(memcmp(w.buf, expect, sizeof expect) == 0);
    seer_writer_free(&w);
  }

  /* dec_field round-trips the inline form, and an empty field. */
  {
    const uint8_t field[] = {0x01, 0x03, 0x03, 'h', 'i', '!'};
    SeerReader r;
    seer_reader_init(&r, field, sizeof field);
    uint8_t *out = NULL;
    size_t outlen = 0;
    assert(seer_dec_field(&r, &out, &outlen) == SEER_OK);
    assert(outlen == 3 && memcmp(out, "hi!", 3) == 0);
    free(out);

    const uint8_t empty[] = {0x00};
    seer_reader_init(&r, empty, sizeof empty);
    assert(seer_dec_field(&r, &out, &outlen) == SEER_OK);
    assert(out == NULL && outlen == 0);
  }

  /* dec_field handles the chunked (0xFE) form: sb4 len, 0xFE, [len][data]..0. */
  {
    const uint8_t chunked[] = {
        0x01, 0x05,           /* sb4 length (ignored for chunked) */
        0xFE,                 /* chunk marker */
        0x03, 'a',  'b', 'c', /* chunk 1 */
        0x02, 'd',  'e',      /* chunk 2 */
        0x00,                 /* terminator */
    };
    SeerReader r;
    seer_reader_init(&r, chunked, sizeof chunked);
    uint8_t *out = NULL;
    size_t outlen = 0;
    assert(seer_dec_field(&r, &out, &outlen) == SEER_OK);
    assert(outlen == 5 && memcmp(out, "abcde", 5) == 0);
    free(out);
  }

  /* A key/value field over 252 bytes (e.g. AUTH_PASSWORD for a long password)
   * goes chunked: sb4 len, 0xFE, 64-byte chunks with ub1 (pre-12.1) or ub4
   * (12.1+) lengths, a zero terminator. 300 bytes = 4 x 64 + 44. */
  for (int wide = 0; wide <= 1; wide++) {
    static uint8_t val[300];
    memset(val, 'P', sizeof val);
    SeerWriter w;
    assert(seer_writer_init(&w, 16));
    SeerSchemaCtx cx = seer_msg_ctx(0, wide ? TTC_FIELD_VERSION_12_1 : TTC_FIELD_VERSION_11_2,
                                    TTC_FIELD_VERSION_11_2);
    SeerAuthPairMsg m = {.key = {.p = (const uint8_t *)"K", .n = 1},
                         .value = {.p = val, .n = sizeof val}};
    seer_schema_encode(SEER_AUTH_PAIR_SCHEMA, &cx, &m, &w);
    /* key: 01 01 | 01 'K' (4) ; value: 02 01 2C (3) | FE (1) | chunks | term |
     * padding 00 (1) */
    size_t lenb = wide ? 2 : 1; /* a chunk length: sb4 var-int 01 NN, or NN */
    size_t want = 4 + 3 + 1 + 4 * (lenb + 64) + (lenb + 44) + 1 + 1;
    assert(w.len == want);
    assert(w.buf[4] == 0x02 && w.buf[5] == 0x01 && w.buf[6] == 0x2C && w.buf[7] == 0xFE);
    if (wide)
      assert(w.buf[8] == 0x01 && w.buf[9] == 0x40 && w.buf[10] == 'P');
    else
      assert(w.buf[8] == 0x40 && w.buf[9] == 'P');
    seer_writer_free(&w);
  }

  /* The same pair at 8i's widths: ub4 little-endian lengths and flags, the
   * key and value each a ub1 length and the bytes, and past 252 bytes OCI's
   * 255-byte chunks, each with a ub1 length (seerdb _OciCodec.value). 300
   * bytes = 255 + 45. */
  {
    static uint8_t val[300];
    memset(val, 'P', sizeof val);
    SeerWriter w;
    assert(seer_writer_init(&w, 16));
    SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
    SeerAuthPairMsg m = {.key = {.p = (const uint8_t *)"K", .n = 1},
                         .value = {.p = val, .n = sizeof val}};
    seer_schema_encode(SEER_AUTH_PAIR_SCHEMA, &cx, &m, &w);
    /* key: 01 00 00 00 | 01 'K' (6); value: 2C 01 00 00 (4) | FE | FF + 255 |
     * 2D + 45 | 00 ; flags 00 00 00 00 (4) */
    assert(seer_writer_ok(&w));
    assert(w.len == 6 + 4 + 1 + 256 + 46 + 1 + 4);
    assert(w.buf[6] == 0x2C && w.buf[7] == 0x01 && w.buf[10] == 0xFE && w.buf[11] == 0xFF);
    assert(w.buf[11 + 256] == 0x2D && w.buf[11 + 256 + 46] == 0x00);
    seer_writer_free(&w);
  }

  /* seer_skip_chunked follows the chunk-length width of the session: one byte
   * before 12.1, a ub4 (sb4 var-int) from 12.1. Each case ends in a 0x99
   * sentinel the skip must land on exactly. */
  {
    const uint8_t pre121[] = {0xFE, 0x03, 'a', 'b', 'c', 0x02, 'd', 'e', 0x00, 0x99};
    SeerReader r;
    seer_reader_init(&r, pre121, sizeof pre121);
    r.sb4_chunks = false;
    seer_skip_chunked(&r);
    assert(seer_reader_ok(&r) && seer_reader_remaining(&r) == 1 && r.buf[r.pos] == 0x99);
  }
  {
    const uint8_t v121[] = {0xFE, 0x01, 0x03, 'a', 'b', 'c', 0x01, 0x02, 'd', 'e', 0x00, 0x99};
    SeerReader r;
    seer_reader_init(&r, v121, sizeof v121);
    r.sb4_chunks = true;
    seer_skip_chunked(&r);
    assert(seer_reader_ok(&r) && seer_reader_remaining(&r) == 1 && r.buf[r.pos] == 0x99);
  }

  /* A LOB WRITE's data (SEER_LOB_DATA_SCHEMA, SF_LOB) is chunked as READ
   * replies carry it (#427): 300 bytes go as a 252-byte and a 48-byte chunk
   * with ub1 lengths at 11.2 (10g and 11g read sb4 ones short, ORA-22993),
   * and as one chunk with an sb4 length from 12.1. */
  {
    static uint8_t data[300];
    memset(data, 'L', sizeof data);
    SeerLobDataMsg m = {.data = {.p = data, .n = sizeof data}};
    for (int wide = 0; wide < 2; wide++) {
      uint8_t fv = wide ? TTC_FIELD_VERSION_12_1 : TTC_FIELD_VERSION_11_2;
      SeerSchemaCtx cx = seer_msg_ctx(0, fv, fv);
      SeerWriter w;
      assert(seer_writer_init(&w, 400));
      seer_schema_encode(SEER_LOB_DATA_SCHEMA, &cx, &m, &w);
      assert(seer_writer_ok(&w));
      assert(w.buf[0] == 0xFE);
      if (wide) { /* FE, sb4 300 (02 01 2C), the bytes, 00 */
        assert(w.len == 1 + 3 + 300 + 1);
        assert(w.buf[1] == 0x02 && w.buf[2] == 0x01 && w.buf[3] == 0x2C);
      } else { /* FE, FC, 252 bytes, 30, 48 bytes, 00 */
        assert(w.len == 1 + 1 + 252 + 1 + 48 + 1);
        assert(w.buf[1] == 0xFC && w.buf[2 + 252] == 0x30);
      }
      assert(w.buf[w.len - 1] == 0x00);
      seer_writer_free(&w);
    }
  }

  printf("test_marshal: all assertions passed\n");
  return 0;
}
