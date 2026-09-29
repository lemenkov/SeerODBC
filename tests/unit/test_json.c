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
  uint8_t *oson = NULL;
  size_t n = 0;
  assert(seer_json_to_oson(in, &oson, &n) == SEER_OK);
  char *back = NULL;
  assert(seer_decode_oson(oson, n, &back) == SEER_OK);
  if (back == NULL || strcmp(back, expect) != 0) {
    fprintf(stderr, "JSON round-trip: in=%s got=%s want=%s\n", in, back ? back : "(null)", expect);
    assert(0);
  }
  free(oson);
  free(back);
}

static void bad(const char *in)
{
  uint8_t *oson = NULL;
  size_t n = 0;
  if (seer_json_to_oson(in, &oson, &n) == SEER_OK) {
    fprintf(stderr, "JSON: expected rejection of %s\n", in);
    assert(0);
  }
  free(oson);
}

/* The encoder's field-name table: hash bytes (FNV-1a, low byte) and names in
 * hash order, as a 23ai server writes them (seerdb PROTOCOL.md §17.0d). Our
 * header: 6-byte magic, ub1 name count, ub2 name-segment size, ub2 tree size,
 * 2 reserved bytes, then the hash array, the ub2 offsets, the <len><name>s. */
static void check_fname_table(const char *doc, const char *want_names, const char *want_hashes)
{
  uint8_t *img = NULL;
  size_t n = 0;
  assert(seer_json_to_oson(doc, &img, &n) == SEER_OK);
  int count = img[6];
  const uint8_t *hash = img + 13;
  const uint8_t *seg = hash + 3 * count;
  char names[256] = "", hashes[256] = "";
  for (int i = 0; i < count; i++) {
    size_t off = (size_t)hash[count + 2 * i] << 8 | hash[count + 2 * i + 1];
    snprintf(names + strlen(names), sizeof names - strlen(names), "%s%.*s", i ? "," : "",
             (int)seg[off], (const char *)seg + off + 1);
    snprintf(hashes + strlen(hashes), sizeof hashes - strlen(hashes), "%s%02x", i ? " " : "",
             hash[i]);
  }
  if (strcmp(names, want_names) != 0 || strcmp(hashes, want_hashes) != 0) {
    fprintf(stderr, "FAIL %s: names '%s' hashes '%s' (want '%s' / '%s')\n", doc, names, hashes,
            want_names, want_hashes);
    assert(0);
  }
  char *back = NULL; /* and it still decodes to the same document */
  assert(seer_decode_oson(img, n, &back) == SEER_OK);
  free(back);
  free(img);
}

/* Decode a hand-assembled server image and compare the JSON text. */
static void check_decode(const char *what, const uint8_t *img, size_t n, const char *want)
{
  char *back = NULL;
  SeerStatus st = seer_decode_oson(img, n, &back);
  if (st != SEER_OK || back == NULL || strcmp(back, want) != 0) {
    fprintf(stderr, "FAIL %s: st=%d got '%s'\n", what, st, back ? back : "(null)");
    assert(0);
  }
  free(back);
}

/* Version 3 (a field name over 255 bytes lives in a second segment): the 23ai
 * image for {"A"x256: 6700} (seerdb PROTOCOL.md §17.0b). */
static void check_v3_long_name(void)
{
  static const uint8_t head[] = {
      0xff, 0x4a, 0x5a, 0x03, 0x20, 0x06, /* magic, version 3, flags        */
      0x00, 0x00, 0x00,                   /* 0 short names, short seg 0     */
      0x01, 0x00,                         /* secondary flags: ub2 offsets   */
      0x00, 0x00, 0x00, 0x01,             /* 1 long name                    */
      0x00, 0x00, 0x01, 0x02,             /* long segment 258 bytes         */
      0x00, 0x08, 0x00, 0x00,             /* tree 8 bytes, reserved         */
      0xc5, 0x62, 0x00, 0x00, 0x01, 0x00, /* ub2 hash, ub2 offset, ub2 len  */
  };
  static const uint8_t tree[] = {0x84, 0x01, 0x01, 0x00, 0x05, 0x21, 0xc2, 0x44};
  uint8_t img[sizeof head + 256 + sizeof tree];
  memcpy(img, head, sizeof head);
  memset(img + sizeof head, 'A', 256);
  memcpy(img + sizeof head + 256, tree, sizeof tree);
  char want[300];
  snprintf(
      want, sizeof want, "{\"%.*s\":6700}", 256,
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  check_decode("OSON v3 long field name", img, sizeof img, want);
}

/* A `store as (compress high)` column (flags 0x2107): relative child offsets
 * and an object sharing another's field ids - the 23ai tree for
 * [{"a":1,"b":"x"},{"a":2,"b":"y"}] (seerdb PROTOCOL.md §17.0c). */
static void check_compressed(void)
{
  static const uint8_t img[] = {
      0xff,
      0x4a,
      0x5a,
      0x01,
      0x21,
      0x07, /* magic, version 1, flags     */
      0x02,
      0x00,
      0x04,
      0x00,
      0x1f,
      0x00,
      0x00, /* 2 names, seg 4, tree 31     */
      0x2c,
      0xe5,
      0x00,
      0x00,
      0x00,
      0x02, /* hashes, offsets             */
      0x01,
      0x61,
      0x01,
      0x62, /* "a", "b"                    */
      /* tree */
      0xc0,
      0x02,
      0x00,
      0x06,
      0x00,
      0x13, /*  0 array: 6, 19        */
      0x86,
      0x02,
      0x01,
      0x02,
      0x00,
      0x08,
      0x00,
      0x0b, /*  6 object a,b: +8,+11  */
      0x21,
      0xc1,
      0x02, /* 14 1                   */
      0x01,
      0x78, /* 17 "x"                 */
      0x9c,
      0x00,
      0x06,
      0x00,
      0x07,
      0x00,
      0x0a, /* 19 ids of 6: +7, +10   */
      0x21,
      0xc1,
      0x03, /* 26 2                   */
      0x01,
      0x79, /* 29 "y"                 */
  };
  check_decode("OSON compressed (relative offsets, shared ids)", img, sizeof img,
               "[{\"a\":1,\"b\":\"x\"},{\"a\":2,\"b\":\"y\"}]");
}

int main(void)
{
  check_v3_long_name();
  check_compressed();
  check_fname_table("{\"a\":1}", "a", "2c");
  check_fname_table("{\"b\":1,\"a\":2}", "a,b", "2c e5");
  check_fname_table("{\"outer\":{\"inner\":{\"deep\":\"v\"}},\"arr\":[{\"k\":1}]}",
                    "arr,inner,deep,outer,k", "18 27 6f 74 ea");

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
