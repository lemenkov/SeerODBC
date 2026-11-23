/* seer_schema_value_scan (#400): where a value ends, found by resuming as a
 * reply arrives. Each value - empty, inline, and chunked past 252 bytes in
 * 8i's, thin's pre-12.1 and thin's 12.1+ forms - is fed a byte at a time:
 * the scan reads short until the value is whole, then ends exactly where the
 * value does, its resume point never going back. A negative sb4 chunk length
 * is a bad value.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "msg.h"
#include "schema.h"
#include "tns_consts.h"
#include "writer.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* `n` bytes encoded as a value (SEER_VALUE_SCHEMA) behind a one-byte token,
 * with trailing bytes after it; the value's end into *end. */
static uint8_t *encode(const SeerSchemaCtx *cx, size_t n, size_t *len, size_t *end)
{
  uint8_t *data = malloc(n ? n : 1);
  assert(data != NULL);
  for (size_t i = 0; i < n; i++)
    data[i] = (uint8_t)(i * 7 + 1);
  SeerWriter w;
  assert(seer_writer_init(&w, n + 64));
  seer_writer_u8(&w, 0x0E); /* a token ahead of it */
  SeerChrMsg m = {.value = {.p = data, .n = n}};
  seer_schema_encode(SEER_VALUE_SCHEMA, cx, &m, &w);
  *end = w.len;
  seer_writer_u8(&w, 0x08); /* what follows it */
  seer_writer_u8(&w, 0x00);
  assert(seer_writer_ok(&w));
  free(data);
  *len = w.len;
  return w.buf;
}

static void check(const SeerSchemaCtx *cx, size_t n)
{
  size_t len = 0, end = 0;
  uint8_t *buf = encode(cx, n, &len, &end);

  /* whole at once */
  size_t pos = 0;
  assert(seer_schema_value_scan(cx, buf, len, 1, &pos) == SCH_OK);
  assert(pos == end);

  /* a byte at a time, resuming */
  pos = 0;
  size_t last = 0;
  bool done = false;
  for (size_t have = 0; have <= len && !done; have++) {
    SeerSchemaResult r = seer_schema_value_scan(cx, buf, have, 1, &pos);
    if (have < end) {
      assert(r == SCH_SHORT);
      assert(pos >= last);
      last = pos;
    } else {
      assert(r == SCH_OK);
      assert(pos == end);
      done = true;
    }
  }
  assert(done);
  free(buf);
}

int main(void)
{
  static const size_t sizes[] = {0, 1, 64, 65, 200, 252, 253, 254, 255, 256, 1000, 70000};
  SeerSchemaCtx o8i = seer_msg_ctx(1, 0, 0);
  SeerSchemaCtx thin11 = seer_msg_ctx(0, TTC_FIELD_VERSION_11_2, TTC_FIELD_VERSION_11_2);
  SeerSchemaCtx thin12 = seer_msg_ctx(0, TTC_FIELD_VERSION_12_1, TTC_FIELD_VERSION_12_1);
  for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
    check(&o8i, sizes[i]);
    check(&thin11, sizes[i]);
    check(&thin12, sizes[i]);
  }

  /* a negative sb4 chunk length from 12.1: fe, then -1 (81 01) */
  static const uint8_t neg[] = {0x0E, 0xFE, 0x81, 0x01, 0x00};
  size_t pos = 0;
  assert(seer_schema_value_scan(&thin12, neg, sizeof neg, 1, &pos) == SCH_BAD);

  printf("value scan: ok\n");
  return 0;
}
