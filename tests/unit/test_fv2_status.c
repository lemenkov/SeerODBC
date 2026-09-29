/* Regression test for the Oracle 9i (fv2) DML / DDL status reply, against
 * replies captured from a live 9.2.0.4 (seerdb tests/test_fv2_status.py). The
 * reply is an RPA piggyback of two parameters, then the short OER. The first
 * parameter is a counter that grows with the instance; once past 2^24 its
 * length byte is 0x04 - the OER token - and a decoder that stopped the
 * parameter loop at a token-valued byte read the counter as the status: every
 * successful CREATE / INSERT / DROP on an aged 9i reported a garbled negative
 * ORA code. The parameters must be consumed by count.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "conn.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t unhex(const char *hex, uint8_t *out)
{
  size_t n = strlen(hex) / 2;
  for (size_t i = 0; i < n; i++) {
    unsigned b;
    if (sscanf(hex + 2 * i, "%2x", &b) != 1)
      assert(0 && "bad hex");
    out[i] = (uint8_t)b;
  }
  return n;
}

static void check(const char *what, const char *hex, int64_t want_rows)
{
  static uint8_t buf[256];
  size_t n = unhex(hex, buf);
  int64_t rows = -1, code = -1;
  seer_test_fv2_decode_dml(buf, n, &rows, &code);
  if (rows != want_rows || code != 0) {
    fprintf(stderr, "FAIL %s: rows=%lld code=%lld (want %lld, 0)\n", what, (long long)rows,
            (long long)code, (long long)want_rows);
    assert(0);
  }
  printf("fv2 status: %s -> rows=%lld, ORA-00000\n", what, (long long)rows);
}

int main(void)
{
  /* the counter at 0x0129c868 (4 bytes: length byte 0x04 == TTI_OER) */
  check("CREATE", "080102040129c868000400000000010100010000000000000000000000000000010100000000",
        0);
  check("INSERT",
        "080102040129c79d000401010000000101010c020000000000028dca01010002baba00000000000101010d0d01"
        "00008dca00010000baba00000000",
        1);
  check("DROP", "080102040129c8750004000000000101010b0c0000000000000000000000000000010100000000",
        0);
  /* the same shape while the counter still fitted three bytes */
  check("CREATE (young instance)",
        "08010203029c6800040000000001010001000000000000000000000000000001010000", 0);
  return 0;
}
