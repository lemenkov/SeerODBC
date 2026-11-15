/* Oracle 8i's status reply (seerdb _O8I_STATUS) behind its optional RPA. An
 * ALTER SESSION's RPA carries the session's changed settings as keyword pairs,
 * and the status always follows them. The pairs are skipped by their layout,
 * and a reply that ends after them is cut short, so the caller reads on for
 * the status: it never passes as a success (seerdb#2687, #176).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "conn.h"

#include <stdio.h>
#include <string.h>

/* RPA: no parameters, an empty transaction id, one pair ("abc" = "", keyword 16). */
static const uint8_t RPA[] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
                              0x03, 'a',  'b',  'c',  0x00, 0x00, 0x00, 0x00, 0x10, 0x00};

/* A status with no error: TTI_OER then 59 zero bytes of fixed fields. */
#define OER_LEN 60

static int expect(const char *what, const uint8_t *buf, size_t len, int want)
{
  uint32_t code = 99;
  int got = seer_test_o8i_status(buf, len, &code);
  if (got != want || (want == 0 && code != 0)) {
    fprintf(stderr, "FAIL %s: got %d code %u, want %d\n", what, got, code, want);
    return 1;
  }
  printf("o8i status: %s -> %d\n", what, got);
  return 0;
}

int main(void)
{
  uint8_t buf[sizeof RPA + OER_LEN];
  memcpy(buf, RPA, sizeof RPA);
  memset(buf + sizeof RPA, 0, OER_LEN);
  buf[sizeof RPA] = 0x04; /* TTI_OER */

  int bad = 0;
  bad += expect("RPA with pairs, then the status", buf, sizeof buf, 0);
  bad += expect("status alone", buf + sizeof RPA, OER_LEN, 0);
  bad += expect("RPA with pairs, status not yet received", buf, sizeof RPA, 1);

  buf[sizeof RPA] = 0x07; /* no TTI_OER: the bytes cannot be the reply */
  bad += expect("RPA, then something other than the status", buf, sizeof buf, -1);
  return bad ? 1 : 0;
}
