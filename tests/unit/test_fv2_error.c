/* The error text of a 9i (fv2) error reply (#246): the "ORA-..." run that is
 * the reply's last field, in its plain (length-prefixed) or chunked form.
 * A 9i error now and then came back with 2 bytes of the reply's tail for its
 * text, its ORA number and SQLSTATE lost: a bare length match took any byte
 * equal to the bytes left for a message. The text must now read "ORA-"; a run
 * with bytes after it is taken when none ends the reply; and a reply with no
 * text never leaves the last call's in place. The prefixes here stand in for
 * the status fields, which these cases don't read.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "conn.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TEXT = "ORA-00904: \"NONEXISTENT\": invalid identifier";

/* Lay out prefix | len TEXT | tail into buf; return its length. */
static size_t plain(uint8_t *buf, const uint8_t *pre, size_t npre, const uint8_t *tail,
                    size_t ntail)
{
  size_t n = 0, tl = strlen(TEXT);
  memcpy(buf, pre, npre);
  n += npre;
  buf[n++] = (uint8_t)tl;
  memcpy(buf + n, TEXT, tl);
  n += tl;
  if (ntail > 0) /* memcpy from NULL is undefined even for 0 bytes */
    memcpy(buf + n, tail, ntail);
  return n + ntail;
}

static void check(const char *what, const uint8_t *buf, size_t n, const char *want)
{
  SeerConn c;
  memset(&c, 0, sizeof c);
  c.last_error = strdup("ORA-00001: the last call's error");
  seer_test_fv2_set_error(&c, buf, n);
  if (c.last_error == NULL || strcmp(c.last_error, want) != 0) {
    fprintf(stderr, "FAIL %s: '%s', want '%s'\n", what, c.last_error ? c.last_error : "(null)",
            want);
    exit(1);
  }
  printf("fv2 error: %s -> %s\n", what, c.last_error);
  free(c.last_error);
}

int main(void)
{
  uint8_t buf[512];
  static const uint8_t pre[] = {0x04, 0x00, 0x01, 0x07, 0x11, 0x22};
  size_t tl = strlen(TEXT);

  /* The plain form, the reply's last field. */
  check("plain, last field", buf, plain(buf, pre, sizeof pre, NULL, 0), TEXT);

  /* A byte before it equal to the bytes left: not a message (no "ORA-"). */
  uint8_t stray[sizeof pre];
  memcpy(stray, pre, sizeof pre);
  stray[4] = (uint8_t)(1 + 1 + tl); /* at offset 4: one byte, then len + TEXT remain */
  check("stray length byte before it", buf, plain(buf, stray, sizeof stray, NULL, 0), TEXT);

  /* Bytes after it, whose second-to-last is 2 - the 2-byte tail #246 got. */
  static const uint8_t tail[] = {0x00, 0x02, 0x41, 0x42};
  check("bytes after it", buf, plain(buf, pre, sizeof pre, tail, sizeof tail), TEXT);

  /* The chunked form (0xFE, runs, a zero length), with bytes after it. */
  size_t n = 0;
  memcpy(buf, pre, sizeof pre);
  n = sizeof pre;
  buf[n++] = 0xFE;
  buf[n++] = 10;
  memcpy(buf + n, TEXT, 10);
  n += 10;
  buf[n++] = (uint8_t)(tl - 10);
  memcpy(buf + n, TEXT + 10, tl - 10);
  n += tl - 10;
  buf[n++] = 0x00;
  check("chunked, last field", buf, n, TEXT);
  buf[n++] = 0x02;
  buf[n++] = 0x41;
  buf[n++] = 0x42;
  check("chunked, bytes after it", buf, n, TEXT);

  /* No "ORA-" text and no readable status: the last call's text would be a
   * lie, so a text-less reply leaves it only when there is nothing better -
   * here, the 2-byte tail alone must not become the message. */
  static const uint8_t bare[] = {0x04, 0x00, 0x01, 0x07, 0x00, 0x02, 0x41, 0x42};
  SeerConn c;
  memset(&c, 0, sizeof c);
  seer_test_fv2_set_error(&c, bare, sizeof bare);
  if (c.last_error != NULL && strcmp(c.last_error, "AB") == 0) {
    fprintf(stderr, "FAIL a 2-byte tail became the message\n");
    return 1;
  }
  free(c.last_error);
  printf("fv2 error: all cases passed\n");
  return 0;
}
