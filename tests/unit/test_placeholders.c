/* Offline unit tests for the placeholder scan (src/tns/placeholders.c, #302):
 * each occurrence's distinct placeholder, past quoted text and comments.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#include "placeholders.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

/* `want` is the occurrences' distinct indexes as digits, "" for none. */
static void check(const char *sql, const char *want, int want_distinct)
{
  int *occ = NULL, nocc = -1, nd = -1;
  char got[64] = "";
  if (seer_sql_placeholders(sql, &occ, &nocc, &nd) != 0) {
    fprintf(stderr, "FAIL %s: out of memory\n", sql);
    failures++;
    return;
  }
  for (int i = 0; i < nocc && i < 63; i++)
    got[i] = (char)('0' + occ[i]);
  if (strcmp(got, want) != 0 || nd != want_distinct) {
    fprintf(stderr, "FAIL %s:\n  got  '%s' (%d distinct)\n  want '%s' (%d distinct)\n", sql, got,
            nd, want, want_distinct);
    failures++;
  }
  free(occ);
}

int main(void)
{
  check("SELECT 1 FROM dual", "", 0);
  check("SELECT :1 || :2 FROM dual", "01", 2);
  check("SELECT :1 || :1 || :2 FROM dual", "001", 2);
  check("SELECT :2 || :1 || :2 FROM dual", "010", 2); /* labels mean nothing */
  check("SELECT :a || :A || :b FROM dual", "001", 2); /* names fold case */
  check("SELECT :\"q\" || :\"q\" FROM dual", "00", 1);
  check("SELECT ':x' || :y FROM dual", "0", 1);              /* in text */
  check("SELECT 'it''s :x' || :y FROM dual", "0", 1);        /* '' inside */
  check("SELECT \":x\" FROM t WHERE c = :y", "0", 1);        /* quoted name */
  check("SELECT q'[:x ']' || :y FROM dual", "0", 1);         /* q-quote */
  check("SELECT Q'{a}' || q'!:z!' || :y FROM dual", "0", 1); /* other delimiters */
  check("SELECT :y -- :x\n || :y FROM dual", "00", 1);       /* line comment */
  check("SELECT :y /* :x */ || :z FROM dual", "01", 2);      /* block comment */
  check("SELECT a::b, :y FROM t", "0", 1);                   /* not a placeholder */
  check("SELECT seq FROM t WHERE a = :x AND b = :x OR c = :y", "001", 2);
  check("INSERT INTO t VALUES (:1, :1 || :2)", "001", 2);
  check("SELECT :n$1, :n#2, :n_3 FROM t", "012", 3);
  if (failures == 0)
    printf("test_placeholders: all assertions passed\n");
  return failures != 0;
}
