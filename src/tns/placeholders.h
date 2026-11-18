/* The bind placeholders of a statement's text, occurrence by occurrence.
 *
 * The core API binds the N-th distinct placeholder by order of appearance.
 * A PL/SQL block takes one value per distinct name, but a SQL statement takes
 * one per occurrence (python-oracledb's Statement._add_bind does the same),
 * so `:1 || :1 || :2` needs three values on the wire (#302). This scan gives
 * each occurrence the index of its distinct placeholder.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_PLACEHOLDERS_H
#define SEER_TNS_PLACEHOLDERS_H

/* Scan `sql` for placeholders (":1", ":name", ":"Quoted""), skipping quoted
 * text ('...', "...", q'[...]'), and -- / block comments. Names compare
 * without regard to case. On return *occ (malloc'd, NULL when there are none;
 * the caller frees) holds, per occurrence, its distinct placeholder's 0-based
 * index; *nocc counts occurrences and *ndistinct distinct names. 0, or -1 when
 * out of memory. */
int seer_sql_placeholders(const char *sql, int **occ, int *nocc, int *ndistinct);

#endif /* SEER_TNS_PLACEHOLDERS_H */
