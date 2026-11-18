/* SQL statement preprocessing - pure string transforms, no ODBC handles.
 *
 * Split out of exec.c so the trickiest parsing logic (ODBC escape expansion,
 * '?' marker rewriting, parameter counting, updatable-cursor rewriting) can be
 * unit-tested offline, with no Driver Manager or database connection.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEERODBC_SQLPREP_H
#define SEERODBC_SQLPREP_H

#include <stddef.h>

/* Prepare statement text for the core: expand the ODBC {call}/{?=call} and
 * inline ({ts}/{d}/{t}/{fn}/{oj}/{escape}) escapes, then rewrite '?' parameter
 * markers to Oracle positional binds :1, :2, ... Returns a malloc'd string
 * (caller frees), or NULL on allocation failure. */
char *seer_sql_prepare(const char *raw);

/* As seer_sql_prepare, the escapes left as written when `scan` is 0
 * (SQL_ATTR_NOSCAN, #248); the '?' markers are rewritten either way. */
char *seer_sql_prepare_scan(const char *raw, int scan);

/* As seer_sql_prepare_scan, for a server of major release `major` (0: not
 * known, read as the newest), which some {fn} translations depend on (#301).
 * NULL with *err set (a static string) when an escape can't be translated
 * without binding a parameter to the wrong argument; NULL with *err NULL when
 * out of memory. `err` may be NULL. */
char *seer_sql_prepare_for(const char *raw, int scan, int major, const char **err);

/* Count the distinct bind placeholders in a prepared statement: positional
 * :1, :2, ... and named :name / :"Quoted", de-duplicated case-insensitively,
 * ignoring placeholders in string/identifier literals, line/block comments,
 * and the PL/SQL ':=' assignment. */
int seer_sql_count_params(const char *sql);

/* If `sql` is a simple single-table SELECT, return a malloc'd copy with a
 * ROWIDTOCHAR(ROWID) column appended (for positioned update/delete) and set
 * *table to a malloc'd base-table reference. Otherwise return NULL (and leave
 * *table NULL). Conservative: any doubt -> NULL.
 *
 * When `lock` is non-zero (SQL_CONCUR_LOCK - pessimistic concurrency), the
 * rewrite also appends `FOR UPDATE` so the fetched rows are row-locked until
 * the transaction ends, unless the statement already carries one. */
char *seer_sql_make_updatable(const char *sql, char **table, int lock);

/* A positioned UPDATE or DELETE (#288): `... WHERE CURRENT OF name` ending
 * the statement (a ';' and blanks may follow), outside literals and
 * comments. On a match, return 1 with *start the offset of CURRENT, *end the
 * offset just past the name, and the name - an identifier, or a "quoted" one
 * without its quotes - copied into `name` (truncated to namelen-1).
 * Otherwise return 0. */
int seer_sql_current_of(const char *sql, size_t *start, size_t *end, char *name, size_t namelen);

#endif /* SEERODBC_SQLPREP_H */
