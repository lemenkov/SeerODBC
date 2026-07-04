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

/* Prepare statement text for the core: expand the ODBC {call}/{?=call} and
 * inline ({ts}/{d}/{t}/{fn}/{oj}/{escape}) escapes, then rewrite '?' parameter
 * markers to Oracle positional binds :1, :2, ... Returns a malloc'd string
 * (caller frees), or NULL on allocation failure. */
char *seer_sql_prepare(const char *raw);

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

#endif /* SEERODBC_SQLPREP_H */
