<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# ODBC conformance

The implemented ODBC **3.x** function set. The Driver Manager maps deprecated
2.x calls onto these, so they are not implemented separately (see the bottom).

Legend: [x] implemented & live-validated · [~] partial · [ ] not implemented

## Connection & environment

| Status | Function | Notes |
|--------|----------|-------|
| [x] | SQLAllocHandle / SQLFreeHandle | ENV / DBC / STMT |
| [x] | SQLSetEnvAttr / SQLGetEnvAttr | ODBC version |
| [x] | SQLConnect / SQLDriverConnect | DSN from odbc.ini; HOST/PORT/SERVICE keys |
| [x] | SQLDisconnect | |
| [x] | SQLSetConnectAttr / SQLGetConnectAttr | autocommit |
| [x] | SQLGetInfo | server-specific answer table (identifier quote, schemas-not-catalogs, txn, scroll options, …) |
| [x] | SQLGetFunctions | incl. SQL_API_ODBC3_ALL_FUNCTIONS |
| [x] | SQLGetDiagRec / SQLGetDiagField | ORA-code → SQLSTATE mapping; multi-record queue (array-DML row errors carry SQL_DIAG_ROW_NUMBER) |
| [x] | SQLEndTran | commit / rollback |

## Statements & results

| Status | Function | Notes |
|--------|----------|-------|
| [x] | SQLPrepare / SQLExecute / SQLExecDirect | `{call}` & inline ODBC escapes, `?`→`:n` |
| [x] | SQLBindParameter | IN / OUT / IN OUT, arrays (PARAMSET_SIZE) with batch-error row status, REF CURSOR |
| [x] | SQLParamData / SQLPutData | data-at-execution: stream a parameter (`SQL_DATA_AT_EXEC`) in chunks |
| [x] | SQLNumParams / SQLDescribeParam | NumParams parses `?` / `:name` (deduped) |
| [x] | SQLNumResultCols / SQLDescribeCol / SQLColAttribute | |
| [x] | SQLBindCol / SQLFetch / SQLGetData | block fetch (ROW_ARRAY_SIZE), SQLGetData fragmentation |
| [x] | SQLFetchScroll | static scrollable cursor (NEXT/PRIOR/FIRST/LAST/ABSOLUTE/RELATIVE) |
| [x] | SQLSetPos | POSITION / REFRESH / positioned UPDATE / DELETE |
| [x] | SQLSetCursorName / SQLGetCursorName | generated `SQL_CURn` names; `UPDATE` / `DELETE ... WHERE CURRENT OF name` rewritten to the named cursor's current ROWID (Oracle has `CURRENT OF` only in PL/SQL) |
| [x] | SQLRowCount / SQLCloseCursor / SQLFreeStmt | |
| [x] | SQLSetStmtAttr / SQLGetStmtAttr | paramset/row-array size, bind type, concurrency (SQL_CONCUR_LOCK → FOR UPDATE), status ptrs |

## Catalog (data-dictionary backed)

| Status | Function | Notes |
|--------|----------|-------|
| [x] | SQLTables / SQLColumns | |
| [x] | SQLPrimaryKeys / SQLForeignKeys | |
| [x] | SQLStatistics | ALL_INDEXES / ALL_IND_COLUMNS |
| [x] | SQLGetTypeInfo | type table, per release (TIMESTAMP from 9i, BINARY_FLOAT / DOUBLE from 10g); attributes as SQLColAttribute reports them |
| [x] | SQLProcedures / SQLProcedureColumns | ALL_OBJECTS / ALL_ARGUMENTS |
| [x] | SQLSpecialColumns | ROWID for SQL_BEST_ROWID |
| [x] | SQLTablePrivileges / SQLColumnPrivileges | ALL_TAB_PRIVS / ALL_COL_PRIVS: granted rights, not an owner's own |

## Unicode (`*W`)

Exporting `SQLConnectW` makes the DM treat the driver as Unicode and route wide
apps to the `*W` entry points; ANSI apps stay on the A functions. Implemented:
`SQLConnectW`, `SQLDriverConnectW`, `SQLPrepareW`, `SQLExecDirectW`,
`SQLGetDiagRecW`, `SQLGetInfoW`, `SQLDescribeColW`, `SQLColAttributeW`,
`SQLTablesW`, `SQLColumnsW`, `SQLGetTypeInfoW`. UTF-16 ↔ UTF-8 both directions;
the DM bridges any `*W` not listed here to the A function. `SQL_C_WCHAR` bind
and fetch are supported regardless.

## Implemented since the first cut

`SQLMoreResults` (implicit result sets), `SQLCancel` (data-at-exec abort + in-band
break), `SQLNativeSql`, `SQLBrowseConnect` (iterative connect), and the full
descriptor API (`SQLGetDescField` / `SQLGetDescRec` read path; `SQLSetDescField` /
`SQLSetDescRec` write path) on the implicit ARD/APD/IRD/IPD reachable via
`SQLGetStmtAttr`. Writing a descriptor field updates the same bind/parameter array
that execute and fetch consume, so it is equivalent to `SQLBindCol` (ARD) or the
value/type halves of `SQLBindParameter` (APD/IPD); the IRD is read-only (`HY016`).
`SQLCopyDesc` copies records (and, within one class, the header fields) between
any two of them, e.g. a SELECT's ARD and IRD to an INSERT's APD and IPD to copy
rows. Explicitly allocated descriptors (`SQLAllocHandle(SQL_HANDLE_DESC)`) are
application descriptors of the connection: set as a statement's ARD they are shared
in place (two statements can fetch into the same buffers), as its APD they supply
the values at execute; their records are their own, the header fields (array size,
bind type and offset) stay the statement's. Freed while in use, the statements go
back to their implicit descriptors.

## Scalar functions (`{fn ...}`)

The preprocessor translates the ODBC scalar functions (Appendix E) into Oracle
SQL, and `SQL_STRING_FUNCTIONS`, `SQL_NUMERIC_FUNCTIONS`,
`SQL_TIMEDATE_FUNCTIONS`, `SQL_SYSTEM_FUNCTIONS`, `SQL_CONVERT_FUNCTIONS`, the
`SQL_TIMEDATE_*_INTERVALS` and the `SQL_CONVERT_<type>` masks report what it
translates on the connected release (#301). The names Oracle shares (ABS, MOD,
ROUND, CONCAT, REPLACE, SOUNDEX, EXTRACT and so on) go through unchanged. The
others become Oracle forms, for example LOCATE → INSTR, LEFT → SUBSTR,
LOG → LN, `USER()` → USER, and CONVERT(v, SQL_INTEGER) → TRUNC(CAST(v AS NUMBER)).
How each family behaves:

- **Date and time:**
  - DAYOFWEEK counts from Sunday whatever NLS_TERRITORY says. WEEK starts weeks
    on Sunday, and week 1 holds January 1.
  - DAYNAME and MONTHNAME are in the session's language.
  - Oracle has no TIME type, so CURTIME and CURRENT_TIME return the current
    DATE with its time of day.
  - TIMESTAMPDIFF counts whole intervals from the first value to the second,
    rounded toward zero; it has no FRAC_SECOND.
  - From 9i, NOW, CURRENT_TIMESTAMP and TIMESTAMPADD keep TIMESTAMP's type and
    fraction (LOCALTIMESTAMP, INTERVAL arithmetic). 8i has neither, so it uses
    SYSDATE and day arithmetic, with no FRAC_SECOND. EXTRACT is Oracle's own on
    every release (#308).
- **CONVERT** goes between text, numbers, DATE and TIMESTAMP. Text in a date
  form is parsed by the session's NLS_DATE_FORMAT. SQL_DOUBLE / SQL_REAL become
  BINARY_DOUBLE / BINARY_FLOAT from 10g, and NUMBER before.
- **Not available:** DIFFERENCE and DATABASE are neither translated nor
  advertised: Oracle has no equivalent and no catalogs. `RAND()` becomes
  DBMS_RANDOM.VALUE, but SQL can't seed it, so RAND is not advertised either.
- **Parameter markers:** a translation keeps the arguments that hold markers in
  their order, and may repeat one (`{fn REPEAT(?, 2)}` is still one parameter).
  When it would swap two of them (`{fn LOCATE(?, ?)}`), the statement is refused
  with HYC00 rather than binding values to the wrong arguments.

## Datetime and interval literals

`SQL_DATETIME_LITERALS` reports the escapes the preprocessor translates on the
connected release (#305):

- **`{d '...'}` and `{ts '...'}`** become Oracle's DATE and TIMESTAMP literals.
- **`{t '...'}`** becomes a DATE whose time of day is the value. Oracle has no
  TIME type.
- **`{INTERVAL [+|-] '...' qualifier}`** becomes Oracle's INTERVAL literal,
  from 9i. Every ODBC qualifier is accepted, with leading and seconds
  precision (`DAY(3) TO SECOND(1)`, `SECOND(2,2)`). Oracle has no unary minus
  for an interval, so a sign outside the quotes moves inside them. A minus on
  a value that already has one cancels it.
- **8i** has no INTERVAL type, so there the escape stays as written and isn't
  advertised.

## SQL-92 capabilities in SQLGetInfo

The SQL-92 description masks say which statement forms each release accepts
as written (#306). `check_sql92_info` runs one statement per bit on every tier
and requires the bit to be set exactly when its statement runs. Oracle's own
spellings of a form don't count. `DROP TABLE ... CASCADE CONSTRAINTS`,
`ALTER TABLE ... MODIFY` and an implicit ON DELETE NO ACTION set no bit,
because the SQL-92 text (`CASCADE`, `ALTER COLUMN ... SET DEFAULT`, `ON DELETE
NO ACTION`) is refused.

- **Schema names** qualify tables in DML and DDL, indexes, privileges and
  procedure calls (`SQL_SCHEMA_USAGE`). There are no catalogs.
- **DDL:**
  - CREATE TABLE takes constraints (named, deferrable), defaults and global
    temporary tables;
  - ALTER TABLE adds columns (`ADD x ...`, without COLUMN) and constraints,
    drops columns, and drops a constraint with CASCADE;
  - CREATE VIEW takes WITH CHECK OPTION, but not CASCADED or LOCAL;
  - CREATE SCHEMA AUTHORIZATION;
  - CREATE and DROP INDEX, with ASC and DESC keys.
- **Foreign keys** take ON DELETE CASCADE and SET NULL. There is no ON UPDATE.
- **Releases differ:**
  - 8i has no ANSI joins, no CURRENT_DATE or CURRENT_TIMESTAMP, no simple
    CASE, COALESCE or NULLIF, and no DEFAULT in VALUES or SET;
  - EXCEPT is accepted from 21c;
  - INTERSECT, OVERLAPS, TRIM, `TRANSLATE ... USING` and EXTRACT work
    everywhere.
- **`SQL_KEYWORDS`** lists Oracle's reserved words that aren't ODBC keywords.
  None of them can name a column on any release.
- **Limits:**
  - 1000 columns per table (ORA-01792 past it);
  - 32 columns per index (ORA-01793);
  - 4000-character literals (ORA-01704);
  - procedure and user names as long as other identifiers (30, or 128 from
    12.2).

  Others, such as the select list, the statement length and the number of
  tables, report 0 because no fixed limit was found.

## SeerODBC-specific identifiers

Server features with no standard ODBC surface are exposed through
driver-specific identifiers. An application defines the numbers itself (they
are not in any Driver Manager header):

| Identifier | Value | Used with | Meaning |
|---|---|---|---|
| `SQL_DESC_SEER_ANNOTATIONS` | 19111 | `SQLColAttribute` (string) | 23ai column annotations as `name=value` lines |
| `SQL_ATTR_SEER_DML_ROW_COUNTS` | 19112 | `SQLSetStmtAttr` (`SQLLEN *`) | per-row affected counts of an array DML (12c+) |
| `SQL_DIAG_SEER_ERROR_OFFSET` | 19113 | `SQLGetDiagField` (`SQLINTEGER`) | the parse offset the server reported with an error |
| `SQL_DESC_SEER_VECTOR_DIMENSIONS` | 19114 | `SQLColAttribute` (numeric) | a VECTOR column's declared dimensions (0 = flexible) |
| `SQL_DESC_SEER_VECTOR_FORMAT` | 19115 | `SQLColAttribute` (numeric) | its element format: 2 FLOAT32, 3 FLOAT64, 4 INT8, 5 BINARY (0 = flexible) |

Diagnostics also follow the vendor's own clients: the native error of a failed
statement is its ORA number, and creating a PL/SQL object that compiled with
errors returns `SQL_SUCCESS_WITH_INFO` with SQLSTATE `01000`, native 24344.

## Not implemented (deliberate / future)

| Function | Why |
|----------|-----|
| SQLBulkOperations | Bookmark-based bulk ops; SeerODBC exposes no bookmarks. Reported unsupported by `SQLGetFunctions`; returns `HYC00`. `SQLSetPos` covers positioned UPDATE/DELETE. |

## Free from the Driver Manager (not implemented on purpose)

The DM maps ODBC 2.x calls onto our 3.x functions:
`SQLAllocEnv/Connect/Stmt → SQLAllocHandle`, `SQLError → SQLGetDiagRec`,
`SQLColAttributes → SQLColAttribute`, `SQLTransact → SQLEndTran`,
`SQLSetParam → SQLBindParameter`, `SQLExtendedFetch → SQLFetchScroll`, and the
`...Option` calls → the `...Attr` calls. The DM also owns Unicode A/W bridging
for any function where only one width is exported.

## Testing

- **Offline unit tests** (`tests/unit/`, no server): protocol codec (reader,
  writer, marshal), O5LOGON crypto vectors (10g/11g/12c), NUMBER/DATE/float
  codecs, the SQL preprocessor (`test_sqlprep`), and the SQL_C_* conversion
  matrix (`test_convert`). Run under ASan/UBSan via `meson test`.
- **Driver-level integration test** (`tests/odbc/test_integration.c`): drives
  the driver through the unixODBC Driver Manager against a live server (15
  checks across the surface, incl. data-at-execution). Self-gating - skipped
  (exit 77) unless
  `SEER_TEST_HOST/SERVICE/USER` are set, so offline `meson test` stays green.
  `SEER_TEST_RELEASE` names the server's release, which the skips key on:
  ```
  SEER_TEST_HOST=127.0.0.1 SEER_TEST_SERVICE=XE SEER_TEST_RELEASE=11 \
  SEER_TEST_USER=pyo SEER_TEST_PASS=pyo123 meson test -C build 'odbc integration'
  ```
  `tests/odbc/run-matrix.sh` runs it across every reachable server version and
  prints a support matrix — **all eight tiers, 8i to 26ai, pass** (8i in its own
  OALL8 dialect, 9i at fv2, 10g at fv4, 23ai natively at fv24). The script also
  runs the core-API suite (`tests/odbc/test_core.c`) on every tier.
  Both suites run one set of checks on every tier, 8i to 26ai, each skipped with
  its reason where the release lacks what it needs or SeerODBC doesn't reach it
  yet (`tests/odbc/gates.h`, keyed on the `SEER_TEST_RELEASE` the script passes
  per tier).
  Where the servers live is set by environment variables (`SEER_CONTAINER_HOST`
  for the container tiers, `SEER_9I_HOST` for the 9i VM, per-tier
  `SEER_<TIER>_{HOST,PORT,TARGET,USER,PASS}` overrides) or a gitignored
  `tests/odbc/matrix.env` (see `matrix.env.example`); `--only` / `--skip`
  select tiers, and an unreachable tier is reported and skipped. The run exits
  non-zero if any tier has a failing check.
- **Live validation**: each feature is exercised against the full
  8i/9i/10g/11g/18c/21c/23ai/26ai matrix through unixODBC (isql + C clients) and
  the core API. See
  `docs/ARCHITECTURE.md` "Protocol progress" and `docs/ROADMAP.md` for the
  per-feature inventory.
