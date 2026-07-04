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
| [x] | SQLGetInfo | Oracle answer table (identifier quote, schemas-not-catalogs, txn, scroll options, …) |
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
| [x] | SQLRowCount / SQLCloseCursor / SQLFreeStmt | |
| [x] | SQLSetStmtAttr / SQLGetStmtAttr | paramset/row-array size, bind type, concurrency (SQL_CONCUR_LOCK → FOR UPDATE), status ptrs |

## Catalog (data-dictionary backed)

| Status | Function | Notes |
|--------|----------|-------|
| [x] | SQLTables / SQLColumns | |
| [x] | SQLPrimaryKeys / SQLForeignKeys | |
| [x] | SQLStatistics | ALL_INDEXES / ALL_IND_COLUMNS |
| [x] | SQLGetTypeInfo | type table |
| [x] | SQLProcedures / SQLProcedureColumns | ALL_OBJECTS / ALL_ARGUMENTS |
| [x] | SQLSpecialColumns | ROWID for SQL_BEST_ROWID |

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

## Not implemented (deliberate / future)

| Function | Why |
|----------|-----|
| SQLBulkOperations | Bookmark-based bulk ops; SeerODBC exposes no bookmarks. Reported unsupported by `SQLGetFunctions`; returns `HYC00`. `SQLSetPos` covers positioned UPDATE/DELETE. |
| Positioned UPDATE via `WHERE CURRENT OF` | `SQLSetPos` covers positioned DML via ROWID. |

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
  `SEER_TEST_HOST/SERVICE/USER` are set, so offline `meson test` stays green:
  ```
  SEER_TEST_HOST=127.0.0.1 SEER_TEST_SERVICE=XE \
  SEER_TEST_USER=pyo SEER_TEST_PASS=pyo123 meson test -C build 'odbc integration'
  ```
  `tests/odbc/run-matrix.sh` runs it across every reachable Oracle version and
  prints a support matrix — **10g, 11g, 21c and 23ai all pass** (10g at fv4, 23ai
  natively at fv24; the earlier 10g-login and 23ai-framing gaps are closed). The
  script also runs a local-only **9i** row via a dedicated core-API test
  (`tests/odbc/test_9i.c`): 9i speaks the legacy fv2 / `TTI_ALL7` dialect and is
  exercised through the `seer_*` core API rather than the Driver Manager.
- **Live validation**: each feature is exercised against the full 10g/11g/21c/23ai
  matrix through unixODBC (isql + C clients), plus the 9i core-API tier. See
  `docs/ARCHITECTURE.md` "Protocol progress" and `docs/ROADMAP.md` for the
  per-feature inventory.
