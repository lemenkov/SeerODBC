<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# SeerODBC architecture

Two layers, strictly separated. The rule that everything else follows from:
**the protocol core does not know ODBC exists.**

```
  +------------------------------------------+
  |  ODBC shim            src/odbc/          |   the SQL* entry points
  |  - handles, connect, exec, results       |   maps ODBC's handle/descriptor
  |  - convert (SQL_C_* <-> native), diag,   |   model onto the core; absorbs
  |    info, attrs, catalog, descriptor      |   all ODBC quirks
  +------------------------------------------+
                    | uses include/seer/seertns.h only
                    v
  +------------------------------------------+
  |  TNS/TTC protocol core   src/tns/        |   speaks Oracle's wire protocol
  |  - reader/writer, packet, transport,     |   native C types only;
  |    auth, ttc, types, session             |   no sql.h anywhere here
  +------------------------------------------+
                    | both link
                    v
  +------------------------------------------+
  |  common   src/common/  (charset, log)    |
  +------------------------------------------+
```

`tools/freeoracle/` links the **core directly**, with no ODBC in the picture —
the DM-independent test path (our `tsql`).

## The five rules

1. **`src/tns/` includes no `sql.h`.** The core deals only in native C types
   and the API in `include/seer/seertns.h`. This keeps it reusable (a future
   Go/Rust/Python binding can FFI straight to it) and testable without a
   Driver Manager.
2. **All packet parsing goes through `src/tns/reader.c`.** Its bounds-checked
   cursor is the single chokepoint for untrusted server bytes; nothing else
   indexes a raw buffer. This is what recovers, in C, the safety a memory-safe
   language would have given the parser — and it's the natural fuzz target.
3. **`src/odbc/convert.c` is the only seam** that touches *both* ODBC C-types
   (`SQL_C_*`) and core native types. The messy type coercion has exactly one
   home. (This is where pyoracle's NUMBER/DATE decode work transplants.)
4. **The driver exports only `SQL*` symbols** (`src/odbc/seerodbc.map`).
   The core and OpenSSL stay out of the host process's dynamic symbol table —
   the same "don't pollute the host process" reasoning that ruled out GLib.
5. **`freeoracle` links the core, not the shim** — so the protocol can be
   proven end-to-end before the ODBC layer exists, and kept honest after.

## Build graph

```
  src/common  -> static_library(seercommon)          => common_dep
  src/tns     -> static_library(seertns)  [+openssl]  => seertns_dep
  src/odbc    -> shared_library(seerodbc)  [version-script]   (the driver)
  tools/...   -> executable(freeoracle)    [links seertns_dep]
  tests/...   -> executable(test_reader)   [links seertns_dep]
```

No cycles: `odbc` depends on `tns` depends on `common`; never the reverse.

## File layout

`src/odbc/` — the ODBC shim, split by concern: `handles.c`, `connect.c`,
`diag.c`, `info.c`, `attrs.c`, `exec.c` (Prepare/Execute/ExecDirect),
`results.c` (NumResultCols/DescribeCol/ColAttribute/Fetch/GetData/BindCol),
`convert.c` (the `SQL_C_*` conversion matrix), `catalog.c` (data-dictionary
catalog functions), `sqlprep.c` (the connection-free SQL preprocessor),
`unicode.c` (the `*W` entry points), and `seerodbc.map` (the exported-symbol
version script).

`src/tns/` — the protocol core: `transport.c` (TCP byte pipe), `packet.c` (TNS
8-byte framing), `reader.c` / `writer.c` (the bounds-checked receive/send
cursors), `session.c` (the TNS connection phase: CONNECT/ACCEPT/REDIRECT/
RESEND/REFUSE), `auth.c` (O5LOGON + 9i O3LOGON), `ttc.c` (negotiation + RPC),
`stmt.c` (execute / fetch / bind, incl. the fv2 `TTI_ALL7` path), `types.c`
(NUMBER/DATE/… codecs), plus `lob.c`, `marshal.c`, and `json.c` / `oson.c`.

`src/common/` — `charset.c` (iconv) and `log.c`.

## Protocol progress

- **Done — full 11g login.** TNS transport + connection phase (PROTOCOL.md
  §1-2), TTC negotiation (§3, §4.1-4.2), session setup + challenge (§4.3-4.4),
  and O5LOGON authentication (§4.5-4.6, the 11g 192-bit variant) plus clean
  teardown (§10). `seer_connect` now returns `SEER_OK` for an authenticated
  session: CONNECT/ACCEPT (with redirect/resend), TTI_PRO, TTI_DTY, TTI_SESS,
  then derives the AES-192 session key (`SHA1(password‖salt)`), exchanges
  session keys, encrypts the password, sends TTI_AUTH, validates
  `AUTH_SVR_RESPONSE`, and decodes `AUTH_VERSION_NO`. `seer_disconnect` sends
  TTI_LOGOFF + the TNS EOF marker.
  - Crypto lives in `auth.c` (OpenSSL EVP: AES-192-CBC / SHA-1 / MD5 / CSPRNG),
    unit-tested against the reference client's known-answer vectors. The
    `marshal` codec and the byte-identical 1190-byte TTI_DTY are likewise
    pinned. The whole login is proven end-to-end via `freeoracle` against a
    crypto-faithful mock server (mutual `SERVER_TO_CLIENT` validation passes).
  - Variants still stubbed (return `SEER_ENOTIMPL`): 10g (DES verifier, no
    salt), 12c+ (256-bit PBKDF2). 11g is the validated target.
- **Done — literal SELECT + fetch** (§5-6). `seer_stmt_prepare`/`execute`/
  `fetch` run a no-bind SELECT: `TTI_ALL8` execute (`stmt.c`, exec message
  pinned to the reference encoder), a response token walk (DCB describe / RXH /
  RXD / BVC differential rows / RPA piggyback / OER status), the `TTI_FETCH`
  continuation loop while the server reports more rows, and ORA-01403
  end-of-fetch masking. Multi-packet reassembly (SDU-37/-81 size test) is in
  `seer_ttc_recv`. Values are rendered to text in `types.c` — NUMBER (base-100)
  and DATE decoders, VARCHAR2/CHAR as AL32UTF8 — unit-tested against reference
  vectors. Proven end-to-end via `freeoracle -q` against a mock that serves a
  describe + rows. Columns accessible via `seer_stmt_num_cols` /
  `seer_stmt_col_name` / `seer_stmt_get_string`; `seer_last_error` surfaces the
  ORA-NNNNN text.
  - Not yet in the row decoder: LOB / LONG / ROWID columns (return
    `SEER_ENOTIMPL`), bind variables, and `SQL_C_*` typed conversion.
- **Done — query through a Driver Manager.** The ODBC shim (`src/odbc/`) drives
  the core end-to-end: real handle structs with a diagnostic record
  (`handles.c`, `diag.c`); `SQLConnect`/`SQLDriverConnect` parse the connection
  string and resolve the DSN's HOST/PORT/SERVICE from `odbc.ini` via
  `SQLGetPrivateProfileString` (`connect.c`); env/conn/stmt attributes
  (`attrs.c`); the `SQLGetInfo` Oracle answer table + `SQLGetFunctions`
  (`info.c`); `SQLPrepare`/`SQLExecute`/`SQLExecDirect` (`exec.c`); and
  `SQLNumResultCols`/`SQLDescribeCol`/`SQLColAttribute`/`SQLBindCol`/`SQLFetch`/
  `SQLGetData`/`SQLRowCount`/`SQLFreeStmt`/`SQLCloseCursor` (`results.c`). Values
  convert to `SQL_C_CHAR` and the common numeric C types. **Proven with stock
  `isql` against the unixODBC DM** (driver → mock server): connects, runs a
  `SELECT`, and renders the rows. Still only the 25 `SQL*` symbols are exported
  (`libodbcinst` is linked but not re-exported).
- **Done — bind variables.** The core takes positional input binds
  (`seer_stmt_bind_int64`/`_text`/`_null` in `stmt.c`): the execute message
  switches to options `0x8029` and emits one OAC descriptor per bind (§5.3)
  plus a single RXD token with the bind values (§5.4). NUMBER binds use the
  base-100 integer encoder (`seer_encode_number_int` in `types.c`, unit-tested
  incl. INT64 extremes round-tripping the decoder); text binds use `encode_chr`
  framing. The ODBC shim adds `SQLBindParameter` (deferred params read at
  execute, converted by C type — integers → NUMBER, char/float → text for
  Oracle implicit conversion) and `SQLNumParams`. Proven end-to-end: a mock
  decodes the bind section from the wire (`['42','hello']`) for both
  `freeoracle -N/-T` and a C client using `SQLBindParameter` through the DM.
- **Done — more column types.** The result decoder (`decode_cell` + `types.c`)
  now handles BINARY_FLOAT / BINARY_DOUBLE (order-preserving IEEE-754, §11.7,
  unit-tested), RAW (hex), and TIMESTAMP / TIMESTAMP WITH (LOCAL) TIME ZONE
  (routed to the DATE decoder), alongside NUMBER / VARCHAR2 / CHAR / DATE. The
  ODBC `SQLDescribeCol`/`SQLColAttribute` map each to its SQL type / type name /
  display size. Verified end-to-end: a mixed `NUMBER, VARCHAR2, BINARY_FLOAT,
  TIMESTAMP` row decodes to `42, hi, 1.5, 2026-06-18 14:30:00`.
- **Validated against a live Oracle 11g XE (11.2.0.2).** `freeoracle` and stock
  `isql` (through unixODBC) both log in and run literal + parameterized,
  single- and multi-row SELECTs returning NUMBER / VARCHAR2 / DATE /
  BINARY_DOUBLE, against a real server. The live run surfaced and fixed two
  bugs no mock caught:
  - **TNS_MARKER handling** (`seer_ttc_recv`): an errored call (e.g. a stray
    trailing `;`) comes bracketed by break/reset markers (§15); we now answer
    with one reset and drain to the inline error instead of failing.
  - **Lenient var-int decode** (`seer_dec_sb4`): a length byte of width 5..0x7f
    is a raw ub2/counter the OER reads through the var-int decoder — consume 2
    bytes, not `width`. Missing this over-read the OER tail on multi-statement
    sessions (worked by luck on single statements / mocks).
- **Done — catalog functions (`SQLTables` / `SQLColumns`), M2.** Each is a
  driver-generated SELECT against the data dictionary (`ALL_TABLES`/`ALL_VIEWS`,
  `ALL_TAB_COLUMNS`) in `catalog.c`, aliased to the exact ODBC result-set
  layout (5 and 18 columns), with the Oracle-text-type → ODBC-type-code mapping
  done in a SQL CASE, and name/schema args bound as LIKE patterns. Runs through
  the core via `seer_odbc_run_query` (exec.c) so the result reads back with
  ordinary SQLFetch/SQLGetData. Verified live: `SQLColumns(PYO.CAP_CHURN_1)`
  returns ID→NUMBER(3), C→CLOB(-1), B→BLOB(-4) with correct nullability.
- **Done — LOB read (`TTI_LOBOPS`, §14).** CLOB/BLOB *values* now come back. A
  LOB column yields only an opaque locator in the row; `stmt.c` captures the
  locator during parse and, once the cursor is fully drained, resolves each via
  `seer_lob_read` (`lob.c`) — a persistent-LOB READ round-trip that accumulates
  the `TTI_LOB` content chunks. CLOB content (UTF-16BE on the wire) is converted
  to UTF-8 via the now-real `seer_iconv` (`charset.c`, iconv); BLOB is rendered
  as hex. Deferring the reads to post-fetch avoids interleaving a LOBOPS call
  while the cursor still has rows pending. Verified live (freeoracle + isql):
  `TO_CLOB('…')`, multi-hundred-char CLOBs, `TO_BLOB(...)`, and LOBs mixed with
  scalar columns all round-trip.
- **Done — binary-safe cells, BLOB/LONG, more catalog.** The core row model is
  now `(data, len, binary)` cells (`SeerCell`) instead of C strings, with
  `seer_stmt_get_data` exposing raw bytes + a binary flag. So:
  - **BLOB / RAW** return real binary; the ODBC shim serves `SQL_C_BINARY` (raw)
    and `SQL_C_CHAR` (hex), both with proper fragmented `SQLGetData`/`SQLBindCol`
    (byte-offset tracking, 01004 on truncation). Verified live: a BLOB
    reassembled across [5][5][2] reads, a CLOB across 8-byte buffers.
  - **LONG / LONG RAW** columns decode (§11.10) - LONG as text, LONG RAW as
    binary. Verified on `ALL_VIEWS.TEXT`.
  - **`SQLGetTypeInfo`** (static type table), **`SQLPrimaryKeys`**, and
    **`SQLStatistics`** (data-dictionary SELECTs). Verified live on `PYO.T_BE`.
  - `seer_iconv` (charset.c) is now a real iconv loop (CLOB UTF-16BE -> UTF-8).
  34 `SQL*` symbols exported, no leakage.
- **Done — conversion matrix + transactions + DML.** `convert.c` is now the
  real SQL_C_* seam: the full integer family, float/double, `SQL_C_NUMERIC`,
  `SQL_C_TYPE_TIMESTAMP`/`DATE`/`TIME` (parsed from the canonical text),
  `SQL_C_BIT`, binary and char/hex with fragmentation. Verified live
  (SLONG/DOUBLE/DATE/TIMESTAMP/BIT). Transactions: a per-connection autocommit
  flag drives the OALL8 `0x100` option, with `seer_commit`/`seer_rollback`
  (TTI_COMMIT/ROLLBACK) behind `SQLEndTran` + `SQL_ATTR_AUTOCOMMIT`. Statement
  classification (`build_exec`) now sends the right option set / All8 type for
  SELECT vs PL/SQL block vs DML/DDL - **DML/DDL had silently always used the
  SELECT option set**; with that fixed, INSERT/UPDATE/DELETE/CREATE work and
  `SQLRowCount` reports DML affected rows (from the OER). Verified live:
  autocommit off rollback/commit, autocommit on, and **committed rows persist
  across reconnect**.
- **Done — PL/SQL blocks, more bind types, and `?` markers.** `build_exec`
  classifies SELECT / PL-SQL block / DML-DDL; `parse_iov` consumes the
  `TTI_IOV` response so anonymous blocks (`BEGIN … END;`) execute. Binds now
  cover RAW (`SQL_C_BINARY`), DATE/TIMESTAMP (from the C date structs, native
  7-byte DATE), and native BINARY_DOUBLE (`SQL_C_DOUBLE`/`FLOAT`), alongside
  NUMBER and text - the `SeerBind` carries its OAC type/size/charset/flag. And
  crucially, the shim now rewrites ODBC `?` parameter markers to Oracle's
  `:1`, `:2`, … (string-literal aware) - **without this no standard ODBC app's
  parameterized queries worked**, since they all use `?`. `SQLFreeStmt
  (SQL_RESET_PARAMS)` clears bindings. Verified live: a 4-column typed-bind
  INSERT (DATE/RAW/BINARY_DOUBLE/VARCHAR) round-trips, and `WHERE f > ?` binds.
- **Done — PL/SQL OUT parameters.** A `SeerBind` carries a direction and a
  captured `out` cell; `seer_stmt_bind_out` declares an OUT param's OAC (typed,
  sized, NULL RXD placeholder); `parse_iov` now reads the server's per-bind
  directions and decodes each OUT value (per the bind's type) into the bind,
  retrievable via `seer_stmt_out_data` (`decode_scalar` is shared with column
  decode). The shim records each parameter's direction/type/size in
  `SQLBindParameter`, binds OUT params, and after execute converts the captured
  values into the app's buffers via `seer_odbc_convert`. Verified live: an
  anonymous block returning NUMBER/VARCHAR/DATE OUTs, and a stored procedure
  `seer_p(IN, OUT, OUT)` called as `BEGIN seer_p(?,?,?); END;` (b=50, c='got 5').
- **Done — `{call}` escape + `SQLDescribeParam`.** The statement preprocessor
  (`exec.c`) expands the ODBC `{call proc(?)}` and `{?=call func(?)}` escapes to
  `BEGIN proc(?); END;` / `BEGIN ? := func(?); END;` (brace/quote-aware) before
  the `?`->`:n` rewrite, so the standard ODBC way to invoke procedures and
  functions works (the `{?=call}` return value is OUT parameter 1).
  `SQLDescribeParam` reports a generic SQL_VARCHAR descriptor (Oracle does not
  describe placeholders pre-execute). Verified live: `{call seer_p(5,?,?)}` ->
  b=50,c='got 5' and `{? = call seer_f(7)}` -> 107.
- **Done — inline escapes + `SQLForeignKeys`/`SQLProcedures`.** The preprocessor
  now also translates inline ODBC escapes anywhere in the text (quote/nesting
  aware, recursive): `{d}`->DATE, `{ts}`->TIMESTAMP, `{t}`->TO_DATE(...),
  `{fn F(args)}`->F (with a small UCASE/LCASE/SUBSTRING/IFNULL/CEILING/TRUNCATE
  alias table), `{oj}`/`{escape}` unwrapped. `SQLForeignKeys` (the ALL_CONSTRAINTS
  R-type 4-way join) and `SQLProcedures` (ALL_OBJECTS) round out catalog
  metadata. Verified live: `{fn UCASE/SUBSTRING/LENGTH/IFNULL}`, `{d}`/`{ts}`
  literals, a parent/child FK, and a listed procedure.
- **Done — REF CURSOR OUT parameters.** A PL/SQL OUT bind of type REF CURSOR
  (Oracle type 102, OAC charset 871, RXD placeholder `{1,0}`) comes back in the
  IOV as an inline describe + nested cursor id (`parse_refcursor_out`, sharing
  `parse_describe_body` with the DCB path). After execute the core adopts that
  describe as the statement's result set and drains the nested cursor with
  TTI_FETCH - so a proc returning `SYS_REFCURSOR` reads exactly like a query.
  The shim exposes it via the `SQL_REFCURSOR` (-9999) extension SQL type: bind
  `SQLBindParameter(..., SQL_PARAM_OUTPUT, SQL_C_DEFAULT, SQL_REFCURSOR, ...)`,
  execute, then `SQLNumResultCols`/`SQLFetch`/`SQLGetData`. Verified live:
  `{call seer_rc(?)}` opening a 3-row cursor fetched back in full.
- **Done — 10g / 12c auth variants.** `auth.c` now dispatches on the verifier
  the server offers (`seer_o5logon`): AUTH_VFR_DATA only -> 11g AES-192/SHA-1
  (unchanged); both AUTH_VFR_DATA + AUTH_PBKDF2_CSK_SALT -> 12c AES-256, KeySess
  via PBKDF2-SHA512(4096)+SHA-512, ConnKey via PBKDF2-SHA512(uppercase-hex,3),
  plus AUTH_PBKDF2_SPEEDY_KEY; neither -> 10g AES-128 over the legacy DES
  verifier (uppercased UTF-16BE user||password, double DES-CBC). The primitives
  generalized to AES-128/192/256 + DES (OpenSSL 3 legacy provider loaded on
  demand) + SHA-512 + PBKDF2; `o5logon0` is now size-parameterized. Verified:
  11g live (regression through the new dispatcher) and 10g/12c via deterministic
  known-answer vectors pinned to the reference's real-capture ground truth
  (DES verifier vs a live 10.2.0.5 `sys.user$`, 256-bit ConnKey vs oracledb).
  The salt-less-but-derived 128-bit scheme stays ENOTIMPL.
- **Done — array (bulk) parameter binding.** `SeerBind` now holds a value per
  iteration; `seer_stmt_set_array_size`/`seer_stmt_bind_row` declare N rows and
  select the current one. `build_exec` sets the OALL8 iteration count
  (`All8[1] = N`), emits one OAC per position (sized to the widest value across
  rows), then one RXD token per row (the n=1 wire is byte-identical to before).
  The shim honours `SQL_ATTR_PARAMSET_SIZE` (column-wise arrays: row i read at
  `buf + i*stride`, per-row indicator array) and writes
  `PARAMS_PROCESSED_PTR` / `PARAM_STATUS_PTR`. Verified live: a 5-row INSERT in
  one execute (`processed=5, rowcount=5`, per-row NULL honoured). OUT/array is
  single-row only; row-wise binding (`PARAM_BIND_TYPE`) is a follow-up.
- **Done — row-array (block) fetch.** The shim honours `SQL_ATTR_ROW_ARRAY_SIZE`:
  one `SQLFetch` advances the core up to R times and delivers each row into the
  bound column arrays (`deliver_row`), column-wise (`buf + row*stride`, indicator
  `&ind[row]`) or row-wise (`+ row*ROW_BIND_TYPE`), writing `ROWS_FETCHED_PTR`
  and `ROW_STATUS_PTR` (`SQL_ROW_SUCCESS`/`SQL_ROW_NOROW`); 0 rows -> SQL_NO_DATA.
  The core already materializes the whole result set, so this is a pure shim
  feature; R=1 is byte-identical to the old single-row fetch. Verified live: a
  7-row result delivered as blocks of 3+3+1.
- **Done — scrollable cursors (`SQLFetchScroll` / `SQLSetPos`).** The whole
  result set is already buffered, so a static scrollable cursor is just random
  positioning: `seer_stmt_set_row` seeks the core to any 0-based row, the shim
  tracks the rowset start, and `fetch_rowset(start)` (shared with `SQLFetch`)
  delivers the block. `SQLFetchScroll` implements NEXT/PRIOR/FIRST/LAST/
  ABSOLUTE/RELATIVE (out-of-range -> SQL_NO_DATA); `SQLSetPos` does POSITION
  (point the cursor for `SQLGetData`) and REFRESH; positioned update/delete and
  bookmarks are HYC00. `SQLGetInfo` reports SQL_SO_STATIC. Verified live over a
  7-row set with rowset size 2: every orientation lands on the right rows.
- **Done — `SQL_C_WCHAR` (UTF-16).** The convert layer gains a wide path: on
  fetch, the column's UTF-8 is `iconv`'d to UTF-16 (host byte order, `SEER_UTF16`)
  and copied with offset tracking, a 2-byte NUL, and a byte-length indicator
  (`copy_wide`, code-unit-aligned truncation -> 01004); on bind, a `SQL_C_WCHAR`
  parameter (length in bytes, or SQL_NTS = 16-bit-NUL-terminated) is `iconv`'d
  UTF-16 -> UTF-8 and bound as text. The shim exports only ANSI entry points, so
  the DM forwards explicit `SQL_C_WCHAR` requests straight through. Verified
  live: a Cyrillic/accented string round-trips bind->readback and fetch (byte-
  exact), and a short buffer truncates cleanly with SQL_SUCCESS_WITH_INFO.
- **Done — Unicode (`*W`) entry points.** `src/odbc/unicode.c` exports the wide
  variants (`SQLConnectW`, `SQLDriverConnectW`, `SQLPrepareW`, `SQLExecDirectW`,
  `SQLGetDiagRecW`, `SQLGetInfoW`, `SQLDescribeColW`, `SQLColAttributeW`,
  `SQLTablesW`, `SQLColumnsW`, `SQLGetTypeInfoW`), which flags us as a Unicode
  driver: the DM routes wide apps here and keeps ANSI apps on the A functions.
  Input wrappers convert SQLWCHAR (UTF-16, `SEER_UTF16`) -> UTF-8 and delegate;
  output wrappers call the A function into a UTF-8 scratch buffer and widen the
  result (char-unit lengths for names/diags, byte-unit for GetInfo/ColAttribute).
  **Key build detail:** the shim links with `-Wl,-Bsymbolic` so a `*W` wrapper's
  call to an ANSI `SQL*` binds to OUR definition, not the Driver Manager's
  identically-named global symbol (which would reject our internal handle).
  Verified live: a fully-wide app connects, runs wide SQL, reads wide column
  names + a Cyrillic value + a wide error message; the ANSI path (isql + bound
  params + describe) is unaffected.
- **Done — `SQLProcedureColumns` / `SQLSpecialColumns`** (catalog surface
  complete). `SQLProcedureColumns` reads `ALL_ARGUMENTS` (top-level args,
  DATA_LEVEL 0): POSITION 0 -> SQL_RETURN_VALUE, IN/OUT/IN OUT -> SQL_PARAM_*,
  DATA_TYPE via the shared type CASE. `SQLSpecialColumns` returns the ROWID
  pseudo-column for SQL_BEST_ROWID (from ALL_TABLES; SCOPE_SESSION, PC_PSEUDO,
  SQL_VARCHAR(18)) and an empty 8-column set for SQL_ROWVER (Oracle has no
  auto-updated row-version column). Verified live. The catalog set is now
  Tables/Columns/PrimaryKeys/ForeignKeys/Statistics/GetTypeInfo/Procedures/
  ProcedureColumns/SpecialColumns.
- **Done — named (`:name`) bind markers + `SQLNumParams` counting.** Native
  Oracle `:name` / `:n` placeholders already bind correctly (the `?`->`:n`
  rewrite leaves them alone and the server matches our positional OACs to the
  parsed placeholders, de-duplicating a repeated `:name` to one bind). The gap
  was structural: `SQLNumParams` returned the bound count (0 before binding).
  It now parses the prepared statement (`count_params`) - counting `?`(=`:n`)
  and distinct `:name`, de-duped case-insensitively, ignoring placeholders in
  string/identifier literals, line/block comments, and the PL/SQL `:=` - so the
  marker count is available right after `SQLPrepare`, as ODBC requires. Verified
  live across all those cases.
- **Done — positioned update/delete (`SQLSetPos` SQL_UPDATE / SQL_DELETE).**
  Gated on `SQL_ATTR_CONCURRENCY` != READ_ONLY: `make_updatable` recognizes a
  simple single-table SELECT (conservative parse - rejects joins, set ops,
  GROUP/DISTINCT, subquery FROM) and appends `ROWIDTOCHAR(ROWID)` (qualifying a
  bare `*`). That column is hidden via `odbc_visible_cols` (it is always last,
  so visible column numbers map straight through); each row's ROWID is captured
  after execute. `SQLSetPos` then synthesizes `DELETE FROM t WHERE ROWID = :r`
  or `UPDATE t SET <bound col> = :k ... WHERE ROWID = :r` (values from the bound
  rowset buffers), run on a throwaway core statement - safe because the core
  fully buffers the result set, so no cursor is mid-fetch. RowNumber 0 applies
  to the whole rowset. Verified live: update one row, delete another, rest
  intact. Read-only cursors are untouched (no ROWID overhead).
- **Done — consolidation pass.** Extracted the connection-free, intricate
  logic - the SQL preprocessor (escape expansion, `?`→`:n`, parameter counting,
  updatable-cursor rewrite) into `src/odbc/sqlprep.c` and the `SQL_C_*`
  conversion matrix in `convert.c` - into a `seerodbcpure` static library that
  the shim links and the new **offline** unit tests (`test_sqlprep`,
  `test_convert`) link directly. Those run under ASan/UBSan with no Driver
  Manager or server, turning previously throwaway live checks into permanent
  regression guards (now 7/7 unit tests). Refreshed `docs/ODBC_CONFORMANCE.md`
  (accurate implemented-function matrix) and the README (status + what-works).
  No behavior change: 53 `SQL*` exported, nothing else leaked, live smoke green.
- **Done — BFILE read (`TTI_LOBOPS` FILE_OPEN/READ/CLOSE, §19.8).** A BFILE
  column (Oracle type 114) arrives in the RXD as a locator like CLOB/BLOB (same
  `ub4 num_bytes | DALC` framing, so `read_lob_locator` is shared) and is
  deferred to the post-fetch resolve pass. Unlike a persistent LOB, an external
  file must be opened first: `seer_bfile_read` (`lob.c`) strips the locator's
  leading `ub2` inner-length, sends **FILE_OPEN** (op `0x0100`, read-only mode
  `0x0B`) and reads the **updated, open-flagged locator** back from the reply
  RPA, **READs** that locator (ub2-length-prefixed, like temp LOBs), then
  **FILE_CLOSEs** it unconditionally (so an opened file is always released). The
  one TTI_LOBOPS field block now serves every opcode via a generalized
  `build_lobop` (operation / prefixed-locator / source-offset / trailing
  amount-or-mode), with the chunk accumulator shared with the CLOB/BLOB READ.
  The shim maps type 114 to `SQL_LONGVARBINARY` / `"BFILE"`; content is served
  as raw bytes (`SQL_C_BINARY`) or hex (`SQL_C_CHAR`), exactly like BLOB.
  Verified live (freeoracle + isql through unixODBC) against a real 11g XE
  `SELECT BFILENAME('SEERBFILE', …)`: a text file and a binary file round-trip
  byte-exact, a missing file (ORA-22288) fails the read gracefully (NULL cell,
  no session desync), and a missing-then-valid two-BFILE row proves the failed
  FILE_OPEN leaves the stream resynchronized for the next read.
- **Done — array-DML batch-error mode (`batcherrors`, §5.1 / §6.7).** An array
  (`SQL_ATTR_PARAMSET_SIZE` > 1) INSERT/UPDATE/DELETE now runs in batch-errors
  mode: `build_exec` ORs `0x80000` into the OALL8 options, so a per-row failure
  no longer aborts the batch - the good rows apply and the failures come back in
  the OER's batch code/offset/message arrays (`parse_oer` captures them instead
  of skipping; the non-fatal `ORA-24381` summary is allowed through). The core
  exposes them via `seer_stmt_set_batch_errors` / `_batch_error_count` /
  `_batch_error`. The shim arms the mode for any array DML and, after execute,
  sets `SQL_ATTR_PARAM_STATUS_PTR` per row (`SQL_PARAM_SUCCESS` / `_ERROR`),
  writes `PARAMS_PROCESSED`, and returns `SQL_SUCCESS_WITH_INFO` (or `SQL_ERROR`
  if every row failed). To surface per-row errors the **diagnostic record was
  upgraded from a single record to a growable queue** (`diag.c`): each failed
  row posts a record carrying its 1-based `SQL_DIAG_ROW_NUMBER`, and
  `SQLGetDiagRec` / `SQLGetDiagField` index the queue (`SQL_DIAG_NUMBER` reports
  the count). Verified live on 11g XE through unixODBC (despite the protocol
  note tagging batcherrors 12c+): a 5-row INSERT with one duplicate PK commits
  the 4 good rows, flags row offset 2 `SQL_PARAM_ERROR`, and yields one
  `ORA-00001` diag at row 3; an all-duplicate batch returns `SQL_ERROR` with
  five row-numbered diags and commits nothing.
- **Done — `FOR UPDATE` locking-hint passthrough (`SQL_CONCUR_LOCK`).** The
  updatable-cursor rewrite (`seer_sql_make_updatable`) gained a `lock` flag:
  when the app sets `SQL_ATTR_CONCURRENCY = SQL_CONCUR_LOCK`, the simple
  single-table SELECT that already gets `ROWIDTOCHAR(ROWID)` appended also gets
  a trailing `FOR UPDATE` (skipped if the statement already carries one), so the
  fetched rows are row-locked until the transaction ends - real pessimistic
  concurrency behind `SQLSetPos` positioned UPDATE/DELETE. The optimistic modes
  (`SQL_CONCUR_ROWVER`/`_VALUES`) keep the ROWID rewrite without locking. The
  shape we accept (single table, no joins/sets/GROUP/DISTINCT/subquery) is
  exactly what `FOR UPDATE` allows. Offline-tested in `test_sqlprep` (FOR UPDATE
  appended after WHERE/ORDER BY, not doubled, absent without the flag); verified
  live on 11g XE with two sessions - a `SQL_CONCUR_LOCK` fetch blocks a
  concurrent `FOR UPDATE NOWAIT` with ORA-00054, while a `SQL_CONCUR_ROWVER`
  fetch leaves it free.
- **Done — driver-level integration test harness + version matrix.**
  `tests/odbc/test_integration.c` drives the driver *through the unixODBC Driver
  Manager* (`SQLDriverConnect` with `DRIVER=<built .so>`) against a live server,
  running 14 checks across the surface: typed scalar fetch (NUMBER / VARCHAR2 /
  DATE), `?` binds, DDL + INSERT + `SQLRowCount`, transaction rollback, array
  DML with batch-error row status, `SQLColumns`, `SQL_CONCUR_LOCK`, and CLOB /
  BLOB. It is **self-gating** - with no `SEER_TEST_HOST/SERVICE/USER` set it
  exits 77 (meson "skip"), so an offline `meson test` stays green; the driver
  `.so` path is baked in at compile time (overridable via `SEER_DRIVER`). Each
  check is independent and error-trapped, so the same binary measures any
  server version. `tests/odbc/run-matrix.sh` runs it against every reachable
  container and prints a support matrix. First run (driver speaks fv=6 / 11g
  framing to all):
  After the three fixes below, the matrix is **green across 10g / 11g / 21c /
  23ai - 14/14 each** (all at the fv=6 framing we negotiate). Original run and
  what each version needed:
  - **11g** (11.2 XE) and **21c** (XEPDB1): 14/14 out of the box - 21c speaks
    11g-compat at fv=6.
  - **23ai** (FREEPDB1): was 13/14 - the *first statement of a connection*
    failed; fixed below.
  - **10g** (orcl, 10.2): was connect-fail, then 3/14 after the auth fix, now
    14/14 after the fv=4 describe fix (both below).
- **Done — 10g live login (legacy DES verifier).** The first live 10g handshake
  exposed a one-line bug: `parse_challenge` (`ttc.c`) required *both*
  `AUTH_SESSKEY` and `AUTH_VFR_DATA`, but a 10g account carrying only the legacy
  DES verifier sends `AUTH_SESSKEY` plus an **empty** `AUTH_VFR_DATA` (no SHA-1
  salt). `seer_o5logon` was already built for this (`salt == NULL` -> derive the
  AES-128 key from the 8-byte DES verifier), so dropping the salt requirement
  from the guard is all it took. Verified live against 10.2.0.5: authenticates,
  and DDL / INSERT+`SQLRowCount` / array-DML round-trip. (This is the first time
  the 10g path ran end to end against a real server - previously only the DES
  crypto was unit-tested, since the live box had always been 11g.)
- **Done — fv=4 (10g) SELECT describe decode.** Two fields in the describe are
  11g additions that a 10g (field version 4) server omits: the per-column
  `uds flags` (a ub4 after the column position) and the describe trailer's
  `dcbqcky` (the query-cache key, which arrived with the 11g result cache).
  `parse_describe_body` read both unconditionally, so on 10g it consumed the
  next column's bytes / the first row token and desynced the whole decode
  (`unexpected response token 1`). Gating both on the negotiated field version
  (`fv >= 6`) - threaded into `parse_describe_body` from `parse_dcb` and
  `parse_refcursor_out` - fixes it. **10g is now 14/14** (full SELECT, typed
  fetch, binds, catalog, LOB, FOR UPDATE); 11g/21c unchanged at 14/14 (they send
  the 11g describe, so the gate is a no-op there). Verified live on 10.2.0.5.
- **Done — 23ai first-response server-capability block.** Talking the fv=6
  framing we negotiate, a 23ai server injects a one-time block on the *first*
  execute of a connection, between the RPA return-parameter fields and the
  trailing OER: a short header, then a `ub1 L` immediately followed by an equal
  `ub4` little-endian L, then L bytes (L=100 here - a sorted list of ~23 server
  feature/function codes), after which the OER begins. `skip_rpa` walked the
  RPA's `Num` fields fine but then landed on this block instead of a token and
  desynced (`unexpected response token 1`); subsequent statements have no block
  and decoded fine, which is why only the first failed. The fix
  (`skip_capability_block`) fires only when the post-RPA position is *not* a
  known token (10g/11g/21c land directly on the OER, so they never enter it),
  locates the `<ub1 L><ub4le L>` self-length, skips L bytes, and commits **only
  if** that lands on a known token - otherwise it leaves the reader untouched
  for the normal error path (no regression). 23ai is now **14/14**; the others
  are unchanged. The clean long-term fix is to negotiate the 23ai field version
  (fv24), whose framing carries no such block - part of the field-version
  milestone below.
- **Done — data-at-execution (`SQLParamData` / `SQLPutData`).** A single-row
  INPUT parameter bound with `SQL_DATA_AT_EXEC` is no longer required up front:
  `exec_core` splits into a prepare step and `exec_finish`, and when a used
  marker's bound indicator is data-at-exec it returns `SQL_NEED_DATA` instead of
  executing. `SQLParamData` then hands the app each such parameter's token (its
  `ParameterValuePtr`), `SQLPutData` accumulates the streamed chunks into a
  per-param buffer (`dae_buf`), and the final `SQLParamData` binds the assembled
  values and runs `exec_finish`. Only markers the statement actually uses count
  (a leftover data-at-exec binding can't turn a later paramless execute into
  `SQL_NEED_DATA`). 55 `SQL*` symbols now (was 53); `SQLGetFunctions` advertises
  both. Verified live (a value streamed in three `SQLPutData` chunks round-trips
  byte-exact) and added as a 15th integration check - **green on 10g/11g/21c/23ai
  (15/15 each)**.
- **In progress — 12c+ field version (the fv24 milestone), phase 1.** We
  previously hard-capped the negotiated TTC field version at 6 (11g framing) and
  spoke fv6 to every server. Phase 1 lifts that for 12c+ servers, gated behind
  `SEER_MAX_FV` (default stays 6, so the fv6 matrix is **byte-identical and
  unaffected** - all four versions remain 15/15). With `SEER_MAX_FV=16`, 21c and
  23ai negotiate fv16 and exercise the native 12c+ wire forms, all version-gated
  so the fv6 path is untouched:
  - **TTI_DTY**: the 12c capability vector (the oracledb 21.1 base, 53/11-byte
    compile/runtime, `CCAP_FIELD_VERSION` patched per negotiated version) and
    the flat UB2 datatype table (flag 3), vs the 11g 1-byte identity map.
  - **Auth**: the 12c `TTI_SESS` (5 pairs, leading `AUTH_TERMINAL`,
    length-prefixed username) and `TTI_AUTH` (length-prefixed username). The
    challenge dispatches to the existing **AES-256/PBKDF2** path - now
    **live-validated for the first time** (auth succeeds against 21c 21.0.48).
  - **Execute**: the 12c OALL8 carries the `al8pidmlrc` block, the
    `al8sqlsig`/SQL-id slot and (12.2_EXT1+) chunk-id pointers, and the SQL is
    length-prefixed.
  - **Describe**: `sb1` scale + an `oaccolid` ub4 after max_size (12.2+).
  - **OER**: the extended error-number + rowcount (12.1+) and SQL-type +
    checksum (20.1+) before the trailing message.
  - **Bind OAC**: the 12c `USE_INDICATORS` form (cont-flag, OID/version, ub2
    charset + csfrm, LOB-prefetch, oaccolid), vs 11g's `encode_token_raw`.
  Result: **21c / 23ai at fv16 pass 13/15** of the integration checks natively
  (typed fetch, binds, DML, array DML + batch errors, catalog, transactions,
  FOR UPDATE, data-at-exec). **Remaining: LOB** at 12c (the locator / LOBOPS
  path desyncs - 2 checks).
- **Next:** finish 12c LOB (CLOB/BLOB at fv16); then **phase 2** - fast-auth
  (`0x22` bundle) + the fv24 framing (an extra function-header byte, annotations
  / vector descriptors) to reach fv24 natively on 23ai and retire the
  capability-block workaround; flip the `SEER_MAX_FV` default once LOB lands.
  This unlocks `arraydmlrowcounts` and implicit result sets. Smaller items:
  catalog `*W` variants (DM bridges them); `SQLNativeSql`.
- **Update — fv24 complete, and well beyond.** Both phases landed: 12c+ LOB, the
  `0x22` fast-auth bundle and the fv24 framing all work; `TTC_FIELD_VERSION_23_4`
  (24) is now the **default** cap (servers negotiate down via `min(server_fv,
  cap)`), and 23ai reaches fv24 natively. The integration matrix is green on
  **10g / 11g / 21c / 23ai**. Since then the driver has grown a large feature
  surface — SQL objects / collections (incl. the deep tail: collections-of-objects,
  objects-with-collection attributes, OUT associative arrays), XMLType (fetch +
  bind, LOB-backed), native JSON + VECTOR binds (all element types incl. sparse),
  Advanced Queuing, XA / two-phase commit, proxy auth + DRCP, TLS / TCPS, and
  statement caching — each matrix-validated and ASan/UBSan-clean. `docs/ROADMAP.md`
  is the live per-feature inventory.
- **Done — Oracle 9i (fv2).** The legacy tier landed too: O3LOGON DES auth and the
  `TTI_ALL7` (`0x47`) query/DML/PL-SQL/LOB dialect (distinct from the `TTI_ALL8` we
  send 10g+), all fv-gated so 10g+ is untouched. Validated against a 9i VM (not
  containerizable) and wired into `run-matrix.sh` as a local-only core-API row, so
  the driver now spans **field versions 2–24** across 9i/10g/11g/21c/23ai. The
  repository is also **REUSE 3.3 compliant** (SPDX tags on every file). The
  remaining gaps are environment-blocked (12c–19c containers, Kerberos, RAC/TAF) or
  deep reverse-engineering without a reference (CQN, server-side scroll framing).

## Language baseline

C17. C23 features only behind `#if __STDC_VERSION__ >= 202311L` so the
codebase keeps building on older toolchains.
