<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Contributing to SeerODBC

SeerODBC reimplements a proprietary wire protocol (Oracle TNS/TTC) and a
published interface standard (ODBC). That posture asks more of its
contributors than an ordinary project. Please read this before sending code.

## Project posture: clean-room

SeerODBC is a **clean-room reverse-engineering** effort. We have no
relationship with Oracle Corporation and no access to Oracle's confidential
materials. The legal defensibility of the project depends on everyone keeping
to the rules below. This is the same posture as the sibling project
`pyoracle`, extended here to the ODBC layer.

### Allowed references

- The **Microsoft ODBC Programmer's Reference** and other public ODBC
  documentation (the ODBC API is a published standard).
- ODBC headers from **unixODBC** (LGPL) or **iODBC** (dual LGPL/BSD), used as
  build-time dependencies. We *depend on* these headers; we do not copy
  driver source.
- `pyoracle`'s `PROTOCOL.md` and its readable reference implementation
  (the protocol the two projects share is documented there).
- Public protocol descriptions: RFCs, blog posts, conference talks,
  community wikis, the Wireshark TNS dissector's *documentation*.
- **Your own packet captures** (Wireshark / tcpdump) of traffic between a
  stock client and a server you are authorized to use.

### Forbidden references

- **Oracle source code, headers, or SDKs** of any kind.
- **Decompiled or disassembled** Oracle binaries (OCI, the JDBC driver,
  sqlplus, the Instant Client, etc.).
- Oracle's confidential or licensed documentation.
- Code copied from any other ODBC driver, regardless of its license —
  including FreeTDS, psqlODBC, and unixODBC's sample driver. We read other
  drivers only to learn *structure*, never to copy *code*.

### How to capture protocol behavior

Reverse-engineer against a **stock client talking to a real server**, not
against SeerODBC's own output. A reference capture (e.g. on `lo`, port 1521)
shows exactly how the canonical client lays out each token, which makes the
wire layouts unambiguous rather than something to guess.

## Code conventions

- **C17** baseline. Use C23 features only behind
  `#if __STDC_VERSION__ >= 202311L` guards.
- The protocol core (`src/tns/`) must **not** include any ODBC header.
- All parsing of received bytes goes through the bounds-checked reader in
  `src/tns/reader.c`. Do not index a raw packet buffer anywhere else.
- Keep the driver's exported symbol surface to the `SQL*` entry points only
  (enforced by `src/odbc/seerodbc.map`).

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the rules in full.

## Sign-off

Commits should carry a `Signed-off-by` line (`git commit -s`), certifying the
[Developer Certificate of Origin](https://developercertificate.org/) — in
particular that your contribution does not draw on any forbidden reference.
