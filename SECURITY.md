<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

SeerODBC is a database driver: it handles credentials, implements Oracle's
authentication crypto (O5LOGON / O3LOGON), parses untrusted data off the wire in
C, and can carry the session over TLS. Security reports are taken seriously.

## Supported versions

SeerODBC is pre-1.0 and under active development. Only the latest `master` is
supported — please reproduce against it before reporting.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/lemenkov/SeerODBC/security/advisories/new),
or by email to **lemenkov@gmail.com**.

Helpful details:

- the affected component (auth/crypto, the TNS/TTC parser, TLS transport, the
  ODBC shim) and the Oracle release involved;
- a reproduction or proof of concept, and the impact you observed;
- any relevant `SEER_LOG=debug` output, a backtrace, or a sanitizer report.

This is a solo, best-effort project — expect an initial acknowledgement within a
few days. Please allow a reasonable window to fix and release before public
disclosure; credit will be given unless you prefer to remain anonymous.

## Scope

Most relevant classes: memory-safety defects in the C protocol parser (the
codebase is developed under ASan/UBSan), authentication or credential-handling
flaws, and TLS/TCPS certificate-verification bypasses.
