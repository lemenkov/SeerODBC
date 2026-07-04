<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# Oracle TNS/TTC wire protocol notes

This document is the **shared protocol asset** between SeerODBC and the
sibling project `pyoracle`. pyoracle's `PROTOCOL.md` is the more mature
reference today; SeerODBC's core is implemented against that specification,
not by copying pyoracle's Python.

> Clean-room reminder: everything here is derived from public references and
> our own packet captures of a stock client talking to an authorized server.
> No Oracle source, no decompiled binaries. See `CONTRIBUTING.md`.

## Scope

- Target **11g** first; keep version negotiation abstracted so **12c** slots
  in without restructuring.
- Transport: TCP (port 1521) and TCPS/TLS (port 2484, via OpenSSL).

## Layers (to be documented as implemented)

1. **TNS** — the framing layer: Connect / Accept / Refuse / Redirect / Data /
   Marker packets, packet header, negotiated SDU/TDU sizes, fragmentation.
2. **TTC (TTI)** — the application layer riding on TNS Data packets:
   protocol negotiation, data-type negotiation, RPC opcodes, the OAC
   (Oracle Access descriptor) column format, row/bind-vector encoding.
3. **Authentication** — O5LOGON (and the older O3LOGON), using AES-CBC + SHA
   session-key exchange. Primitives come from OpenSSL `EVP_*`.
4. **Type decoding** — NUMBER, DATE/TIMESTAMP, VARCHAR2/CHAR, RAW, the LOB
   locators, etc. (the wire <-> native mapping in `src/tns/types.c`).

## Not TLS: Oracle Native Network Encryption

Distinct from TCPS/TLS. It is a proprietary scheme negotiated inside the TNS
handshake (Diffie-Hellman key exchange, then AES/3DES/RC4). OpenSSL provides
the cryptographic primitives but **none of the framing** — that framing is
reverse-engineering work, tracked separately from the TLS transport path.

## References

- pyoracle `PROTOCOL.md` and its reference implementation.
- Public TNS/TTC protocol descriptions; the Wireshark TNS dissector's
  documented field layouts.
- Our own `tcpdump`/`tshark` captures.
