<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# The replay corpus

Each file here is one live run of a test suite against one server release:
every byte the driver sent and received, recorded inside the driver. A replay
runs the same suite again offline (#396). No socket is opened: each send must
match the record byte for byte, each read is answered from it, and the suite's
check lines must be the ones the live run gave. So both suites run on every
tier with no database: in CI, under ASan + UBSan, and on 8i, 9i, 10g, 18c and
26ai, which no public container image covers.

| file | what |
|---|---|
| `<tier>-odbc.wire.xz` | the ODBC suite (`test_integration`) through unixODBC |
| `<tier>-core.wire.xz` | the core-API suite (`test_core`) |

## Replay

```sh
meson setup build-corpus -Dwire_corpus=true
meson test -C build-corpus 'replay corpus'
# or one record, with its first difference reported:
tests/odbc/replay-corpus.sh build-corpus tests/fixtures/corpus/23ai-core.wire.xz
```

**Only a `wire_corpus` build can replay or record.** That build makes the
client's random values (the login's session keys and salts, native
encryption's Diffie-Hellman key) a fixed stream, and the process id, host name
and OS user fixed. The server's replies depend on them, so a replay can only
match if they repeat. For the same reason such a build must never be used for
anything but this: its logins are predictable.

## Record

When a change alters what goes on the wire, the records no longer match and
the replay says where. Re-record against the lab servers, which needs every
tier reachable, and review the diff:

```sh
meson setup build-corpus -Dwire_corpus=true && meson compile -C build-corpus
SEER_MATRIX_RECORD_DIR=/tmp/corpus tests/odbc/run-matrix.sh build-corpus
xz -9 -T0 /tmp/corpus/*.wire && mv /tmp/corpus/*.wire.xz tests/fixtures/corpus/
```

`run-matrix.sh` records each tier in `TZ=UTC`, and leaves out the TLS-proxy
leg, whose port and certificate change every run, so its check skips in a
recording.

## The record format

One event per line, after `#` header lines:
- `# suite` and `# env` lines: what the suite ran with;
- `# expect` lines: its check lines.

Then each connection, in the C2S / S2C form of seerdb's
`tools/capture_proxy.py`:
- `CONNECT <id> <host:port> ok|refused`;
- `C2S <id> <len>` or `S2C <id> <len>`, the bytes in hex on the next line;
- `RFAIL <id>`, a read that failed or timed out;
- `WAIT0 <id>`, a wait that found nothing in time;
- `OOB <id>`, a break;
- `CLOSE <id>`.

A replay repeats `RFAIL`, `WAIT0` and `OOB` where they happened, so the
timeout and cancel paths run as they did live, without the waiting.

26ai's records are larger: that server requires native encryption, so its
bytes are ciphertext, which doesn't compress. A replay decrypts them with the
same, fixed keys.
