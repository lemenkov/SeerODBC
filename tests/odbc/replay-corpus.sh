#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
# SPDX-License-Identifier: Apache-2.0
#
# Replay the wire corpus offline (#396): each record in tests/fixtures/corpus
# (<tier>-<odbc|core>.wire, xz-compressed in the tree) is run again through
# its suite with SEER_WIRE_REPLAY set. No socket is opened: the driver's every
# send must match the record byte for byte and every read is answered from it.
# The suite's check lines must be the ones the live run gave (the header's
# "# expect" lines).
#
#   tests/odbc/replay-corpus.sh BUILD_DIR [RECORD...]
#
# BUILD_DIR must be configured with -Dwire_corpus=true. With no RECORD the
# whole corpus is replayed. Records are made with run-matrix.sh and
# SEER_MATRIX_RECORD_DIR; see tests/fixtures/corpus/README.md.
set -u

build="${1:?usage: replay-corpus.sh BUILD_DIR [RECORD...]}"
shift
here="$(cd "$(dirname "$0")" && pwd)"
corpus="$here/../fixtures/corpus"
if [[ $# -eq 0 ]]; then
    set -- "$corpus"/*.wire.xz
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
for rec in "$@"; do
    [[ -f "$rec" ]] || { echo "no record: $rec"; fail=1; continue; }
    name=$(basename "$rec" .xz)
    wire="$tmp/$name"
    case "$rec" in
        *.xz) xz -dc "$rec" >"$wire" || { echo "FAIL $name: can't unpack"; fail=1; continue; } ;;
        *) cp "$rec" "$wire" ;;
    esac
    suite=$(sed -n 's/^# suite //p' "$wire" | head -1)
    if [[ "$suite" != test_core && "$suite" != test_integration ]]; then
        echo "FAIL $name: no suite in its header"; fail=1; continue
    fi
    envs=()
    while IFS= read -r kv; do envs+=("$kv"); done < <(sed -n 's/^# env //p' "$wire")
    sed -n 's/^# expect //p' "$wire" >"$tmp/want"
    env "${envs[@]}" SEER_WIRE_REPLAY="$wire" "$build/tests/$suite" >"$tmp/out" 2>"$tmp/err"
    sed 's/\x1b\[[0-9;]*m//g' "$tmp/out" | grep -E '^ *(PASS|FAIL|SKIP) ' >"$tmp/got"
    if diff -q "$tmp/want" "$tmp/got" >/dev/null; then
        echo "ok   $name ($(wc -l <"$tmp/got") checks)"
    else
        fail=1
        echo "FAIL $name"
        grep -m3 'wire replay' "$tmp/err" | sed 's/^/     /'
        diff "$tmp/want" "$tmp/got" | head -8 | sed 's/^/     /'
    fi
done
exit $fail
