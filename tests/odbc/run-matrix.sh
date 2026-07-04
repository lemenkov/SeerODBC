#!/usr/bin/env bash

# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0
set -u

BUILD="${1:-build}"
BIN="$BUILD/tests/test_integration"
TPC_BIN="$BUILD/tests/test_tpc"
OBJBIND_BIN="$BUILD/tests/test_objbind"
AQ_BIN="$BUILD/tests/test_aq"
NINE_BIN="$BUILD/tests/test_9i"
if [[ ! -x "$BIN" ]]; then
    echo "integration test not built: $BIN (run: meson compile -C $BUILD)" >&2
    exit 1
fi

# Server tiers. All run here (this is the LOCAL runner); the split records which
# are eligible for public GitHub CI.
#   Public tier: 11g XE / 21c XE / 23ai FREE - freely redistributable images, so a
#   public CI can pull them.
#   Local only: 10g (containerizable, but its image can't be redistributed) and 9i
#   (not containerizable at all - runs in a VM). Neither can ship to GitHub CI, so
#   they are ours to test locally.
# Row: name|host|port|target|user|pass|kind
#   kind=odbc -> ODBC integration test (+ core-API extras); `target` is SERVICE_NAME
#   kind=fv2  -> Oracle 9i core-API test (test_9i);         `target` is the SID
#                (fv2 speaks a different dialect; self-gates if the VM is down)
PUBLIC_SERVERS=(
    "11g|127.0.0.1|1521|XE|pyo|pyo123|odbc"
    "21c|127.0.0.1|1522|XEPDB1|pyo|pyo123|odbc"
    "23ai|127.0.0.1|1523|FREEPDB1|system|oracle123|odbc"
)
LOCAL_SERVERS=(
    "10g|127.0.0.1|1525|orcl|system|oracle|odbc"
    "9i|127.0.0.1|1526|orcl|pyo|pyo123|fv2"
)
SERVERS=( "${PUBLIC_SERVERS[@]}" "${LOCAL_SERVERS[@]}" )

# Optional TLS coverage: a terminating proxy (tls_proxy.py) gives the driver a
# TCPS endpoint forwarding to each server's plaintext listener. Needs python3 +
# openssl; without them the TLS check skips. Sets SEER_TLS_PROXY_PORT/CA per run.
PROXY_SCRIPT="$(dirname "$0")/tls_proxy.py"
have_tls_proxy=0
command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 \
    && [[ -f "$PROXY_SCRIPT" ]] && have_tls_proxy=1

start_tls_proxy() {   # $1 backend_host  $2 backend_port -> sets TLS_PORT/TLS_CA/TLS_PID
    TLS_PORT=""; TLS_CA=""; TLS_PID=""
    [[ $have_tls_proxy -eq 1 ]] || return 0
    local out; out=$(mktemp)
    python3 "$PROXY_SCRIPT" "$1" "$2" >"$out" 2>/dev/null &
    TLS_PID=$!
    for _ in $(seq 1 30); do
        grep -q '^CA=' "$out" && break
        sleep 0.2
    done
    TLS_PORT=$(sed -n 's/^PORT=//p' "$out")
    TLS_CA=$(sed -n 's/^CA=//p' "$out")
    rm -f "$out"
    [[ -n "$TLS_PORT" && -n "$TLS_CA" ]] || { kill "$TLS_PID" 2>/dev/null; TLS_PID=""; }
}

for row in "${SERVERS[@]}"; do
    IFS='|' read -r name host port target user pass kind <<<"$row"
    echo "============================================================"
    echo " $name  ($host:$port/$target as $user)"
    echo "============================================================"

    if [[ "$kind" == "fv2" ]]; then
        # Oracle 9i: its own core-API test, SID-addressed; self-gates if unreachable.
        SEER_TEST_HOST="$host" SEER_TEST_PORT="$port" SEER_TEST_SID="$target" \
            SEER_TEST_USER="$user" SEER_TEST_PASS="$pass" \
            "$NINE_BIN" 2>/dev/null | grep -vE '^SUMMARY' | sed 's/^/  /'
        summary=$(SEER_TEST_HOST="$host" SEER_TEST_PORT="$port" SEER_TEST_SID="$target" \
            SEER_TEST_USER="$user" SEER_TEST_PASS="$pass" \
            "$NINE_BIN" 2>/dev/null | grep '^SUMMARY')
    else
        # ODBC integration test (+ core-API extras: two-phase commit, object bind,
        # AQ), service-name addressed, with an optional TLS-proxy leg.
        start_tls_proxy "$host" "$port"
        SEER_TEST_HOST="$host" SEER_TEST_PORT="$port" SEER_TEST_SERVICE="$target" \
            SEER_TEST_USER="$user" SEER_TEST_PASS="$pass" \
            SEER_TLS_PROXY_PORT="$TLS_PORT" SEER_TLS_CA="$TLS_CA" \
            "$BIN" 2>/dev/null | grep -vE '^(target|SUMMARY)' | sed 's/^/  /'
        for extra in "$TPC_BIN" "$OBJBIND_BIN" "$AQ_BIN"; do
            if [[ -x "$extra" ]]; then
                SEER_TEST_HOST="$host" SEER_TEST_PORT="$port" SEER_TEST_SERVICE="$target" \
                    SEER_TEST_USER="$user" SEER_TEST_PASS="$pass" \
                    "$extra" 2>/dev/null | grep -vE '^SUMMARY' | sed 's/^/  /'
            fi
        done
        summary=$(SEER_TEST_HOST="$host" SEER_TEST_PORT="$port" SEER_TEST_SERVICE="$target" \
            SEER_TEST_USER="$user" SEER_TEST_PASS="$pass" \
            SEER_TLS_PROXY_PORT="$TLS_PORT" SEER_TLS_CA="$TLS_CA" "$BIN" 2>/dev/null | grep '^SUMMARY')
        [[ -n "$TLS_PID" ]] && kill "$TLS_PID" 2>/dev/null
    fi

    printf '%-6s %s\n' "$name" "${summary:-no summary (connect failed)}"
    eval "RESULT_$name=\"\${summary:-connect failed}\""
done

echo
echo "==================== matrix ================================"
echo "-- public CI tier (redistributable containers) --"
for row in "${PUBLIC_SERVERS[@]}"; do
    IFS='|' read -r name _ _ _ _ _ <<<"$row"
    var="RESULT_$name"
    printf '%-6s %s\n' "$name" "${!var:-?}"
done
echo "-- local only (not in public CI) --"
for row in "${LOCAL_SERVERS[@]}"; do
    IFS='|' read -r name _ _ _ _ _ <<<"$row"
    var="RESULT_$name"
    printf '%-6s %s\n' "$name" "${!var:-?}"
done
