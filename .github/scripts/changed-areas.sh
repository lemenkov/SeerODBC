#!/bin/sh
# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
# SPDX-License-Identifier: CC0-1.0

# Decide which parts of tests.yml a change needs, from the files it touches.
# Prints GitHub step outputs (code=, windows=, macos=), one per line.
#
# usage: changed-areas.sh [FILE...]   (no FILE: read the names from stdin)
#
#   code     the driver, its tests or the build: run every job
#   windows  Windows packaging: the native and the cross Windows builds
#   macos    the Homebrew formula: the macOS build, which installs it
#
# A file in none of these (docs, the RPM spec, other workflows) runs nothing.
# Jobs that a later area needs are a superset: code implies windows and macos.

code=false
windows=false
macos=false

classify() {
    case "$1" in
        src/* | include/* | tests/* | tools/* | subprojects/* | meson.build | \
            meson_options.txt | */meson.build | .github/workflows/tests.yml | \
            .github/scripts/changed-areas.sh)
            code=true ;;
        packaging/windows/*) windows=true ;;
        packaging/homebrew/*) macos=true ;;
    esac
}

if [ $# -gt 0 ]; then
    for f in "$@"; do classify "$f"; done
else
    while IFS= read -r f; do classify "$f"; done
fi

if [ "$code" = true ]; then
    windows=true
    macos=true
fi
echo "code=$code"
echo "windows=$windows"
echo "macos=$macos"
