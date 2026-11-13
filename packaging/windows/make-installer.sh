#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
# SPDX-License-Identifier: Apache-2.0
#
# Build the Windows installer from the two release zips (make-zip.sh):
#
#   packaging/windows/make-installer.sh X64_ZIP X86_ZIP [OUT_DIR]
#
# Writes OUT_DIR/seerodbc-<version>-windows-setup.exe, one installer carrying
# both drivers (seerodbc.nsi). Needs makensis 3.x and unzip: on Fedora the
# mingw32-nsis package, on Debian/Ubuntu nsis, on Windows an NSIS install.
set -euo pipefail

x64=${1:?usage: make-installer.sh X64_ZIP X86_ZIP [OUT_DIR]}
x86=${2:?usage: make-installer.sh X64_ZIP X86_ZIP [OUT_DIR]}
out=${3:-.}
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../.." && pwd)
command -v makensis >/dev/null || { echo "make-installer: makensis not found" >&2; exit 1; }

# The zips are seerodbc-<version>-windows-<arch>.zip; both must be one version.
ver() { basename "$1" | sed -n 's/^seerodbc-\(.*\)-windows-\(x64\|x86\)\.zip$/\1/p'; }
version=$(ver "$x64")
[ -n "$version" ] && [ "$(ver "$x86")" = "$version" ] ||
  { echo "make-installer: expected seerodbc-<version>-windows-{x64,x86}.zip of one version" >&2; exit 1; }
case "$x64" in *-x64.zip) ;; *) echo "make-installer: $x64 is not the x64 zip" >&2; exit 1 ;; esac
case "$x86" in *-x86.zip) ;; *) echo "make-installer: $x86 is not the x86 zip" >&2; exit 1 ;; esac

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
unzip -q "$x64" -d "$stage/x64"
unzip -q "$x86" -d "$stage/x86"
mkdir -p "$out"
outfile=$(cd "$out" && pwd)/seerodbc-$version-windows-setup.exe

makensis -V2 -NOCD \
  "-DVERSION=$version" \
  "-DX64DIR=$stage/x64/seerodbc-$version-windows-x64" \
  "-DX86DIR=$stage/x86/seerodbc-$version-windows-x86" \
  "-DTOPDIR=$top" \
  "-DOUTFILE=$outfile" \
  "$here/seerodbc.nsi"
echo "$outfile"
