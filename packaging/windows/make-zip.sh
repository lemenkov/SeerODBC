#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
# SPDX-License-Identifier: Apache-2.0
#
# Package a MinGW-w64 build of SeerODBC as the Windows release zip:
#
#   packaging/windows/make-zip.sh BUILD_DIR [OUT_DIR]
#
# The zip holds seerodbc.dll, seer_smoke.exe and seersql.exe, every DLL they
# need that Windows doesn't ship (found by walking their imports, as the
# toolchains name them differently: MSYS2's libiconv-2.dll is Fedora's
# iconv.dll, and OpenSSL brings zlib1.dll), OpenSSL's ossl-modules\legacy.dll
# (DES, for 10g logins), the registration scripts, selftest.ps1, README,
# LICENSE and NOTICE.
#
# Runs under MSYS2 (MINGW64 / MINGW32) and on Linux with a MinGW-w64 cross
# toolchain. MINGW_BIN names the directory holding the runtime DLLs when it
# isn't found by itself.
set -euo pipefail

build=${1:?usage: make-zip.sh BUILD_DIR [OUT_DIR]}
out=${2:-$build}
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../.." && pwd)

dll="$build/src/odbc/seerodbc.dll"
[ -f "$dll" ] || { echo "make-zip: $dll not found - is $build a Windows build?" >&2; exit 1; }

# The DLL's machine decides the toolchain and the zip's name.
objdump=
for o in objdump x86_64-w64-mingw32-objdump i686-w64-mingw32-objdump; do
  command -v "$o" >/dev/null 2>&1 && { objdump=$o; break; }
done
[ -n "$objdump" ] || { echo "make-zip: no objdump found" >&2; exit 1; }
case "$("$objdump" -f "$dll")" in
  *pei-x86-64*) arch=x64 triplet=x86_64-w64-mingw32 msys=/mingw64 ;;
  *pei-i386*) arch=x86 triplet=i686-w64-mingw32 msys=/mingw32 ;;
  *) echo "make-zip: $dll is not a Windows DLL" >&2; exit 1 ;;
esac
command -v "$triplet-objdump" >/dev/null 2>&1 && objdump=$triplet-objdump

if [ -z "${MINGW_BIN:-}" ]; then
  for d in "$msys/bin" "/usr/$triplet/sys-root/mingw/bin"; do
    [ -d "$d" ] && { MINGW_BIN=$d; break; }
  done
fi
[ -d "${MINGW_BIN:-}" ] || { echo "make-zip: set MINGW_BIN to the MinGW runtime DLLs" >&2; exit 1; }
modules="$MINGW_BIN/../lib/ossl-modules"

version=$(sed -n "s/^ *version *: *'\([^']*\)'.*/\1/p" "$top/meson.build" | head -1)
name="seerodbc-$version-windows-$arch"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
dest="$stage/$name"
mkdir -p "$dest/ossl-modules"

cp "$dll" "$dest/"
for exe in "$build/tests/seer_smoke.exe" "$build/tools/seersql/seersql.exe"; do
  [ -f "$exe" ] && cp "$exe" "$dest/"
done
cp "$modules/legacy.dll" "$dest/ossl-modules/"

# Bundle every import that isn't Windows' own, transitively. Windows' DLLs are
# the ones not in the MinGW runtime directory.
queue=("$dest"/*.dll "$dest"/*.exe "$dest/ossl-modules/legacy.dll")
while [ ${#queue[@]} -gt 0 ]; do
  f=${queue[0]}
  queue=("${queue[@]:1}")
  while read -r dep; do
    [ -e "$dest/$dep" ] && continue
    src=$(find "$MINGW_BIN" -maxdepth 1 -iname "$dep" -print -quit)
    [ -n "$src" ] || continue # a system DLL
    cp "$src" "$dest/"
    queue+=("$dest/$(basename "$src")")
  done < <("$objdump" -p "$f" | sed -n 's/^\s*DLL Name: //p')
done

cp "$here/register.cmd" "$here/add-dsn.cmd" "$here/selftest.ps1" "$here/README.md" "$dest/"
cp "$top/LICENSE" "$top/NOTICE" "$dest/"
# Batch files must be CRLF on Windows, whatever the checkout did.
sed -i 's/\r*$/\r/' "$dest"/*.cmd
if [ "$arch" = x86 ]; then # 32-bit: the 32-bit registry view
  sed -i 's|/reg:64|/reg:32|' "$dest"/*.cmd
fi

mkdir -p "$out"
rm -f "$out/$name.zip"
(cd "$stage" && zip -qr -X "$name.zip" "$name")
mv "$stage/$name.zip" "$out/"
echo "$out/$name.zip:"
(cd "$dest" && find . -type f | sort | sed 's|^\./|  |')
