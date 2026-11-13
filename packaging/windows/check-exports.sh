#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
# SPDX-License-Identifier: Apache-2.0
#
# Check the ODBC entry points a Windows build of the driver exports:
#
#   packaging/windows/check-exports.sh path/to/seerodbc.dll
#
# - The Driver Manager looks them up by their plain names (SQLConnect), so a
#   32-bit __stdcall build must not export them decorated (_SQLConnect@28).
# - Microsoft's Driver Manager calls the W form of every function a Unicode
#   driver exports, with no ANSI fallback (a missing one is a NULL call inside
#   odbc32.dll): each export that has a W form in ODBC (sqlucode.h) needs its
#   W export too.
#
# Runs under MSYS2 and on Linux with a MinGW-w64 cross toolchain.
set -euo pipefail
export LC_ALL=C # objdump's headings are translated otherwise

dll=${1:?usage: check-exports.sh path/to/seerodbc.dll}
objdump=objdump
for o in x86_64-w64-mingw32-objdump i686-w64-mingw32-objdump; do
  command -v "$o" >/dev/null 2>&1 && { objdump=$o; break; }
done

exports=$("$objdump" -p "$dll" | sed -n '/\[Ordinal\/Name Pointer\] Table/,/^$/p')
n=$(grep -c ' SQL' <<<"$exports" || true)
bad=$(grep -E ' _?SQL[A-Za-z]*@[0-9]+' <<<"$exports" || true)
echo "$dll: $n SQL exports"
if [ "$n" -lt 60 ] || [ -n "$bad" ]; then
  echo "::error::unexpected exports: $n SQL names, decorated: $bad"
  echo "$exports"
  exit 1
fi

missing=
for f in BrowseConnect ColAttribute ColAttributes ColumnPrivileges Columns \
         Connect DescribeCol DriverConnect Error ExecDirect ForeignKeys \
         GetConnectAttr GetConnectOption GetCursorName GetDescField GetDescRec \
         GetDiagField GetDiagRec GetInfo GetStmtAttr GetTypeInfo NativeSql \
         Prepare PrimaryKeys ProcedureColumns Procedures SetConnectAttr \
         SetConnectOption SetCursorName SetDescField SetStmtAttr SpecialColumns \
         Statistics TablePrivileges Tables; do
  if grep -qE " SQL$f\$" <<<"$exports" && ! grep -qE " SQL${f}W\$" <<<"$exports"; then
    missing="$missing SQL${f}W"
  fi
done
if [ -n "$missing" ]; then
  echo "::error::exported without their W form:$missing"
  exit 1
fi
echo "exports OK: undecorated, every W form present"
