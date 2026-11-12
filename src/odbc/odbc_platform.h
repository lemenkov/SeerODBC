/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEERODBC_PLATFORM_H
#define SEERODBC_PLATFORM_H

/*
 * Include this before any <sql.h> / <sqlext.h> / <sqlucode.h>.
 *
 * On Windows the native ODBC headers are thin wrappers that use Windows types
 * (HWND, DWORD, GUID, BYTE, ...) without defining them, expecting <windows.h> to
 * have been included first. On unixODBC / iODBC the headers are self-contained,
 * so this is a no-op there. WIN32_LEAN_AND_MEAN trims the heavy sub-headers we do
 * not need and avoids some of windows.h's macro pollution.
 */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

/* SQLColAttribute[W]'s NumericAttribute: SQLLEN * everywhere but 32-bit
 * Windows, whose headers keep ODBC 3.0's SQLPOINTER there. Either way it points
 * at an SQLLEN, which on 32-bit Windows is 4 bytes. */
#if defined(_WIN32) && !defined(_WIN64)
#define SEER_COLATTR_NUMERIC SQLPOINTER
#else
#define SEER_COLATTR_NUMERIC SQLLEN *
#endif

#endif /* SEERODBC_PLATFORM_H */
