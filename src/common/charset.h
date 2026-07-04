/* Charset conversion - a thin iconv wrapper.
 *
 * Oracle charsets (AL32UTF8, WE8MSWIN1252, ...) need converting to and from
 * the UTF-8 / UTF-16 the ODBC shim hands to applications via SQLCHAR /
 * SQLWCHAR. This is the one place GLib's g_convert would have helped - and
 * g_convert is itself just an iconv wrapper, so we call iconv directly and
 * keep the dependency surface minimal.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_COMMON_CHARSET_H
#define SEER_COMMON_CHARSET_H

#include <stddef.h>

/* The iconv name for SQLWCHAR data: UTF-16 in the host byte order (SQLWCHAR is
 * 16-bit on unixODBC). Used by the ODBC shim's SQL_C_WCHAR conversions. */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SEER_UTF16 "UTF-16BE"
#else
#define SEER_UTF16 "UTF-16LE"
#endif

/* Convert `in` (in_len bytes, encoding `from`) to encoding `to`.
 * On success returns 0 and stores a newly malloc'd buffer in *out (NUL
 * terminated for convenience, length in *out_len, not counting the NUL).
 * The caller frees *out. Returns -1 on failure. */
int seer_iconv(const char *from, const char *to,
               const char *in, size_t in_len,
               char **out, size_t *out_len);

#endif /* SEER_COMMON_CHARSET_H */
