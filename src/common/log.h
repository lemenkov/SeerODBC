/* Minimal leveled logging to stderr.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_COMMON_LOG_H
#define SEER_COMMON_LOG_H

/* The usual levels, most severe first. What each is for:
 *   ERROR    the driver failed at its job: a reply it can't decode, a lost
 *            connection, a TLS or protocol failure.
 *   WARNING  unexpected but survivable, or a request refused for a reason the
 *            caller would not otherwise see (a value decoded as NULL, a
 *            feature this server or mode lacks).
 *   INFO     connection milestones: connected, negotiated, authenticated.
 *   DEBUG    the rest: per-call detail, wire tracing, and server errors (an
 *            ORA-nnnnn), which reach the caller through the API anyway.
 * The default threshold is WARNING. SEERODBC_DEBUG=1 lowers it to DEBUG in the
 * ODBC driver; seersql shows INFO, and DEBUG with -v. */
typedef enum {
  SEER_LOG_ERROR = 0,
  SEER_LOG_WARNING,
  SEER_LOG_INFO,
  SEER_LOG_DEBUG,
} SeerLogLevel;

void seer_log_set_level(SeerLogLevel level);

/* On MinGW the bare "printf" format archetype means Microsoft's msvcrt printf,
 * which lacks the C99 'z'/'ll' length modifiers - so -Wformat rejects our %zu.
 * We build with __USE_MINGW_ANSI_STDIO (C99-conformant printf at run time), so
 * check formats against the matching "gnu_printf" archetype. Elsewhere the plain
 * "printf" archetype is correct. */
#if defined(__MINGW32__)
#define SEER_PRINTF_ARCHETYPE gnu_printf
#else
#define SEER_PRINTF_ARCHETYPE printf
#endif

void seer_log(SeerLogLevel level, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(SEER_PRINTF_ARCHETYPE, 2, 3)))
#endif
    ;

#endif /* SEER_COMMON_LOG_H */
