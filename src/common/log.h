/* Minimal leveled logging to stderr.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_COMMON_LOG_H
#define SEER_COMMON_LOG_H

typedef enum {
    SEER_LOG_ERROR = 0,
    SEER_LOG_WARN,
    SEER_LOG_INFO,
    SEER_LOG_DEBUG,
} SeerLogLevel;

void seer_log_set_level(SeerLogLevel level);

void seer_log(SeerLogLevel level, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

#endif /* SEER_COMMON_LOG_H */
