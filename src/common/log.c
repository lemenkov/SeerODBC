/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "log.h"

#include <stdarg.h>
#include <stdio.h>

static SeerLogLevel g_level = SEER_LOG_WARNING;

void seer_log_set_level(SeerLogLevel level)
{
  g_level = level;
}

void seer_log(SeerLogLevel level, const char *fmt, ...)
{
  if (level > g_level)
    return;

  /* One line each, naming who printed it and how serious it is, as it lands
   * in the host application's stderr. */
  static const char *const NAMES[] = {"ERROR", "WARNING", "INFO", "DEBUG"};
  fprintf(stderr, "seerodbc: %s: ", NAMES[level]);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}
