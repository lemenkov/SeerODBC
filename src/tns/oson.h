/* OSON (Oracle binary JSON image) -> JSON text decoder.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_OSON_H
#define SEER_TNS_OSON_H

#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"

/* Decode an OSON image (`img`, `len` bytes) to a malloc'd NUL-terminated JSON
 * text string in *out (caller frees). SEER_EPROTO on a malformed image. */
SeerStatus seer_decode_oson(const uint8_t *img, size_t len, char **out);

#endif /* SEER_TNS_OSON_H */
