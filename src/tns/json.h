/* JSON text -> OSON (native binary JSON) encoder.
 *
 * Parses a JSON document and encodes it to an OSON image, the inverse of
 * seer_decode_oson. Used for native JSON binds and AQ JSON payloads.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_JSON_H
#define SEER_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"   /* SeerStatus */

/* Parse JSON text and encode it to an OSON image. On SEER_OK *out is a malloc'd
 * buffer of *outlen bytes (caller frees). Supports the common small-document
 * subset: objects/arrays up to 255 entries, up to 255 distinct keys, strings up
 * to 255 bytes, and scalars (string / number / true / false / null). Malformed
 * input or anything beyond the subset returns SEER_EPARAM (SEER_ENOMEM on OOM). */
SeerStatus seer_json_to_oson(const char *json_text, uint8_t **out, size_t *outlen);

#endif
