/* LOB content retrieval via TTI_LOBOPS READ (PROTOCOL.md §14).
 *
 * A LOB column in a result set carries only an opaque locator; the bytes are
 * fetched with a separate round-trip. seer_lob_read issues a persistent-LOB
 * READ for the whole value and returns the raw content (UTF-16BE for CLOB,
 * raw bytes for BLOB - the caller converts).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_LOB_H
#define SEER_TNS_LOB_H

#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"

/* Read the full content of the LOB named by `locator` (loclen bytes). On
 * SEER_OK, *out is a malloc'd buffer of *outlen bytes (may be 0 for an empty
 * LOB); caller frees. */
SeerStatus seer_lob_read(SeerConn *conn, const uint8_t *locator, size_t loclen,
                         uint8_t **out, size_t *outlen);

/* Read the content of an external BFILE named by its (RXD-captured) `locator`.
 * Unlike a persistent LOB this needs an explicit FILE_OPEN -> READ ->
 * FILE_CLOSE sequence over TTI_LOBOPS (PROTOCOL.md §19.8). On SEER_OK *out is a
 * malloc'd buffer of *outlen raw file bytes; caller frees. */
SeerStatus seer_bfile_read(SeerConn *conn, const uint8_t *locator, size_t loclen,
                           uint8_t **out, size_t *outlen);

#endif /* SEER_TNS_LOB_H */
