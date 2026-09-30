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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"

/* Read the full content of the LOB named by `locator` (loclen bytes). On
 * SEER_OK, *out is a malloc'd buffer of *outlen bytes (may be 0 for an empty
 * LOB); caller frees. */
SeerStatus seer_lob_read(SeerConn *conn, const uint8_t *locator, size_t loclen, uint8_t **out,
                         size_t *outlen);

/* Read the content of an external BFILE named by its (RXD-captured) `locator`.
 * Unlike a persistent LOB this needs an explicit FILE_OPEN -> READ ->
 * FILE_CLOSE sequence over TTI_LOBOPS (PROTOCOL.md §19.8). On SEER_OK *out is a
 * malloc'd buffer of *outlen raw file bytes; caller frees. */
SeerStatus seer_bfile_read(SeerConn *conn, const uint8_t *locator, size_t loclen, uint8_t **out,
                           size_t *outlen);

/* Allocate a session-duration temporary CLOB (or BLOB, `blob`) with
 * TTI_LOBOPS CREATE_TEMP. On SEER_OK *locator is its malloc'd locator of
 * *loclen bytes; caller frees. 12.1+ (SEER_ENOTIMPL on older servers). */
SeerStatus seer_lob_create_temp(SeerConn *conn, bool blob, uint8_t **locator, size_t *loclen);

/* Write `n` bytes of `data` into the temporary LOB named by `locator`, from
 * offset 1 (TTI_LOBOPS WRITE): UTF-16BE for a CLOB, raw bytes for a BLOB. On
 * SEER_OK *resp is the server's raw reply - an RPA and the call's OER - for the
 * caller to check (caller frees). */
SeerStatus seer_lob_write(SeerConn *conn, const uint8_t *locator, size_t loclen,
                          const uint8_t *data, size_t n, uint8_t **resp, size_t *rlen);

#endif /* SEER_TNS_LOB_H */
