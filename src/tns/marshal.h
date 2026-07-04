/* TTC wire-encoding primitives (PROTOCOL.md §12), built on the reader/writer.
 *
 * Oracle's TTC layer marshals integers as a length byte plus that many
 * big-endian magnitude bytes (the high bit of the length byte flags a negative,
 * sign-magnitude value). The same length-coded form, doubled, frames the
 * key/value pairs used in authentication.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_MARSHAL_H
#define SEER_TNS_MARSHAL_H

#include <stddef.h>
#include <stdint.h>

#include "reader.h"
#include "seer/seertns.h"
#include "writer.h"

/* Encode a non-negative 32-bit integer (the SB4/UB4 form): a byte count
 * (0..4) followed by that many big-endian magnitude bytes; 0 -> a single
 * 0x00. */
void seer_enc_sb4(SeerWriter *w, uint32_t v);

/* Decode the same form. Handles the sign-magnitude negative case. Reads
 * through the reader's bounds checks; on over-read the reader latches overflow
 * and this returns 0. */
int64_t seer_dec_sb4(SeerReader *r);

/* Encode one key/value pair (PROTOCOL.md §12.3): each of key and value is
 * either a single 0x00 (empty) or <sb4 len><ub1 len><bytes>, followed by an
 * sb4 `padding` trailer (normally 0). Both lengths must be < 256. */
void seer_enc_kv(SeerWriter *w, const void *key, size_t klen,
                 const void *val, size_t vlen, uint32_t padding);

/* Decode one length-coded field (the key or value half of a KV pair).
 * Allocates *out (caller frees). An empty field yields *out=NULL, *outlen=0
 * and SEER_OK. Handles both the inline (<len><bytes>) and chunked (0xFE) forms. */
SeerStatus seer_dec_field(SeerReader *r, uint8_t **out, size_t *outlen);

/* Decode a DALC (PROTOCOL.md §12.2): a single length byte then that many
 * bytes; 0x00/0xFF are empty/null (*out=NULL); 0xFE is the chunked (ub1 per
 * chunk) form. Allocates *out (caller frees). */
SeerStatus seer_dec_dalc(SeerReader *r, uint8_t **out, size_t *outlen);

/* Skip a chunked-bytes field (oracledb skip_bytes form): a length byte, then
 * that many bytes; 0xFE is chunked with sb4-prefixed chunks; 0xFF is null. */
void seer_skip_chunked(SeerReader *r);

/* Skip a bytes-with-length field: an sb4 count, then (if > 0) a chunked-bytes
 * blob. */
void seer_skip_bytes_with_length(SeerReader *r);

/* Read a str-with-length (sb4 count, then a DALC). Allocates a NUL-terminated
 * *out (caller frees); empty yields an empty string. */
SeerStatus seer_read_str(SeerReader *r, char **out);

#endif /* SEER_TNS_MARSHAL_H */
