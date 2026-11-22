/* TTC messages as schemas (#395 spike): what each carries, once, for every
 * path - 10g+ thin, 9i's O7 calls (thin's codec) and 8i (8i's). See schema.h.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_MSG_H
#define SEER_TNS_MSG_H

#include "schema.h"

/* The bind descriptor (OAC). One field list on every path; 8i packs its
 * integers little-endian (its "13 zero bytes and a big-endian charset" are
 * the array, continuation, TOID and version fields and an LE ub2 charset),
 * 9i lacks max_chars, 12.2 adds oaccolid. The values each path sends -
 * flags, charsets, 9i's VARNUM - are the caller's: policy, not encoding. */
typedef struct {
  int64_t data_type, flags, precision, scale;
  int64_t max_length, max_array, cont_flags, toid_length;
  SeerBytes toid;
  int64_t version, charset, csfrm, max_chars, oaccolid;
} SeerOacMsg;

extern const SeerField SEER_OAC_SCHEMA[];

/* The context a connection's messages are written and read in. */
SeerSchemaCtx seer_msg_ctx(int is_8i, uint8_t fv, uint8_t server_fv);

#endif /* SEER_TNS_MSG_H */
