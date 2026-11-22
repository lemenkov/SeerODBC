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

/* A LOBOPS call's body, after the function header. One field list on every
 * path (seerdb _O7_LOBOPS): 8i and 9i carry the offsets and amount in the
 * short slots, 10g+ adds the long ones and three reserved array slots and
 * may ub2-prefix the locator; 9i sends the locator's first byte as 00. After
 * the locator: the charset when its pointer is set, the amount when either
 * amount pointer is. */
typedef struct {
  int64_t src_ptr, src_len, dst_ptr, dst_len, short_src_off, short_dst_off;
  int64_t charset_ptr, short_amount_ptr, null_lob_ptr, op, scn_ptr, scn_len;
  int64_t src_off, dst_off, amount_ptr; /* 10g+ */
  int64_t loc_prefixed, loc_len;        /* thin: a ub2-prefixed locator */
  SeerBytes locator;
  int64_t charset, has_amount, amount;
} SeerLobopMsg;

extern const SeerField SEER_LOBOPS_SCHEMA[];

/* A LOB data message's content (TTI_LOB, after its token): a value, chunked
 * past 252 bytes - on thin. 8i and 9i frame it as ub1 chunks to a zero
 * whether or not it starts with 0xFE (#395 spike finding: their readers
 * keep that form). */
typedef struct {
  SeerBytes data;
} SeerLobDataMsg;

extern const SeerField SEER_LOB_DATA_SCHEMA[];

/* The end-of-call status (TTI_OER, after its token). One field list on every
 * path, where three readers had it (#395 spike): 10g+ leads with the call
 * status and sequence number, which 9i and 8i don't send; the flags and
 * cursor options are one raw byte each from 12.1, compressed integers
 * before (and on 9i), single bytes on 8i; 12.1 adds the extended error and
 * row count, and a server from 20.1 the SQL type and checksum. Between the
 * head and the tail come the batch errors' messages, which stay code; the
 * error's text closes it when there is an error and bytes remain. */
typedef struct {
  int64_t call_status, seq, rows, code, array_err1, array_err2, cursor, position;
  int64_t sql_type, fatal, flags, cursor_opts, upi, warnings;
  int64_t rowid_obj, rowid_file, rowid_res, rowid_block, rowid_slot, os_error;
  int64_t stmt_no, call_no, padding, iterations;
  SeerBytes oerrdd, codes, offsets;
  int64_t nmsgs;
  int64_t ext_error, ext_rows, sql_type2, checksum;
  SeerBytes message;
} SeerOerMsg;

/* In three parts, as the readers stop: up to the code (a short 9i status
 * ends there), up to the warnings, then the rowid to the batch counts. */
extern const SeerField SEER_OER_HEAD_SCHEMA[];
extern const SeerField SEER_OER_FLAGS_SCHEMA[];
extern const SeerField SEER_OER_BATCH_SCHEMA[];
extern const SeerField SEER_OER_TAIL_SCHEMA[];

/* The context a connection's messages are written and read in. */
SeerSchemaCtx seer_msg_ctx(int is_8i, uint8_t fv, uint8_t server_fv);

#endif /* SEER_TNS_MSG_H */
