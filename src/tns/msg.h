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
  /* 9i's CREATE_TEMP: the short offsets each with its length byte, `01 00`
   * for a 0 (ojdbc14) */
  int64_t explicit_short;
} SeerLobopMsg;

extern const SeerField SEER_LOBOPS_SCHEMA[];

/* A LOBOPS reply's RPA, after its token: the locator as the server now has it
 * (a big-endian ub2 length and the bytes), then the amount when the call
 * asked for one - GETLEN's and READ's length, FILE_OPEN's mode. The same on
 * every path (seerdb _O7_LOBOPS_REPLY), only the amount's width per codec. */
typedef struct {
  int64_t loc_len;
  SeerBytes locator;
  int64_t has_amount, amount;
} SeerLobopReplyMsg;

extern const SeerField SEER_LOBOPS_REPLY_SCHEMA[];

/* The locator as 8i / 9i keep it: its ub2 length and the bytes, malloc'd. */
uint8_t *seer_lobop_reply_locator(const SeerLobopReplyMsg *m, size_t *n);

/* A LOB data message's content (TTI_LOB, after its token): a value, chunked
 * past 252 bytes - by ub1 chunks on 8i and 9i (whose servers always chunk it:
 * 963 of 963 in the replay corpus) and by sb4 ones from 12.1. */
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

/* A row's plain cell: its value (a ub1 length, or 0xFE and chunks; 0 and
 * 0xFF are empty / NULL). Read in place - only a chunked value is copied. */
typedef struct {
  SeerBytes value;
} SeerCellMsg;

extern const SeerField SEER_CELL_SCHEMA[];

/* A function call's header: the message type (TTI_FUN, or the piggyback
 * 0x11), the function, the sequence number, and from field version 24 the
 * call's token - 0 for an ordinary call, a pipelined op's own (#158). */
typedef struct {
  int64_t type, function, seq, call_token;
} SeerFunHeadMsg;

extern const SeerField SEER_FUN_HEAD_SCHEMA[];

/* Close cursors (TTI_OCCA, a piggyback ahead of the next call; seerdb
 * _CLOSE_CURSORS): the list's pointer, then the cursor ids, counted. */
typedef struct {
  int64_t list_ptr;
  const int *ids;
  int64_t n;
} SeerCloseCursorsMsg;

extern const SeerField SEER_CLOSE_CURSORS_SCHEMA[];

/* The context a connection's messages are written and read in. */
SeerSchemaCtx seer_msg_ctx(int is_8i, uint8_t fv, uint8_t server_fv);

#endif /* SEER_TNS_MSG_H */
