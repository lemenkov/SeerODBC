/* TTC messages as schemas (#395 spike): what each carries, once, for every
 * path - 10g+ thin, 9i's O7 calls (thin's codec) and 8i (8i's). See schema.h.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_MSG_H
#define SEER_TNS_MSG_H

#include "schema.h"

/* The OAC's fields, shared by the bind descriptor and a describe's column:
 * a struct holding them names these members. */
#define SEER_OAC_MEMBERS                                                                           \
  int64_t data_type, flags, precision, scale;                                                      \
  int64_t max_length, max_array, cont_flags, toid_length;                                          \
  SeerBytes toid;                                                                                  \
  int64_t version, charset, csfrm, max_chars, oaccolid

/* The bind descriptor (OAC). One field list on every path; 8i packs its
 * integers little-endian (its "13 zero bytes and a big-endian charset" are
 * the array, continuation, TOID and version fields and an LE ub2 charset),
 * 9i lacks max_chars, 12.2 adds oaccolid. The values each path sends -
 * flags, charsets, 9i's VARNUM - are the caller's: policy, not encoding. */
typedef struct {
  SEER_OAC_MEMBERS;
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

/* A row's cells. Every kind ends, where the path has one, in the cell's
 * trailer: on 8i an indicator (-1 NULL) and a return code, ub2s, after every
 * cell; on 9i the indicator alone, a compressed integer (00, or 81 01 for
 * NULL); from 10g a LONG's two, and no other cell's. A value is a ub1 length,
 * or 0xFE and chunks (0 and 0xFF NULL; on 8i a NULL is the trailer alone),
 * read in place - only a chunked one is copied. A NULL value has no pointer;
 * an empty one a pointer and no length. */
typedef struct {
  SeerBytes value;
  int64_t indicator, return_code;
  /* ROWID */
  int64_t rowid_size, rowid_obj, rowid_file, rowid_res, rowid_block, rowid_slot;
} SeerCellMsg;

extern const SeerField SEER_CELL_SCHEMA[];        /* a plain value */
extern const SeerField SEER_LONG_CELL_SCHEMA[];   /* LONG / LONG RAW */
extern const SeerField SEER_LOB_CELL_SCHEMA[];    /* a LOB's locator, counted */
extern const SeerField SEER_UROWID_CELL_SCHEMA[]; /* a UROWID, counted */
extern const SeerField SEER_ROWID_CELL_SCHEMA[];  /* a ROWID's five fields */

/* An OUT value (after a block's IOV, in its RXD): the value, then from 10g
 * its return code (a ub4: 0, or 1405 for a NULL); on 8i and 9i the cell's
 * indicator instead (-1 NULL). The special OUTs - arrays, objects, LOBs, an
 * 8i / 9i bind the block never assigned - keep their own readers. */
extern const SeerField SEER_OUT_CELL_SCHEMA[];

/* The I/O vector (TTI_IOV, after its token; seerdb _O7_IOV / _O8I_IOV), a
 * block's bind prompt: flags, the requests and iterations - the binds are
 * iterations * 256 + requests - the iterations this time, on thin the
 * buffer length, then the bit vector and the rowid, each counted (on 8i the
 * eight zero bytes there). One direction byte per bind follows
 * (SEER_IOV_DIRS_SCHEMA): 0x10 OUT, 0x20 IN, 0x30 IN OUT. */
typedef struct {
  int64_t flags, requests, iterations, iterations_now, buffer_len;
  SeerBytes bit_vector, rowid;
  int64_t nbinds;
  SeerBytes directions;
} SeerIovMsg;

extern const SeerField SEER_IOV_SCHEMA[];
extern const SeerField SEER_IOV_DIRS_SCHEMA[];

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

/* A row header (TTI_RXH, after its token; seerdb _O7_RXH): flags, four
 * counts (ub2s on 8i), then the bit vector naming the columns the next row
 * sends - a clear bit repeats the previous row's value - and the rowid, each
 * counted. The same on every path. */
typedef struct {
  int64_t flags, requests, iteration, iterations, buffer_len;
  SeerBytes bit_vector, rowid;
} SeerRxhMsg;

extern const SeerField SEER_RXH_SCHEMA[];

/* The return parameters (TTI_RPA, after its token) ahead of a status: a
 * count (a ub2 on 8i) and that many ub4 parameters, then the transaction id
 * (a ub2 length and the bytes), the session's changed settings as keyword
 * pairs (a count; each a text and a binary value, counted, and a ub2
 * keyword - an ALTER SESSION returns its NLS values), and on thin a
 * registration (a length and the bytes). The same on 10g+ and 8i
 * (seerdb _O8I_RPA); 9i's count grows with the instance, so it reads its own. */
typedef struct {
  int64_t nparams, txn_len;
  SeerBytes txn;
  int64_t npairs, reg_len;
  SeerBytes reg;
} SeerRpaMsg;

extern const SeerField SEER_RPA_HEAD_SCHEMA[]; /* the count and the parameters */
extern const SeerField SEER_RPA_TAIL_SCHEMA[]; /* the transaction id to the end */

/* An object or collection value's frame (python-oracledb read_dbobject;
 * seerdb _OBJECT_FRAME): the type OID (on 9i a 36-byte type block), the
 * object OID and the snapshot, each counted; a ub2 version, the image's
 * length (0 for a NULL object), ub2 flags, then the image as a value. The
 * same on every path; what follows it - a row cell's trailer, an OUT's
 * return code - is the caller's. */
typedef struct {
  SeerBytes type_oid, oid, snapshot;
  int64_t version, image_len, flags;
  SeerBytes image;
} SeerObjectMsg;

extern const SeerField SEER_OBJECT_SCHEMA[];

/* A describe's column (seerdb _DCB_COLUMN / _O8I_DESCRIBE / _O7_DESCRIBE_COLUMN):
 * the OAC's fields, then nullable, the name's length in bytes, the name and
 * the type's schema and name, each counted - the same on every path - and on
 * 10g+ the position, from 11.2 the UDS flags, from 23.1 the SQL domain's
 * schema and name. 23ai's annotations follow as code, then its vector
 * fields (SEER_DCB_VECTOR_SCHEMA). The scale is a raw signed byte from 12.1
 * and on 8i, a compressed integer before. */
typedef struct {
  SEER_OAC_MEMBERS;
  int64_t null_ok, name_bytes;
  SeerBytes name, type_schema, type_name;
  int64_t position, uds_flags;
  SeerBytes domain_schema, domain_name;
  int64_t vector_dims, vector_format, vector_flags;
} SeerDcbColumnMsg;

extern const SeerField SEER_DCB_COLUMN_SCHEMA[];
extern const SeerField SEER_DCB_VECTOR_SCHEMA[];

/* A describe's trailer: the describe time, counted; then on thin four flag
 * fields and, from 11.2, the query-cache key. */
typedef struct {
  SeerBytes time;
  int64_t dcbflag, dcbmdbz, dcbmnpr, dcbmxpr;
  SeerBytes query_key;
} SeerDcbTrailerMsg;

extern const SeerField SEER_DCB_TRAILER_SCHEMA[];

/* The context a connection's messages are written and read in. */
SeerSchemaCtx seer_msg_ctx(int is_8i, uint8_t fv, uint8_t server_fv);

#endif /* SEER_TNS_MSG_H */
