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

/* A bind value's bytes alone, as SF_CHR writes them: a VARCHAR or RAW
 * value, a REF, an object image, 8i's text values. */
typedef struct {
  SeerBytes value;
} SeerChrMsg;

extern const SeerField SEER_CHR_SCHEMA[];

/* TTI_PRO, the protocol negotiation (after its token). Both ways it starts
 * with the protocol versions, highest first, and a 0, then a banner and a
 * NUL - the client's the versions it takes, the server's the one it chose.
 * The reply goes on: the database charset (little-endian), the server's
 * flags, a little-endian count of 5-byte charset elements and the elements,
 * a big-endian-counted FDO block, then the compile capabilities (none on 8i)
 * and the runtime capabilities, each a length byte and the bytes. */
typedef struct {
  SeerBytes versions, banner;
  int64_t db_charset, server_flags, nelem, fdo_len;
  SeerBytes fdo;
  int64_t ccaps_len;
  SeerBytes ccaps;
  int64_t rcaps_len;
  SeerBytes rcaps;
} SeerProMsg;

extern const SeerField SEER_PRO_SCHEMA[];       /* the request */
extern const SeerField SEER_PRO_REPLY_SCHEMA[]; /* the reply to the compile caps */
extern const SeerField SEER_PRO_RCAPS_SCHEMA[]; /* the runtime caps after them */

/* The fast-auth bundle (TNS_MSG_TYPE_FAST_AUTH, after its type; the
 * one-round-trip login from fv24): a version (1), the server-converts-chars
 * flag and a second flag; then the TTI_PRO message, token included; then the
 * charset, a flag and the ncharset (0: the server's), the field version to
 * use; then TTI_DTY and AUTH phase 1, each a message of its own. */
typedef struct {
  int64_t version, flags1, flags2;
  int64_t charset, flag, ncharset, field_version;
} SeerFastAuthMsg;

extern const SeerField SEER_FAST_AUTH_HEAD_SCHEMA[];
extern const SeerField SEER_FAST_AUTH_TAIL_SCHEMA[];

/* TTI_DTY, the data-type negotiation (after its token): the charsets in and
 * out, little-endian; a flags byte - 3 with 12c's two-byte type table, 1
 * with the one-byte one; the compile and runtime capabilities, each a length
 * byte and the bytes; then the type table. */
typedef struct {
  int64_t charset_in, charset_out, flags, ccaps_len;
  SeerBytes ccaps;
  int64_t rcaps_len;
  SeerBytes rcaps;
} SeerDtyMsg;

extern const SeerField SEER_DTY_HEAD_SCHEMA[];

/* One type table entry: the type, the type it converts to, its
 * representation and a 0. From 12.1 a big-endian ub2 each; before, a byte
 * each, and an entry with no conversion ends after it. The table ends with a
 * 0 type, SEER_DTY_END_SCHEMA. */
typedef struct {
  int64_t type, conv, rep, reserved;
} SeerDtyEntryMsg;

extern const SeerField SEER_DTY_ENTRY_SCHEMA[];
extern const SeerField SEER_DTY_END_SCHEMA[];

/* Opening a server cursor (OOPEN, function 2: 8i's TTI_OOPEN, 9i's
 * O7_OPEN), after the function header: a pointer byte for the cursor
 * returned, then the cursor - 0, a new one. The reply's RPA is the new
 * cursor's id. */
typedef struct {
  int64_t cursor_ptr, cursor;
} SeerOpenMsg;

extern const SeerField SEER_OPEN_SCHEMA[];
extern const SeerField SEER_OPEN_REPLY_SCHEMA[];

/* 9i's describe of an open cursor (O7_DESCRIBE), after the function header:
 * 07, the cursor, then 00 00 01 02 01 01 - as ojdbc14 sends them, the
 * fields not known. */
typedef struct {
  int64_t cursor;
} SeerO7DescribeMsg;

extern const SeerField SEER_O7_DESCRIBE_SCHEMA[];

/* A value alone, read: the DCB's describe-info preamble. */
extern const SeerField SEER_VALUE_SCHEMA[];

/* A describe's head, before its columns: the maximum row size, the column
 * count and, when there are columns, a reserved byte. */
typedef struct {
  int64_t max_row_size, ncols, reserved;
} SeerDescribeHeadMsg;

extern const SeerField SEER_DESCRIBE_HEAD_SCHEMA[];

/* A column's annotation map on 23ai (fv24, #89): the count, and when there
 * are annotations a pointer byte, the count again and a pointer byte; then
 * each annotation as an AUTH_ pair (SEER_AUTH_PAIR_SCHEMA: the name, the
 * value, a flags word) and a trailing flags word. */
typedef struct {
  int64_t count, ptr, count2, ptr2, flags;
} SeerDcbAnnotationsMsg;

extern const SeerField SEER_DCB_ANNOTATIONS_HEAD_SCHEMA[];
extern const SeerField SEER_DCB_ANNOTATIONS_TAIL_SCHEMA[];

/* An implicit result (TTI_IRD, after the count): a preamble - a ub1 length
 * and its bytes - then the describe, then the cursor id. */
typedef struct {
  int64_t nres, pre_len;
  SeerBytes preamble;
  int64_t cursor_id;
} SeerImplicitMsg;

extern const SeerField SEER_IMPLICIT_COUNT_SCHEMA[];
extern const SeerField SEER_IMPLICIT_HEAD_SCHEMA[];
extern const SeerField SEER_IMPLICIT_TAIL_SCHEMA[];

/* A cursor value: a length byte, the describe, the cursor id, then for a REF
 * CURSOR OUT bind (§6.5) an indicator; a nested CURSOR(...) column has
 * none. */
typedef struct {
  int64_t len, cursor_id, has_indicator, indicator;
} SeerCursorValueMsg;

extern const SeerField SEER_CURSOR_VALUE_HEAD_SCHEMA[];
extern const SeerField SEER_CURSOR_VALUE_TAIL_SCHEMA[];

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

/* A LOB data message's content (TTI_LOB, after its token), both ways
 * (SF_LOB). Read, a value chunked past 252 bytes - by ub1 chunks on 8i and
 * 9i (whose servers always chunk it: 963 of 963 in the replay corpus) and by
 * sb4 ones from 12.1; written, as a LOB write sends it. */
typedef struct {
  SeerBytes data;
} SeerLobDataMsg;

extern const SeerField SEER_LOB_DATA_SCHEMA[];

/* A LOB bound by its locator on 10g+ (seerdb PROTOCOL.md §14.4): the prefix
 * 01 28 28, the locator's big-endian ub2 length and its bytes; a value LOB
 * (JSON, VECTOR) then its image, as a bind value. */
typedef struct {
  int64_t loc_len;
  SeerBytes locator;
  int64_t has_image;
  SeerBytes image;
} SeerLobBindMsg;

extern const SeerField SEER_LOB_BIND_SCHEMA[];

/* The 38-byte locator a value LOB is bound with (JSON #70, VECTOR #62):
 * fixed fields, the image's length in three big-endian bytes - a ub1 and a
 * ub2, so an image past 64 KiB fits (seerdb/seerdb@d15e421) - and 22
 * zeros. */
typedef struct {
  int64_t len_hi, len_lo;
} SeerValueLocatorMsg;

extern const SeerField SEER_VALUE_LOCATOR_SCHEMA[];

#define SEER_VALUE_LOCATOR_LEN 38

/* A LOB locator as a bind value before 10g: its N4 length, then the locator
 * as a value - inline at 8i's widths, as SF_CHR writes one on 9i (§19.3.1,
 * §19.17b). */
typedef struct {
  int64_t loc_len;
  SeerBytes locator;
} SeerLegacyLobBindMsg;

extern const SeerField SEER_LEGACY_LOB_BIND_SCHEMA[];

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

/* The batch errors' messages, after SEER_OER_BATCH_SCHEMA when it counts
 * some (§6.7): an indicator byte, then each message counted and two
 * trailing bytes. The same on 10g+ and 9i. */
typedef struct {
  int64_t indicator;
  SeerBytes text;
} SeerOerTextMsg;

extern const SeerField SEER_OER_MSGS_HEAD_SCHEMA[];
extern const SeerField SEER_OER_MSG_SCHEMA[];

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

/* An OUT value's tail alone, SEER_OUT_CELL_SCHEMA without the value: what
 * follows an OUT object's image. */
extern const SeerField SEER_OUT_TAIL_SCHEMA[];

/* DML RETURNING's return data (§5.6, an RXD after a RETURNING execute): per
 * OUT bind the affected-row count, then per row its value and real length -
 * larger than what arrived when the server cut the value to the bind's size
 * (seerdb/seerdb@1812615). A CLOB / BLOB target's value is the LOB block
 * (§22.1d): from 12.1 the block's length (0 for a NULL, and nothing more),
 * the LOB's size, the chunk size and the locator as a value; before 12.1
 * (measured on 10g / 11g) the locator counted, as a fetched LOB column. */
typedef struct {
  int64_t nrows;
  SeerBytes value;
  int64_t block_len, lob_size, chunk_size;
  SeerBytes locator;
  int64_t actual_len;
} SeerReturningMsg;

extern const SeerField SEER_RETURNING_COUNT_SCHEMA[];
extern const SeerField SEER_RETURNING_VALUE_SCHEMA[];
extern const SeerField SEER_RETURNING_LOB_SCHEMA[];

/* The special OUT forms on 8i (§19.17b / §19.17c), each in a SeerCellMsg but
 * the array's count:
 * - a LOB: its locator, counted, then the indicator; no return code;
 * - a bind the block never assigned: ff, then the indicator (3105);
 * - an associative array: a count, then each element as
 *   SEER_OUT_CELL_SCHEMA (the REF OUT the same, without the count). */
typedef struct {
  int64_t count;
} SeerOutArrayMsg;

extern const SeerField SEER_LOB_OUT_SCHEMA[];
extern const SeerField SEER_OUT_UNSET_SCHEMA[];
extern const SeerField SEER_OUT_ARRAY_SCHEMA[];

/* On 9i: an OUT bind the block never assigned is four fixed bytes
 * (seerdb #801), and an OUT object's image is followed by the indicator
 * alone, when the reply has one. The LOB form is SEER_LOB_OUT_SCHEMA's. */
extern const SeerField SEER_O7_OUT_UNSET_SCHEMA[];
extern const SeerField SEER_OUT_IND_SCHEMA[];

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

/* The bodies after a function header of three thin-only calls: the
 * begin-pipeline piggyback (func 199, §32) - the error set's id and mode,
 * then the pipeline's mode; the pipeline end (func 200) - the pipeline's id;
 * the session-state piggyback (func 176, §35) - the state. */
typedef struct {
  int64_t error_set_id, error_set_mode, mode, pipeline_id, state;
} SeerThinCallMsg;

extern const SeerField SEER_PIPELINE_BEGIN_SCHEMA[];
extern const SeerField SEER_PIPELINE_END_SCHEMA[];
extern const SeerField SEER_SESSION_STATE_SCHEMA[];

/* AQ (seerdb PROTOCOL.md §29, oracledb AqEnqMessage / AqDeqMessage /
 * AqArrayMessage). The message properties: priority, delay, expiration, the
 * correlation, the attempts, the exception queue, the state, the enqueue
 * time and transaction - each string a count and, when > 0, the bytes - then
 * the extensions, counted (a byte leads them when there are any), and the
 * user property, the commit SCNs, the flags and from 21.1 the shard id. An
 * extension is its text and binary values, each counted, and its keyword. A
 * client writes the head, the four agent extensions and the tail; a reply's
 * block is read whole by SEER_AQ_PROPS_SCHEMA, the extensions passed over. */
typedef struct {
  int64_t priority, delay, expiration, correlation_len;
  SeerBytes correlation;
  int64_t attempts, exception_queue_len;
  SeerBytes exception_queue;
  int64_t state, enq_time_len;
  SeerBytes enq_time;
  int64_t enq_txn_len;
  SeerBytes enq_txn;
  int64_t n_ext, ext_lead;
  int64_t user_prop, cscn, dscn, flags, shard_id;
} SeerAqPropsMsg;

typedef struct {
  int64_t text_len;
  SeerBytes text;
  int64_t bin_len;
  SeerBytes bin;
  int64_t keyword;
} SeerAqExtMsg;

extern const SeerField SEER_AQ_PROPS_HEAD_SCHEMA[];
extern const SeerField SEER_AQ_EXT_SCHEMA[];
extern const SeerField SEER_AQ_PROPS_TAIL_SCHEMA[];
extern const SeerField SEER_AQ_PROPS_SCHEMA[];

/* An enqueue (func 121) after its header: the queue name's pointer and
 * length, the message properties, then the recipients, the visibility, the
 * relative message id, the sequence deviation, the payload TOID, the message
 * version, the payload and RAW payload pointers and the RAW length, the
 * returned message id, the enqueue flags, the extensions, the source and
 * maximum sequence numbers, the output ack, the correlation, the sender's
 * name, address and charsets, and from 20.1 the JSON payload's pointer. Its
 * data section: the queue name - raw below 12.1, a bind value from (11g read
 * the 12c length byte as part of the name, seerdb §29) - the TOID and the
 * payload's bytes. */
typedef struct {
  int64_t qname_ptr, qname_len;
  int64_t recipients_ptr, recipients, visibility, relmsgid_ptr, relmsgid_len, seq_deviation;
  int64_t toid_ptr, toid_len, msg_version, payload_ptr, raw_ptr, raw_len;
  int64_t msgid_ptr, msgid_len, enq_flags, ext1_ptr, ext1_n, ext2_ptr, ext2_n;
  int64_t srcseq_ptr, srcseq_len, maxseq_ptr, maxseq_len, ack_len, corr_ptr, corr_len;
  int64_t sender_name_ptr, sender_name_len, sender_addr_ptr, sender_addr_len;
  int64_t sender_cs_ptr, sender_ncs_ptr, json_ptr;
  SeerBytes qname, toid, payload;
  int64_t payload_len;
} SeerAqEnqMsg;

extern const SeerField SEER_AQ_ENQ_HEAD_SCHEMA[];
extern const SeerField SEER_AQ_ENQ_TAIL_SCHEMA[];

/* An array AQ call (func 145) after its header: the input parameters'
 * pointer and length, the flags (return the message ids), the output
 * parameters' pointer and length, the operation, the iteration count's
 * pointer and from 21.1 the shard id. An enqueue goes on with the count, the
 * relative message id, a row header, the queue name (counted, then as a bind
 * value), the TOID, the message version and the flags; then per message a
 * row of data - its flags, the properties, the recipients, the visibility,
 * the relative message id, the sequence deviation and the RAW payload,
 * counted - and a closing status token. */
typedef struct {
  int64_t in_ptr, in_len, ret_flags, out_ptr, out_len, op, iters_ptr, shard_id;
  int64_t iters, relmsgid_len, rxh, qname_len;
  SeerBytes qname, toid;
  int64_t toid_len, msg_version, flags;
  int64_t rxd, aqi_flags, recipients, visibility, relmsgid, seq_deviation, raw_len;
  SeerBytes payload;
  int64_t sta;
} SeerAqArrayMsg;

extern const SeerField SEER_AQ_ARRAY_HEAD_SCHEMA[];
extern const SeerField SEER_AQ_ARRAY_ENQ_HEAD_SCHEMA[];
extern const SeerField SEER_AQ_ARRAY_ENQ_ROW_SCHEMA[];
extern const SeerField SEER_AQ_ARRAY_ENQ_ROW_TAIL_SCHEMA[];
extern const SeerField SEER_AQ_ARRAY_ENQ_END_SCHEMA[];

/* A dequeue (func 122) after its header: the queue name's pointer and
 * length, the pointers of the message properties and recipient list and
 * their lengths, the consumer name's pointer and length, the mode, the
 * navigation, the visibility, the wait, the selector message id's and the
 * correlation's pointers and lengths, the payload TOID's, the message
 * version, the payload's pointer, the returned message id's, the dequeue
 * flags, the condition's and the extensions' pointers and lengths, from 20.1
 * the JSON payload's pointer and from 21.1 the shard id. Its data section:
 * the queue name, the consumer name and the correlation when given - each
 * raw below 12.1, a bind value from (as the enqueue's) - and the TOID. */
typedef struct {
  int64_t qname_ptr, qname_len, props_ptr, props_len_ptr, recip_ptr, recip_len_ptr;
  int64_t consumer_ptr, consumer_len, mode, navigation, visibility, wait;
  int64_t selector_ptr, selector_len, corr_ptr, corr_len, toid_ptr, toid_len, msg_version;
  int64_t payload_ptr, msgid_ptr, msgid_len, deq_flags, cond_ptr, cond_len, ext_ptr, ext_n;
  int64_t json_ptr, shard_id;
  SeerBytes qname, consumer, correlation, toid;
} SeerAqDeqMsg;

extern const SeerField SEER_AQ_DEQ_SCHEMA[];

/* An array dequeue's row (func 145, after SEER_AQ_ARRAY_HEAD_SCHEMA): the
 * queue name, counted, the message properties, then the recipients, the
 * consumer name, the mode, the navigation, the visibility, the wait, the
 * selector message id, the correlation, the condition and the extensions -
 * each string counted - the relative message id, the sequence deviation, the
 * TOID, counted, the message version, the payload's and RAW payload's
 * lengths, a ub4 oracledb leaves unnamed, the flags, and the extensions' and
 * source sequence's lengths. */
typedef struct {
  int64_t qname_len;
  SeerBytes qname;
  int64_t recipients, consumer_len;
  SeerBytes consumer;
  int64_t mode, navigation, visibility, wait, selector_len;
  SeerBytes selector;
  int64_t corr_len;
  SeerBytes correlation;
  int64_t cond_len;
  SeerBytes condition;
  int64_t ext_n, relmsgid, seq_deviation, toid_len;
  SeerBytes toid;
  int64_t msg_version, payload_len, raw_len, unnamed, flags, ext_len, srcseq_len;
} SeerAqArrayDeqRowMsg;

extern const SeerField SEER_AQ_ARRAY_DEQ_ROW_HEAD_SCHEMA[];
extern const SeerField SEER_AQ_ARRAY_DEQ_ROW_TAIL_SCHEMA[];

/* AQ replies, after the RPA token. A dequeue's: the properties' length (0:
 * no message), the properties, the recipients, the payload (an object's
 * form, SEER_OBJECT_HEAD_SCHEMA) and the 16-byte message id; an enqueue's is
 * the message id alone. An array call's: the iteration count, then per
 * iteration the properties' length and, when > 0, a byte and the
 * properties; the recipients; the payload's presence and the payload; the
 * message ids, counted; the extensions' length and the output ack. */
typedef struct {
  int64_t iters, props_len, props_lead, recipients, payload_n, msgid_len;
  SeerBytes msgid;
  int64_t ext_len, ack;
} SeerAqReplyMsg;

extern const SeerField SEER_AQ_DEQ_REPLY_HEAD_SCHEMA[];
extern const SeerField SEER_AQ_DEQ_REPLY_MID_SCHEMA[];
extern const SeerField SEER_AQ_MSGID_SCHEMA[];
extern const SeerField SEER_AQ_ARRAY_REPLY_HEAD_SCHEMA[];
extern const SeerField SEER_AQ_ITER_HEAD_SCHEMA[];
extern const SeerField SEER_AQ_ITER_MID_SCHEMA[];
extern const SeerField SEER_AQ_ITER_TAIL_SCHEMA[];

/* Two-phase commit (seerdb PROTOCOL.md §28): TXN_SWITCH (begin/end) and
 * TXN_CHANGE_STATE (prepare/commit/abort) share a head - the operation, the
 * stored context's pointer and length, and the xid's descriptor (format id,
 * gtrid and bqual lengths, the payload's pointer and length). SWITCH goes on
 * with the flags, the timeout, three out pointers and from 11.2 the internal
 * and external names' pointers and lengths; CHANGE_STATE with the timeout,
 * the state, the out-state pointer and from 10.2 the flags. Both end with
 * the context's bytes and the 128-byte xid, SWITCH with an app value too.
 * The reply's RPA carries an app value and the begin context, counted, or
 * the state. */
typedef struct {
  int64_t op, ctx_ptr, ctx_len;
  int64_t format_id, gtrid_len, bqual_len, xid_ptr, xid_len;
  int64_t flags, timeout, state, out_ptr;
  int64_t int_name_ptr, int_name_len, ext_name_ptr, ext_name_len;
  SeerBytes ctx, xid;
  int64_t app_value;
} SeerTpcMsg;

extern const SeerField SEER_TPC_SWITCH_SCHEMA[];
extern const SeerField SEER_TPC_CHANGE_STATE_SCHEMA[];
extern const SeerField SEER_TPC_CONTEXT_REPLY_SCHEMA[];
extern const SeerField SEER_TPC_STATE_REPLY_SCHEMA[];

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
 * length (0 for a NULL object), ub2 flags, then the image as a value - as
 * a bind value is written (SF_CHR), which reads as any value. The same on
 * every path, both ways; what follows it - a row cell's trailer, an OUT's
 * return code - is the caller's. */
typedef struct {
  SeerBytes type_oid, oid, snapshot;
  int64_t version, image_len, flags;
  SeerBytes image;
} SeerObjectMsg;

extern const SeerField SEER_OBJECT_SCHEMA[];
/* The same, split: everything up to the image, then the image alone - for
 * an AQ payload, whose image a reader takes only past its 4-byte header. */
extern const SeerField SEER_OBJECT_HEAD_SCHEMA[];
extern const SeerField SEER_OBJECT_IMAGE_SCHEMA[];

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

/* An OALL8 execute / fetch call's body, after the function header (seerdb
 * _ALL8_HEAD / _O8I_ALL8): the options, the cursor, the SQL's pointer and
 * length, al8i4's pointer and count, al8o4 / al8o4l, the prefetch size and
 * rows, the LONG size, the binds' pointer and count, the al8app .. al8kvl
 * pointers - the same on 10g+ and 8i, 8i's widths fixed - then on thin the
 * defines' pointer and count, the register bytes (five more but on a 10g
 * server), 12.1's al8pidmlrc, 12.2's SQL-signature slot and 12.2_EXT1's
 * chunk ids; then the SQL (caller-framed: raw before 12.1, one sb4 chunk
 * from 12.1, 64-byte chunks on 8i) and the al8i4 words. */
typedef struct {
  int64_t options, cursor, sql_ptr, sql_len, al8i4_ptr, al8i4_len, al8o4, al8o4l;
  int64_t prefetch_size, prefetch_rows, max_long, binds_ptr, bind_count;
  int64_t al8app, al8txn, al8txl, al8kv, al8kvl, defines_ptr, define_count;
  int64_t reg0, reg1, reg2, register_tail;
  int64_t pidmlrc_ptr, pidmlrc_len, pidmlrc_ptr2;
  SeerBytes sql; /* SF_SQL: the text itself */
  const uint32_t *al8i4;
  int64_t al8i4_n;
} SeerAll8Msg;

extern const SeerField SEER_ALL8_SCHEMA[];

/* A FETCH call's body (TTI_FETCH, after the function header; seerdb _FETCH):
 * the cursor and the rows to return. */
typedef struct {
  int64_t cursor, rows;
} SeerFetchMsg;

extern const SeerField SEER_FETCH_SCHEMA[];

/* A 9i TTI_ALL7 call's body, after the function header (seerdb _O7_ALL7):
 * one layout for a parse, a PL/SQL block and an execute - the options, the
 * cursor, the SQL's pointer and length (in characters, #2275), nine bytes
 * every ALL7 call carries (their fields not known: captured from ojdbc14),
 * the defines' pointer and count, the binds' pointer and count, the SQL,
 * `01 01`, the rows (1, an array DML's, or a fetch's 10) and five zero
 * bytes. The binds' descriptors and values, or the defines, follow. */
typedef struct {
  int64_t options, cursor, sql_ptr, sql_len, defines_ptr, define_count, binds_ptr, bind_count;
  SeerBytes sql; /* SF_SQL: the text itself */
  int64_t rows;
} SeerO7All7Msg;

extern const SeerField SEER_O7_ALL7_SCHEMA[];

/* A call on a cursor by its id (seerdb _O7_CURSOR_CALL): 9i's close (03 14)
 * and free (03 08), after the function header. */
typedef struct {
  int64_t cursor;
} SeerCursorCallMsg;

extern const SeerField SEER_CURSOR_CALL_SCHEMA[];

/* A login call's head after the function header (seerdb _AUTH_HEAD): OSESSKEY
 * (TTI_SESS) or OAUTH (TTI_AUTH) - a pointer, the user's length, the logon
 * mode, a pointer, the pairs' count, two pointers, then the user: with its
 * length from 12.1 and on 8i, raw before (read by its length). */
typedef struct {
  int64_t user_ptr, user_len, mode, pairs_ptr, npairs, ptr3, ptr4;
  SeerBytes user;
  int64_t user_bytes;
} SeerAuthHeadMsg;

extern const SeerField SEER_AUTH_HEAD_SCHEMA[];

/* One AUTH_ key / value pair (seerdb _AUTH_PAIR): the key's length and, when
 * not empty, the key; the value's the same way; a flags word. */
typedef struct {
  SeerBytes key, value;
  int64_t flags;
} SeerAuthPairMsg;

extern const SeerField SEER_AUTH_PAIR_SCHEMA[];

/* A server piggyback (TTI_SVR_PIGGYBACK, after its opcode; python-oracledb's
 * _process_server_side_piggyback), passed over:
 * - SESS_RET (DRCP #130): the DTYs' count and length, the pairs' count, a
 *   length byte when there are pairs, the pairs (each as an AUTH_ pair), the
 *   session flags, id and serial;
 * - OS_PID_MTS: a ub2 and the pid as a value;
 * - SYNC (sessionless transactions, §31): as SESS_RET with the length byte
 *   always there and the overall flags after the pairs. */
typedef struct {
  int64_t ndtys, dtys_len, npairs, pairs_len;
  int64_t flags, session_id, serial;
  SeerBytes pid;
} SeerSvrPiggybackMsg;

extern const SeerField SEER_SVR_PIG_SESS_RET_SCHEMA[];
extern const SeerField SEER_SVR_PIG_MTS_SCHEMA[];
extern const SeerField SEER_SVR_PIG_SYNC_SCHEMA[];

/* A login reply after its TTI_RPA token (seerdb _PRE10_AUTH_REPLY; the thin
 * one the same way): the pairs' count - thin variable-width, 8i a ub2 - then
 * that many SEER_AUTH_PAIR_SCHEMA pairs. On thin the last pair's flags may be
 * missing when the reply ends there. */
typedef struct {
  int64_t npairs;
} SeerAuthReplyMsg;

extern const SeerField SEER_AUTH_REPLY_SCHEMA[];

/* The context a connection's messages are written and read in. */
SeerSchemaCtx seer_msg_ctx(int is_8i, uint8_t fv, uint8_t server_fv);

#endif /* SEER_TNS_MSG_H */
