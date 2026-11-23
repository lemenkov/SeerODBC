/* TTC messages as schemas (#395 spike); see msg.h.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "msg.h"

#include <stdlib.h>
#include <string.h>

#include "tns_consts.h"

#define THIN SEER_CODEC_THIN

SeerSchemaCtx seer_msg_ctx(int is_8i, uint8_t fv, uint8_t server_fv)
{
  SeerSchemaCtx cx = {
      .codec = is_8i ? SEER_CODEC_O8I : SEER_CODEC_THIN,
      .fv = fv,
      .server_fv = server_fv,
      .wide_chunks = fv >= TTC_FIELD_VERSION_12_1,
  };
  return cx;
}

/* seerdb _OAC / _O7_OAC (seerdb#2284), the fields only OCI writes left out.
 * The scale is a raw signed byte from 12.1 (and on 8i, one byte), a
 * compressed integer before - the same 00 for the 0 a bind sends, not for a
 * describe's negative scale. 9.2 and 8i have no max_chars. */
#define OAC_FIELDS(T)                                                                              \
  SEER_F(SF_U8, T, data_type), SEER_F(SF_U8, T, flags), SEER_F(SF_U8, T, precision),               \
      SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_12_1, 0, T, scale),                                   \
      SEER_FV(SF_N1, 0, 0, TTC_FIELD_VERSION_12_1, T, scale), SEER_F(SF_N4, T, max_length),        \
      SEER_F(SF_N4, T, max_array), SEER_F(SF_N4, T, cont_flags), SEER_F(SF_N4, T, toid_length),    \
      {.kind = SF_VALUE,                                                                           \
       .flags = SG_IF_SET,                                                                         \
       .off = offsetof(T, toid),                                                                   \
       .if_off = offsetof(T, toid_length)},                                                        \
      SEER_F(SF_N2, T, version), SEER_F(SF_N2, T, charset), SEER_F(SF_U8, T, csfrm),               \
      SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_10_2, 0, T, max_chars),                               \
      SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_12_2, 0, T, oaccolid)

const SeerField SEER_OAC_SCHEMA[] = {
    OAC_FIELDS(SeerOacMsg),
    SEER_END,
};

const SeerField SEER_CHR_SCHEMA[] = {
    SEER_F(SF_CHR, SeerChrMsg, value),
    SEER_END,
};

const SeerField SEER_OPEN_SCHEMA[] = {
    SEER_F(SF_U8, SeerOpenMsg, cursor_ptr),
    SEER_F(SF_N4, SeerOpenMsg, cursor),
    SEER_END,
};

const SeerField SEER_OPEN_REPLY_SCHEMA[] = {
    SEER_F(SF_N4, SeerOpenMsg, cursor),
    SEER_END,
};

static const uint8_t O7_DESCRIBE_HEAD[1] = {0x07};
static const uint8_t O7_DESCRIBE_TAIL[6] = {0x00, 0x00, 0x01, 0x02, 0x01, 0x01};
const SeerField SEER_O7_DESCRIBE_SCHEMA[] = {
    {.kind = SF_CONST, .arg = sizeof O7_DESCRIBE_HEAD, .lit = O7_DESCRIBE_HEAD},
    SEER_F(SF_N4, SeerO7DescribeMsg, cursor),
    {.kind = SF_CONST, .arg = sizeof O7_DESCRIBE_TAIL, .lit = O7_DESCRIBE_TAIL},
    SEER_END,
};

const SeerField SEER_VALUE_SCHEMA[] = {
    SEER_F(SF_VALUE, SeerChrMsg, value),
    SEER_END,
};

const SeerField SEER_DESCRIBE_HEAD_SCHEMA[] = {
    SEER_F(SF_N4, SeerDescribeHeadMsg, max_row_size),
    SEER_F(SF_N4, SeerDescribeHeadMsg, ncols),
    {.kind = SF_U8,
     .flags = SG_IF_SET,
     .off = offsetof(SeerDescribeHeadMsg, reserved),
     .if_off = offsetof(SeerDescribeHeadMsg, ncols)},
    SEER_END,
};

#define A SeerDcbAnnotationsMsg
#define IF_ANN(kind_, member_)                                                                     \
  {.kind = (kind_), .flags = SG_IF_SET, .off = offsetof(A, member_), .if_off = offsetof(A, count)}
const SeerField SEER_DCB_ANNOTATIONS_HEAD_SCHEMA[] = {
    SEER_F(SF_N4, A, count), IF_ANN(SF_U8, ptr), IF_ANN(SF_N4, count2),
    IF_ANN(SF_U8, ptr2),     SEER_END,
};

const SeerField SEER_DCB_ANNOTATIONS_TAIL_SCHEMA[] = {
    SEER_F(SF_N4, A, flags),
    SEER_END,
};
#undef IF_ANN
#undef A

const SeerField SEER_IMPLICIT_COUNT_SCHEMA[] = {
    SEER_F(SF_N4, SeerImplicitMsg, nres),
    SEER_END,
};

const SeerField SEER_IMPLICIT_HEAD_SCHEMA[] = {
    SEER_F(SF_U8, SeerImplicitMsg, pre_len),
    {.kind = SF_RAW,
     .off = offsetof(SeerImplicitMsg, preamble),
     .arg = offsetof(SeerImplicitMsg, pre_len)},
    SEER_END,
};

const SeerField SEER_IMPLICIT_TAIL_SCHEMA[] = {
    SEER_F(SF_N2, SeerImplicitMsg, cursor_id),
    SEER_END,
};

const SeerField SEER_CURSOR_VALUE_HEAD_SCHEMA[] = {
    SEER_F(SF_U8, SeerCursorValueMsg, len),
    SEER_END,
};

const SeerField SEER_CURSOR_VALUE_TAIL_SCHEMA[] = {
    SEER_F(SF_N2, SeerCursorValueMsg, cursor_id),
    {.kind = SF_U8,
     .flags = SG_IF_SET,
     .off = offsetof(SeerCursorValueMsg, indicator),
     .if_off = offsetof(SeerCursorValueMsg, has_indicator)},
    SEER_END,
};

#define D SeerDcbColumnMsg
const SeerField SEER_DCB_COLUMN_SCHEMA[] = {
    OAC_FIELDS(D),
    SEER_F(SF_U8, D, null_ok),
    SEER_F(SF_U8, D, name_bytes),
    SEER_F(SF_COUNTED, D, name),
    SEER_F(SF_COUNTED, D, type_schema),
    SEER_F(SF_COUNTED, D, type_name),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_10_2, 0, D, position),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_11_2, 0, D, uds_flags),
    SEER_FV(SF_COUNTED, THIN, TTC_FIELD_VERSION_23_1, 0, D, domain_schema),
    SEER_FV(SF_COUNTED, THIN, TTC_FIELD_VERSION_23_1, 0, D, domain_name),
    SEER_END,
};

const SeerField SEER_DCB_VECTOR_SCHEMA[] = {
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_23_1 + 1, 0, D, vector_dims),
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_23_1 + 1, 0, D, vector_format),
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_23_1 + 1, 0, D, vector_flags),
    SEER_END,
};
#undef D

const SeerField SEER_DCB_TRAILER_SCHEMA[] = {
    SEER_F(SF_COUNTED, SeerDcbTrailerMsg, time),
    SEER_FC(SF_N4, THIN, SeerDcbTrailerMsg, dcbflag),
    SEER_FC(SF_N4, THIN, SeerDcbTrailerMsg, dcbmdbz),
    SEER_FC(SF_N4, THIN, SeerDcbTrailerMsg, dcbmnpr),
    SEER_FC(SF_N4, THIN, SeerDcbTrailerMsg, dcbmxpr),
    SEER_FV(SF_COUNTED, THIN, TTC_FIELD_VERSION_11_2, 0, SeerDcbTrailerMsg, query_key),
    SEER_END,
};

#define IF_SET(kind_, type_, member_, cond_)                                                       \
  {.kind = (kind_),                                                                                \
   .flags = SG_IF_SET,                                                                             \
   .off = offsetof(type_, member_),                                                                \
   .if_off = offsetof(type_, cond_)}

#define O SeerOerMsg
const SeerField SEER_OER_HEAD_SCHEMA[] = {
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_10_2, 0, O, call_status),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_10_2, 0, O, seq),
    SEER_F(SF_N4, O, rows),
    SEER_F(SF_N2, O, code),
    SEER_END,
};

const SeerField SEER_OER_FLAGS_SCHEMA[] = {
    SEER_F(SF_N2, O, array_err1),
    SEER_F(SF_N2, O, array_err2),
    SEER_F(SF_N2, O, cursor),
    SEER_F(SF_N2, O, position),
    SEER_F(SF_U8, O, sql_type),
    SEER_F(SF_U8, O, fatal),
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_12_1, 0, O, flags),
    SEER_FV(SF_N1, 0, 0, TTC_FIELD_VERSION_12_1, O, flags),
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_12_1, 0, O, cursor_opts),
    SEER_FV(SF_N1, 0, 0, TTC_FIELD_VERSION_12_1, O, cursor_opts),
    SEER_F(SF_U8, O, upi),
    SEER_F(SF_U8, O, warnings),
    SEER_END,
};

const SeerField SEER_OER_BATCH_SCHEMA[] = {
    SEER_F(SF_N4, O, rowid_obj),
    SEER_F(SF_N2, O, rowid_file),
    SEER_F(SF_U8, O, rowid_res),
    SEER_F(SF_N4, O, rowid_block),
    SEER_F(SF_N2, O, rowid_slot),
    SEER_F(SF_N4, O, os_error),
    SEER_F(SF_U8, O, stmt_no),
    SEER_F(SF_U8, O, call_no),
    SEER_F(SF_N2, O, padding),
    SEER_F(SF_N4, O, iterations),
    {.kind = SF_COUNTED, .off = offsetof(O, oerrdd), .arg = SF_N2},
    SEER_F(SF_COUNTED, O, codes),
    SEER_F(SF_COUNTED, O, offsets),
    SEER_F(SF_N4, O, nmsgs),
    SEER_END,
};

const SeerField SEER_OER_MSGS_HEAD_SCHEMA[] = {
    SEER_F(SF_U8, SeerOerTextMsg, indicator),
    SEER_END,
};

const SeerField SEER_OER_MSG_SCHEMA[] = {
    SEER_F(SF_COUNTED, SeerOerTextMsg, text),
    SEER_PAD(2),
    SEER_END,
};

const SeerField SEER_OER_TAIL_SCHEMA[] = {
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_12_1, 0, O, ext_error),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_12_1, 0, O, ext_rows),
    {.kind = SF_N4,
     .codecs = THIN,
     .fv_min = TTC_FIELD_VERSION_12_1,
     .sfv_min = TTC_FIELD_VERSION_20_1,
     .off = offsetof(O, sql_type2)},
    {.kind = SF_N4,
     .codecs = THIN,
     .fv_min = TTC_FIELD_VERSION_12_1,
     .sfv_min = TTC_FIELD_VERSION_20_1,
     .off = offsetof(O, checksum)},
    {.kind = SF_VALUE,
     .flags = SG_IF_SET | SG_IF_MORE,
     .off = offsetof(O, message),
     .if_off = offsetof(O, code)},
    SEER_END,
};
#undef O

/* The trailer's guards: the indicator on 8i and 9i (fv 2), the return code
 * on 8i. */
#define CELL_INDICATOR SEER_FV(SF_N2, 0, 0, TTC_FIELD_VERSION_10_2, SeerCellMsg, indicator)
#define CELL_RETURN_CODE SEER_FC(SF_N2, SEER_CODEC_O8I, SeerCellMsg, return_code)

const SeerField SEER_CELL_SCHEMA[] = {
    SEER_F(SF_VALUE, SeerCellMsg, value),
    CELL_INDICATOR,
    CELL_RETURN_CODE,
    SEER_END,
};

const SeerField SEER_LONG_CELL_SCHEMA[] = {
    SEER_F(SF_VALUE, SeerCellMsg, value),
    SEER_F(SF_N2, SeerCellMsg, indicator),
    SEER_F(SF_N2, SeerCellMsg, return_code),
    SEER_END,
};

const SeerField SEER_LOB_CELL_SCHEMA[] = {
    SEER_F(SF_COUNTED, SeerCellMsg, value),
    CELL_INDICATOR,
    CELL_RETURN_CODE,
    SEER_END,
};

const SeerField SEER_UROWID_CELL_SCHEMA[] = {
    {.kind = SF_COUNTED, .off = offsetof(SeerCellMsg, value), .arg = SF_N2},
    CELL_INDICATOR,
    CELL_RETURN_CODE,
    SEER_END,
};

#define OUT_TAIL                                                                                   \
  SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_10_2, 0, SeerCellMsg, return_code), CELL_INDICATOR
const SeerField SEER_OUT_CELL_SCHEMA[] = {
    SEER_F(SF_VALUE, SeerCellMsg, value),
    OUT_TAIL,
    SEER_END,
};

const SeerField SEER_OUT_TAIL_SCHEMA[] = {
    OUT_TAIL,
    SEER_END,
};
#undef OUT_TAIL

#define R SeerReturningMsg
const SeerField SEER_RETURNING_COUNT_SCHEMA[] = {
    SEER_F(SF_N4, R, nrows),
    SEER_END,
};

const SeerField SEER_RETURNING_VALUE_SCHEMA[] = {
    SEER_F(SF_VALUE, R, value),
    SEER_F(SF_N4, R, actual_len),
    SEER_END,
};

#define IF_BLOCK(kind_, member_)                                                                   \
  {.kind = (kind_),                                                                                \
   .codecs = THIN,                                                                                 \
   .fv_min = TTC_FIELD_VERSION_12_1,                                                               \
   .flags = SG_IF_SET,                                                                             \
   .off = offsetof(R, member_),                                                                    \
   .if_off = offsetof(R, block_len)}
const SeerField SEER_RETURNING_LOB_SCHEMA[] = {
    SEER_FV(SF_COUNTED, THIN, 0, TTC_FIELD_VERSION_12_1, R, locator),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_12_1, 0, R, block_len),
    IF_BLOCK(SF_N4, lob_size),
    IF_BLOCK(SF_N4, chunk_size),
    IF_BLOCK(SF_VALUE, locator),
    SEER_F(SF_N4, R, actual_len),
    SEER_END,
};
#undef IF_BLOCK
#undef R

const SeerField SEER_LOB_OUT_SCHEMA[] = {
    SEER_F(SF_COUNTED, SeerCellMsg, value),
    CELL_INDICATOR,
    SEER_END,
};

static const uint8_t UNSET_MARK[1] = {0xFF};
const SeerField SEER_OUT_UNSET_SCHEMA[] = {
    {.kind = SF_CONST, .arg = 1, .lit = UNSET_MARK},
    CELL_INDICATOR,
    SEER_END,
};

const SeerField SEER_OUT_ARRAY_SCHEMA[] = {
    SEER_F(SF_N4, SeerOutArrayMsg, count),
    SEER_END,
};

static const uint8_t O7_UNSET_MARK[4] = {0xFF, 0x02, 0x0C, 0x21};
const SeerField SEER_O7_OUT_UNSET_SCHEMA[] = {
    {.kind = SF_CONST, .arg = sizeof O7_UNSET_MARK, .lit = O7_UNSET_MARK},
    SEER_END,
};

const SeerField SEER_OUT_IND_SCHEMA[] = {
    {.kind = SF_N2, .flags = SG_IF_MORE, .off = offsetof(SeerCellMsg, indicator)},
    SEER_END,
};

const SeerField SEER_IOV_SCHEMA[] = {
    SEER_F(SF_U8, SeerIovMsg, flags),
    SEER_F(SF_N2, SeerIovMsg, requests),
    SEER_F(SF_N2, SeerIovMsg, iterations),
    SEER_F(SF_N4, SeerIovMsg, iterations_now),
    SEER_FC(SF_N2, THIN, SeerIovMsg, buffer_len),
    SEER_F(SF_COUNTED, SeerIovMsg, bit_vector),
    SEER_F(SF_COUNTED, SeerIovMsg, rowid),
    SEER_END,
};

const SeerField SEER_IOV_DIRS_SCHEMA[] = {
    {.kind = SF_RAW, .off = offsetof(SeerIovMsg, directions), .arg = offsetof(SeerIovMsg, nbinds)},
    SEER_END,
};

#define IF_ROWID(kind_, member_)                                                                   \
  {.kind = (kind_),                                                                                \
   .flags = SG_IF_SET,                                                                             \
   .off = offsetof(SeerCellMsg, member_),                                                          \
   .if_off = offsetof(SeerCellMsg, rowid_size)}
const SeerField SEER_ROWID_CELL_SCHEMA[] = {
    {.kind = SF_U8, .flags = SG_FF_NULL, .off = offsetof(SeerCellMsg, rowid_size)},
    IF_ROWID(SF_N4, rowid_obj),
    IF_ROWID(SF_N2, rowid_file),
    IF_ROWID(SF_N1, rowid_res),
    IF_ROWID(SF_N4, rowid_block),
    IF_ROWID(SF_N2, rowid_slot),
    CELL_INDICATOR,
    CELL_RETURN_CODE,
    SEER_END,
};

const SeerField SEER_LOB_DATA_SCHEMA[] = {
    SEER_F(SF_LOB, SeerLobDataMsg, data),
    SEER_END,
};

static const uint8_t LOB_BIND_PREFIX[3] = {0x01, 0x28, 0x28};
const SeerField SEER_LOB_BIND_SCHEMA[] = {
    {.kind = SF_CONST, .arg = sizeof LOB_BIND_PREFIX, .lit = LOB_BIND_PREFIX},
    SEER_F(SF_BE2, SeerLobBindMsg, loc_len),
    {.kind = SF_RAW,
     .off = offsetof(SeerLobBindMsg, locator),
     .arg = offsetof(SeerLobBindMsg, loc_len)},
    {.kind = SF_CHR,
     .flags = SG_IF_SET,
     .off = offsetof(SeerLobBindMsg, image),
     .if_off = offsetof(SeerLobBindMsg, has_image)},
    SEER_END,
};

static const uint8_t VALUE_LOCATOR_HEAD[13] = {0x00, 0x04, 0x61, 0x08, 0x00, 0x00, 0x00,
                                               0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
const SeerField SEER_VALUE_LOCATOR_SCHEMA[] = {
    {.kind = SF_CONST, .arg = sizeof VALUE_LOCATOR_HEAD, .lit = VALUE_LOCATOR_HEAD},
    SEER_F(SF_U8, SeerValueLocatorMsg, len_hi),
    SEER_F(SF_BE2, SeerValueLocatorMsg, len_lo),
    SEER_PAD(22),
    SEER_END,
};

const SeerField SEER_LEGACY_LOB_BIND_SCHEMA[] = {
    SEER_F(SF_N4, SeerLegacyLobBindMsg, loc_len),
    SEER_FC(SF_VALUE, SEER_CODEC_O8I, SeerLegacyLobBindMsg, locator),
    SEER_FC(SF_CHR, THIN, SeerLegacyLobBindMsg, locator),
    SEER_END,
};

const SeerField SEER_RXH_SCHEMA[] = {
    SEER_F(SF_U8, SeerRxhMsg, flags),      SEER_F(SF_N2, SeerRxhMsg, requests),
    SEER_F(SF_N2, SeerRxhMsg, iteration),  SEER_F(SF_N2, SeerRxhMsg, iterations),
    SEER_F(SF_N2, SeerRxhMsg, buffer_len), SEER_F(SF_COUNTED, SeerRxhMsg, bit_vector),
    SEER_F(SF_COUNTED, SeerRxhMsg, rowid), SEER_END,
};

/* An RPA's parameter, and one of its keyword pairs: read and passed over. */
typedef struct {
  int64_t v;
} SeerN4Item;
static const SeerField N4_ITEM[] = {SEER_F(SF_N4, SeerN4Item, v), SEER_END};

typedef struct {
  SeerBytes text, binary;
  int64_t keyword;
} SeerRpaPair;
static const SeerField RPA_PAIR[] = {
    SEER_F(SF_COUNTED, SeerRpaPair, text),
    SEER_F(SF_COUNTED, SeerRpaPair, binary),
    SEER_F(SF_N2, SeerRpaPair, keyword),
    SEER_END,
};

const SeerField SEER_RPA_HEAD_SCHEMA[] = {
    SEER_F(SF_N2, SeerRpaMsg, nparams),
    {.kind = SF_EACH,
     .arg = offsetof(SeerRpaMsg, nparams),
     .sub = N4_ITEM,
     .subsize = sizeof(SeerN4Item)},
    SEER_END,
};

const SeerField SEER_RPA_TAIL_SCHEMA[] = {
    SEER_F(SF_N2, SeerRpaMsg, txn_len),
    {.kind = SF_RAW, .off = offsetof(SeerRpaMsg, txn), .arg = offsetof(SeerRpaMsg, txn_len)},
    SEER_F(SF_N2, SeerRpaMsg, npairs),
    {.kind = SF_EACH,
     .arg = offsetof(SeerRpaMsg, npairs),
     .sub = RPA_PAIR,
     .subsize = sizeof(SeerRpaPair)},
    SEER_FC(SF_N4, THIN, SeerRpaMsg, reg_len),
    {.kind = SF_RAW,
     .codecs = THIN,
     .off = offsetof(SeerRpaMsg, reg),
     .arg = offsetof(SeerRpaMsg, reg_len)},
    SEER_END,
};

#define OBJECT_HEAD                                                                                \
  SEER_F(SF_COUNTED, SeerObjectMsg, type_oid), SEER_F(SF_COUNTED, SeerObjectMsg, oid),             \
      SEER_F(SF_COUNTED, SeerObjectMsg, snapshot), SEER_F(SF_N2, SeerObjectMsg, version),          \
      SEER_F(SF_N4, SeerObjectMsg, image_len), SEER_F(SF_N2, SeerObjectMsg, flags)

const SeerField SEER_OBJECT_SCHEMA[] = {
    OBJECT_HEAD,
    {.kind = SF_CHR,
     .flags = SG_IF_SET,
     .off = offsetof(SeerObjectMsg, image),
     .if_off = offsetof(SeerObjectMsg, image_len)},
    SEER_END,
};

const SeerField SEER_OBJECT_HEAD_SCHEMA[] = {
    OBJECT_HEAD,
    SEER_END,
};

const SeerField SEER_OBJECT_IMAGE_SCHEMA[] = {
    SEER_F(SF_VALUE, SeerObjectMsg, image),
    SEER_END,
};
#undef OBJECT_HEAD

#define A SeerAll8Msg
const SeerField SEER_ALL8_SCHEMA[] = {
    SEER_F(SF_N4, A, options),
    SEER_F(SF_N4, A, cursor),
    SEER_F(SF_U8, A, sql_ptr),
    SEER_F(SF_N4, A, sql_len),
    SEER_F(SF_U8, A, al8i4_ptr),
    SEER_F(SF_N4, A, al8i4_len),
    SEER_F(SF_U8, A, al8o4),
    SEER_F(SF_U8, A, al8o4l),
    SEER_F(SF_N4, A, prefetch_size),
    SEER_F(SF_N4, A, prefetch_rows),
    SEER_F(SF_N4, A, max_long),
    SEER_F(SF_U8, A, binds_ptr),
    SEER_F(SF_N4, A, bind_count),
    SEER_F(SF_U8, A, al8app),
    SEER_F(SF_U8, A, al8txn),
    SEER_F(SF_U8, A, al8txl),
    SEER_F(SF_U8, A, al8kv),
    SEER_F(SF_U8, A, al8kvl),
    SEER_FC(SF_U8, THIN, A, defines_ptr),
    SEER_FC(SF_N4, THIN, A, define_count),
    SEER_FC(SF_U8, THIN, A, reg0),
    SEER_FC(SF_U8, THIN, A, reg1),
    SEER_FC(SF_U8, THIN, A, reg2),
    {.kind = SF_PAD,
     .codecs = THIN,
     .flags = SG_IF_SET,
     .arg = 5,
     .if_off = offsetof(A, register_tail)},
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_12_1, 0, A, pidmlrc_ptr),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_12_1, 0, A, pidmlrc_len),
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_12_1, 0, A, pidmlrc_ptr2),
    {.kind = SF_PAD, .codecs = THIN, .fv_min = TTC_FIELD_VERSION_12_2, .arg = 5}, /* SQL id */
    {.kind = SF_PAD,
     .codecs = THIN,
     .fv_min = TTC_FIELD_VERSION_12_2 + 1,
     .arg = 2}, /* chunk ids */
    {.kind = SF_SQL, .flags = SG_IF_SET, .if_off = offsetof(A, sql_ptr), .off = offsetof(A, sql)},
    {.kind = SF_N4S, .off = offsetof(A, al8i4), .arg = offsetof(A, al8i4_n)},
    SEER_END,
};
#undef A

const SeerField SEER_FETCH_SCHEMA[] = {
    SEER_F(SF_N4, SeerFetchMsg, cursor),
    SEER_F(SF_N4, SeerFetchMsg, rows),
    SEER_END,
};

static const uint8_t O7_ALL7_MID[9] = {0, 0, 0x01, 0x01, 0x07, 0x01, 0x01, 0x02, 0};
static const uint8_t O7_ALL7_ROWS_LEAD[2] = {0x01, 0x01};

#define S SeerO7All7Msg
const SeerField SEER_O7_ALL7_SCHEMA[] = {
    SEER_F(SF_N4, S, options),
    SEER_F(SF_N4, S, cursor),
    SEER_F(SF_U8, S, sql_ptr),
    SEER_F(SF_N4, S, sql_len),
    {.kind = SF_CONST, .arg = sizeof O7_ALL7_MID, .lit = O7_ALL7_MID},
    SEER_F(SF_U8, S, defines_ptr),
    SEER_F(SF_N4, S, define_count),
    SEER_F(SF_U8, S, binds_ptr),
    SEER_F(SF_N4, S, bind_count),
    {.kind = SF_SQL, .flags = SG_IF_SET, .if_off = offsetof(S, sql_ptr), .off = offsetof(S, sql)},
    {.kind = SF_CONST, .arg = sizeof O7_ALL7_ROWS_LEAD, .lit = O7_ALL7_ROWS_LEAD},
    SEER_F(SF_N4, S, rows),
    SEER_PAD(5),
    SEER_END,
};
#undef S

const SeerField SEER_CURSOR_CALL_SCHEMA[] = {
    SEER_F(SF_N4, SeerCursorCallMsg, cursor),
    SEER_END,
};

#define H SeerAuthHeadMsg
const SeerField SEER_AUTH_HEAD_SCHEMA[] = {
    SEER_F(SF_U8, H, user_ptr),
    SEER_F(SF_N4, H, user_len),
    SEER_F(SF_N4, H, mode),
    SEER_F(SF_U8, H, pairs_ptr),
    SEER_F(SF_N4, H, npairs),
    SEER_F(SF_U8, H, ptr3),
    SEER_F(SF_U8, H, ptr4),
    SEER_FV(SF_VALUE, 0, TTC_FIELD_VERSION_12_1, 0, H, user),
    {.kind = SF_RAW,
     .codecs = THIN,
     .fv_max = TTC_FIELD_VERSION_12_1,
     .off = offsetof(H, user),
     .arg = offsetof(H, user_bytes)},
    SEER_END,
};
#undef H

const SeerField SEER_AUTH_PAIR_SCHEMA[] = {
    SEER_F(SF_COUNTED, SeerAuthPairMsg, key),
    SEER_F(SF_COUNTED, SeerAuthPairMsg, value),
    /* written always; read on thin only while bytes remain */
    {.kind = SF_N4, .flags = SG_IF_MORE, .off = offsetof(SeerAuthPairMsg, flags)},
    SEER_END,
};

#define P SeerSvrPiggybackMsg
#define PIG_PAIRS                                                                                  \
  {.kind = SF_EACH,                                                                                \
   .arg = offsetof(P, npairs),                                                                     \
   .sub = SEER_AUTH_PAIR_SCHEMA,                                                                   \
   .subsize = sizeof(SeerAuthPairMsg)}
const SeerField SEER_SVR_PIG_SESS_RET_SCHEMA[] = {
    SEER_F(SF_N2, P, ndtys),
    SEER_F(SF_U8, P, dtys_len),
    SEER_F(SF_N2, P, npairs),
    {.kind = SF_U8,
     .flags = SG_IF_SET,
     .off = offsetof(P, pairs_len),
     .if_off = offsetof(P, npairs)},
    PIG_PAIRS,
    SEER_F(SF_N4, P, flags),
    SEER_F(SF_N4, P, session_id),
    SEER_F(SF_N2, P, serial),
    SEER_END,
};

const SeerField SEER_SVR_PIG_MTS_SCHEMA[] = {
    SEER_F(SF_N2, P, ndtys),
    SEER_F(SF_VALUE, P, pid),
    SEER_END,
};

const SeerField SEER_SVR_PIG_SYNC_SCHEMA[] = {
    SEER_F(SF_N2, P, ndtys),
    SEER_F(SF_U8, P, dtys_len),
    SEER_F(SF_N2, P, npairs),
    SEER_F(SF_U8, P, pairs_len),
    PIG_PAIRS,
    SEER_F(SF_N4, P, flags),
    SEER_END,
};
#undef PIG_PAIRS
#undef P

const SeerField SEER_AUTH_REPLY_SCHEMA[] = {
    SEER_F(SF_N2, SeerAuthReplyMsg, npairs),
    SEER_END,
};

const SeerField SEER_FUN_HEAD_SCHEMA[] = {
    SEER_F(SF_U8, SeerFunHeadMsg, type),
    SEER_F(SF_U8, SeerFunHeadMsg, function),
    SEER_F(SF_U8, SeerFunHeadMsg, seq),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_23_1 + 1, 0, SeerFunHeadMsg, call_token),
    SEER_END,
};

const SeerField SEER_PIPELINE_BEGIN_SCHEMA[] = {
    SEER_F(SF_N4, SeerThinCallMsg, error_set_id),
    SEER_F(SF_U8, SeerThinCallMsg, error_set_mode),
    SEER_F(SF_U8, SeerThinCallMsg, mode),
    SEER_END,
};

const SeerField SEER_PIPELINE_END_SCHEMA[] = {
    SEER_F(SF_N4, SeerThinCallMsg, pipeline_id),
    SEER_END,
};

const SeerField SEER_SESSION_STATE_SCHEMA[] = {
    SEER_F(SF_N4, SeerThinCallMsg, state),
    SEER_END,
};

#define P SeerAqPropsMsg
#define AQ_STR(len_, val_)                                                                         \
  SEER_F(SF_N4, P, len_),                                                                          \
  {                                                                                                \
    .kind = SF_CHR, .flags = SG_IF_SET, .off = offsetof(P, val_), .if_off = offsetof(P, len_)      \
  }
#define AQ_PROPS_HEAD                                                                              \
  SEER_F(SF_N4, P, priority), SEER_F(SF_N4, P, delay), SEER_F(SF_N4, P, expiration),               \
      AQ_STR(correlation_len, correlation), SEER_F(SF_N4, P, attempts),                            \
      AQ_STR(exception_queue_len, exception_queue), SEER_F(SF_N4, P, state),                       \
      AQ_STR(enq_time_len, enq_time), AQ_STR(enq_txn_len, enq_txn), SEER_F(SF_N4, P, n_ext),       \
  {                                                                                                \
    .kind = SF_U8, .flags = SG_IF_SET, .off = offsetof(P, ext_lead), .if_off = offsetof(P, n_ext)  \
  }
#define AQ_PROPS_TAIL                                                                              \
  SEER_F(SF_N4, P, user_prop), SEER_F(SF_N4, P, cscn), SEER_F(SF_N4, P, dscn),                     \
      SEER_F(SF_N4, P, flags), SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_21_1, 0, P, shard_id)

const SeerField SEER_AQ_PROPS_HEAD_SCHEMA[] = {
    AQ_PROPS_HEAD,
    SEER_END,
};

const SeerField SEER_AQ_EXT_SCHEMA[] = {
    SEER_F(SF_N4, SeerAqExtMsg, text_len),
    {.kind = SF_CHR,
     .flags = SG_IF_SET,
     .off = offsetof(SeerAqExtMsg, text),
     .if_off = offsetof(SeerAqExtMsg, text_len)},
    SEER_F(SF_N4, SeerAqExtMsg, bin_len),
    {.kind = SF_CHR,
     .flags = SG_IF_SET,
     .off = offsetof(SeerAqExtMsg, bin),
     .if_off = offsetof(SeerAqExtMsg, bin_len)},
    SEER_F(SF_N4, SeerAqExtMsg, keyword),
    SEER_END,
};

const SeerField SEER_AQ_PROPS_TAIL_SCHEMA[] = {
    AQ_PROPS_TAIL,
    SEER_END,
};

const SeerField SEER_AQ_PROPS_SCHEMA[] = {
    AQ_PROPS_HEAD,
    {.kind = SF_EACH,
     .arg = offsetof(P, n_ext),
     .sub = SEER_AQ_EXT_SCHEMA,
     .subsize = sizeof(SeerAqExtMsg)},
    AQ_PROPS_TAIL,
    SEER_END,
};
#undef AQ_PROPS_TAIL
#undef AQ_PROPS_HEAD
#undef AQ_STR
#undef P

#define E SeerAqEnqMsg
const SeerField SEER_AQ_ENQ_HEAD_SCHEMA[] = {
    SEER_F(SF_U8, E, qname_ptr),
    SEER_F(SF_N4, E, qname_len),
    SEER_END,
};

const SeerField SEER_AQ_ENQ_TAIL_SCHEMA[] = {
    SEER_F(SF_U8, E, recipients_ptr),
    SEER_F(SF_N4, E, recipients),
    SEER_F(SF_N4, E, visibility),
    SEER_F(SF_U8, E, relmsgid_ptr),
    SEER_F(SF_N4, E, relmsgid_len),
    SEER_F(SF_N4, E, seq_deviation),
    SEER_F(SF_U8, E, toid_ptr),
    SEER_F(SF_N4, E, toid_len),
    SEER_F(SF_N4, E, msg_version),
    SEER_F(SF_U8, E, payload_ptr),
    SEER_F(SF_U8, E, raw_ptr),
    SEER_F(SF_N4, E, raw_len),
    SEER_F(SF_U8, E, msgid_ptr),
    SEER_F(SF_N4, E, msgid_len),
    SEER_F(SF_N4, E, enq_flags),
    SEER_F(SF_U8, E, ext1_ptr),
    SEER_F(SF_N4, E, ext1_n),
    SEER_F(SF_U8, E, ext2_ptr),
    SEER_F(SF_N4, E, ext2_n),
    SEER_F(SF_U8, E, srcseq_ptr),
    SEER_F(SF_N4, E, srcseq_len),
    SEER_F(SF_U8, E, maxseq_ptr),
    SEER_F(SF_N4, E, maxseq_len),
    SEER_F(SF_U8, E, ack_len),
    SEER_F(SF_U8, E, corr_ptr),
    SEER_F(SF_N4, E, corr_len),
    SEER_F(SF_U8, E, sender_name_ptr),
    SEER_F(SF_N4, E, sender_name_len),
    SEER_F(SF_U8, E, sender_addr_ptr),
    SEER_F(SF_N4, E, sender_addr_len),
    SEER_F(SF_U8, E, sender_cs_ptr),
    SEER_F(SF_U8, E, sender_ncs_ptr),
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_20_1, 0, E, json_ptr),
    /* the data section */
    {.kind = SF_RAW,
     .codecs = THIN,
     .fv_max = TTC_FIELD_VERSION_12_1,
     .off = offsetof(E, qname),
     .arg = offsetof(E, qname_len)},
    SEER_FV(SF_CHR, THIN, TTC_FIELD_VERSION_12_1, 0, E, qname),
    {.kind = SF_RAW, .off = offsetof(E, toid), .arg = offsetof(E, toid_len)},
    {.kind = SF_RAW, .off = offsetof(E, payload), .arg = offsetof(E, payload_len)},
    SEER_END,
};
#undef E

#define Y SeerAqArrayMsg
const SeerField SEER_AQ_ARRAY_HEAD_SCHEMA[] = {
    SEER_F(SF_U8, Y, in_ptr),
    SEER_F(SF_N4, Y, in_len),
    SEER_F(SF_N4, Y, ret_flags),
    SEER_F(SF_U8, Y, out_ptr),
    SEER_F(SF_U8, Y, out_len),
    SEER_F(SF_N4, Y, op),
    SEER_F(SF_U8, Y, iters_ptr),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_21_1, 0, Y, shard_id),
    SEER_END,
};

const SeerField SEER_AQ_ARRAY_ENQ_HEAD_SCHEMA[] = {
    SEER_F(SF_N4, Y, iters),
    SEER_F(SF_N4, Y, relmsgid_len),
    SEER_F(SF_U8, Y, rxh),
    SEER_F(SF_N4, Y, qname_len),
    SEER_F(SF_CHR, Y, qname),
    {.kind = SF_RAW, .off = offsetof(Y, toid), .arg = offsetof(Y, toid_len)},
    SEER_F(SF_N4, Y, msg_version),
    SEER_F(SF_N4, Y, flags),
    SEER_END,
};

const SeerField SEER_AQ_ARRAY_ENQ_ROW_SCHEMA[] = {
    SEER_F(SF_U8, Y, rxd),
    SEER_F(SF_N4, Y, aqi_flags),
    SEER_END,
};

const SeerField SEER_AQ_ARRAY_ENQ_ROW_TAIL_SCHEMA[] = {
    SEER_F(SF_N4, Y, recipients),
    SEER_F(SF_N4, Y, visibility),
    SEER_F(SF_N4, Y, relmsgid),
    SEER_F(SF_N4, Y, seq_deviation),
    SEER_F(SF_N4, Y, raw_len),
    {.kind = SF_RAW, .off = offsetof(Y, payload), .arg = offsetof(Y, raw_len)},
    SEER_END,
};

const SeerField SEER_AQ_ARRAY_ENQ_END_SCHEMA[] = {
    SEER_F(SF_U8, Y, sta),
    SEER_END,
};
#undef Y

/* A data-section string: raw below 12.1, a bind value from (seerdb §29). */
#define AQ_DATA_STR(T_, len_, val_)                                                                \
  {.kind = SF_RAW,                                                                                 \
   .codecs = THIN,                                                                                 \
   .fv_max = TTC_FIELD_VERSION_12_1,                                                               \
   .off = offsetof(T_, val_),                                                                      \
   .arg = offsetof(T_, len_)},                                                                     \
  {                                                                                                \
    .kind = SF_CHR, .codecs = THIN, .fv_min = TTC_FIELD_VERSION_12_1, .flags = SG_IF_SET,          \
    .off = offsetof(T_, val_), .if_off = offsetof(T_, len_)                                        \
  }

#define D SeerAqDeqMsg
const SeerField SEER_AQ_DEQ_SCHEMA[] = {
    SEER_F(SF_U8, D, qname_ptr),
    SEER_F(SF_N4, D, qname_len),
    SEER_F(SF_U8, D, props_ptr),
    SEER_F(SF_U8, D, props_len_ptr),
    SEER_F(SF_U8, D, recip_ptr),
    SEER_F(SF_U8, D, recip_len_ptr),
    SEER_F(SF_U8, D, consumer_ptr),
    SEER_F(SF_N4, D, consumer_len),
    SEER_F(SF_N4, D, mode),
    SEER_F(SF_N4, D, navigation),
    SEER_F(SF_N4, D, visibility),
    SEER_F(SF_N4, D, wait),
    SEER_F(SF_U8, D, selector_ptr),
    SEER_F(SF_N4, D, selector_len),
    SEER_F(SF_U8, D, corr_ptr),
    SEER_F(SF_N4, D, corr_len),
    SEER_F(SF_U8, D, toid_ptr),
    SEER_F(SF_N4, D, toid_len),
    SEER_F(SF_N4, D, msg_version),
    SEER_F(SF_U8, D, payload_ptr),
    SEER_F(SF_U8, D, msgid_ptr),
    SEER_F(SF_N4, D, msgid_len),
    SEER_F(SF_N4, D, deq_flags),
    SEER_F(SF_U8, D, cond_ptr),
    SEER_F(SF_N4, D, cond_len),
    SEER_F(SF_U8, D, ext_ptr),
    SEER_F(SF_N4, D, ext_n),
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_20_1, 0, D, json_ptr),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_21_1, 0, D, shard_id),
    /* the data section */
    {.kind = SF_RAW,
     .codecs = THIN,
     .fv_max = TTC_FIELD_VERSION_12_1,
     .off = offsetof(D, qname),
     .arg = offsetof(D, qname_len)},
    SEER_FV(SF_CHR, THIN, TTC_FIELD_VERSION_12_1, 0, D, qname),
    AQ_DATA_STR(D, consumer_len, consumer),
    AQ_DATA_STR(D, corr_len, correlation),
    {.kind = SF_RAW, .off = offsetof(D, toid), .arg = offsetof(D, toid_len)},
    SEER_END,
};
#undef D
#undef AQ_DATA_STR

#define R SeerAqArrayDeqRowMsg
#define AQ_STR(len_, val_)                                                                         \
  SEER_F(SF_N4, R, len_),                                                                          \
  {                                                                                                \
    .kind = SF_CHR, .flags = SG_IF_SET, .off = offsetof(R, val_), .if_off = offsetof(R, len_)      \
  }
const SeerField SEER_AQ_ARRAY_DEQ_ROW_HEAD_SCHEMA[] = {
    SEER_F(SF_N4, R, qname_len),
    SEER_F(SF_CHR, R, qname),
    SEER_END,
};

const SeerField SEER_AQ_ARRAY_DEQ_ROW_TAIL_SCHEMA[] = {
    SEER_F(SF_N4, R, recipients),   AQ_STR(consumer_len, consumer),
    SEER_F(SF_N4, R, mode),         SEER_F(SF_N4, R, navigation),
    SEER_F(SF_N4, R, visibility),   SEER_F(SF_N4, R, wait),
    AQ_STR(selector_len, selector), AQ_STR(corr_len, correlation),
    AQ_STR(cond_len, condition),    SEER_F(SF_N4, R, ext_n),
    SEER_F(SF_N4, R, relmsgid),     SEER_F(SF_N4, R, seq_deviation),
    SEER_F(SF_N4, R, toid_len),     SEER_F(SF_CHR, R, toid),
    SEER_F(SF_N4, R, msg_version),  SEER_F(SF_N4, R, payload_len),
    SEER_F(SF_N4, R, raw_len),      SEER_F(SF_N4, R, unnamed),
    SEER_F(SF_N4, R, flags),        SEER_F(SF_N4, R, ext_len),
    SEER_F(SF_N4, R, srcseq_len),   SEER_END,
};
#undef AQ_STR
#undef R

#define Q SeerAqReplyMsg
const SeerField SEER_AQ_DEQ_REPLY_HEAD_SCHEMA[] = {
    SEER_F(SF_N4, Q, props_len),
    SEER_END,
};

const SeerField SEER_AQ_DEQ_REPLY_MID_SCHEMA[] = {
    SEER_F(SF_N4, Q, recipients),
    SEER_END,
};

const SeerField SEER_AQ_MSGID_SCHEMA[] = {
    {.kind = SF_RAW, .off = offsetof(Q, msgid), .arg = offsetof(Q, msgid_len)},
    SEER_END,
};

const SeerField SEER_AQ_ARRAY_REPLY_HEAD_SCHEMA[] = {
    SEER_F(SF_N4, Q, iters),
    SEER_END,
};

const SeerField SEER_AQ_ITER_HEAD_SCHEMA[] = {
    SEER_F(SF_N4, Q, props_len),
    {.kind = SF_U8,
     .flags = SG_IF_SET,
     .off = offsetof(Q, props_lead),
     .if_off = offsetof(Q, props_len)},
    SEER_END,
};

const SeerField SEER_AQ_ITER_MID_SCHEMA[] = {
    SEER_F(SF_N4, Q, recipients),
    SEER_F(SF_N4, Q, payload_n),
    SEER_END,
};

const SeerField SEER_AQ_ITER_TAIL_SCHEMA[] = {
    SEER_F(SF_N4, Q, msgid_len),
    {.kind = SF_VALUE,
     .flags = SG_IF_SET,
     .off = offsetof(Q, msgid),
     .if_off = offsetof(Q, msgid_len)},
    SEER_F(SF_N4, Q, ext_len),
    SEER_F(SF_N4, Q, ack),
    SEER_END,
};
#undef Q

#define T SeerTpcMsg
#define TPC_HEAD                                                                                   \
  SEER_F(SF_N4, T, op), SEER_F(SF_U8, T, ctx_ptr), SEER_F(SF_N4, T, ctx_len),                      \
      SEER_F(SF_N4, T, format_id), SEER_F(SF_N4, T, gtrid_len), SEER_F(SF_N4, T, bqual_len),       \
      SEER_F(SF_U8, T, xid_ptr), SEER_F(SF_N4, T, xid_len)
#define TPC_TAIL                                                                                   \
  {.kind = SF_RAW, .off = offsetof(T, ctx), .arg = offsetof(T, ctx_len)},                          \
  {                                                                                                \
    .kind = SF_RAW, .off = offsetof(T, xid), .arg = offsetof(T, xid_len)                           \
  }

static const uint8_t TPC_OUT_PTRS[3] = {1, 1, 1};

const SeerField SEER_TPC_SWITCH_SCHEMA[] = {
    TPC_HEAD,
    SEER_F(SF_N4, T, flags),
    SEER_F(SF_N4, T, timeout),
    {.kind = SF_CONST, .arg = sizeof TPC_OUT_PTRS, .lit = TPC_OUT_PTRS},
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_11_2, 0, T, int_name_ptr),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_11_2, 0, T, int_name_len),
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_11_2, 0, T, ext_name_ptr),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_11_2, 0, T, ext_name_len),
    TPC_TAIL,
    SEER_F(SF_N4, T, app_value),
    SEER_END,
};

const SeerField SEER_TPC_CHANGE_STATE_SCHEMA[] = {
    TPC_HEAD,
    SEER_F(SF_N4, T, timeout),
    SEER_F(SF_N4, T, state),
    SEER_F(SF_U8, T, out_ptr),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_10_2, 0, T, flags),
    TPC_TAIL,
    SEER_END,
};

const SeerField SEER_TPC_CONTEXT_REPLY_SCHEMA[] = {
    SEER_F(SF_N4, T, app_value),
    SEER_F(SF_N4, T, ctx_len),
    {.kind = SF_RAW, .off = offsetof(T, ctx), .arg = offsetof(T, ctx_len)},
    SEER_END,
};

const SeerField SEER_TPC_STATE_REPLY_SCHEMA[] = {
    SEER_F(SF_N4, T, state),
    SEER_END,
};
#undef TPC_TAIL
#undef TPC_HEAD
#undef T

const SeerField SEER_CLOSE_CURSORS_SCHEMA[] = {
    SEER_F(SF_U8, SeerCloseCursorsMsg, list_ptr),
    {.kind = SF_INTS,
     .off = offsetof(SeerCloseCursorsMsg, ids),
     .arg = offsetof(SeerCloseCursorsMsg, n)},
    SEER_END,
};

const SeerField SEER_LOBOPS_REPLY_SCHEMA[] = {
    SEER_F(SF_BE2, SeerLobopReplyMsg, loc_len),
    {.kind = SF_RAW,
     .off = offsetof(SeerLobopReplyMsg, locator),
     .arg = offsetof(SeerLobopReplyMsg, loc_len)},
    IF_SET(SF_N4, SeerLobopReplyMsg, amount, has_amount),
    SEER_END,
};

uint8_t *seer_lobop_reply_locator(const SeerLobopReplyMsg *m, size_t *n)
{
  uint8_t *loc = malloc(2 + m->locator.n);
  if (loc == NULL)
    return NULL;
  loc[0] = (uint8_t)(m->locator.n >> 8);
  loc[1] = (uint8_t)m->locator.n;
  if (m->locator.n > 0)
    memcpy(loc + 2, m->locator.p, m->locator.n);
  *n = 2 + m->locator.n;
  return loc;
}

const SeerField SEER_LOBOPS_SCHEMA[] = {
    SEER_F(SF_U8, SeerLobopMsg, src_ptr),
    SEER_F(SF_N4, SeerLobopMsg, src_len),
    SEER_F(SF_U8, SeerLobopMsg, dst_ptr),
    SEER_F(SF_N4, SeerLobopMsg, dst_len),
    {.kind = SF_N4,
     .flags = SG_IF_CLEAR,
     .off = offsetof(SeerLobopMsg, short_src_off),
     .if_off = offsetof(SeerLobopMsg, explicit_short)},
    {.kind = SF_U8L,
     .flags = SG_IF_SET,
     .off = offsetof(SeerLobopMsg, short_src_off),
     .if_off = offsetof(SeerLobopMsg, explicit_short)},
    {.kind = SF_N4,
     .flags = SG_IF_CLEAR,
     .off = offsetof(SeerLobopMsg, short_dst_off),
     .if_off = offsetof(SeerLobopMsg, explicit_short)},
    {.kind = SF_U8L,
     .flags = SG_IF_SET,
     .off = offsetof(SeerLobopMsg, short_dst_off),
     .if_off = offsetof(SeerLobopMsg, explicit_short)},
    SEER_F(SF_U8, SeerLobopMsg, charset_ptr),
    SEER_F(SF_U8, SeerLobopMsg, short_amount_ptr),
    SEER_F(SF_U8, SeerLobopMsg, null_lob_ptr),
    SEER_F(SF_N4, SeerLobopMsg, op),
    SEER_F(SF_U8, SeerLobopMsg, scn_ptr),
    SEER_F(SF_N4, SeerLobopMsg, scn_len),
    /* 10g+: the long offsets, the amount pointer, three empty array slots */
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_10_2, 0, SeerLobopMsg, src_off),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_10_2, 0, SeerLobopMsg, dst_off),
    SEER_FV(SF_U8, THIN, TTC_FIELD_VERSION_10_2, 0, SeerLobopMsg, amount_ptr),
    {.kind = SF_PAD, .codecs = THIN, .fv_min = TTC_FIELD_VERSION_10_2, .arg = 6},
    IF_SET(SF_BE2, SeerLobopMsg, loc_len, loc_prefixed),
    /* 9i: the locator's first byte goes as 00 (ojdbc14) */
    {.kind = SF_PAD, .codecs = THIN, .fv_max = TTC_FIELD_VERSION_10_2, .arg = 1},
    {.kind = SF_RAW,
     .off = offsetof(SeerLobopMsg, locator),
     .arg = offsetof(SeerLobopMsg, loc_len)},
    IF_SET(SF_N4, SeerLobopMsg, charset, charset_ptr),
    IF_SET(SF_N4, SeerLobopMsg, amount, has_amount),
    SEER_END,
};
