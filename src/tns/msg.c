/* TTC messages as schemas (#395 spike); see msg.h.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "msg.h"

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

/* seerdb _OAC / _O7_OAC (seerdb#2284), the fields only OCI writes left out. */
const SeerField SEER_OAC_SCHEMA[] = {
    SEER_F(SF_U8, SeerOacMsg, data_type),
    SEER_F(SF_U8, SeerOacMsg, flags),
    SEER_F(SF_U8, SeerOacMsg, precision),
    SEER_F(SF_N1, SeerOacMsg, scale),
    SEER_F(SF_N4, SeerOacMsg, max_length),
    SEER_F(SF_N4, SeerOacMsg, max_array),
    SEER_F(SF_N4, SeerOacMsg, cont_flags),
    SEER_F(SF_N4, SeerOacMsg, toid_length),
    {.kind = SF_VALUE,
     .flags = SG_IF_SET,
     .off = offsetof(SeerOacMsg, toid),
     .if_off = offsetof(SeerOacMsg, toid_length)},
    SEER_F(SF_N2, SeerOacMsg, version),
    SEER_F(SF_N2, SeerOacMsg, charset),
    SEER_F(SF_U8, SeerOacMsg, csfrm),
    /* 9.2 has no max_chars, and 8i none either */
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_10_2, 0, SeerOacMsg, max_chars),
    SEER_FV(SF_N4, THIN, TTC_FIELD_VERSION_12_2, 0, SeerOacMsg, oaccolid),
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

const SeerField SEER_CELL_SCHEMA[] = {
    SEER_F(SF_VALUE, SeerCellMsg, value),
    SEER_END,
};

const SeerField SEER_LOB_DATA_SCHEMA[] = {
    SEER_F(SF_VALUE, SeerLobDataMsg, data),
    SEER_END,
};

const SeerField SEER_LOBOPS_SCHEMA[] = {
    SEER_F(SF_U8, SeerLobopMsg, src_ptr),
    SEER_F(SF_N4, SeerLobopMsg, src_len),
    SEER_F(SF_U8, SeerLobopMsg, dst_ptr),
    SEER_F(SF_N4, SeerLobopMsg, dst_len),
    SEER_F(SF_N4, SeerLobopMsg, short_src_off),
    SEER_F(SF_N4, SeerLobopMsg, short_dst_off),
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
