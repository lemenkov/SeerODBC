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
