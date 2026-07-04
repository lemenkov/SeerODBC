/* TNS packet framing (PROTOCOL.md §1).
 *
 * Every TNS packet is an 8-byte header followed by a body:
 *
 *   u16 packet length (total, incl. header)   u16 packet flags (0)
 *   u8  packet type                           u8  flags (0)
 *   u16 header checksum (0)
 *
 * We target 11g, where the length is a 16-bit field. (12c+ widens it to 32
 * bits by reusing the flags field; tracked for later.) TNS_DATA packets carry
 * two extra "data flags" bytes at the start of their body - that belongs to
 * the TTC layer, so it is handled there, not here.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_PACKET_H
#define SEER_TNS_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"
#include "transport.h"

#define TNS_HEADER_LEN 8

typedef enum {
    TNS_PT_CONNECT   = 1,
    TNS_PT_ACCEPT    = 2,
    TNS_PT_ACK       = 3,
    TNS_PT_REFUSE    = 4,
    TNS_PT_REDIRECT  = 5,
    TNS_PT_DATA      = 6,
    TNS_PT_NULL      = 7,
    TNS_PT_ABORT     = 9,
    TNS_PT_RESEND    = 11,
    TNS_PT_MARKER    = 12,
    TNS_PT_ATTENTION = 13,
    TNS_PT_CONTROL   = 14,
} TnsPacketType;

/* Frame `payload` as a TNS packet of `type` and write it. payload_len must
 * leave room for the 8-byte header within a 16-bit total length. */
SeerStatus seer_packet_send(SeerTransport *t, uint8_t type,
                            const void *payload, size_t payload_len);

/* Read one TNS packet. On SEER_OK, *out_type is the packet type and *out_body
 * is a malloc'd copy of the body (everything after the 8-byte header), of
 * length *out_len. *out_body is NULL when the body is empty. Caller frees. */
SeerStatus seer_packet_recv(SeerTransport *t, uint8_t *out_type,
                            uint8_t **out_body, size_t *out_len);

#endif /* SEER_TNS_PACKET_H */
