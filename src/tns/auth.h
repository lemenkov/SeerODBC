/* O5LOGON authentication crypto (PROTOCOL.md §4.5), all verifier variants.
 *
 * Pure functions over byte buffers - no socket, no TTC framing. OpenSSL EVP
 * provides AES-128/192/256-CBC, DES-CBC, SHA-1/512, MD5, PBKDF2 and the
 * CSPRNG. The TTC layer (ttc.c) wraps these into the TTI_AUTH message and
 * validates the server's response.
 *
 * The server's challenge selects the variant:
 *   AUTH_VFR_DATA present, no AUTH_PBKDF2_CSK_SALT -> 11g, AES-192 / SHA-1
 *   both present                                   -> 12c, AES-256 / PBKDF2
 *   neither present                                -> 10g, AES-128 over the
 *                                                     legacy DES verifier
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_AUTH_H
#define SEER_TNS_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"

/* Result of the O5LOGON computation. auth_pass / auth_sess / speedy_key are
 * raw bytes the caller hex-encodes for the wire; conn_key is the session key
 * (16/24/32 bytes by variant) used to encrypt the password and validate the
 * server response. speedy_key is set only for the 256-bit (12c) variant. */
typedef struct {
    uint8_t *auth_pass;     /* AES-CBC(ConnKey) of the padded password */
    size_t   auth_pass_len;
    uint8_t *auth_sess;     /* AES-CBC(KeySess) of the client session key */
    size_t   auth_sess_len;
    uint8_t *speedy_key;    /* AES-CBC(ConnKey) of the derived key (12c only) */
    size_t   speedy_key_len;
    uint8_t  conn_key[32];
    size_t   conn_key_len;  /* 16 (10g) / 24 (11g) / 32 (12c) */
} SeerO5Logon;

void seer_o5logon_free(SeerO5Logon *o);

/* Dispatch on the verifier the server offered (see the variant table above)
 * and produce the auth material. `salt` is decoded AUTH_VFR_DATA (NULL/0 if
 * absent); `derived_salt` is decoded AUTH_PBKDF2_CSK_SALT (NULL/0 if absent);
 * `sess` is the decoded AUTH_SESSKEY; user/password are NUL-terminated UTF-8. */
SeerStatus seer_o5logon(const uint8_t *sess, size_t sess_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *derived_salt, size_t derived_salt_len,
                        const char *user, const char *password,
                        SeerO5Logon *out);

/* General deterministic core (no RNG when cli_sess is supplied) - the
 * unit-testable seam. `key_sess` is the AES key (16/24/32 bytes); `cli_sess`
 * is sess_len bytes or NULL to generate; `derived_salt`/`derived_key` are the
 * 12c inputs (NULL for 10g/11g); `bits` is 128/192/256. */
SeerStatus seer_o5logon0(const uint8_t *sess, size_t sess_len,
                         const uint8_t *key_sess, size_t key_sess_len,
                         const uint8_t *derived_salt, size_t derived_salt_len,
                         const uint8_t *derived_key, size_t derived_key_len,
                         const uint8_t *cli_sess,
                         const char *password, int bits, SeerO5Logon *out);

/* Backward-compatible 192-bit deterministic core wrapper. */
SeerStatus seer_o5logon0_192(const uint8_t *sess, size_t sess_len,
                             const uint8_t key_sess[24], const uint8_t *cli_sess,
                             const char *password, SeerO5Logon *out);

/* The legacy DES password verifier (10g path; exposed for tests): uppercased
 * UTF-16BE of username||password, double DES-CBC under 0x0123456789ABCDEF,
 * the last 8 bytes of the second pass. */
void seer_des_verifier(const char *user, const char *password, uint8_t out[8]);

/* O3LOGON (Oracle 9i / pre-10g thin auth): decrypt the server's AUTH_SESSKEY with
 * the DES verifier `key_sess`, then DES-encrypt the zero-padded password under the
 * recovered session key to form AUTH_PASSWORD. Caller frees *auth_pass. */
SeerStatus seer_o3logon(const uint8_t *sess, size_t sess_len,
                        const uint8_t key_sess[8], const char *password,
                        uint8_t **auth_pass, size_t *auth_pass_len);

/* Mutual auth: decrypt the server's AUTH_SVR_RESPONSE with conn_key (length
 * 16/24/32) and check for the "SERVER_TO_CLIENT" marker. */
bool seer_o5logon_validate(const uint8_t *resp, size_t resp_len,
                           const uint8_t *conn_key, size_t conn_key_len);

#endif /* SEER_TNS_AUTH_H */
