/* Unit test for O5LOGON crypto (auth.c), pinned to the reference client's
 * known-answer vectors (192-bit / 11g).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "auth.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    /* test_o5logon0_192_bit: deterministic core with a fixed client key. */
    const uint8_t sess[48] = {
        133,116,72,228,112,43,211,202,81,171,240,178,217,51,25,244,
        17,153,217,160,237,192,58,132,219,67,232,8,142,208,11,224,
        177,173,243,130,147,163,110,100,101,238,151,30,47,239,182,196,
    };
    const uint8_t key_sess[24] = {
        155,246,157,138,79,20,130,177,192,74,88,47,3,111,223,103,
        122,144,148,143,0,0,0,0,
    };
    const uint8_t cli_sess[48] = {
        254,21,49,233,19,16,109,99,125,4,62,46,96,172,72,12,
        39,169,178,114,83,9,119,159,122,112,199,108,204,130,62,183,
        228,171,137,125,215,132,73,249,226,39,150,231,117,33,160,73,
    };
    const uint8_t expect_pass[32] = {
        17,180,8,36,95,158,219,176,171,207,132,159,57,91,132,61,
        51,224,232,69,36,165,81,252,23,204,148,69,249,67,175,59,
    };
    const uint8_t expect_sess[48] = {
        197,111,72,69,246,89,52,8,12,157,199,214,85,93,228,247,
        146,144,240,127,101,232,78,145,174,46,196,214,202,196,81,6,
        83,93,200,162,139,209,65,108,68,80,227,210,15,155,239,7,
    };
    const uint8_t expect_conn[24] = {
        136,47,159,158,118,54,245,71,3,63,153,55,248,39,220,82,
        61,148,222,183,87,164,249,26,
    };

    SeerO5Logon out;
    assert(seer_o5logon0_192(sess, sizeof sess, key_sess, cli_sess,
                             "MYORAPASS", &out) == SEER_OK);
    assert(out.auth_pass_len == sizeof expect_pass);
    assert(memcmp(out.auth_pass, expect_pass, sizeof expect_pass) == 0);
    assert(out.auth_sess_len == sizeof expect_sess);
    assert(memcmp(out.auth_sess, expect_sess, sizeof expect_sess) == 0);
    assert(out.conn_key_len == 24);
    assert(memcmp(out.conn_key, expect_conn, 24) == 0);
    seer_o5logon_free(&out);

    /* validate(): the right key sees "SERVER_TO_CLIENT", a wrong key doesn't. */
    const uint8_t resp[48] = {
        0x38,0xD0,0x8E,0x44,0x01,0x5F,0x28,0x9A,0x45,0x15,0xD4,0x3C,0x78,0x8D,0x8F,0x9A,
        0x61,0xD9,0x98,0x80,0x1C,0xC6,0x2F,0xEB,0x4F,0xFC,0x8A,0x01,0xB8,0xAD,0x05,0x9F,
        0x53,0x79,0x5B,0x38,0xC3,0x87,0xC8,0xED,0x47,0x4C,0xCF,0x14,0x80,0x15,0x79,0xCD,
    };
    const uint8_t good_key[24] = {
        62,241,238,220,137,70,185,169,127,39,225,28,118,151,2,153,
        134,7,95,7,193,22,220,85,
    };
    const uint8_t wrong_key[24] = {
        48,239,131,22,229,156,6,142,24,185,41,243,97,102,239,200,
        212,187,118,220,228,206,111,215,
    };
    assert(seer_o5logon_validate(resp, sizeof resp, good_key, 24) == true);
    assert(seer_o5logon_validate(resp, sizeof resp, wrong_key, 24) == false);

    /* 10g: the legacy DES verifier, pinned to a live 10.2.0.5 sys.user$. */
    uint8_t ver[8];
    const uint8_t expect_ver[8] = { 0xE2,0x42,0xA4,0x14,0x20,0x69,0x06,0xCB };
    seer_des_verifier("PYO", "pyo123", ver);
    assert(memcmp(ver, expect_ver, 8) == 0);

    /* 10g core (128-bit, AES over the DES verifier): deterministic vector. */
    const uint8_t s128[32] = {
        50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,
        66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,
    };
    const uint8_t k128[16] = { 155,246,157,138,79,20,130,177,0,0,0,0,0,0,0,0 };
    uint8_t cli128[32];
    for (int i = 0; i < 32; i++) cli128[i] = (uint8_t)i;
    const uint8_t p128[32] = {
        55,192,208,209,95,234,139,250,170,135,36,108,22,208,105,122,
        67,55,165,244,96,119,243,18,225,38,229,135,181,222,255,208,
    };
    const uint8_t c128[16] = { 230,130,226,228,56,177,119,45,24,12,186,61,56,54,124,251 };
    assert(seer_o5logon0(s128, sizeof s128, k128, sizeof k128, NULL, 0, NULL, 0,
                         cli128, "pyo123", 128, &out) == SEER_OK);
    assert(out.conn_key_len == 16 && memcmp(out.conn_key, c128, 16) == 0);
    assert(out.auth_pass_len == 32 && memcmp(out.auth_pass, p128, 32) == 0);
    assert(out.speedy_key == NULL);
    seer_o5logon_free(&out);

    /* 12c core (256-bit, AES-256 / PBKDF2-SHA512): deterministic vector. */
    uint8_t s256[48], k256[32];
    for (int i = 0; i < 48; i++) s256[i] = (uint8_t)(100 + i);
    for (int i = 0; i < 32; i++) k256[i] = (uint8_t)(200 + i);
    const uint8_t dsalt[8] = { 0,17,34,51,68,85,102,119 };
    uint8_t dkey[80], cli256[48];
    for (int i = 0; i < 80; i++) dkey[i] = (uint8_t)i;
    for (int i = 0; i < 48; i++) cli256[i] = (uint8_t)i;
    const uint8_t c256[32] = {
        118,51,91,189,151,77,54,119,154,140,245,216,209,135,152,33,
        154,160,43,152,123,211,249,166,168,96,54,47,214,220,114,14,
    };
    const uint8_t p256[32] = {
        249,132,18,182,206,227,104,254,139,176,149,212,16,13,5,103,
        28,16,18,248,222,237,227,132,125,158,238,252,230,89,201,17,
    };
    assert(seer_o5logon0(s256, sizeof s256, k256, sizeof k256, dsalt, sizeof dsalt,
                         dkey, sizeof dkey, cli256, "pyo123", 256, &out) == SEER_OK);
    assert(out.conn_key_len == 32 && memcmp(out.conn_key, c256, 32) == 0);
    assert(out.auth_pass_len == 32 && memcmp(out.auth_pass, p256, 32) == 0);
    assert(out.speedy_key != NULL && out.speedy_key_len == 80);
    seer_o5logon_free(&out);

    /* 9i O3LOGON: pinned to a live JDBC-thin -> 9.2.0.4 capture (pyoracle #90).
     * The server's AUTH_SESSKEY 83B9CF7F17B84F76, DES-decrypted under the PYO
     * verifier, then used to DES-encrypt "pyo123" -> AUTH_PASSWORD F18CC9AF1CE5A7E8. */
    const uint8_t o3_sess[8] = { 0x83,0xB9,0xCF,0x7F,0x17,0xB8,0x4F,0x76 };
    const uint8_t o3_pass[8] = { 0xF1,0x8C,0xC9,0xAF,0x1C,0xE5,0xA7,0xE8 };
    uint8_t *ap = NULL;
    size_t   apn = 0;
    assert(seer_o3logon(o3_sess, sizeof o3_sess, expect_ver, "pyo123", &ap, &apn) == SEER_OK);
    assert(apn == 8 && memcmp(ap, o3_pass, 8) == 0);
    free(ap);

    printf("test_auth: all assertions passed\n");
    return 0;
}
