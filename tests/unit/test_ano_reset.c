/* ANO data integrity across a break/reset, pinned to a live session.
 *
 * With data integrity on, a break/reset marker exchange (how a server with
 * DISABLE_OOB reports a SQL error) makes both peers re-derive their MAC
 * keystreams: the seed chains forward, each direction's keystream is re-keyed
 * from it and carries on from its current block. The fixture is one real
 * session against a 26ai server requiring AES256 + SHA256: every DATA payload
 * the server sent, with its MAC. Each is re-encrypted into its wire form here
 * and unwrapped through a client channel, re-deriving (seer_ano_reset) where
 * the session had a break/reset. All must verify - and without the reset, the
 * first payload after it must not.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ano.h"

#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PACKETS 16

typedef struct {
  int reset;
  uint8_t *plain; /* payload || MAC */
  size_t plain_len, payload_len;
} Packet;

static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
  size_t n = 0;
  while (hex[0] && hex[1] && hex[0] != ' ' && hex[0] != '\n' && n < cap) {
    unsigned b;
    assert(sscanf(hex, "%2x", &b) == 1);
    out[n++] = (uint8_t)b;
    hex += 2;
  }
  return n;
}

/* The wire form of one packet: AES-256-CBC (zero IV) over payload||MAC zero-
 * padded to the block, then the padding marker (count + 1) and the key-fold
 * flag 0. */
static uint8_t *wire(const uint8_t *key, const Packet *p, size_t *len)
{
  size_t pad = (16 - p->plain_len % 16) % 16;
  size_t ct = p->plain_len + pad;
  uint8_t *in = calloc(1, ct);
  uint8_t *out = malloc(ct + 2);
  assert(in != NULL && out != NULL);
  memcpy(in, p->plain, p->plain_len);
  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
  int ol = 0, fl = 0;
  static const uint8_t iv[16] = {0};
  assert(EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), NULL, key, iv) == 1);
  EVP_CIPHER_CTX_set_padding(c, 0);
  assert(EVP_EncryptUpdate(c, out, &ol, in, (int)ct) == 1);
  assert(EVP_EncryptFinal_ex(c, out + ol, &fl) == 1);
  EVP_CIPHER_CTX_free(c);
  out[ct] = (uint8_t)(pad + 1);
  out[ct + 1] = 0x00;
  free(in);
  *len = ct + 2;
  return out;
}

int main(void)
{
  FILE *f = fopen(SEER_ANO_RESET_FIXTURE, "r");
  assert(f != NULL && "cannot open ano_reset_session.txt");
  static char line[16384];
  static uint8_t shared[512], siv[64];
  size_t shared_len = 0, siv_len = 0;
  Packet pk[MAX_PACKETS];
  int np = 0;
  while (fgets(line, sizeof line, f) != NULL) {
    if (strncmp(line, "shared=", 7) == 0) {
      shared_len = unhex(line + 7, shared, sizeof shared);
    } else if (strncmp(line, "server_iv=", 10) == 0) {
      siv_len = unhex(line + 10, siv, sizeof siv);
    } else if (strncmp(line, "packet ", 7) == 0 && np < MAX_PACKETS) {
      Packet *p = &pk[np++];
      p->reset = strstr(line, "reset=1") != NULL;
      const char *pay = strstr(line, "payload=") + 8;
      const char *mac = strstr(line, "mac=") + 4;
      p->plain = malloc(sizeof line);
      assert(p->plain != NULL);
      p->payload_len = unhex(pay, p->plain, sizeof line);
      p->plain_len = p->payload_len + unhex(mac, p->plain + p->payload_len, 64);
    }
  }
  fclose(f);
  assert(shared_len >= 32 && siv_len >= 16 && np >= 5);

  /* With the re-derivation at each break/reset, every payload verifies. */
  SeerAno *a = NULL;
  assert(seer_ano_channel_new(17, 5, shared, shared_len, siv, siv_len, true, &a) == SEER_OK);
  int first_reset = -1;
  for (int i = 0; i < np; i++) {
    if (pk[i].reset) {
      assert(seer_ano_reset(a) == SEER_OK);
      if (first_reset < 0)
        first_reset = i;
    }
    size_t wl = 0;
    uint8_t *w = wire(shared, &pk[i], &wl);
    uint8_t *out = NULL;
    size_t ol = 0;
    SeerStatus st = seer_ano_unwrap(a, w, wl, &out, &ol);
    if (st != SEER_OK || ol != pk[i].payload_len || memcmp(out, pk[i].plain, ol) != 0) {
      fprintf(stderr, "packet %d%s: unwrap st=%d len=%zu\n", i + 1,
              pk[i].reset ? " (after reset)" : "", st, ol);
      return 1;
    }
    free(out);
    free(w);
  }
  seer_ano_free(a);
  printf("%d packets verified, %d after a break/reset\n", np, np - first_reset);

  /* Without it, the first payload after the break/reset fails its MAC. */
  assert(seer_ano_channel_new(17, 5, shared, shared_len, siv, siv_len, true, &a) == SEER_OK);
  for (int i = 0; i <= first_reset; i++) {
    size_t wl = 0;
    uint8_t *w = wire(shared, &pk[i], &wl);
    uint8_t *out = NULL;
    size_t ol = 0;
    SeerStatus st = seer_ano_unwrap(a, w, wl, &out, &ol);
    assert(i < first_reset ? st == SEER_OK : st != SEER_OK);
    free(out);
    free(w);
  }
  seer_ano_free(a);
  printf("without the re-derivation packet %d fails, as it must\n", first_reset + 1);

  for (int i = 0; i < np; i++)
    free(pk[i].plain);
  return 0;
}
