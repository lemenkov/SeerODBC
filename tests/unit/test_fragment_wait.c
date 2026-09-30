/* A server reply is split into DATA packets without any flag: a packet filled
 * to exactly SDU-37 bytes means "more follows" (§1.3). A message can also end
 * in a packet of exactly that size - a 10g LOB read on a 2048 SDU did - and
 * the receiver used to wait for a continuation that never came, stalling the
 * call for the whole 30 s socket timeout and then failing it. Here a local
 * "server" sends (1) one complete 2011-byte packet on a 2048 SDU, which must
 * come back promptly as the whole message, and (2) a genuine two-packet
 * message, which must still be reassembled. With native encryption on, a
 * fragment is whole AES blocks and can fall short of that size or run a byte
 * over it: (3) an encrypted SDU-36 fragment and a short last packet must be
 * reassembled, and (4) an encrypted last packet of that size must end its
 * message after the bounded wait.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ano.h"
#include "conn.h"
#include "packet.h"
#include "transport.h"
#include "ttc.h"

#include "seer/seertns.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SDU 2048

/* Write one legacy-framed DATA packet of `total` bytes (header included)
 * whose payload is `total` - 10 copies of `fill`. */
static int send_data_packet(int fd, size_t total, uint8_t fill)
{
  uint8_t *p = calloc(1, total);
  if (p == NULL)
    return -1;
  p[0] = (uint8_t)(total >> 8);
  p[1] = (uint8_t)total;
  p[4] = TNS_PT_DATA;
  /* bytes 8-9: data flags 0 */
  memset(p + 10, fill, total - 10);
  ssize_t n = write(fd, p, total);
  free(p);
  return n == (ssize_t)total ? 0 : -1;
}

/* Write one legacy-framed DATA packet carrying `data` (after the data flags). */
static int send_data_bytes(int fd, const uint8_t *data, size_t len)
{
  size_t total = len + 10;
  uint8_t *p = calloc(1, total);
  if (p == NULL)
    return -1;
  p[0] = (uint8_t)(total >> 8);
  p[1] = (uint8_t)total;
  p[4] = TNS_PT_DATA;
  memcpy(p + 10, data, len);
  ssize_t n = write(fd, p, total);
  free(p);
  return n == (ssize_t)total ? 0 : -1;
}

/* Encrypt `len` bytes of `fill` with the server channel and send them. */
static int send_encrypted(int fd, SeerAno *server, size_t len, uint8_t fill)
{
  uint8_t *pt = malloc(len);
  uint8_t *w = NULL;
  size_t wl = 0;
  if (pt == NULL)
    return -1;
  memset(pt, fill, len);
  int rc = seer_ano_wrap(server, pt, len, &w, &wl) == SEER_OK ? send_data_bytes(fd, w, wl) : -1;
  free(pt);
  free(w);
  return rc;
}

static double now(void)
{
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

int main(void)
{
  int lfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t al = sizeof a;
  if (lfd < 0 || bind(lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(lfd, 1) != 0 ||
      getsockname(lfd, (struct sockaddr *)&a, &al) != 0) {
    perror("listen");
    return 1;
  }
  SeerConn c = {0};
  c.sdu = SDU;
  if (seer_transport_connect("127.0.0.1", ntohs(a.sin_port), 5000, &c.t) != SEER_OK) {
    fprintf(stderr, "connect failed\n");
    return 1;
  }
  int sfd = accept(lfd, NULL, NULL);
  if (sfd < 0) {
    perror("accept");
    return 1;
  }
  int fails = 0;

  /* (1) A complete message in one packet of exactly SDU-37 bytes; the "server"
   * then goes quiet (the socket stays open, as a real one does). */
  if (send_data_packet(sfd, SDU - 37, 0x41) != 0)
    return 1;
  uint8_t *msg = NULL;
  size_t len = 0;
  double t0 = now();
  SeerStatus st = seer_ttc_recv(&c, &msg, &len);
  double took = now() - t0;
  if (st != SEER_OK || len != SDU - 37 - 10 || took > 10.0) {
    fprintf(stderr, "exact-size final packet: st=%d len=%zu (want %d) took %.1fs\n", st, len,
            SDU - 37 - 10, took);
    fails++;
  } else {
    printf("exact-size final packet: %zu bytes in %.1fs\n", len, took);
  }
  free(msg);

  /* (2) A real continuation: an SDU-37 packet, then a short one. */
  if (send_data_packet(sfd, SDU - 37, 0x42) != 0 || send_data_packet(sfd, 100, 0x43) != 0)
    return 1;
  msg = NULL;
  len = 0;
  st = seer_ttc_recv(&c, &msg, &len);
  if (st != SEER_OK || len != (SDU - 37 - 10) + (100 - 10) || msg[0] != 0x42 ||
      msg[len - 1] != 0x43) {
    fprintf(stderr, "two-packet message: st=%d len=%zu\n", st, len);
    fails++;
  } else {
    printf("two-packet message: %zu bytes reassembled\n", len);
  }
  free(msg);

  /* (3) + (4) with encryption (AES256 + SHA256): a 1968-byte payload wraps to
   * 2000 cipher bytes + 2 trailer bytes, a 2012-byte packet: SDU-36. */
  static const uint8_t key[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  static const uint8_t iv[] = "foo bar baz bat quux";
  SeerAno *server = NULL;
  if (seer_ano_channel_new(17, 5, key, sizeof key, iv, 20, false, &server) != SEER_OK ||
      seer_ano_channel_new(17, 5, key, sizeof key, iv, 20, true, &c.ano) != SEER_OK)
    return 1;
  if (send_encrypted(sfd, server, 1968, 0x44) != 0 || send_encrypted(sfd, server, 100, 0x45) != 0)
    return 1;
  msg = NULL;
  len = 0;
  t0 = now();
  st = seer_ttc_recv(&c, &msg, &len);
  took = now() - t0;
  if (st != SEER_OK || len != 1968 + 100 || msg[0] != 0x44 || msg[len - 1] != 0x45 || took > 1.0) {
    fprintf(stderr, "encrypted fragment: st=%d len=%zu took %.1fs\n", st, len, took);
    fails++;
  } else {
    printf("encrypted SDU-36 fragment: %zu bytes reassembled\n", len);
  }
  free(msg);

  if (send_encrypted(sfd, server, 1968, 0x46) != 0)
    return 1;
  msg = NULL;
  len = 0;
  t0 = now();
  st = seer_ttc_recv(&c, &msg, &len);
  took = now() - t0;
  if (st != SEER_OK || len != 1968 || msg[0] != 0x46 || took > 10.0) {
    fprintf(stderr, "encrypted exact-size final packet: st=%d len=%zu took %.1fs\n", st, len, took);
    fails++;
  } else {
    printf("encrypted exact-size final packet: %zu bytes in %.1fs\n", len, took);
  }
  free(msg);
  seer_ano_free(server);
  seer_ano_free(c.ano);
  c.ano = NULL;

  seer_transport_close(c.t);
  close(sfd);
  close(lfd);
  return fails ? 1 : 0;
}
