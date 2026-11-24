/* The login timeout (#403): a listener that takes the TCP connect and then
 * never answers must fail the connect with SEER_ETIMEOUT once the limit runs
 * out - promptly, and saying so ("login timed out after 1 s waiting for ...")
 * rather than as a bare I/O error - so that the ODBC shim reports HYT00. A
 * peer that closes the connection instead is a broken link, SEER_EIO, not a
 * timeout.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "seer/seertns.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* A listening socket on 127.0.0.1 and an ephemeral port; -1 on failure. */
static int listen_local(uint16_t *port)
{
  int ls = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0)
    return -1;
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t al = sizeof a;
  if (bind(ls, (struct sockaddr *)&a, sizeof a) != 0 || listen(ls, 4) != 0 ||
      getsockname(ls, (struct sockaddr *)&a, &al) != 0) {
    close(ls);
    return -1;
  }
  *port = ntohs(a.sin_port);
  return ls;
}

static void *accept_and_close(void *arg)
{
  int ls = *(int *)arg;
  int c = accept(ls, NULL, NULL);
  if (c >= 0)
    close(c);
  return NULL;
}

static double now(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static SeerStatus try_connect(uint16_t port, int timeout_ms, char *err, size_t errlen, double *took)
{
  SeerConnParams p = {0};
  p.host = "127.0.0.1";
  p.port = port;
  p.service_name = "NOSUCH";
  p.username = "nobody";
  p.password = "nothing";
  p.connect_timeout_ms = timeout_ms;
  SeerConn *conn = NULL;
  double t0 = now();
  SeerStatus st = seer_connect_diag(&p, &conn, err, errlen);
  *took = now() - t0;
  if (conn != NULL)
    seer_disconnect(conn);
  return st;
}

int main(void)
{
  int fails = 0;
  uint16_t port = 0;
  char err[512];
  double took = 0;

  /* (1) The kernel completes the TCP handshake from the backlog; nothing is
   * ever accepted, so the CONNECT packet is never answered. */
  int ls = listen_local(&port);
  if (ls < 0) {
    perror("listen");
    return 1;
  }
  SeerStatus st = try_connect(port, 1000, err, sizeof err, &took);
  if (st != SEER_ETIMEOUT || strstr(err, "login timed out after 1 s") == NULL || took > 5.0) {
    fprintf(stderr, "silent listener: status %d (%s) after %.1f s: '%s'\n", (int)st,
            seer_strerror(st), took, err);
    fails++;
  } else {
    printf("silent listener: SEER_ETIMEOUT after %.1f s: %s\n", took, err);
  }
  close(ls);

  /* (2) A peer that closes the connection: a link that broke, not a timeout. */
  ls = listen_local(&port);
  if (ls < 0) {
    perror("listen");
    return 1;
  }
  pthread_t th;
  pthread_create(&th, NULL, accept_and_close, &ls);
  st = try_connect(port, 5000, err, sizeof err, &took);
  pthread_join(th, NULL);
  close(ls);
  if (st != SEER_EIO || strstr(err, "timed out") != NULL) {
    fprintf(stderr, "closing peer: status %d (%s): '%s'\n", (int)st, seer_strerror(st), err);
    fails++;
  } else {
    printf("closing peer: SEER_EIO, not a timeout\n");
  }

  return fails ? 1 : 0;
}
