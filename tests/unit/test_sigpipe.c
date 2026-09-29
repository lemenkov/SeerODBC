/* A send on a socket whose peer has gone away must fail with an error, never
 * raise SIGPIPE: the default action kills the whole application that loaded
 * the driver. seer_sock_send passes MSG_NOSIGNAL (Linux) and sockets get
 * SO_NOSIGPIPE where that exists (macOS/BSD). With SIGPIPE at its default
 * disposition, reaching the end of this test proves no signal was raised.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "netcompat.h"

#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
  signal(SIGPIPE, SIG_DFL);
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    perror("socketpair");
    return 1;
  }
  seer_sock_nosigpipe(sv[0]);
  close(sv[1]); /* the peer goes away */
  const char msg[] = "hello";
  ptrdiff_t n = seer_sock_send(sv[0], msg, sizeof msg);
  close(sv[0]);
  if (n >= 0) {
    fprintf(stderr, "send to a closed peer succeeded (%td)\n", n);
    return 1;
  }
  printf("send to a closed peer failed cleanly (errno %d), no SIGPIPE\n", seer_sock_errno());
  return 0;
}
