/* Offline unit tests for the tnsnames.ora reader (src/odbc/tnsnames.c, #374).
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#include "tnsnames.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *FILE1 =
    "# a comment line\n"
    "ORCL =\n"
    "  (DESCRIPTION =\n"
    "    (ADDRESS = (PROTOCOL = TCP)(HOST = db1.example.com)(PORT = 1521))\n"
    "    (CONNECT_DATA = (SERVER = DEDICATED) (SERVICE_NAME = orclpdb)) # trailing\n"
    "  )\n"
    "\n"
    "legacy, Old.World =\n"
    "  (description = (address = (protocol = tcp)(host = 10.0.0.9)(port = 1525))\n"
    "                 (connect_data = (sid = ORCL9)))\n"
    "HA = (DESCRIPTION =\n"
    "  (ADDRESS_LIST = (LOAD_BALANCE = off) (FAILOVER = on)\n"
    "    (ADDRESS = (PROTOCOL = TCP)(HOST = a.example)(PORT = 1601))\n"
    "    (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC))\n"
    "    (ADDRESS = (PROTOCOL = TCPS)(HOST = b.example)))\n"
    "  (CONNECT_DATA = (SERVICE_NAME = ha.example)))\n"
    "V6 = (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = fe80::1)(PORT = 1700))\n"
    "  (CONNECT_DATA = (SERVICE_NAME = six)))\n"
    "BROKEN = (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = x)\n"
    "IPCONLY = (DESCRIPTION = (ADDRESS = (PROTOCOL = IPC)(KEY = X))\n"
    "  (CONNECT_DATA = (SERVICE_NAME = s)))\n"
    "AFTER = (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = after.example)(PORT = 2000))\n"
    "  (CONNECT_DATA = (SERVICE_NAME = after)))\n";

/* Owner-only (0600) rather than the umask-default 0666. */
static FILE *fopen_private(const char *path)
{
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  assert(fd >= 0);
  FILE *f = fdopen(fd, "w");
  assert(f != NULL);
  return f;
}

int main(void)
{
  SeerTnsEntry e;

  assert(seer_tns_lookup_text(FILE1, "ORCL", NULL, &e) == 0);
  assert(strcmp(e.hosts, "db1.example.com:1521") == 0);
  assert(strcmp(e.service, "orclpdb") == 0 && !e.is_sid && !e.tcps);

  /* case-insensitive keywords and alias; a second name; SID */
  assert(seer_tns_lookup_text(FILE1, "LEGACY", NULL, &e) == 0);
  assert(strcmp(e.hosts, "10.0.0.9:1525") == 0 && strcmp(e.service, "ORCL9") == 0 && e.is_sid);
  assert(seer_tns_lookup_text(FILE1, "old.world", NULL, &e) == 0 && e.is_sid);

  /* an address list: TCP and TCPS in order (TCPS with the default port), IPC
   * skipped */
  assert(seer_tns_lookup_text(FILE1, "ha", NULL, &e) == 0);
  assert(strcmp(e.hosts, "a.example:1601,b.example:1521") == 0);
  assert(strcmp(e.service, "ha.example") == 0 && e.tcps);

  /* an IPv6 host is bracketed for the address list */
  assert(seer_tns_lookup_text(FILE1, "V6", NULL, &e) == 0);
  assert(strcmp(e.hosts, "[fe80::1]:1700") == 0);

  /* no TCP address: found, nothing to connect to */
  assert(seer_tns_lookup_text(FILE1, "IPCONLY", NULL, &e) == -2);
  /* a comment ending the file, no newline: no overrun */
  assert(seer_tns_lookup_text("# only a comment", "X", NULL, &e) == -1);
  assert(seer_tns_lookup_text("A = (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = h)(PORT = "
                              "9))(CONNECT_DATA = (SID = s))) # end",
                              "a", NULL, &e) == 0 &&
         e.is_sid);
  /* not there */
  assert(seer_tns_lookup_text(FILE1, "NOSUCH", NULL, &e) == -1);
  /* an entry after a malformed one is still found */
  assert(seer_tns_lookup_text(FILE1, "AFTER", NULL, &e) == 0);
  assert(strcmp(e.hosts, "after.example:2000") == 0);

  /* IFILE, relative to the including file's directory; and seer_tns_lookup
   * through TNS_ADMIN */
  char dir[] = "/tmp/seer_tnsXXXXXX";
  assert(mkdtemp(dir) != NULL);
  char p1[256], p2[256];
  snprintf(p1, sizeof p1, "%s/tnsnames.ora", dir);
  snprintf(p2, sizeof p2, "%s/more.ora", dir);
  FILE *f = fopen_private(p1);
  fputs("IFILE = more.ora\nMAIN = (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = m)(PORT = 1))"
        "(CONNECT_DATA = (SERVICE_NAME = main)))\n",
        f);
  fclose(f);
  f = fopen_private(p2);
  fputs("INCLUDED = (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = inc)(PORT = 2))"
        "(CONNECT_DATA = (SERVICE_NAME = inc)))\n",
        f);
  fclose(f);
  setenv("TNS_ADMIN", dir, 1);
  char searched[512];
  assert(seer_tns_lookup("MAIN", &e, searched, sizeof searched) == 0);
  assert(strcmp(e.hosts, "m:1") == 0);
  assert(seer_tns_lookup("included", &e, searched, sizeof searched) == 0);
  assert(strcmp(e.hosts, "inc:2") == 0 && strcmp(e.service, "inc") == 0);
  assert(seer_tns_lookup("NOWHERE", &e, searched, sizeof searched) == -1);
  assert(strstr(searched, p1) != NULL); /* the error can name what was searched */
  unlink(p1);
  unlink(p2);
  rmdir(dir);

  printf("test_tnsnames: all assertions passed\n");
  return 0;
}
