/* tnsnames.ora lookup (#374): a TNS alias to the address list and service
 * SeerODBC connects with.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef SEERODBC_TNSNAMES_H
#define SEERODBC_TNSNAMES_H

#include <stddef.h>

typedef struct {
  char hosts[1024]; /* "host:port,host:port", in the entry's order */
  char service[256];
  int is_sid; /* CONNECT_DATA had SID, not SERVICE_NAME */
  int tcps;   /* an address was PROTOCOL=TCPS */
} SeerTnsEntry;

/* Look `alias` up (case-insensitive) in tnsnames.ora, searched as Oracle
 * clients do: $TNS_ADMIN, $ORACLE_HOME/network/admin, then /etc (not on
 * Windows). `searched` gets the files tried, for an error message. Returns 0
 * found, -1 not found (or no file), -2 found with no TCP / TCPS address or no
 * service. */
int seer_tns_lookup(const char *alias, SeerTnsEntry *out, char *searched, size_t searched_len);

/* The same over a file's text; `dir` resolves a relative IFILE (NULL: none
 * followed). For the unit tests and seer_tns_lookup. */
int seer_tns_lookup_text(const char *text, const char *alias, const char *dir, SeerTnsEntry *out);

#endif
