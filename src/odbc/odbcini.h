/* Self-contained reader for ODBC's odbc.ini / odbcinst.ini: a drop-in for the
 * Driver Manager's SQLGetPrivateProfileString().
 *
 * Reading these files ourselves is the one thing that lets the shim load
 * identically under unixODBC and iODBC with no libodbcinst / libiodbcinst at
 * run time. Both managers export the same profile-string API, but from
 * different sonames (libodbcinst.so.2 vs libiodbcinst.so.2), so linking either
 * one pins the driver to that manager. An odbc.ini is a plain INI file; the only
 * part worth borrowing from a manager is the file-search policy, and that is
 * shared env-var convention we can reproduce.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_ODBCINI_H
#define SEER_ODBCINI_H

/* Same contract as SQLGetPrivateProfileString(): copy the value of `entry` in
 * `section` into `retbuf` (at most retbuf_len-1 bytes, always NUL-terminated)
 * and return the number of bytes written, excluding the NUL. If the key is
 * absent, `defstr` (may be NULL, treated as "") is copied instead. `section` and
 * `entry` are matched case-insensitively, per ODBC convention.
 *
 * `filename` selects the file set, mirroring the managers' magic names:
 *   "odbc.ini"      -> user file (ODBCINI, else $HOME/.odbc.ini), then the
 *                      system file ((ODBCSYSINI, else /etc)/odbc.ini);
 *                      the first match wins, so user entries override system.
 *   "odbcinst.ini"  -> ODBCINSTINI (if absolute), else
 *                      (ODBCSYSINI, else /etc)/odbcinst.ini.
 *   anything with a '/' -> that path, verbatim.
 *   any other bare name -> (ODBCSYSINI, else /etc)/<name>.
 *
 * Enumeration (section == NULL or entry == NULL) is not implemented - the shim
 * never needs it - and such calls return the default. */
int seer_get_private_profile_string(const char *section, const char *entry,
                                    const char *defstr, char *retbuf,
                                    int retbuf_len, const char *filename);

#endif /* SEER_ODBCINI_H */
