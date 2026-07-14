/* Unit test for the self-contained odbc.ini reader (src/odbc/odbcini.c). Writes
 * throwaway INI files in a temp dir and points the ODBC env vars at them, so it
 * needs neither a Driver Manager nor a server - it runs fully offline.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "odbcini.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char dir[4096];

static void write_file(const char *name, const char *content)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    /* Owner-only (0600): these are throwaway files, but keep CodeQL's
     * world-writable-creation check happy and set the right example. */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "w");
    assert(f != NULL);
    fputs(content, f);
    fclose(f);
}

/* Assert that section/key resolves to `want` (NULL means "expect the default"). */
static void expect(const char *section, const char *key, const char *want,
                   const char *filename)
{
    char buf[512];
    int n = seer_get_private_profile_string(section, key, "DEFLT", buf,
                                            sizeof buf, filename);
    const char *expected = want != NULL ? want : "DEFLT";
    if (strcmp(buf, expected) != 0 || n != (int)strlen(expected)) {
        fprintf(stderr, "[%s] %s -> got \"%s\" (n=%d), expected \"%s\"\n",
                section, key, buf, n, expected);
        assert(0);
    }
}

int main(void)
{
    char tmpl[] = "/tmp/seer_odbcini_XXXXXX";
    char *d = mkdtemp(tmpl);
    assert(d != NULL);
    snprintf(dir, sizeof dir, "%s", d);

    /* A user odbc.ini with comments, blank lines, odd spacing, and a DSN. */
    write_file("user.ini",
        "; a comment\n"
        "\n"
        "[Prod]\n"
        "  HOST = db.example.com \n"
        "Port=1521\n"
        "Service = XE\n"
        "# another comment\n"
        "[Other]\n"
        "HOST=wrong.example.com\n");

    char userpath[4096];
    snprintf(userpath, sizeof userpath, "%s/user.ini", dir);
    setenv("ODBCINI", userpath, 1);
    unsetenv("HOME");          /* force the ODBCINI path, not ~/.odbc.ini */

    /* Basic value, with surrounding whitespace trimmed. */
    expect("Prod", "HOST", "db.example.com", "odbc.ini");
    expect("Prod", "Port", "1521", "odbc.ini");
    expect("Prod", "Service", "XE", "odbc.ini");

    /* Section and key are matched case-insensitively (ODBC convention). */
    expect("prod", "host", "db.example.com", "odbc.ini");
    expect("PROD", "SERVICE", "XE", "odbc.ini");

    /* Missing key and missing section both fall back to the default. */
    expect("Prod", "Password", NULL, "odbc.ini");
    expect("Nope", "HOST", NULL, "odbc.ini");

    /* A section boundary is respected: [Other]'s HOST must not leak into [Prod]. */
    expect("Other", "HOST", "wrong.example.com", "odbc.ini");
    expect("Prod", "HOST", "db.example.com", "odbc.ini");

    /* An explicit path (contains '/') is read verbatim, ignoring env. */
    expect("Prod", "HOST", "db.example.com", userpath);

    /* System-dir fallback: unset ODBCINI, put odbc.ini under ODBCSYSINI. */
    unsetenv("ODBCINI");
    write_file("odbc.ini", "[Sys]\nHOST=system.example.com\n");
    setenv("ODBCSYSINI", dir, 1);
    expect("Sys", "HOST", "system.example.com", "odbc.ini");

    /* Precedence: with both files present, the user file wins for a shared DSN. */
    write_file("odbc.ini", "[Prod]\nHOST=system.example.com\n");  /* system copy */
    setenv("ODBCINI", userpath, 1);                               /* user copy too */
    expect("Prod", "HOST", "db.example.com", "odbc.ini");

    /* odbcinst.ini resolves under ODBCSYSINI. */
    write_file("odbcinst.ini", "[SeerODBC]\nDriver=libseerodbc.so\nFileUsage=0\n");
    expect("SeerODBC", "Driver", "libseerodbc.so", "odbcinst.ini");
    expect("SeerODBC", "FileUsage", "0", "odbcinst.ini");

    /* Defensive: NULL section/entry (enumeration) yields the default, no crash. */
    {
        char buf[16];
        assert(seer_get_private_profile_string(NULL, "HOST", "D", buf, sizeof buf,
                                               "odbc.ini") == 1);
        assert(strcmp(buf, "D") == 0);
    }

    /* Clean up the temp files and dir. */
    const char *names[] = { "user.ini", "odbc.ini", "odbcinst.ini" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        unlink(path);
    }
    rmdir(dir);

    printf("odbcini: all checks passed\n");
    return 0;
}
