/* Diagnostics: the per-handle diagnostic record plus SQLGetDiagRec /
 * SQLGetDiagField. Applications read every error and warning through these.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "odbc_internal.h"

const char *seer_odbc_sqlstate(SeerStatus st)
{
  switch (st) {
  case SEER_OK:
    return "00000";
  case SEER_EIO:
    return "08S01"; /* communication link failure */
  case SEER_EPROTO:
    return "08S01";
  case SEER_EAUTH:
    return "28000"; /* invalid authorization      */
  case SEER_ENOMEM:
    return "HY001"; /* memory allocation error    */
  case SEER_EPARAM:
    return "HY009"; /* invalid argument           */
  case SEER_EDB:
    return "HY000"; /* general error (ORA-NNNNN)   */
  case SEER_ENODATA:
    return "02000"; /* no data                    */
  case SEER_ENOTIMPL:
    return "HYC00"; /* optional feature not impl. */
  }
  return "HY000";
}

void seer_odbc_diag_clear(SQLHANDLE handle)
{
  if (handle == NULL)
    return;
  OdbcHeader *h = (OdbcHeader *)handle;
  h->diag.count = 0; /* keep the buffer; just drop the records */
}

void seer_odbc_diag_free(SQLHANDLE handle)
{
  if (handle == NULL)
    return;
  OdbcHeader *h = (OdbcHeader *)handle;
  free(h->diag.recs);
  h->diag.recs = NULL;
  h->diag.count = 0;
  h->diag.cap = 0;
}

/* The SQLSTATE of a server error, by what the ORA code means; NULL for one
 * with no closer state than HY000 (#207). */
static const char *ora_sqlstate(SQLINTEGER code)
{
  switch (code) {
  case 1:    /* unique constraint violated */
  case 1400: /* cannot insert NULL */
  case 1407: /* cannot update to NULL */
  case 2290: /* check constraint violated */
  case 2291: /* parent key not found */
  case 2292: /* child record found */
    return "23000";
  case 942: /* table or view does not exist */
    return "42S02";
  case 955: /* name is already used by an existing object */
    return "42S01";
  case 904: /* invalid identifier */
    return "42S22";
  case 900:  /* invalid SQL statement */
  case 905:  /* missing keyword */
  case 906:  /* missing left parenthesis */
  case 907:  /* missing right parenthesis */
  case 917:  /* missing comma */
  case 921:  /* unexpected end of SQL command */
  case 923:  /* FROM keyword not found where expected */
  case 933:  /* SQL command not properly ended */
  case 936:  /* missing expression */
  case 1031: /* insufficient privileges */
    return "42000";
  case 60:   /* deadlock detected */
  case 8177: /* can't serialize access for this transaction */
    return "40001";
  case 1476: /* divisor is equal to zero */
    return "22012";
  case 1722: /* invalid number */
    return "22018";
  case 1438: /* value larger than specified precision */
    return "22003";
  case 1401:  /* inserted value too large for column (before 10g) */
  case 12899: /* value too large for column */
    return "22001";
  case 1830: /* date format picture ends before converting entire input */
  case 1840: /* input value not long enough for date format */
  case 1841: /* (full) year must be between -4713 and +9999 */
  case 1858: /* a non-numeric character was found where a numeric was expected */
  case 1861: /* literal does not match format string */
    return "22007";
  case 1843: /* not a valid month */
  case 1847: /* day of month must be between 1 and last day of month */
    return "22008";
  default:
    return NULL;
  }
}

/* Append a record, growing the queue. Returns the new record or NULL on OOM.
 * A server error's text gives its native error when the caller passed none,
 * and a general error (HY000) takes the ORA code's own SQLSTATE (#207). */
static OdbcDiagRec *diag_push(OdbcHeader *h, const char *state, SQLINTEGER native, const char *msg,
                              SQLLEN row)
{
  if (native == 0 && msg != NULL && strncmp(msg, "ORA-", 4) == 0)
    native = (SQLINTEGER)atoi(msg + 4);
  if (native > 0 && (state == NULL || strcmp(state, "HY000") == 0)) {
    const char *mapped = ora_sqlstate(native);
    if (mapped != NULL)
      state = mapped;
  }
  if (h->diag.count == h->diag.cap) {
    int cap = h->diag.cap ? h->diag.cap * 2 : 4;
    OdbcDiagRec *r = realloc(h->diag.recs, (size_t)cap * sizeof *r);
    if (r == NULL)
      return NULL;
    h->diag.recs = r;
    h->diag.cap = cap;
  }
  OdbcDiagRec *rec = &h->diag.recs[h->diag.count++];
  snprintf(rec->state, sizeof rec->state, "%.5s", state ? state : "HY000");
  rec->native = native;
  snprintf(rec->message, sizeof rec->message, "%s", msg ? msg : "");
  rec->row_number = row;
  rec->error_offset = 0;
  return rec;
}

SQLRETURN seer_odbc_diag(SQLHANDLE handle, const char *state, SQLINTEGER native, const char *msg,
                         SQLRETURN ret)
{
  if (handle == NULL)
    return ret;
  OdbcHeader *h = (OdbcHeader *)handle;
  h->diag.count = 0; /* replace any existing records */
  diag_push(h, state, native, msg, SQL_NO_ROW_NUMBER);
  return ret;
}

SQLRETURN seer_odbc_exec_error(OdbcStmt *s, SeerStatus st)
{
  SeerConn *c = s->dbc != NULL ? s->dbc->conn : NULL;
  /* The server's text belongs to a database error; any other failure is
   * described by its own status, not by whatever ORA text came last. */
  const char *ora = st == SEER_EDB ? seer_last_error(c) : NULL;
  /* The native error is the ORA number, as SQLGetDiagRec callers expect. */
  SQLINTEGER native = (ora != NULL && strncmp(ora, "ORA-", 4) == 0) ? (SQLINTEGER)atoi(ora + 4) : 0;
  SQLRETURN r =
      seer_odbc_diag(s, seer_odbc_sqlstate(st), native, ora ? ora : seer_strerror(st), SQL_ERROR);
  OdbcHeader *h = (OdbcHeader *)s;
  if (h->diag.count > 0)
    h->diag.recs[h->diag.count - 1].error_offset = (SQLINTEGER)seer_last_error_offset(c);
  return r;
}

void seer_odbc_diag_add(SQLHANDLE handle, const char *state, SQLINTEGER native, const char *msg,
                        SQLLEN row_number)
{
  if (handle == NULL)
    return;
  diag_push((OdbcHeader *)handle, state, native, msg, row_number);
}

SQLRETURN SQL_API SQLGetDiagRec(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT RecNumber,
                                SQLCHAR *SQLState, SQLINTEGER *NativeErrorPtr, SQLCHAR *MessageText,
                                SQLSMALLINT BufferLength, SQLSMALLINT *TextLengthPtr)
{
  (void)HandleType;
  if (Handle == NULL || RecNumber < 1)
    return SQL_NO_DATA;

  OdbcHeader *h = (OdbcHeader *)Handle;
  if (RecNumber > h->diag.count)
    return SQL_NO_DATA;
  const OdbcDiagRec *rec = &h->diag.recs[RecNumber - 1];

  if (SQLState != NULL)
    memcpy(SQLState, rec->state, 6);
  if (NativeErrorPtr != NULL)
    *NativeErrorPtr = rec->native;

  size_t mlen = strlen(rec->message);
  if (TextLengthPtr != NULL)
    *TextLengthPtr = (SQLSMALLINT)mlen;
  if (MessageText != NULL && BufferLength > 0) {
    SQLSMALLINT n =
        (SQLSMALLINT)(mlen < (size_t)BufferLength - 1 ? mlen : (size_t)BufferLength - 1);
    memcpy(MessageText, rec->message, n);
    MessageText[n] = '\0';
    if ((size_t)n < mlen)
      return SQL_SUCCESS_WITH_INFO;
  }
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLGetDiagField(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT RecNumber,
                                  SQLSMALLINT DiagIdentifier, SQLPOINTER DiagInfoPtr,
                                  SQLSMALLINT BufferLength, SQLSMALLINT *StringLengthPtr)
{
  (void)HandleType;
  if (Handle == NULL)
    return SQL_NO_DATA;
  OdbcHeader *h = (OdbcHeader *)Handle;

  /* Header (record-independent) fields use RecNumber 0. */
  if (DiagIdentifier == SQL_DIAG_NUMBER) {
    if (DiagInfoPtr != NULL)
      *(SQLINTEGER *)DiagInfoPtr = h->diag.count;
    return SQL_SUCCESS;
  }

  if (RecNumber < 1 || RecNumber > h->diag.count)
    return SQL_NO_DATA;
  const OdbcDiagRec *rec = &h->diag.recs[RecNumber - 1];

  switch (DiagIdentifier) {
  case SQL_DIAG_SQLSTATE:
    if (DiagInfoPtr != NULL && BufferLength >= 6)
      memcpy(DiagInfoPtr, rec->state, 6);
    if (StringLengthPtr != NULL)
      *StringLengthPtr = 5;
    return SQL_SUCCESS;
  case SQL_DIAG_NATIVE:
    if (DiagInfoPtr != NULL)
      *(SQLINTEGER *)DiagInfoPtr = rec->native;
    return SQL_SUCCESS;
  case SQL_DIAG_MESSAGE_TEXT:
    if (DiagInfoPtr != NULL && BufferLength > 0)
      snprintf(DiagInfoPtr, (size_t)BufferLength, "%s", rec->message);
    if (StringLengthPtr != NULL)
      *StringLengthPtr = (SQLSMALLINT)strlen(rec->message);
    return SQL_SUCCESS;
  case SQL_DIAG_ROW_NUMBER:
    if (DiagInfoPtr != NULL)
      *(SQLLEN *)DiagInfoPtr = rec->row_number;
    return SQL_SUCCESS;
  case SQL_DIAG_SEER_ERROR_OFFSET:
    if (DiagInfoPtr != NULL)
      *(SQLINTEGER *)DiagInfoPtr = rec->error_offset;
    return SQL_SUCCESS;
  default:
    return SQL_NO_DATA;
  }
}
