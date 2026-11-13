/* Windows driver setup: ConfigDSN / ConfigDriver.
 *
 * The ODBC installer (odbccp32) calls ConfigDSN to add, change or remove a
 * SeerODBC data source - from the ODBC Data Source Administrator, from
 * SQLConfigDataSource, and so from PowerShell's Add-/Set-/Remove-OdbcDsn. With
 * a parent window it shows a dialog (setup.rc); without one it works from the
 * attribute string alone ("DSN=x\0HOST=y\0...\0\0"). Either way the values go
 * through the installer's SQLWritePrivateProfileString, into the registry keys
 * odbcini.c reads back on connect, in the user or system DSN set the installer
 * has selected (SQLSetConfigMode).
 *
 * Only the fields the dialog shows are edited there; any other value a DSN
 * carries (SSL, EXPIRE_TIME, ...) is kept, and a silent request may set any
 * keyword.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "odbc_platform.h" /* <windows.h> before the ODBC headers */

#include <sql.h>
#include <sqlext.h>
#include <odbcinst.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "setup.h"

#define ODBC_INI "ODBC.INI"
#define FIELD_MAX 256

/* The fields the dialog edits. */
typedef struct {
  char dsn[SQL_MAX_DSN_LENGTH + 1];
  char desc[FIELD_MAX];
  char host[FIELD_MAX];
  char port[8];
  char service[FIELD_MAX];
  char uid[FIELD_MAX];
} DsnFields;

static const struct {
  const char *key; /* the DSN keyword odbcini.c / connect.c read */
  size_t off;
  size_t size;
  int ctl; /* its dialog control */
} FIELDS[] = {
    {"Description", offsetof(DsnFields, desc), FIELD_MAX, IDC_DESC},
    {"HOST", offsetof(DsnFields, host), FIELD_MAX, IDC_HOST},
    {"PORT", offsetof(DsnFields, port), 8, IDC_PORT},
    {"SERVICE", offsetof(DsnFields, service), FIELD_MAX, IDC_SERVICE},
    {"UID", offsetof(DsnFields, uid), FIELD_MAX, IDC_UID},
};
#define NFIELDS (sizeof FIELDS / sizeof FIELDS[0])

static char *field(DsnFields *f, size_t i)
{
  return (char *)f + FIELDS[i].off;
}

static void copy_str(char *dst, size_t size, const char *src)
{
  snprintf(dst, size, "%s", src ? src : "");
}

/* ------------------------------------------------------- attribute string */

/* Walk "KEY=value\0KEY=value\0\0": the value of `key`, or NULL. */
static const char *attr_get(const char *attrs, const char *key, size_t *vlen)
{
  size_t klen = strlen(key);
  for (const char *p = attrs; p != NULL && *p != '\0'; p += strlen(p) + 1) {
    const char *eq = strchr(p, '=');
    if (eq != NULL && (size_t)(eq - p) == klen && _strnicmp(p, key, klen) == 0) {
      if (vlen)
        *vlen = strlen(eq + 1);
      return eq + 1;
    }
  }
  return NULL;
}

static int is_field_key(const char *key, size_t klen)
{
  if (klen == 3 && _strnicmp(key, "DSN", 3) == 0)
    return 1;
  if (klen == 6 && _strnicmp(key, "DRIVER", 6) == 0)
    return 1;
  for (size_t i = 0; i < NFIELDS; i++)
    if (strlen(FIELDS[i].key) == klen && _strnicmp(key, FIELDS[i].key, klen) == 0)
      return 1;
  return 0;
}

/* Overlay the attribute string's values for the dialog's fields onto `f`. */
static void fields_from_attrs(DsnFields *f, const char *attrs)
{
  const char *v = attr_get(attrs, "DSN", NULL);
  if (v)
    copy_str(f->dsn, sizeof f->dsn, v);
  for (size_t i = 0; i < NFIELDS; i++) {
    v = attr_get(attrs, FIELDS[i].key, NULL);
    if (v)
      copy_str(field(f, i), FIELDS[i].size, v);
  }
}

/* An existing DSN's values for the dialog's fields. */
static void fields_from_ini(DsnFields *f, const char *dsn)
{
  for (size_t i = 0; i < NFIELDS; i++)
    SQLGetPrivateProfileString(dsn, FIELDS[i].key, "", field(f, i), (int)FIELDS[i].size, ODBC_INI);
}

/* ------------------------------------------------------------ the writing */

static BOOL fail(DWORD code, const char *msg)
{
  SQLPostInstallerError(code, msg);
  return FALSE;
}

/* A field set is complete enough to save: a valid name, a host and a service;
 * a port, when given, in range. Returns NULL or the reason. */
static const char *fields_invalid(const DsnFields *f)
{
  if (f->dsn[0] == '\0' || !SQLValidDSN(f->dsn))
    return "The data source name is empty or contains a character ODBC does not allow "
           "([]{}(),;?*=!@\\).";
  if (f->host[0] == '\0')
    return "A host is needed.";
  if (f->service[0] == '\0')
    return "A service name is needed.";
  if (f->port[0] != '\0') {
    char *end = NULL;
    long p = strtol(f->port, &end, 10);
    if (*end != '\0' || p < 1 || p > 65535)
      return "The port must be a number from 1 to 65535.";
  }
  return NULL;
}

/* Copy every value of DSN `from` but Driver to DSN `to` (a rename). */
static void copy_values(const char *from, const char *to)
{
  char keys[4096], val[1024];
  int n = SQLGetPrivateProfileString(from, NULL, "", keys, (int)sizeof keys, ODBC_INI);
  for (const char *k = keys; n > 0 && k < keys + n && *k != '\0'; k += strlen(k) + 1) {
    if (_stricmp(k, "Driver") == 0)
      continue;
    SQLGetPrivateProfileString(from, k, "", val, (int)sizeof val, ODBC_INI);
    SQLWritePrivateProfileString(to, k, val, ODBC_INI);
  }
}

/* Save `f` as a DSN of `driver`, plus every attribute of `attrs` that isn't one
 * of the dialog's fields. `old` is the DSN's former name when it is being
 * changed (renamed when it differs), else NULL. An empty field is removed. */
static BOOL save_dsn(const char *driver, const DsnFields *f, const char *attrs, const char *old)
{
  if (!SQLWriteDSNToIni(f->dsn, driver))
    return fail(ODBC_ERROR_REQUEST_FAILED, "Could not create the data source.");
  int renamed = old != NULL && _stricmp(old, f->dsn) != 0;
  if (renamed)
    copy_values(old, f->dsn);
  for (size_t i = 0; i < NFIELDS; i++) {
    const char *v = (const char *)f + FIELDS[i].off;
    SQLWritePrivateProfileString(f->dsn, FIELDS[i].key, v[0] ? v : NULL, ODBC_INI);
  }
  for (const char *p = attrs; p != NULL && *p != '\0'; p += strlen(p) + 1) {
    const char *eq = strchr(p, '=');
    if (eq == NULL || is_field_key(p, (size_t)(eq - p)))
      continue;
    char key[128];
    size_t klen = (size_t)(eq - p) < sizeof key - 1 ? (size_t)(eq - p) : sizeof key - 1;
    memcpy(key, p, klen);
    key[klen] = '\0';
    SQLWritePrivateProfileString(f->dsn, key, eq[1] ? eq + 1 : NULL, ODBC_INI);
  }
  if (renamed)
    SQLRemoveDSNFromIni(old);
  return TRUE;
}

/* ------------------------------------------------------------ the dialog */

typedef struct {
  DsnFields f;
} DialogCtx;

static const char g_module_anchor = 0; /* an address inside this DLL */

static HINSTANCE this_module(void)
{
  HMODULE self = NULL;
  GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                     &g_module_anchor, &self);
  return (HINSTANCE)self;
}

static void dialog_read(HWND dlg, DsnFields *f)
{
  GetDlgItemTextA(dlg, IDC_DSN, f->dsn, (int)sizeof f->dsn);
  for (size_t i = 0; i < NFIELDS; i++)
    GetDlgItemTextA(dlg, FIELDS[i].ctl, field(f, i), (int)FIELDS[i].size);
}

/* Connect with the dialog's values through this driver itself (not the Driver
 * Manager) and report what happened. */
static void test_connection(HWND dlg, const DsnFields *f, const char *pwd)
{
  if (strchr(f->host, ';') || strchr(f->service, ';') || strchr(f->uid, ';') || strchr(pwd, ';')) {
    MessageBoxA(dlg, "A value contains ';', which a connection string cannot carry.", "SeerODBC",
                MB_OK | MB_ICONWARNING);
    return;
  }
  char cs[1200];
  snprintf(cs, sizeof cs, "HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;", f->host,
           f->port[0] ? f->port : "1521", f->service, f->uid, pwd);

  HCURSOR old = SetCursor(LoadCursor(NULL, IDC_WAIT));
  SQLHENV env = SQL_NULL_HENV;
  SQLHDBC dbc = SQL_NULL_HDBC;
  char msg[1200];
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
  SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
  SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
  SQLRETURN r =
      SQLDriverConnect(dbc, NULL, (SQLCHAR *)cs, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
  if (SQL_SUCCEEDED(r)) {
    char ver[128] = "";
    SQLGetInfo(dbc, SQL_DBMS_VER, ver, (SQLSMALLINT)sizeof ver, NULL);
    snprintf(msg, sizeof msg, "Connected to %s:%s/%s.\n\nServer version %s.", f->host,
             f->port[0] ? f->port : "1521", f->service, ver);
    SQLDisconnect(dbc);
  } else {
    SQLCHAR state[6] = "", text[1024] = "";
    SQLINTEGER native = 0;
    SQLGetDiagRec(SQL_HANDLE_DBC, dbc, 1, state, &native, text, (SQLSMALLINT)sizeof text, NULL);
    snprintf(msg, sizeof msg, "Could not connect.\n\n[%s] %s", (char *)state, (char *)text);
  }
  SQLFreeHandle(SQL_HANDLE_DBC, dbc);
  SQLFreeHandle(SQL_HANDLE_ENV, env);
  SetCursor(old);
  MessageBoxA(dlg, msg, "SeerODBC", MB_OK | (SQL_SUCCEEDED(r) ? MB_ICONINFORMATION : MB_ICONERROR));
}

static INT_PTR CALLBACK dialog_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
  DialogCtx *ctx = (DialogCtx *)GetWindowLongPtrA(dlg, GWLP_USERDATA);
  switch (msg) {
  case WM_INITDIALOG:
    ctx = (DialogCtx *)lp;
    SetWindowLongPtrA(dlg, GWLP_USERDATA, (LONG_PTR)ctx);
    SendDlgItemMessageA(dlg, IDC_DSN, EM_LIMITTEXT, SQL_MAX_DSN_LENGTH, 0);
    SetDlgItemTextA(dlg, IDC_DSN, ctx->f.dsn);
    for (size_t i = 0; i < NFIELDS; i++) {
      SendDlgItemMessageA(dlg, FIELDS[i].ctl, EM_LIMITTEXT, FIELDS[i].size - 1, 0);
      SetDlgItemTextA(dlg, FIELDS[i].ctl, field(&ctx->f, i));
    }
    if (ctx->f.port[0] == '\0')
      SetDlgItemTextA(dlg, IDC_PORT, "1521");
    SendDlgItemMessageA(dlg, IDC_PWD, EM_LIMITTEXT, FIELD_MAX - 1, 0);
    return TRUE;
  case WM_COMMAND:
    switch (LOWORD(wp)) {
    case IDOK: {
      DsnFields f = ctx->f;
      dialog_read(dlg, &f);
      const char *why = fields_invalid(&f);
      if (why != NULL) {
        MessageBoxA(dlg, why, "SeerODBC", MB_OK | MB_ICONWARNING);
        return TRUE;
      }
      ctx->f = f;
      EndDialog(dlg, IDOK);
      return TRUE;
    }
    case IDCANCEL:
      EndDialog(dlg, IDCANCEL);
      return TRUE;
    case IDC_TEST: {
      DsnFields f = ctx->f;
      char pwd[FIELD_MAX];
      dialog_read(dlg, &f);
      GetDlgItemTextA(dlg, IDC_PWD, pwd, (int)sizeof pwd);
      test_connection(dlg, &f, pwd);
      SecureZeroMemory(pwd, sizeof pwd);
      return TRUE;
    }
    default:
      break;
    }
    break;
  default:
    break;
  }
  return FALSE;
}

/* ------------------------------------------------------------ entry points */

static BOOL config_dsn(HWND parent, WORD req, LPCSTR driver, LPCSTR attrs)
{
  size_t vlen = 0;
  const char *named = attr_get(attrs, "DSN", &vlen);
  char old[SQL_MAX_DSN_LENGTH + 1] = "";
  if (named != NULL)
    copy_str(old, sizeof old, named);

  if (req == ODBC_REMOVE_DSN) {
    if (old[0] == '\0')
      return fail(ODBC_ERROR_INVALID_NAME, "No data source name (DSN=) given.");
    if (!SQLRemoveDSNFromIni(old))
      return fail(ODBC_ERROR_REQUEST_FAILED, "Could not remove the data source.");
    return TRUE;
  }

  DialogCtx ctx;
  memset(&ctx, 0, sizeof ctx);
  if (req == ODBC_CONFIG_DSN) {
    if (old[0] == '\0')
      return fail(ODBC_ERROR_INVALID_NAME, "No data source name (DSN=) given.");
    copy_str(ctx.f.dsn, sizeof ctx.f.dsn, old);
    fields_from_ini(&ctx.f, old);
  }
  fields_from_attrs(&ctx.f, attrs);

  if (parent != NULL) {
    INT_PTR r = DialogBoxParamA(this_module(), MAKEINTRESOURCEA(IDD_DSN), parent, dialog_proc,
                                (LPARAM)&ctx);
    if (r != IDOK)
      return FALSE; /* cancelled: nothing changes */
  } else {
    const char *why = fields_invalid(&ctx.f);
    if (why != NULL)
      return fail(ctx.f.dsn[0] == '\0' ? ODBC_ERROR_INVALID_NAME : ODBC_ERROR_INVALID_KEYWORD_VALUE,
                  why);
  }
  return save_dsn(driver, &ctx.f, attrs, req == ODBC_CONFIG_DSN ? old : NULL);
}

BOOL INSTAPI ConfigDSN(HWND hwndParent, WORD fRequest, LPCSTR lpszDriver, LPCSTR lpszAttributes)
{
  if (lpszDriver == NULL || lpszDriver[0] == '\0')
    return fail(ODBC_ERROR_INVALID_NAME, "No driver name given.");

  /* The system-DSN requests: the same work, in the system DSN set. */
  WORD req = fRequest;
  int sys = 0;
  switch (fRequest) {
  case ODBC_ADD_DSN:
  case ODBC_CONFIG_DSN:
  case ODBC_REMOVE_DSN:
    break;
  case ODBC_ADD_SYS_DSN:
    req = ODBC_ADD_DSN;
    sys = 1;
    break;
  case ODBC_CONFIG_SYS_DSN:
    req = ODBC_CONFIG_DSN;
    sys = 1;
    break;
  case ODBC_REMOVE_SYS_DSN:
    req = ODBC_REMOVE_DSN;
    sys = 1;
    break;
  default:
    return fail(ODBC_ERROR_INVALID_REQUEST_TYPE, "Unknown ConfigDSN request.");
  }

  UWORD mode = ODBC_BOTH_DSN;
  if (sys) {
    SQLGetConfigMode(&mode);
    SQLSetConfigMode(ODBC_SYSTEM_DSN);
  }
  BOOL ok = config_dsn(hwndParent, req, lpszDriver, lpszAttributes);
  if (sys)
    SQLSetConfigMode(mode);
  return ok;
}

/* Installing, removing or configuring the driver itself needs nothing from it:
 * the installer writes ODBCINST.INI. */
BOOL INSTAPI ConfigDriver(HWND hwndParent, WORD fRequest, LPCSTR lpszDriver, LPCSTR lpszArgs,
                          LPSTR lpszMsg, WORD cbMsgMax, WORD *pcbMsgOut)
{
  (void)hwndParent;
  (void)lpszDriver;
  (void)lpszArgs;
  if (lpszMsg != NULL && cbMsgMax > 0)
    lpszMsg[0] = '\0';
  if (pcbMsgOut != NULL)
    *pcbMsgOut = 0;
  switch (fRequest) {
  case ODBC_INSTALL_DRIVER:
  case ODBC_REMOVE_DRIVER:
  case ODBC_CONFIG_DRIVER:
    return TRUE;
  default:
    return fail(ODBC_ERROR_INVALID_REQUEST_TYPE, "Unknown ConfigDriver request.");
  }
}
