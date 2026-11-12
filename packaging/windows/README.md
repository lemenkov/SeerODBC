<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# SeerODBC on Windows

SeerODBC is a 64-bit Windows ODBC driver, `seerodbc.dll`. It is loaded by the
Windows ODBC Driver Manager (`odbc32.dll`). Applications and tools that use
ODBC (Excel, Power BI, LibreOffice, scripting languages' ODBC modules) reach
the database through it.

A driver's bitness must match the *application's*, not the system's: a 64-bit
application needs this 64-bit driver. A 32-bit build for 32-bit applications is
tracked in seerdb/SeerODBC#62.

## Install

1. Unpack the release zip into a folder of your choice. For example,
   `C:\Program Files\SeerODBC`. Keep the files together: `seerodbc.dll` loads
   the DLLs beside it and OpenSSL's `ossl-modules\legacy.dll` (needed for
   10g's DES-based login).
2. Open an **elevated** Command Prompt (*Run as administrator*) in that folder
   and register the driver:

   ```bat
   register.cmd
   ```

   It records `seerodbc.dll` by its full path under
   `HKLM\SOFTWARE\ODBC\ODBCINST.INI`, so the folder must stay where it is. Run
   it again after moving the folder. `register.cmd /remove` unregisters it.

The driver now appears in the *ODBC Data Source Administrator (64-bit)*, on the
*Drivers* tab, as **SeerODBC**.

## Connect

**With a connection string**, no setup needed:

```
DRIVER={SeerODBC};HOST=db.example.com;PORT=1521;SERVICE=ORCLPDB1;UID=scott;PWD=tiger;
```

The keywords are the same as on Linux and macOS. They include `SID=` for old
servers, `SSL=1` / `TLSCA=` for TCPS, `CCLASS=` / `PURITY=` for DRCP,
`EXPIRE_TIME=` and `LOBINLINE=1`.

**With a data source (DSN)**:

```bat
add-dsn.cmd MyDb db.example.com 1521 ORCLPDB1
add-dsn.cmd MyDb db.example.com 1521 ORCLPDB1 /system
```

The first creates a DSN for the current user. The second creates a system DSN,
visible to every account and to services, and needs an elevated prompt.
Applications then connect with `DSN=MyDb;UID=...;PWD=...;`. Other keywords can
be added as string values under the DSN's registry key, which is
`HKCU\SOFTWARE\ODBC\ODBC.INI\MyDb` or, for a system DSN,
`HKLM\SOFTWARE\ODBC\ODBC.INI\MyDb`.

The Data Source Administrator lists these DSNs but cannot edit them yet. That
needs a driver setup DLL (`ConfigDSN`), which is still to come
(seerdb/SeerODBC#60).

## Check the install

`seer_smoke.exe`, in the zip, connects through the Driver Manager and runs a few
checks (a query, bound columns, a parameter, the wide API, an error):

```bat
seer_smoke.exe "DRIVER={SeerODBC};HOST=db.example.com;PORT=1521;SERVICE=ORCLPDB1;UID=scott;PWD=tiger;"
seer_smoke.exe "DSN=MyDb;UID=scott;PWD=tiger;"
```

It ends with `SUMMARY pass=6 fail=0` when all is well.

For a trace of what the driver does, set `SEERODBC_DEBUG=1` in the
environment of the application, or of `seer_smoke.exe`.

## Troubleshooting

- **"Data source name not found and no default driver specified"**: the
  driver isn't registered for this bitness, or the DSN name is misspelt. Check
  the *64-bit* Data Source Administrator.
- **"The specified module could not be found"**: a DLL from the zip is missing
  beside `seerodbc.dll`, or the folder was moved after `register.cmd` ran.
- **ORA-01017 against a 10g server with the right password**: OpenSSL's legacy
  provider didn't load. Keep `ossl-modules\legacy.dll` beside the driver, or
  set `OPENSSL_MODULES` to the folder that holds it. With `SEERODBC_DEBUG=1`
  the driver logs this.
