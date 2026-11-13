<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->

# SeerODBC on Windows

SeerODBC is a Windows ODBC driver, `seerodbc.dll`, built for 64-bit and for
32-bit applications. It is loaded by the Windows ODBC Driver Manager
(`odbc32.dll`). Applications and tools that use ODBC (Excel, Power BI,
LibreOffice, scripting languages' ODBC modules) reach the database through it.

A driver's bitness must match the *application's*, not the system's: a 64-bit
application needs the 64-bit driver, and a 32-bit one (32-bit Office, older BI
tools) needs the 32-bit driver, even on 64-bit Windows.

Each release ships both as one installer, `seerodbc-<version>-windows-setup.exe`,
and as a zip per bitness, `seerodbc-<version>-windows-x64.zip` and `-x86.zip`.

## Install with the installer

Run `seerodbc-<version>-windows-setup.exe`. It asks for administrator rights,
because drivers are registered machine-wide. It installs:

- the 64-bit driver in `C:\Program Files\SeerODBC`, registered for 64-bit
  applications;
- the 32-bit driver in `C:\Program Files (x86)\SeerODBC`, registered for 32-bit
  applications.

Both are selected by default; untick the one you don't need. On 32-bit Windows
only the 32-bit driver is offered. Each folder holds the same tools as the zip
(`seer_smoke.exe`, `seersql.exe`, `add-dsn.cmd`, `selftest.ps1`).

The installer is unsigned for now, so Windows SmartScreen may warn before it
runs.

Remove it from *Settings > Apps > Installed apps* (**SeerODBC**), or run
`uninstall.exe` in `C:\Program Files\SeerODBC`. Data sources (DSNs) are left
as they are.

For scripted installs: `setup.exe /S` installs both drivers silently, and
`"C:\Program Files\SeerODBC\uninstall.exe" /S` removes them.

## Install from the zip

The zip needs no installer, which suits a portable copy or a machine where the
installer can't run.

1. Unpack the zip that matches your application's bitness into a folder of your
   choice. Keep the files together: `seerodbc.dll` loads the DLLs beside it and
   OpenSSL's `ossl-modules\legacy.dll` (needed for 10g's DES-based login).
2. Open an **elevated** Command Prompt (*Run as administrator*) in that folder
   and register the driver:

   ```bat
   register.cmd
   ```

   It records `seerodbc.dll` by its full path under
   `HKLM\SOFTWARE\ODBC\ODBCINST.INI`, in the registry view of the zip's
   bitness, so the folder must stay where it is. Run it again after moving the
   folder. `register.cmd /remove` unregisters it.

The driver now appears in the *ODBC Data Source Administrator* of the matching
bitness, on the *Drivers* tab, as **SeerODBC**.

## Connect

**With a connection string**, no setup needed:

```
DRIVER={SeerODBC};HOST=db.example.com;PORT=1521;SERVICE=ORCLPDB1;UID=scott;PWD=tiger;
```

The keywords are the same as on Linux and macOS. They include `SID=` for old
servers, `SSL=1` / `TLSCA=` for TCPS, `CCLASS=` / `PURITY=` for DRCP,
`EXPIRE_TIME=` and `LOBINLINE=1`.

**With a data source (DSN)**, made in the *ODBC Data Source Administrator*
(`odbcad32.exe`, or *ODBC Data Sources* in the Start menu; the 64-bit one for
64-bit applications, the 32-bit one for 32-bit applications). On the *User DSN*
or *System DSN* tab, *Add...*, pick **SeerODBC**, and fill in:

- **Data source name** and an optional description;
- **Host**, **Port** (1521 unless the listener says otherwise) and **Service
  name**;
- **User ID**, optional. The password is never stored: applications pass it as
  `PWD=` when they connect. The dialog's password box is only for **Test
  connection**, which logs in with the values shown and reports the server's
  version or its error.

*Configure...* edits a DSN (renaming it keeps every value), and *Remove*
deletes it. Other keywords (`SSL=1`, `EXPIRE_TIME=`, ...) can be set as string
values under the DSN's registry key: `HKCU\SOFTWARE\ODBC\ODBC.INI\<name>` for a
user DSN, `HKLM\SOFTWARE\ODBC\ODBC.INI\<name>` for a system DSN. The dialog
keeps them.

The same works from PowerShell, and from scripts and installers that call
`SQLConfigDataSource`:

```powershell
Add-OdbcDsn -Name MyDb -DriverName SeerODBC -DsnType User -Platform 64-bit `
  -SetPropertyValue 'HOST=db.example.com', 'PORT=1521', 'SERVICE=ORCLPDB1'
Set-OdbcDsn -Name MyDb -DsnType User -Platform 64-bit -SetPropertyValue 'EXPIRE_TIME=10'
Remove-OdbcDsn -Name MyDb -DsnType User -Platform 64-bit
```

From the zip, without the Administrator, `add-dsn.cmd` does the same:

```bat
add-dsn.cmd MyDb db.example.com 1521 ORCLPDB1
add-dsn.cmd MyDb db.example.com 1521 ORCLPDB1 /system
```

The first creates a DSN for the current user. The second creates a system DSN,
visible to every account and to services, and needs an elevated prompt.

Applications then connect with `DSN=MyDb;UID=...;PWD=...;`.

## Check the install

`seer_smoke.exe`, in the zip, connects through the Driver Manager and runs a few
checks (a query, bound columns, a parameter, the wide API, an error):

```bat
seer_smoke.exe "DRIVER={SeerODBC};HOST=db.example.com;PORT=1521;SERVICE=ORCLPDB1;UID=scott;PWD=tiger;"
seer_smoke.exe "DSN=MyDb;UID=scott;PWD=tiger;"
```

It ends with `SUMMARY pass=6 fail=0` when all is well.

`selftest.ps1` checks the whole install in one go, from an elevated PowerShell
in the unpacked folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\selftest.ps1 `
  -Server db.example.com:1521/ORCLPDB1 -User scott -Password tiger
```

It registers the driver, checks that Windows' ODBC tooling (`Get-OdbcDriver`)
lists it for this zip's bitness, makes a DSN for each `-Server`, and runs
`seer_smoke.exe` by connection string and by DSN. It removes what it added
unless given `-Keep`, and ends with a `SUMMARY` line. For a copy the installer
put in place, add `-Installed`: the driver is then checked as registered, not
registered or removed, so run the `selftest.ps1` inside that installed folder.

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
