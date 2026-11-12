@echo off
rem SPDX-FileCopyrightText: 2026 Peter Lemenkov and the SeerODBC contributors
rem SPDX-License-Identifier: Apache-2.0
rem
rem Create (or update) a SeerODBC data source. Until the driver has a setup
rem DLL, the ODBC Data Source Administrator can list these but not edit them.
rem
rem   add-dsn.cmd NAME HOST PORT SERVICE [/system]
rem
rem A user DSN (HKCU) by default; /system makes a system DSN (HKLM, visible to
rem every account and to services), which needs an elevated prompt. User name
rem and password are given at connect time (UID= / PWD=), not stored.

setlocal
set "VIEW=/reg:64"
if "%~4"=="" (
  echo usage: add-dsn.cmd NAME HOST PORT SERVICE [/system]
  exit /b 1
)
set "ROOT=HKCU"
if /i "%~5"=="/system" set "ROOT=HKLM"
set "INI=%ROOT%\SOFTWARE\ODBC\ODBC.INI"

reg add "%INI%\ODBC Data Sources" /v "%~1" /t REG_SZ /d SeerODBC /f %VIEW% >nul || goto :denied
reg add "%INI%\%~1" /v Driver /t REG_SZ /d "%~dp0seerodbc.dll" /f %VIEW% >nul || goto :denied
reg add "%INI%\%~1" /v HOST /t REG_SZ /d "%~2" /f %VIEW% >nul || goto :denied
reg add "%INI%\%~1" /v PORT /t REG_SZ /d "%~3" /f %VIEW% >nul || goto :denied
reg add "%INI%\%~1" /v SERVICE /t REG_SZ /d "%~4" /f %VIEW% >nul || goto :denied
echo Data source %~1 (%ROOT%): %~2:%~3/%~4
exit /b 0

:denied
echo Could not write the registry (a /system DSN needs an elevated prompt).
exit /b 1
