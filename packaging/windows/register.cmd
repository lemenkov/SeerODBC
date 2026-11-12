@echo off
rem SPDX-FileCopyrightText: 2026 Peter Lemenkov and the SeerODBC contributors
rem SPDX-License-Identifier: Apache-2.0
rem
rem Register the SeerODBC driver (seerodbc.dll in this folder) with the Windows
rem ODBC Driver Manager. Run from an elevated (Administrator) prompt: drivers
rem are registered machine-wide, under HKLM.
rem
rem   register.cmd             register the driver in this folder
rem   register.cmd /remove     unregister it

setlocal
rem The registry view must match the DLL's bitness: /reg:64 for the 64-bit
rem build, /reg:32 for the 32-bit one (WOW6432Node).
set "VIEW=/reg:64"
set "DLL=%~dp0seerodbc.dll"
set "INST=HKLM\SOFTWARE\ODBC\ODBCINST.INI"

if /i "%~1"=="/remove" goto :remove

if not exist "%DLL%" (
  echo seerodbc.dll was not found in %~dp0
  exit /b 1
)
reg add "%INST%\ODBC Drivers" /v SeerODBC /t REG_SZ /d Installed /f %VIEW% >nul || goto :denied
reg add "%INST%\SeerODBC" /v Driver /t REG_SZ /d "%DLL%" /f %VIEW% >nul || goto :denied
reg add "%INST%\SeerODBC" /v APILevel /t REG_SZ /d 1 /f %VIEW% >nul || goto :denied
reg add "%INST%\SeerODBC" /v ConnectFunctions /t REG_SZ /d YYN /f %VIEW% >nul || goto :denied
reg add "%INST%\SeerODBC" /v DriverODBCVer /t REG_SZ /d 03.80 /f %VIEW% >nul || goto :denied
reg add "%INST%\SeerODBC" /v FileUsage /t REG_SZ /d 0 /f %VIEW% >nul || goto :denied
reg add "%INST%\SeerODBC" /v SQLLevel /t REG_SZ /d 1 /f %VIEW% >nul || goto :denied
reg add "%INST%\SeerODBC" /v UsageCount /t REG_DWORD /d 1 /f %VIEW% >nul || goto :denied
echo Registered the SeerODBC driver: %DLL%
exit /b 0

:remove
reg delete "%INST%\SeerODBC" /f %VIEW% >nul 2>&1
reg delete "%INST%\ODBC Drivers" /v SeerODBC /f %VIEW% >nul 2>&1
echo Unregistered the SeerODBC driver (its data sources are left as they are).
exit /b 0

:denied
echo Could not write the registry. Run this from an elevated (Administrator) prompt.
exit /b 1
