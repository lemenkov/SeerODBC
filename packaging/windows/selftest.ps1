# SPDX-FileCopyrightText: 2026 Peter Lemenkov and the SeerODBC contributors
# SPDX-License-Identifier: Apache-2.0
#
# Check an unpacked SeerODBC zip end to end on this machine: register the
# driver, confirm Windows' ODBC tooling lists it, create a DSN, and run
# seer_smoke.exe against each server by connection string and by DSN.
#
# Run it from an elevated PowerShell, in the unpacked folder:
#
#   powershell -ExecutionPolicy Bypass -File .\selftest.ps1 `
#     -Server db1.example.com:1521/ORCLPDB1, db2:1522/FREEPDB1 `
#     -User scott -Password tiger
#
# -Keep leaves the driver registered and the test DSN in place afterwards.
# -Installed checks a copy the installer put in place: the driver is already
# registered, so it is neither registered nor unregistered here, only checked.
# Run the selftest.ps1 inside the installed folder (Program Files\SeerODBC, or
# Program Files (x86)\SeerODBC for the 32-bit driver).
# Exit status: 0 when every check passed, 1 otherwise.

param(
  [Parameter(Mandatory = $true)] [string[]] $Server, # host:port/service
  [Parameter(Mandatory = $true)] [string] $User,
  [Parameter(Mandatory = $true)] [string] $Password,
  [switch] $Keep,
  [switch] $Installed
)

$ErrorActionPreference = 'Stop'
# "powershell -File" hands -Server a,b over as one string: split it here.
$Server = @($Server | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dll = Join-Path $here 'seerodbc.dll'
$smoke = Join-Path $here 'seer_smoke.exe'
$results = New-Object System.Collections.Generic.List[object]

# Run a native program, capturing stdout and stderr as text. Windows
# PowerShell 5.1 turns each stderr line into an error record, which 'Stop'
# makes fatal; relax that for the call. $LASTEXITCODE is the program's.
function Run {
  $ErrorActionPreference = 'Continue'
  $prog = $args[0]
  $rest = @($args | Select-Object -Skip 1)
  & $prog @rest 2>&1 | ForEach-Object { "$_" }
}

function Note([string] $name, [bool] $ok, [string] $detail = '') {
  $results.Add([pscustomobject]@{ Check = $name; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail })
  $colour = if ($ok) { 'Green' } else { 'Red' }
  Write-Host ('  {0} {1}{2}' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $(if ($detail) { ": $detail" } else { '' })) -ForegroundColor $colour
}

# The zip's bitness: a PE32+ DLL is 64-bit. It decides the registry view and
# which ODBC Administrator (and Get-OdbcDriver platform) sees the driver.
$bytes = [System.IO.File]::ReadAllBytes($dll)
$pe = [BitConverter]::ToInt32($bytes, 0x3c)
$machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
$platform = if ($machine -eq 0x8664) { '64-bit' } else { '32-bit' }
Write-Host "SeerODBC self-test: $dll ($platform)"
Write-Host ("Windows {0}, PowerShell {1}" -f [Environment]::OSVersion.Version, $PSVersionTable.PSVersion)

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
  Write-Host 'Run this from an elevated (Administrator) PowerShell: registering a driver writes HKLM.' -ForegroundColor Red
  exit 1
}

# 1. register (an installed copy is registered already)
if (-not $Installed) {
  $out = Run "$here\register.cmd"
  Note 'register.cmd' ($LASTEXITCODE -eq 0) ($out -join ' ')
}

# 2. Windows sees it
try {
  $drv = Get-OdbcDriver -Name 'SeerODBC' -Platform $platform
  $path = ($drv.Attribute['Driver'])
  Note "Get-OdbcDriver ($platform) lists SeerODBC" ($path -ieq $dll) $path
} catch {
  Note "Get-OdbcDriver ($platform) lists SeerODBC" $false $_.Exception.Message
}

# 3. per server: a DSN, then seer_smoke by connection string and by DSN
$n = 0
foreach ($s in $Server) {
  $n++
  if ($s -notmatch '^([^:/]+):(\d+)/(.+)$') {
    Note "server '$s'" $false 'expected host:port/service'
    continue
  }
  $h, $p, $svc = $Matches[1], $Matches[2], $Matches[3]
  $dsn = "SeerSelfTest$n"
  $out = Run "$here\add-dsn.cmd" $dsn $h $p $svc
  Note "add-dsn.cmd $dsn ($s)" ($LASTEXITCODE -eq 0) ($out -join ' ')

  foreach ($cs in @("DRIVER={SeerODBC};HOST=$h;PORT=$p;SERVICE=$svc;UID=$User;PWD=$Password;",
                    "DSN=$dsn;UID=$User;PWD=$Password;")) {
    $how = if ($cs.StartsWith('DSN=')) { 'DSN' } else { 'DRIVER=' }
    $log = Run $smoke $cs
    $summary = ($log | Select-String -Pattern '^SUMMARY' | Select-Object -Last 1)
    $who = ($log | Select-String -Pattern '^connected:' | Select-Object -First 1)
    $detail = "$summary".Trim()
    if ($who) { $detail = "$detail; $("$who".Trim())" }
    Note "seer_smoke $s by $how" ($LASTEXITCODE -eq 0) $detail
    if ($LASTEXITCODE -ne 0) { $log | ForEach-Object { Write-Host "      $_" } }
  }
  if (-not $Keep) {
    Remove-Item -Path "HKCU:\SOFTWARE\ODBC\ODBC.INI\$dsn" -Recurse -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKCU:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources' -Name $dsn -ErrorAction SilentlyContinue
  }
}

# 4. unregister, unless asked to keep it (or the installer owns it)
if (-not $Keep -and -not $Installed) {
  $out = Run "$here\register.cmd" /remove
  Note 'register.cmd /remove' ($LASTEXITCODE -eq 0) ($out -join ' ')
}

$failed = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
Write-Host ''
Write-Host ("SUMMARY pass={0} fail={1}" -f ($results.Count - $failed), $failed)
exit $(if ($failed) { 1 } else { 0 })
