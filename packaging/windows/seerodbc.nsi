; SPDX-FileCopyrightText: 2026 Peter Lemenkov and the SeerODBC contributors
; SPDX-License-Identifier: Apache-2.0
;
; The SeerODBC Windows installer: both drivers in one setup.exe. A driver's
; bitness has to match the application's, not Windows', so on 64-bit Windows
; the 64-bit driver goes to Program Files\SeerODBC and the 32-bit one to
; Program Files (x86)\SeerODBC, each registered in its own registry view. On
; 32-bit Windows only the 32-bit driver is offered.
;
; Built by make-installer.sh from the two release zips; it passes
;   VERSION   the driver version (x.y.z)
;   X64DIR    the unpacked x64 zip
;   X86DIR    the unpacked x86 zip
;   TOPDIR    the source tree (for LICENSE)
;   OUTFILE   the setup.exe to write
;
; Silent install: setup.exe /S (both drivers, as on the components page).
; Silent removal: "Program Files\SeerODBC\uninstall.exe" /S

Unicode true
SetCompressor /SOLID lzma

!include MUI2.nsh
!include LogicLib.nsh
!include x64.nsh
!include Sections.nsh

!define PRODUCT "SeerODBC"
!define INST "SOFTWARE\ODBC\ODBCINST.INI"
!define UNINST "Software\Microsoft\Windows\CurrentVersion\Uninstall\SeerODBC"
!define DIR64 "$PROGRAMFILES64\SeerODBC"
!define DIR32 "$PROGRAMFILES32\SeerODBC"

Name "${PRODUCT} ${VERSION}"
OutFile "${OUTFILE}"
RequestExecutionLevel admin ; drivers are registered machine-wide, under HKLM
InstallDir "${DIR64}"       ; fixed per bitness: there is no directory page
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT}"
VIAddVersionKey "FileDescription" "${PRODUCT} ODBC driver setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Peter Lemenkov and the SeerODBC contributors, Apache-2.0"

!define MUI_ABORTWARNING
!define MUI_COMPONENTSPAGE_SMALLDESC
!insertmacro MUI_PAGE_LICENSE "${TOPDIR}\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Register the driver in DIR with the ODBC Driver Manager, in the registry view
; already selected (SetRegView): the same values as register.cmd. The driver
; is its own setup DLL (ConfigDSN, for the ODBC Data Source Administrator).
!macro RegisterDriver DIR
  WriteRegStr HKLM "${INST}\ODBC Drivers" "${PRODUCT}" "Installed"
  WriteRegStr HKLM "${INST}\${PRODUCT}" "Driver" "${DIR}\seerodbc.dll"
  WriteRegStr HKLM "${INST}\${PRODUCT}" "Setup" "${DIR}\seerodbc.dll"
  WriteRegStr HKLM "${INST}\${PRODUCT}" "APILevel" "1"
  WriteRegStr HKLM "${INST}\${PRODUCT}" "ConnectFunctions" "YYN"
  WriteRegStr HKLM "${INST}\${PRODUCT}" "DriverODBCVer" "03.80"
  WriteRegStr HKLM "${INST}\${PRODUCT}" "FileUsage" "0"
  WriteRegStr HKLM "${INST}\${PRODUCT}" "SQLLevel" "1"
  WriteRegDWORD HKLM "${INST}\${PRODUCT}" "UsageCount" 1
!macroend

; Unregister it from the registry view already selected. Data sources (DSNs)
; are the user's and stay, as with register.cmd /remove.
!macro UnregisterDriver
  DeleteRegKey HKLM "${INST}\${PRODUCT}"
  DeleteRegValue HKLM "${INST}\ODBC Drivers" "${PRODUCT}"
!macroend

Section "64-bit driver" SecX64
  SetOutPath "${DIR64}"
  File /r "${X64DIR}\*"
  SetRegView 64
  !insertmacro RegisterDriver "${DIR64}"
  SetRegView default
  DetailPrint "Registered the 64-bit driver: ${DIR64}\seerodbc.dll"
SectionEnd

Section "32-bit driver" SecX86
  SetOutPath "${DIR32}"
  File /r "${X86DIR}\*"
  SetRegView 32
  !insertmacro RegisterDriver "${DIR32}"
  SetRegView default
  DetailPrint "Registered the 32-bit driver: ${DIR32}\seerodbc.dll"
SectionEnd

; The uninstaller lives next to the 64-bit driver when there is one.
Section "-uninstaller"
  ${IfNot} ${SectionIsSelected} ${SecX64}
  ${AndIfNot} ${SectionIsSelected} ${SecX86}
    Abort "Nothing to install: select at least one driver."
  ${EndIf}
  ${If} ${SectionIsSelected} ${SecX64}
    StrCpy $INSTDIR "${DIR64}"
  ${Else}
    StrCpy $INSTDIR "${DIR32}"
  ${EndIf}
  WriteUninstaller "$INSTDIR\uninstall.exe"
  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}
  WriteRegStr HKLM "${UNINST}" "DisplayName" "${PRODUCT} ${VERSION} (ODBC driver)"
  WriteRegStr HKLM "${UNINST}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST}" "Publisher" "The SeerODBC contributors"
  WriteRegStr HKLM "${UNINST}" "URLInfoAbout" "https://github.com/seerdb/SeerODBC"
  WriteRegStr HKLM "${UNINST}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST}" "NoRepair" 1
  SetRegView default
SectionEnd

LangString DESC_X64 ${LANG_ENGLISH} "For 64-bit applications. Installed in ${DIR64}."
LangString DESC_X86 ${LANG_ENGLISH} "For 32-bit applications (32-bit Office, older BI tools). Installed in ${DIR32}."
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecX64} $(DESC_X64)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecX86} $(DESC_X86)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function .onInit
  ${IfNot} ${RunningX64} ; 32-bit Windows: no 64-bit driver to offer
    !insertmacro UnselectSection ${SecX64}
    SectionSetFlags ${SecX64} ${SF_RO}
    SectionSetText ${SecX64} ""
    StrCpy $INSTDIR "${DIR32}"
  ${EndIf}
FunctionEnd

Section "Uninstall"
  ${If} ${RunningX64}
    SetRegView 64
    !insertmacro UnregisterDriver
    DeleteRegKey HKLM "${UNINST}"
  ${EndIf}
  SetRegView 32
  !insertmacro UnregisterDriver
  DeleteRegKey HKLM "${UNINST}" ; a 32-bit Windows install keeps it here
  SetRegView default
  ; Each folder holds exactly what this installer put there.
  ${If} ${RunningX64}
    RMDir /r "${DIR64}"
  ${EndIf}
  RMDir /r "${DIR32}"
SectionEnd
