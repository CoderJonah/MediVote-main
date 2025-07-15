
; MediVote Windows Installer
; Professional installer for MediVote application

!define APPNAME "MediVote"
!define COMPANYNAME "The Median"
!define DESCRIPTION "Secure Blockchain-Based Voting System"
!define VERSIONMAJOR 1
!define VERSIONMINOR 0
!define VERSIONBUILD 0
!define HELPURL "https://github.com/the-median/medivote"
!define UPDATEURL "https://github.com/the-median/medivote/releases"
!define ABOUTURL "https://themedian.org"
!define INSTALLSIZE 50000

RequestExecutionLevel admin
InstallDir "$PROGRAMFILES\${APPNAME}"
Name "${APPNAME}"
Icon "assets\medivote_icon.ico"
outFile "MediVote-Setup.exe"

!include LogicLib.nsh

page components
page directory
page instfiles

!macro VerifyUserIsAdmin
UserInfo::GetAccountType
pop $0
${If} $0 != "admin"
    messageBox mb_iconstop "Administrator rights required!"
    setErrorLevel 740
    quit
${EndIf}
!macroend

function .onInit
    setShellVarContext all
    !insertmacro VerifyUserIsAdmin
functionEnd

section "MediVote Application" SecApp
    setOutPath $INSTDIR
    
    ; Main executable
    file "dist\MediVote.exe"
    
    ; Assets
    file /r "assets"
    
    ; Configuration
    file ".env"
    file "requirements.txt"
    
    ; Create desktop shortcut
    createShortCut "$DESKTOP\MediVote.lnk" "$INSTDIR\MediVote.exe" "" "$INSTDIR\assets\medivote_icon.ico"
    
    ; Create start menu shortcuts
    createDirectory "$SMPROGRAMS\${APPNAME}"
    createShortCut "$SMPROGRAMS\${APPNAME}\MediVote.lnk" "$INSTDIR\MediVote.exe" "" "$INSTDIR\assets\medivote_icon.ico"
    createShortCut "$SMPROGRAMS\${APPNAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"
    
    ; Registry information for add/remove programs
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME} - ${DESCRIPTION}"
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "InstallLocation" "$\"$INSTDIR$\""
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayIcon" "$\"$INSTDIR\assets\medivote_icon.ico$\""
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${COMPANYNAME}"
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "HelpLink" "${HELPURL}"
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "URLUpdateInfo" "${UPDATEURL}"
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "URLInfoAbout" "${ABOUTURL}"
    writeRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}"
    writeRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "VersionMajor" ${VERSIONMAJOR}
    writeRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "VersionMinor" ${VERSIONMINOR}
    writeRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoModify" 1
    writeRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoRepair" 1
    writeRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "EstimatedSize" ${INSTALLSIZE}
    
    ; Create uninstaller
    writeUninstaller "$INSTDIR\uninstall.exe"
    
sectionEnd

section "Python Runtime" SecPython
    ; Download and install Python if not present
    nsExec::ExecToLog 'powershell -Command "if (!(Get-Command python -ErrorAction SilentlyContinue)) { Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.11.7/python-3.11.7-amd64.exe -OutFile $env:TEMP\python-installer.exe; Start-Process -FilePath $env:TEMP\python-installer.exe -ArgumentList /quiet,InstallAllUsers=1,PrependPath=1 -Wait }"'
sectionEnd

section "Uninstall"
    ; Remove shortcuts
    delete "$DESKTOP\MediVote.lnk"
    delete "$SMPROGRAMS\${APPNAME}\MediVote.lnk"
    delete "$SMPROGRAMS\${APPNAME}\Uninstall.lnk"
    rmDir "$SMPROGRAMS\${APPNAME}"
    
    ; Remove files
    delete "$INSTDIR\MediVote.exe"
    delete "$INSTDIR\uninstall.exe"
    delete "$INSTDIR\.env"
    delete "$INSTDIR\requirements.txt"
    rmDir /r "$INSTDIR\assets"
    rmDir "$INSTDIR"
    
    ; Remove registry entries
    deleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
sectionEnd
