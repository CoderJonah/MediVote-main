#!/usr/bin/env python3
"""
MediVote Professional Windows Installer Creator
Creates a professional installer using Inno Setup.
"""

import os
import sys
import subprocess
from pathlib import Path

def print_status(message: str):
    """Prints a status message."""
    print(f"[INFO] {message}")

def print_error(message: str):
    """Prints an error message."""
    print(f"[ERROR] {message}")

def create_inno_setup_script():
    """Create the Inno Setup script file (.iss)."""
    print_status("Creating Inno Setup script (medivote_installer.iss)...")

    # This script defines how the installer will look and behave.
    inno_script = '''
; MediVote Inno Setup Script
#define MyAppName "MediVote"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "The Median"
#define MyAppURL "https://themedian.org"
#define MyAppExeName "MediVote.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=installer
OutputBaseFilename=MediVote-Setup
SetupIconFile=assets\\medivote_icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}";

[Files]
Source: "dist\\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\\*"; DestDir: "{app}\\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
; --- THIS LINE HAS BEEN REMOVED ---
; Source: ".env"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"
Name: "{group}\\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\\{#MyAppName}"; Filename: "{app}\\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
    '''
    
    with open('medivote_installer.iss', 'w', encoding='utf-8') as f:
        f.write(inno_script)
    
    print_status("Inno Setup script created successfully.")

def build_installer():
    """Build the installer using the Inno Setup compiler."""
    print_status("Building installer with Inno Setup...")

    inno_setup_path = r"C:\Program Files (x86)\Inno Setup 6\iscc.exe"

    if not os.path.exists(inno_setup_path):
        print_error(f"Inno Setup compiler not found at '{inno_setup_path}'")
        print_error("Please ensure Inno Setup is installed to its default location.")
        return False

    try:
        result = subprocess.run(
            [inno_setup_path, 'medivote_installer.iss'],
            capture_output=True, text=True, check=True
        )
        print_status("Inno Setup compilation successful.")
        print(result.stdout)
        return True
    except FileNotFoundError:
        print_error("Could not run the Inno Setup compiler. Is it installed and accessible?")
        return False
    except subprocess.CalledProcessError as e:
        print_error("Inno Setup compilation failed.")
        print_error(f"Output:\n{e.stdout}\n{e.stderr}")
        return False

def main():
    """Main function to create the installer."""
    print("--- MediVote Installer Builder ---")

    if not Path("dist/MediVote.exe").exists():
        print_error("MediVote.exe not found in 'dist/' directory.")
        print_error("Please run 'python build_installer.py' first to create the executable.")
        return False
    
    create_inno_setup_script()

    if build_installer():
        print("\n🎉 Success! Installer created in the 'installer' directory.")
        return True
    else:
        print("\n❌ Failed to create the installer. Please check the errors above.")
        return False

if __name__ == "__main__":
    if main():
        sys.exit(0)
    else:
        sys.exit(1)