#!/usr/bin/env python3
"""
MediVote Professional Installer Builder (Robust Version)
Creates a professional installer with executable, desktop shortcuts, and all dependencies.
This version includes fixes for common DLL loading issues.
"""

import os
import sys
import platform
import subprocess
import shutil
from pathlib import Path

def print_status(message: str):
    """Prints a status message."""
    print(f"[INFO] {message}")

def print_error(message: str):
    """Prints an error message."""
    print(f"[ERROR] {message}")

def clean_previous_builds():
    """Removes old build artifacts to ensure a clean slate."""
    print_status("Cleaning up previous build artifacts...")
    for folder in ["build", "dist", "installer"]:
        if os.path.exists(folder):
            shutil.rmtree(folder)
            print_status(f"Removed folder: {folder}")
    if os.path.exists("MediVote.spec"):
        os.remove("MediVote.spec")
        print_status("Removed file: MediVote.spec")

def build_executable():
    """Build the executable using PyInstaller with explicit paths."""
    print_status("Building executable with PyInstaller...")

    python_path = Path(sys.executable).parent.parent
    lib_path = python_path / "Lib"

    if not lib_path.exists():
        print_error(f"Could not find Python Lib directory at: {lib_path}")
        return False

    pyinstaller_command = [
        "pyinstaller",
        "--clean",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name", "MediVote",
        "--icon", os.path.join("assets", "medivote_icon.ico"),
        "--add-data", f"{os.path.join('backend')}{os.pathsep}backend",
        "--add-data", f"{os.path.join('frontend')}{os.pathsep}frontend",
        "--add-data", f"{os.path.join('assets')}{os.pathsep}assets",
        # --- THIS LINE HAS BEEN REMOVED ---
        # "--add-data", f".env{os.pathsep}.", 
        "--paths", str(lib_path),
        "--hidden-import", "uvicorn.lifespan.on",
        "--hidden-import", "uvicorn.loops.auto",
        "--hidden-import", "uvicorn.protocols.http.auto",
        "medivote_main.py",
    ]

    print_status(f"Running command: {' '.join(pyinstaller_command)}")

    try:
        process = subprocess.Popen(pyinstaller_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print_error("PyInstaller failed.")
            print_error(f"STDOUT:\n{stdout}")
            print_error(f"STDERR:\n{stderr}")
            return False
        
        print_status("Executable built successfully in 'dist' folder.")
        return True

    except Exception as e:
        print_error(f"An error occurred while building the executable: {e}")
        return False

def main():
    """Main build process."""
    if platform.system() != "Windows":
        print_error("This build script is configured for Windows.")
        sys.exit(1)
        
    clean_previous_builds()
    
    if not build_executable():
        sys.exit(1)
        
    print("\n[NEXT STEP] Run 'python create_msi_installer.py' to create the final setup file.")

if __name__ == "__main__":
    main()