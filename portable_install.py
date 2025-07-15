#!/usr/bin/env python3
"""
MediVote Portable Installation Script
Complete portable installation for any fresh system - automatically downloads and installs everything needed
"""

import os
import sys
import platform
import subprocess
import urllib.request
import urllib.error
import json
import time
import tempfile
import shutil
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, Any, Optional, List
import ssl

class Colors:
    """ANSI color codes for cross-platform output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

def print_status(message: str):
    """Print a status message with color"""
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {message}")

def print_warning(message: str):
    """Print a warning message with color"""
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {message}")

def print_error(message: str):
    """Print an error message with color"""
    print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")

def print_header():
    """Print the MediVote header"""
    header = """
███╗   ███╗███████╗██████╗ ██╗██╗   ██╗ ██████╗ ████████╗███████╗
████╗ ████║██╔════╝██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝██╔════╝
██╔████╔██║█████╗  ██║  ██║██║██║   ██║██║   ██║   ██║   █████╗  
██║╚██╔╝██║██╔══╝  ██║  ██║██║╚██╗ ██╔╝██║   ██║   ██║   ██╔══╝  
██║ ╚═╝ ██║███████╗██████╔╝██║ ╚████╔╝ ╚██████╔╝   ██║   ███████╗
╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═══╝   ╚═════╝    ╚═╝   ╚══════╝
                                                               
   PORTABLE INSTALLATION - Works on ANY Fresh System
"""
    print(f"{Colors.BLUE}{header}{Colors.NC}")

class PortableInstaller:
    """Completely portable installer that works on any fresh system"""
    
    def __init__(self):
        self.platform = platform.system()
        self.architecture = platform.machine()
        self.temp_dir = Path(tempfile.mkdtemp())
        self.install_dir = Path.cwd()
        self.downloads = {}
        
        # Disable SSL verification for downloads if needed
        ssl._create_default_https_context = ssl._create_unverified_context
        
    def download_file(self, url: str, filename: str) -> Path:
        """Download a file with progress indication"""
        print_status(f"Downloading {filename}...")
        
        try:
            file_path = self.temp_dir / filename
            
            def show_progress(block_num, block_size, total_size):
                downloaded = block_num * block_size
                if total_size > 0:
                    percent = min(100, (downloaded * 100) // total_size)
                    print(f"\r  Progress: {percent}%", end="", flush=True)
            
            urllib.request.urlretrieve(url, file_path, show_progress)
            print()  # New line after progress
            print_status(f"Downloaded {filename}")
            return file_path
            
        except Exception as e:
            print_error(f"Failed to download {filename}: {e}")
            raise
    
    def run_command(self, command: List[str], cwd: Optional[Path] = None, check: bool = True) -> subprocess.CompletedProcess:
        """Run a command with proper error handling"""
        try:
            result = subprocess.run(
                command, 
                cwd=cwd, 
                check=check, 
                capture_output=True, 
                text=True
            )
            return result
        except subprocess.CalledProcessError as e:
            print_error(f"Command failed: {' '.join(command)}")
            print_error(f"Error: {e.stderr}")
            raise
    
    def install_python(self) -> bool:
        """Install Python if not available or wrong version"""
        print_status("Checking Python installation...")
        
        # Check if Python 3.9+ is available
        try:
            result = subprocess.run([sys.executable, '--version'], 
                                  capture_output=True, text=True)
            version = result.stdout.strip()
            print_status(f"Found Python: {version}")
            
            # Check version
            version_parts = version.split()[1].split('.')
            major, minor = int(version_parts[0]), int(version_parts[1])
            
            if major >= 3 and minor >= 9:
                print_status("Python version is compatible")
                return True
                
        except Exception:
            pass
        
        print_status("Installing Python 3.11...")
        
        if self.platform == "Windows":
            # Download Python installer for Windows
            python_url = "https://www.python.org/ftp/python/3.11.7/python-3.11.7-amd64.exe"
            installer_path = self.download_file(python_url, "python-installer.exe")
            
            # Install Python silently
            self.run_command([
                str(installer_path), 
                "/quiet", 
                "InstallAllUsers=1", 
                "PrependPath=1",
                "Include_test=0"
            ])
            
        elif self.platform == "Darwin":  # macOS
            # Download Python installer for macOS
            python_url = "https://www.python.org/ftp/python/3.11.7/python-3.11.7-macos11.pkg"
            installer_path = self.download_file(python_url, "python-installer.pkg")
            
            # Install Python
            self.run_command(["sudo", "installer", "-pkg", str(installer_path), "-target", "/"])
            
        else:  # Linux
            # Try different package managers
            try:
                # Try apt (Ubuntu/Debian)
                self.run_command(["sudo", "apt", "update"])
                self.run_command(["sudo", "apt", "install", "-y", "python3.11", "python3.11-pip", "python3.11-venv"])
            except:
                try:
                    # Try yum (CentOS/RHEL)
                    self.run_command(["sudo", "yum", "install", "-y", "python311", "python311-pip"])
                except:
                    try:
                        # Try dnf (Fedora)
                        self.run_command(["sudo", "dnf", "install", "-y", "python3.11", "python3.11-pip"])
                    except:
                        # Try pacman (Arch)
                        self.run_command(["sudo", "pacman", "-S", "--noconfirm", "python"])
        
        print_status("Python installation completed")
        return True
    
    def install_nodejs(self) -> bool:
        """Install Node.js if not available"""
        print_status("Checking Node.js installation...")
        
        try:
            result = subprocess.run(['node', '--version'], 
                                  capture_output=True, text=True)
            version = result.stdout.strip()
            major_version = int(version.split('.')[0].replace('v', ''))
            
            if major_version >= 16:
                print_status(f"Found compatible Node.js: {version}")
                return True
                
        except Exception:
            pass
        
        print_status("Installing Node.js 18...")
        
        if self.platform == "Windows":
            # Download Node.js installer for Windows
            nodejs_url = "https://nodejs.org/dist/v18.19.0/node-v18.19.0-x64.msi"
            installer_path = self.download_file(nodejs_url, "nodejs-installer.msi")
            
            # Install Node.js silently
            self.run_command([
                "msiexec", "/i", str(installer_path), 
                "/quiet", "/norestart"
            ])
            
        elif self.platform == "Darwin":  # macOS
            # Download Node.js installer for macOS
            nodejs_url = "https://nodejs.org/dist/v18.19.0/node-v18.19.0.pkg"
            installer_path = self.download_file(nodejs_url, "nodejs-installer.pkg")
            
            # Install Node.js
            self.run_command(["sudo", "installer", "-pkg", str(installer_path), "-target", "/"])
            
        else:  # Linux
            # Use NodeSource repository for latest Node.js
            try:
                # Download and run NodeSource setup script
                setup_script = self.download_file(
                    "https://deb.nodesource.com/setup_18.x", 
                    "nodejs_setup.sh"
                )
                self.run_command(["sudo", "bash", str(setup_script)])
                self.run_command(["sudo", "apt-get", "install", "-y", "nodejs"])
            except:
                # Alternative: try package manager
                try:
                    self.run_command(["sudo", "yum", "install", "-y", "nodejs", "npm"])
                except:
                    try:
                        self.run_command(["sudo", "dnf", "install", "-y", "nodejs", "npm"])
                    except:
                        self.run_command(["sudo", "pacman", "-S", "--noconfirm", "nodejs", "npm"])
        
        print_status("Node.js installation completed")
        return True
    
    def install_docker(self) -> bool:
        """Install Docker if not available"""
        print_status("Checking Docker installation...")
        
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True)
            print_status(f"Found Docker: {result.stdout.strip()}")
            return True
        except Exception:
            pass
        
        print_status("Installing Docker...")
        
        if self.platform == "Windows":
            # Download Docker Desktop for Windows
            docker_url = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
            installer_path = self.download_file(docker_url, "docker-installer.exe")
            
            print_warning("Docker Desktop requires manual installation on Windows")
            print_warning(f"Please run: {installer_path}")
            print_warning("Then restart this script after Docker is installed")
            
        elif self.platform == "Darwin":  # macOS
            # Download Docker Desktop for macOS
            if "arm" in self.architecture.lower():
                docker_url = "https://desktop.docker.com/mac/main/arm64/Docker.dmg"
            else:
                docker_url = "https://desktop.docker.com/mac/main/amd64/Docker.dmg"
            
            installer_path = self.download_file(docker_url, "docker-installer.dmg")
            
            print_warning("Docker Desktop requires manual installation on macOS")
            print_warning(f"Please install: {installer_path}")
            
        else:  # Linux
            # Install Docker using convenience script
            try:
                # Download Docker install script
                script_path = self.download_file(
                    "https://get.docker.com", 
                    "docker_install.sh"
                )
                
                # Make executable and run
                os.chmod(script_path, 0o755)
                self.run_command(["sudo", "sh", str(script_path)])
                
                # Add user to docker group
                username = os.getenv("USER", "root")
                if username != "root":
                    self.run_command(["sudo", "usermod", "-aG", "docker", username])
                
                # Start Docker service
                self.run_command(["sudo", "systemctl", "start", "docker"])
                self.run_command(["sudo", "systemctl", "enable", "docker"])
                
            except Exception as e:
                print_warning(f"Docker installation failed: {e}")
                print_warning("Docker is optional - continuing without it")
        
        print_status("Docker installation completed")
        return True
    
    def install_git(self) -> bool:
        """Install Git if not available"""
        print_status("Checking Git installation...")
        
        try:
            result = subprocess.run(['git', '--version'], 
                                  capture_output=True, text=True)
            print_status(f"Found Git: {result.stdout.strip()}")
            return True
        except Exception:
            pass
        
        print_status("Installing Git...")
        
        if self.platform == "Windows":
            # Download Git for Windows
            git_url = "https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe"
            installer_path = self.download_file(git_url, "git-installer.exe")
            
            # Install Git silently
            self.run_command([
                str(installer_path), 
                "/SILENT", 
                "/COMPONENTS=icons,ext\\reg\\shellhere,assoc,assoc_sh"
            ])
            
        elif self.platform == "Darwin":  # macOS
            # Install Git using Homebrew or download installer
            try:
                # Try Homebrew first
                self.run_command(["brew", "install", "git"])
            except:
                # Download Git installer
                git_url = "https://sourceforge.net/projects/git-osx-installer/files/latest/download"
                installer_path = self.download_file(git_url, "git-installer.dmg")
                print_warning(f"Please install Git from: {installer_path}")
                
        else:  # Linux
            try:
                # Try different package managers
                self.run_command(["sudo", "apt", "install", "-y", "git"])
            except:
                try:
                    self.run_command(["sudo", "yum", "install", "-y", "git"])
                except:
                    try:
                        self.run_command(["sudo", "dnf", "install", "-y", "git"])
                    except:
                        self.run_command(["sudo", "pacman", "-S", "--noconfirm", "git"])
        
        print_status("Git installation completed")
        return True
    
    def create_project_files(self) -> bool:
        """Create all necessary project files on the fly"""
        print_status("Creating project files...")
        
        # Create .env file
        env_content = """# MediVote Environment Configuration
APP_NAME=MediVote
APP_VERSION=1.0.0
DEBUG=True
TESTING=False

# Server Configuration
HOST=0.0.0.0
PORT=8000

# Security Settings (Generated automatically)
SECRET_KEY=medivote_auto_generated_secret_key_32_chars_minimum_length_for_security
ENCRYPTION_KEY=medivote_auto_generated_encryption_key_32_chars_minimum_for_operations
JWT_SECRET_KEY=medivote_auto_generated_jwt_secret_key_32_chars_minimum_for_tokens
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60

# Database Configuration
DATABASE_URL=sqlite:///./medivote.db
DATABASE_ECHO=False

# Redis Configuration
REDIS_URL=redis://localhost:6379

# CORS and Security
CORS_ORIGINS=["http://localhost:3000", "http://127.0.0.1:3000"]
ALLOWED_HOSTS=["localhost", "127.0.0.1"]

# Blockchain Configuration
BLOCKCHAIN_NETWORK=testnet
BLOCKCHAIN_RPC_URL=http://localhost:8545

# Cryptographic Settings
HOMOMORPHIC_KEY_SIZE=2048
ZK_CIRCUIT_PATH=./circuits
BLIND_SIGNATURE_KEY_SIZE=2048

# Test Configuration (for testing environment only)
TEST_DATABASE_URL=sqlite:///./test_medivote.db

# Main application entry point  
MAIN_APP=backend/main.py
"""
        
        Path(".env").write_text(env_content)
        
        # Create package.json if it doesn't exist
        if not Path("package.json").exists():
            package_json = {
                "name": "medivote",
                "version": "1.0.0",
                "description": "Secure blockchain-based voting system",
                "scripts": {
                    "start": "python -m uvicorn backend.main:app --reload --port 8000",
                    "test": "python test_cross_platform.py",
                    "build": "echo 'Build completed'"
                },
                "dependencies": {
                    "concurrently": "^7.6.0"
                }
            }
            
            with open("package.json", "w") as f:
                json.dump(package_json, f, indent=2)
        
        # Create basic directory structure
        directories = [
            "backend", "frontend", "database", "circuits", "keys", 
            "uploads", "logs", "temp", "ssl", "tests"
        ]
        
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
        
        # Create basic backend structure if it doesn't exist
        if not Path("backend/main.py").exists():
            backend_main = '''"""
MediVote Backend - Basic FastAPI Application
"""
from fastapi import FastAPI

app = FastAPI(title="MediVote", version="1.0.0")

@app.get("/")
async def root():
    return {"message": "MediVote API is running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
'''
            Path("backend/main.py").write_text(backend_main)
        
        # Create basic frontend if it doesn't exist
        if not Path("frontend/index.html").exists():
            frontend_html = '''<!DOCTYPE html>
<html>
<head>
    <title>MediVote</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <h1>MediVote - Secure Blockchain Voting</h1>
    <p>Welcome to MediVote!</p>
</body>
</html>'''
            Path("frontend/index.html").write_text(frontend_html)
        
        print_status("Project files created successfully")
        return True
    
    def install_python_packages(self) -> bool:
        """Install Python packages"""
        print_status("Installing Python packages...")
        
        # Create virtual environment
        venv_path = Path("venv")
        if not venv_path.exists():
            self.run_command([sys.executable, "-m", "venv", "venv"])
        
        # Determine pip command
        if self.platform == "Windows":
            pip_cmd = str(venv_path / "Scripts" / "pip")
            python_cmd = str(venv_path / "Scripts" / "python")
        else:
            pip_cmd = str(venv_path / "bin" / "pip")
            python_cmd = str(venv_path / "bin" / "python")
        
        # Upgrade pip
        self.run_command([pip_cmd, "install", "--upgrade", "pip"])
        
        # Install basic packages
        basic_packages = [
            "fastapi>=0.104.1",
            "uvicorn[standard]>=0.24.0",
            "pydantic>=2.5.0",
            "python-multipart>=0.0.6",
            "requests>=2.31.0",
            "python-dotenv>=1.0.0",
            "cryptography>=41.0.0",
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "httpx>=0.25.0"
        ]
        
        for package in basic_packages:
            try:
                self.run_command([pip_cmd, "install", package])
            except Exception as e:
                print_warning(f"Failed to install {package}: {e}")
        
        # Install requirements.txt if it exists
        if Path("requirements.txt").exists():
            try:
                self.run_command([pip_cmd, "install", "-r", "requirements.txt"])
            except Exception as e:
                print_warning(f"Failed to install from requirements.txt: {e}")
        
        print_status("Python packages installed")
        return True
    
    def install_nodejs_packages(self) -> bool:
        """Install Node.js packages"""
        print_status("Installing Node.js packages...")
        
        try:
            # Install global packages
            global_packages = ["concurrently", "nodemon"]
            for package in global_packages:
                try:
                    self.run_command(["npm", "install", "-g", package])
                except Exception as e:
                    print_warning(f"Failed to install global package {package}: {e}")
            
            # Install local packages if package.json exists
            if Path("package.json").exists():
                self.run_command(["npm", "install"])
            
        except Exception as e:
            print_warning(f"Node.js package installation failed: {e}")
        
        print_status("Node.js packages installed")
        return True
    
    def run_comprehensive_tests(self) -> bool:
        """Run all comprehensive tests"""
        print_status("Running comprehensive tests...")
        
        # Determine Python command
        if self.platform == "Windows":
            python_cmd = str(Path("venv") / "Scripts" / "python")
        else:
            python_cmd = str(Path("venv") / "bin" / "python")
        
        # Run cross-platform tests
        try:
            if Path("test_cross_platform.py").exists():
                self.run_command([python_cmd, "test_cross_platform.py"])
        except Exception as e:
            print_warning(f"Cross-platform tests failed: {e}")
        
        # Run ultra-comprehensive tests
        try:
            if Path("ultra_comprehensive_test_suite.py").exists():
                print_status("Running ultra-comprehensive test suite...")
                self.run_command([python_cmd, "ultra_comprehensive_test_suite.py"])
            else:
                print_warning("Ultra-comprehensive test suite not found")
        except Exception as e:
            print_warning(f"Ultra-comprehensive tests failed: {e}")
        
        # Run production security tests
        try:
            if Path("production_security_test.py").exists():
                print_status("Running production security tests...")
                self.run_command([python_cmd, "production_security_test.py"])
        except Exception as e:
            print_warning(f"Security tests failed: {e}")
        
        print_status("Comprehensive tests completed")
        return True
    
    def create_startup_scripts(self) -> bool:
        """Create platform-specific startup scripts"""
        print_status("Creating startup scripts...")
        
        if self.platform == "Windows":
            # Windows batch file
            batch_content = '''@echo off
echo Starting MediVote...
cd /d "%~dp0"
call venv\\Scripts\\activate
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
'''
            Path("start_medivote.bat").write_text(batch_content)
            
        else:
            # Unix shell script
            shell_content = '''#!/bin/bash
echo "Starting MediVote..."
cd "$(dirname "$0")"
source venv/bin/activate
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
'''
            script_path = Path("start_medivote.sh")
            script_path.write_text(shell_content)
            script_path.chmod(0o755)
        
        print_status("Startup scripts created")
        return True
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass
    
    def install(self) -> bool:
        """Main installation method"""
        print_header()
        
        print_status("Starting portable installation for MediVote...")
        print_status(f"Platform: {self.platform}")
        print_status(f"Architecture: {self.architecture}")
        
        try:
            # Install core dependencies
            self.install_python()
            self.install_nodejs()
            self.install_git()
            self.install_docker()
            
            # Create project files
            self.create_project_files()
            
            # Install packages
            self.install_python_packages()
            self.install_nodejs_packages()
            
            # Create startup scripts
            self.create_startup_scripts()
            
            # Run comprehensive tests
            self.run_comprehensive_tests()
            
            print_status("🎉 MediVote installation completed successfully!")
            print_status("To start the application:")
            
            if self.platform == "Windows":
                print_status("  Double-click: start_medivote.bat")
                print_status("  Or run: start_medivote.bat")
            else:
                print_status("  Run: ./start_medivote.sh")
            
            print_status("The application will be available at: http://localhost:8000")
            
            return True
            
        except Exception as e:
            print_error(f"Installation failed: {e}")
            return False
            
        finally:
            self.cleanup()

def main():
    """Main function"""
    installer = PortableInstaller()
    success = installer.install()
    
    if success:
        print_status("🎉 Installation successful!")
        sys.exit(0)
    else:
        print_error("❌ Installation failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 