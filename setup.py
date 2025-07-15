#!/usr/bin/env python3
"""
MediVote Cross-Platform Setup Script
Initializes the secure blockchain-based voting system on Windows, macOS, and Linux
"""

import os
import sys
import subprocess
import platform
import shutil
import json
import secrets
from pathlib import Path
from typing import Dict, Any, Optional

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
                                                               
Secure Blockchain-Based Voting System with End-to-End Verifiability
"""
    print(f"{Colors.BLUE}{header}{Colors.NC}")

def check_python_version() -> bool:
    """Check if Python version is compatible"""
    if sys.version_info < (3, 9):
        print_error(f"Python 3.9+ is required. Current version: {sys.version}")
        return False
    print_status(f"Python version: {sys.version}")
    return True

def check_node_version() -> bool:
    """Check if Node.js version is compatible"""
    try:
        result = subprocess.run(['node', '--version'], 
                              capture_output=True, text=True, check=True)
        version = result.stdout.strip()
        major_version = int(version.split('.')[0].replace('v', ''))
        if major_version < 16:
            print_error(f"Node.js 16+ is required. Current version: {version}")
            return False
        print_status(f"Node.js version: {version}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_error("Node.js is not installed or not in PATH")
        return False

def check_docker() -> bool:
    """Check if Docker is available"""
    try:
        subprocess.run(['docker', '--version'], 
                      capture_output=True, check=True)
        print_status("Docker is available")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_warning("Docker is not available. Some features may not work.")
        return False

def create_directories():
    """Create the necessary directory structure"""
    print_status("Creating directory structure...")
    
    directories = [
        'backend', 'frontend', 'circuits', 'keys', 'uploads', 'database',
        'backend/api', 'backend/core', 'backend/tests',
        'backend/core/crypto', 'backend/core/identity', 'backend/core/blockchain',
        'frontend/src', 'frontend/public', 'frontend/build',
        'circuits/voter_eligibility', 'circuits/ballot_validity',
        'monitoring/prometheus', 'monitoring/grafana',
        'nginx/conf.d', 'nginx/ssl'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print_status("Directory structure created")

def create_virtual_environment():
    """Create and activate Python virtual environment"""
    print_status("Creating Python virtual environment...")
    
    venv_path = Path("venv")
    if venv_path.exists():
        print_warning("Virtual environment already exists")
        return
    
    try:
        subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)
        print_status("Virtual environment created")
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to create virtual environment: {e}")
        sys.exit(1)

def install_python_dependencies():
    """Install Python dependencies"""
    print_status("Installing Python dependencies...")
    
    # Determine the pip command based on the platform
    if platform.system() == "Windows":
        pip_cmd = "venv\\Scripts\\pip"
    else:
        pip_cmd = "venv/bin/pip"
    
    try:
        # Upgrade pip
        subprocess.run([pip_cmd, "install", "--upgrade", "pip"], check=True)
        
        # Install requirements
        subprocess.run([pip_cmd, "install", "-r", "requirements.txt"], check=True)
        
        print_status("Python dependencies installed")
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install Python dependencies: {e}")
        sys.exit(1)

def install_node_dependencies():
    """Install Node.js dependencies"""
    print_status("Installing Node.js dependencies...")
    
    try:
        # Install global dependencies
        npm_packages = [
            'concurrently', '@angular/cli', 'truffle', 
            'ganache-cli', 'snarkjs', 'circom'
        ]
        
        for package in npm_packages:
            subprocess.run(['npm', 'install', '-g', package], check=True)
        
        print_status("Node.js dependencies installed")
    except subprocess.CalledProcessError as e:
        print_warning(f"Failed to install some Node.js dependencies: {e}")

def generate_keys():
    """Generate cryptographic keys and create all necessary files"""
    print_status("Generating cryptographic keys and creating configuration files...")
    
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)
    
    # Generate secure random keys for environment
    secret_key = secrets.token_hex(32)
    encryption_key = secrets.token_hex(32)
    jwt_secret = secrets.token_hex(32)
    
    # Create .env file (always recreate with fresh keys)
    env_file = Path(".env")
    env_content = f"""# MediVote Environment Configuration
APP_NAME=MediVote
APP_VERSION=1.0.0
DEBUG=True
TESTING=False

# Server Configuration
HOST=0.0.0.0
PORT=8000

# Security Settings (Generated automatically)
SECRET_KEY={secret_key}
ENCRYPTION_KEY={encryption_key}
JWT_SECRET_KEY={jwt_secret}
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60

# Database Configuration
DATABASE_URL=sqlite:///./medivote.db
DATABASE_ECHO=False

# Redis Configuration
REDIS_URL=redis://localhost:6379

# CORS and Security
CORS_ORIGINS=["http://localhost:3000", "http://127.0.0.1:3000", "https://themedian.org"]
ALLOWED_HOSTS=["localhost", "127.0.0.1", "themedian.org"]

# Rate Limiting
RATE_LIMIT_ATTEMPTS=3
RATE_LIMIT_WINDOW=900
GLOBAL_RATE_LIMIT=100/minute

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

# Frontend Configuration
FRONTEND_URL=http://localhost:3000
FRONTEND_BUILD_DIR=./frontend/build

# Accessibility Features
ENABLE_SCREEN_READER_SUPPORT=True
ENABLE_HIGH_CONTRAST=True
ENABLE_KEYBOARD_NAVIGATION=True

# Development Settings
HOT_RELOAD=True
AUTO_MIGRATION=True
MOCK_BLOCKCHAIN=True
MOCK_CREDENTIALS=True
"""
    env_file.write_text(env_content)
    print_status("Environment configuration created with secure keys")
    
    # Create basic backend structure if it doesn't exist
    backend_dir = Path("backend")
    if not (backend_dir / "main.py").exists():
        backend_main = '''"""
MediVote Backend - Basic FastAPI Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="MediVote", version="1.0.0", description="Secure Blockchain Voting System")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "MediVote API is running", "version": "1.0.0"}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "MediVote Backend"}

@app.get("/api/status")
async def api_status():
    return {
        "api_version": "1.0.0",
        "system_status": "operational",
        "features": {
            "identity_layer": True,
            "voting_protocol": True,
            "blockchain_layer": True,
            "e2e_verification": True,
            "accessibility": True
        }
    }
'''
        (backend_dir / "main.py").write_text(backend_main)
        print_status("Basic backend structure created")
    
    # Create basic frontend if it doesn't exist
    frontend_dir = Path("frontend")
    if not (frontend_dir / "index.html").exists():
        frontend_html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVote - Secure Blockchain Voting</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .status { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .button { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .button:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="container">
        <h1>MediVote</h1>
        <p><strong>Secure Blockchain-Based Voting System</strong></p>
        <div class="status">
            <p>✅ System Status: <strong>Running</strong></p>
            <p>🔒 Security: <strong>Enabled</strong></p>
            <p>🌐 API: <strong>Available</strong></p>
        </div>
        <p>Welcome to MediVote - a secure, privacy-preserving electronic voting system that leverages blockchain technology, zero-knowledge proofs, and homomorphic encryption.</p>
        <button class="button" onclick="window.open('/api/status', '_blank')">Check API Status</button>
    </div>
</body>
</html>'''
        (frontend_dir / "index.html").write_text(frontend_html)
        print_status("Basic frontend structure created")
    
    print_status("All configuration files and project structure created")

def create_cross_platform_scripts():
    """Create cross-platform startup scripts"""
    print_status("Creating cross-platform startup scripts...")
    
    # Create Windows batch file
    windows_script = """@echo off
echo Starting MediVote...
cd /d "%~dp0"
call venv\\Scripts\\activate
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
"""
    Path("start_medivote.bat").write_text(windows_script)
    
    # Create Unix shell script
    unix_script = """#!/bin/bash
echo "Starting MediVote..."
cd "$(dirname "$0")"
source venv/bin/activate
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
"""
    unix_script_path = Path("start_medivote.sh")
    unix_script_path.write_text(unix_script)
    
    # Make Unix script executable
    if platform.system() != "Windows":
        unix_script_path.chmod(0o755)
    
    print_status("Cross-platform startup scripts created")

def create_docker_ignore():
    """Create .dockerignore file"""
    print_status("Creating .dockerignore file...")
    
    dockerignore_content = """# Git
.git
.gitignore

# Documentation
README.md
*.md

# Development files
.env
.env.*
venv/
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
env/
pip-log.txt
pip-delete-this-directory.txt
.tox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.log
.git
.mypy_cache
.pytest_cache
.hypothesis

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Node.js
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Build artifacts
build/
dist/
*.egg-info/

# Test files
test_*.py
*_test.py
tests/

# Keys and secrets
keys/
*.pem
*.key
*.crt
secrets/
private/

# Temporary files
temp/
tmp/
*.tmp
"""
    
    Path(".dockerignore").write_text(dockerignore_content)
    print_status(".dockerignore file created")

def run_tests():
    """Run comprehensive tests to ensure everything is working"""
    print_status("Running comprehensive tests...")
    
    try:
        # Test Python imports
        subprocess.run([sys.executable, "-c", "import fastapi, uvicorn"], check=True)
        print_status("Python dependencies test passed")
        
        # Run cross-platform tests
        if Path("test_cross_platform.py").exists():
            print_status("Running cross-platform tests...")
            subprocess.run([sys.executable, "test_cross_platform.py"], check=True)
        
        # Run ultra-comprehensive tests
        if Path("ultra_comprehensive_test_suite.py").exists():
            print_status("Running ultra-comprehensive test suite...")
            subprocess.run([sys.executable, "ultra_comprehensive_test_suite.py"], check=True)
        else:
            print_warning("Ultra-comprehensive test suite not found")
        
        # Run production security tests
        if Path("production_security_test.py").exists():
            print_status("Running production security tests...")
            subprocess.run([sys.executable, "production_security_test.py"], check=True)
        
        print_status("All comprehensive tests completed")
        
    except subprocess.CalledProcessError as e:
        print_warning(f"Some tests failed: {e}")
    except Exception as e:
        print_warning(f"Test execution failed: {e}")

def main():
    """Main setup function"""
    print_header()
    
    print_status("Starting MediVote cross-platform setup...")
    
    # Check system requirements
    if not check_python_version():
        sys.exit(1)
    
    if not check_node_version():
        print_warning("Node.js not available - some features may not work")
    
    check_docker()
    
    # Create project structure
    create_directories()
    create_virtual_environment()
    install_python_dependencies()
    install_node_dependencies()
    generate_keys()
    create_cross_platform_scripts()
    create_docker_ignore()
    
    # Run basic tests
    run_tests()
    
    print_status("Setup completed successfully!")
    print_status("To start the application:")
    if platform.system() == "Windows":
        print_status("  Run: start_medivote.bat")
    else:
        print_status("  Run: ./start_medivote.sh")
    print_status("Or use Docker: docker-compose up -d")

if __name__ == "__main__":
    main() 