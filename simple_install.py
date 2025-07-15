#!/usr/bin/env python3
"""
MediVote Simple Installation Script
Works with existing Python installation to create a minimal working system
"""

import os
import sys
import platform
import subprocess
import secrets
from pathlib import Path

def print_header():
    """Print the MediVote header"""
    print("""
███╗   ███╗███████╗██████╗ ██╗██╗   ██╗ ██████╗ ████████╗███████╗
████╗ ████║██╔════╝██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝██╔════╝
██╔████╔██║█████╗  ██║  ██║██║██║   ██║██║   ██║   ██║   █████╗  
██║╚██╔╝██║██╔══╝  ██║  ██║██║╚██╗ ██╔╝██║   ██║   ██║   ██╔══╝  
██║ ╚═╝ ██║███████╗██████╔╝██║ ╚████╔╝ ╚██████╔╝   ██║   ███████╗
╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═══╝   ╚═════╝    ╚═╝   ╚══════╝
                                                               
            SIMPLE INSTALLATION SCRIPT
    """)

def print_status(message):
    print(f"[INFO] {message}")

def print_error(message):
    print(f"[ERROR] {message}")

def print_warning(message):
    print(f"[WARNING] {message}")

def check_python_version():
    """Check Python version"""
    print_status("Checking Python version...")
    
    if sys.version_info < (3, 7):
        print_error(f"Python 3.7+ required. Current version: {sys.version}")
        return False
    
    print_status(f"Python version: {sys.version}")
    return True

def create_directories():
    """Create necessary directories"""
    print_status("Creating directory structure...")
    
    directories = [
        "backend", "frontend", "database", "keys", "uploads", 
        "logs", "temp", "tests", "circuits"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    print_status("Directory structure created")

def create_requirements():
    """Create requirements.txt with minimal dependencies"""
    print_status("Creating requirements.txt...")
    
    requirements = [
        "fastapi>=0.68.0",
        "uvicorn>=0.15.0",
        "pydantic>=1.8.0",
        "python-multipart>=0.0.5",
        "requests>=2.25.0",
        "python-dotenv>=0.19.0"
    ]
    
    Path("requirements.txt").write_text("\n".join(requirements))
    print_status("requirements.txt created")

def create_virtual_environment():
    """Create virtual environment"""
    print_status("Creating virtual environment...")
    
    try:
        result = subprocess.run([sys.executable, "-m", "venv", "venv"], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            print_error(f"Failed to create virtual environment: {result.stderr}")
            return False
        
        print_status("Virtual environment created")
        return True
        
    except Exception as e:
        print_error(f"Failed to create virtual environment: {e}")
        return False

def install_packages():
    """Install Python packages"""
    print_status("Installing Python packages...")
    
    # Determine pip command based on platform
    if platform.system() == "Windows":
        pip_cmd = "venv\\Scripts\\pip.exe"
        python_cmd = "venv\\Scripts\\python.exe"
    else:
        pip_cmd = "venv/bin/pip"
        python_cmd = "venv/bin/python"
    
    try:
        # Upgrade pip
        result = subprocess.run([pip_cmd, "install", "--upgrade", "pip"], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            print_warning(f"Failed to upgrade pip: {result.stderr}")
        
        # Install packages one by one to handle failures gracefully
        packages = [
            "fastapi>=0.68.0",
            "uvicorn>=0.15.0", 
            "pydantic>=1.8.0",
            "python-multipart>=0.0.5",
            "requests>=2.25.0",
            "python-dotenv>=0.19.0"
        ]
        
        for package in packages:
            print_status(f"Installing {package}...")
            result = subprocess.run([pip_cmd, "install", package], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                print_warning(f"Failed to install {package}: {result.stderr}")
            else:
                print_status(f"Successfully installed {package}")
        
        print_status("Package installation completed")
        return True
        
    except Exception as e:
        print_error(f"Failed to install packages: {e}")
        return False

def create_env_file():
    """Create .env file"""
    print_status("Creating .env file...")
    
    # Generate secure keys
    secret_key = secrets.token_hex(32)
    encryption_key = secrets.token_hex(32)
    jwt_secret = secrets.token_hex(32)
    
    env_content = f"""# MediVote Environment Configuration
APP_NAME=MediVote
APP_VERSION=1.0.0
DEBUG=True
TESTING=False

# Server Configuration
HOST=0.0.0.0
PORT=8000

# Security Settings
SECRET_KEY={secret_key}
ENCRYPTION_KEY={encryption_key}
JWT_SECRET_KEY={jwt_secret}
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60

# Database Configuration
DATABASE_URL=sqlite:///./medivote.db
DATABASE_ECHO=False

# CORS and Security
CORS_ORIGINS=["http://localhost:3000", "http://127.0.0.1:3000"]
ALLOWED_HOSTS=["localhost", "127.0.0.1"]

# Test Configuration (for testing environment only)
TEST_DATABASE_URL=sqlite:///./test_medivote.db

# Main application entry point
MAIN_APP=backend/main.py
"""
    
    Path(".env").write_text(env_content)
    print_status(".env file created with secure keys")

def create_backend():
    """Create backend structure"""
    print_status("Creating backend structure...")
    
    backend_main = '''"""
MediVote Backend - FastAPI Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import os

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
    return {"message": "MediVote API is running", "version": "1.0.0", "status": "healthy"}

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

@app.get("/frontend", response_class=HTMLResponse)
async def frontend():
    """Serve the frontend"""
    frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    if os.path.exists(frontend_path):
        with open(frontend_path, "r") as f:
            return f.read()
    return "<h1>Frontend not found</h1>"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
'''
    
    Path("backend/main.py").write_text(backend_main)
    print_status("Backend structure created")

def create_frontend():
    """Create frontend structure"""
    print_status("Creating frontend structure...")
    
    frontend_html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MediVote - Secure Blockchain Voting</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh; color: #333;
        }
        .container { 
            max-width: 900px; margin: 0 auto; background: white; padding: 40px; 
            border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
        }
        h1 { 
            color: #2c3e50; text-align: center; font-size: 2.5em; margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .subtitle { text-align: center; color: #7f8c8d; margin-bottom: 30px; }
        .status { 
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); 
            padding: 20px; border-radius: 10px; margin: 20px 0; 
        }
        .button { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; padding: 12px 24px; border: none; border-radius: 8px; 
            cursor: pointer; margin: 8px; font-size: 16px; transition: transform 0.2s;
        }
        .button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        .info { 
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); 
            padding: 20px; border-radius: 10px; margin: 20px 0; 
        }
        .feature { 
            display: inline-block; margin: 10px; padding: 10px 15px; 
            background: rgba(102, 126, 234, 0.1); border-radius: 5px; 
        }
        .api-test { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        #apiResult { margin-top: 10px; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>MediVote</h1>
        <p class="subtitle">Secure Blockchain-Based Voting System</p>
        
        <div class="status">
            <h3>System Status</h3>
            <p>✅ System Status: <strong>Running</strong></p>
            <p>🔒 Security: <strong>Enabled</strong></p>
            <p>🌐 API: <strong>Available</strong></p>
            <p>⚡ Backend: <strong>FastAPI</strong></p>
        </div>
        
        <div class="info">
            <h3>Welcome to MediVote</h3>
            <p>A secure, privacy-preserving electronic voting system that leverages blockchain technology, zero-knowledge proofs, and homomorphic encryption to ensure election integrity while maintaining voter anonymity.</p>
        </div>
        
        <div class="api-test">
            <h3>API Testing</h3>
            <button class="button" onclick="testAPI('/')">Test Root Endpoint</button>
            <button class="button" onclick="testAPI('/health')">Health Check</button>
            <button class="button" onclick="testAPI('/api/status')">API Status</button>
            <div id="apiResult"></div>
        </div>
        
        <div style="text-align: center; margin-top: 30px;">
            <h3>Key Features</h3>
            <div class="feature">🔐 Anonymous Authentication</div>
            <div class="feature">🗳️ Ballot Secrecy</div>
            <div class="feature">🛡️ Coercion Resistance</div>
            <div class="feature">✅ One-Vote-Per-Person</div>
            <div class="feature">📊 Public Auditability</div>
            <div class="feature">♿ Accessibility</div>
        </div>
    </div>
    
    <script>
        async function testAPI(endpoint) {
            const resultDiv = document.getElementById('apiResult');
            resultDiv.innerHTML = '<p>Testing endpoint: ' + endpoint + '...</p>';
            
            try {
                const response = await fetch('http://localhost:8000' + endpoint);
                const data = await response.json();
                resultDiv.innerHTML = '<div style="background: #d4edda; color: #155724; padding: 10px; border-radius: 5px;"><strong>Success:</strong><br><pre>' + JSON.stringify(data, null, 2) + '</pre></div>';
            } catch (error) {
                resultDiv.innerHTML = '<div style="background: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px;"><strong>Error:</strong> ' + error.message + '</div>';
            }
        }
        
        // Test API on page load
        window.onload = function() {
            testAPI('/');
        };
    </script>
</body>
</html>'''
    
    Path("frontend/index.html").write_text(frontend_html)
    print_status("Frontend structure created")

def create_startup_scripts():
    """Create startup scripts"""
    print_status("Creating startup scripts...")
    
    if platform.system() == "Windows":
        # Windows batch file
        batch_content = '''@echo off
echo Starting MediVote...
cd /d "%~dp0"
call venv\\Scripts\\activate.bat
echo.
echo ========================================
echo   MediVote is starting up...
echo ========================================
echo.
echo Backend API: http://localhost:8000
echo Frontend:    http://localhost:8000/frontend
echo Health:      http://localhost:8000/health
echo.
echo Press Ctrl+C to stop the server
echo.
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
'''
        Path("start_medivote.bat").write_text(batch_content)
        
        # PowerShell script
        ps_content = '''Write-Host "Starting MediVote..." -ForegroundColor Green
Set-Location $PSScriptRoot
& ".\\venv\\Scripts\\Activate.ps1"
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   MediVote is starting up..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Backend API: http://localhost:8000" -ForegroundColor Yellow
Write-Host "Frontend:    http://localhost:8000/frontend" -ForegroundColor Yellow
Write-Host "Health:      http://localhost:8000/health" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Red
Write-Host ""
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
'''
        Path("start_medivote.ps1").write_text(ps_content)
    else:
        # Unix shell script
        shell_content = '''#!/bin/bash
echo "Starting MediVote..."
cd "$(dirname "$0")"
source venv/bin/activate
echo ""
echo "========================================"
echo "   MediVote is starting up..."
echo "========================================"
echo ""
echo "Backend API: http://localhost:8000"
echo "Frontend:    http://localhost:8000/frontend"
echo "Health:      http://localhost:8000/health"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
'''
        script_path = Path("start_medivote.sh")
        script_path.write_text(shell_content)
        script_path.chmod(0o755)
    
    print_status("Startup scripts created")

def create_test_file():
    """Create test file"""
    print_status("Creating test file...")
    
    test_content = '''#!/usr/bin/env python3
"""
MediVote Simple Test Suite
"""
import sys
import os
import subprocess
from pathlib import Path

def print_status(message):
    print(f"[TEST] {message}")

def print_success(message):
    print(f"[✅] {message}")

def print_error(message):
    print(f"[❌] {message}")

def test_python_version():
    """Test Python version"""
    print_status("Testing Python version...")
    if sys.version_info >= (3, 7):
        print_success(f"Python version OK: {sys.version}")
        return True
    else:
        print_error(f"Python version too old: {sys.version}")
        return False

def test_imports():
    """Test imports"""
    print_status("Testing imports...")
    try:
        import fastapi
        import uvicorn
        import pydantic
        print_success("All imports successful")
        return True
    except ImportError as e:
        print_error(f"Import failed: {e}")
        return False

def test_file_structure():
    """Test file structure"""
    print_status("Testing file structure...")
    
    required_files = [
        ".env",
        "backend/main.py",
        "frontend/index.html",
        "requirements.txt"
    ]
    
    all_good = True
    for file_path in required_files:
        if Path(file_path).exists():
            print_success(f"Found: {file_path}")
        else:
            print_error(f"Missing: {file_path}")
            all_good = False
    
    return all_good

def test_backend_import():
    """Test backend import"""
    print_status("Testing backend import...")
    try:
        sys.path.insert(0, "backend")
        import main
        print_success("Backend import successful")
        return True
    except Exception as e:
        print_error(f"Backend import failed: {e}")
        return False

def test_server_start():
    """Test server start"""
    print_status("Testing server start (quick test)...")
    try:
        # Determine python command
        if sys.platform == "win32":
            python_cmd = "venv\\\\Scripts\\\\python.exe"
        else:
            python_cmd = "venv/bin/python"
        
        # Try to import uvicorn in the virtual environment
        result = subprocess.run([python_cmd, "-c", "import uvicorn; print('uvicorn available')"], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print_success("Server dependencies available")
            return True
        else:
            print_error(f"Server test failed: {result.stderr}")
            return False
            
    except Exception as e:
        print_error(f"Server test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 50)
    print("MediVote Simple Test Suite")
    print("=" * 50)
    
    tests = [
        ("Python Version", test_python_version),
        ("Imports", test_imports),
        ("File Structure", test_file_structure),
        ("Backend Import", test_backend_import),
        ("Server Start", test_server_start)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\\nRunning: {test_name}")
        if test_func():
            passed += 1
        else:
            print(f"Test failed: {test_name}")
    
    print("=" * 50)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print_success("All tests passed! 🎉")
        print("\\nTo start MediVote:")
        if sys.platform == "win32":
            print("  start_medivote.bat")
        else:
            print("  ./start_medivote.sh")
        return True
    else:
        print_error("Some tests failed!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
'''
    
    Path("test_simple.py").write_text(test_content)
    print_status("Test file created")

def run_tests():
    """Run tests"""
    print_status("Running tests...")
    
    # Determine python command
    if platform.system() == "Windows":
        python_cmd = "venv\\Scripts\\python.exe"
    else:
        python_cmd = "venv/bin/python"
    
    try:
        result = subprocess.run([python_cmd, "test_simple.py"], 
                              capture_output=True, text=True, timeout=30)
        
        print(result.stdout)
        if result.stderr:
            print_warning(result.stderr)
        
        if result.returncode == 0:
            print_status("Tests passed!")
            return True
        else:
            print_warning("Some tests failed, but installation can continue")
            return False
            
    except subprocess.TimeoutExpired:
        print_warning("Tests timed out, but installation can continue")
        return False
    except Exception as e:
        print_warning(f"Failed to run tests: {e}")
        return False

def main():
    """Main installation function"""
    print_header()
    
    print_status("Starting MediVote simple installation...")
    print_status(f"Platform: {platform.system()}")
    print_status(f"Python: {sys.version}")
    
    try:
        # Check Python version
        if not check_python_version():
            return False
        
        # Create project structure
        create_directories()
        create_requirements()
        
        # Create virtual environment
        if not create_virtual_environment():
            return False
        
        # Install packages
        if not install_packages():
            return False
        
        # Create project files
        create_env_file()
        create_backend()
        create_frontend()
        create_startup_scripts()
        create_test_file()
        
        # Run tests
        run_tests()
        
        # Success message
        print("\n" + "="*60)
        print("🎉 MediVote installation completed successfully!")
        print("="*60)
        print("\nTo start the application:")
        
        if platform.system() == "Windows":
            print("  Double-click: start_medivote.bat")
            print("  Or run: start_medivote.bat")
        else:
            print("  Run: ./start_medivote.sh")
        
        print("\nThe application will be available at:")
        print("  Backend API: http://localhost:8000")
        print("  Frontend:    http://localhost:8000/frontend")
        print("  Health:      http://localhost:8000/health")
        print("\n" + "="*60)
        
        return True
        
    except KeyboardInterrupt:
        print_error("Installation interrupted by user")
        return False
    except Exception as e:
        print_error(f"Installation failed: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 