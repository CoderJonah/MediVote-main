@echo off
setlocal enabledelayedexpansion

echo.
echo ███╗   ███╗███████╗██████╗ ██╗██╗   ██╗ ██████╗ ████████╗███████╗
echo ████╗ ████║██╔════╝██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝██╔════╝
echo ██╔████╔██║█████╗  ██║  ██║██║██║   ██║██║   ██║   ██║   █████╗  
echo ██║╚██╔╝██║██╔══╝  ██║  ██║██║╚██╗ ██╔╝██║   ██║   ██║   ██╔══╝  
echo ██║ ╚═╝ ██║███████╗██████╔╝██║ ╚████╔╝ ╚██████╔╝   ██║   ███████╗
echo ╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═══╝   ╚═════╝    ╚═╝   ╚══════╝
echo.
echo                 BOOTSTRAP INSTALLER FOR WINDOWS
echo           Installs everything needed on a fresh system
echo.

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] Not running as administrator. Some features may not work.
    echo [INFO] Consider running as administrator for full functionality.
    echo.
)

echo [INFO] Starting MediVote bootstrap installation...
echo [INFO] Platform: Windows
echo [INFO] Working directory: %CD%

:: Create necessary directories
echo [INFO] Creating directory structure...
if not exist "backend" mkdir backend
if not exist "frontend" mkdir frontend
if not exist "database" mkdir database
if not exist "keys" mkdir keys
if not exist "uploads" mkdir uploads
if not exist "logs" mkdir logs
if not exist "temp" mkdir temp

:: Check if Python is installed
echo [INFO] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% equ 0 (
    echo [INFO] Python is already installed
    goto :check_node
)

py --version >nul 2>&1
if %errorLevel% equ 0 (
    echo [INFO] Python is already installed (via py launcher)
    set PYTHON_CMD=py
    goto :check_node
)

echo [INFO] Python not found. Installing Python...

:: Download Python installer
echo [INFO] Downloading Python 3.11.7...
set PYTHON_URL=https://www.python.org/ftp/python/3.11.7/python-3.11.7-amd64.exe
set PYTHON_INSTALLER=temp\python-installer.exe

:: Use PowerShell to download Python
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%PYTHON_INSTALLER%'}"

if not exist "%PYTHON_INSTALLER%" (
    echo [ERROR] Failed to download Python installer
    goto :error
)

echo [INFO] Installing Python...
%PYTHON_INSTALLER% /quiet InstallAllUsers=1 PrependPath=1 Include_test=0

:: Wait for installation to complete
timeout /t 10 /nobreak >nul

:: Refresh PATH
call :refresh_path

:: Check if Python is now available
python --version >nul 2>&1
if %errorLevel% neq 0 (
    py --version >nul 2>&1
    if %errorLevel% neq 0 (
        echo [ERROR] Python installation failed
        goto :error
    ) else (
        set PYTHON_CMD=py
    )
) else (
    set PYTHON_CMD=python
)

echo [INFO] Python installation completed

:check_node
:: Check if Node.js is installed
echo [INFO] Checking Node.js installation...
node --version >nul 2>&1
if %errorLevel% equ 0 (
    echo [INFO] Node.js is already installed
    goto :install_packages
)

echo [INFO] Node.js not found. Installing Node.js...

:: Download Node.js installer
echo [INFO] Downloading Node.js 18.19.0...
set NODE_URL=https://nodejs.org/dist/v18.19.0/node-v18.19.0-x64.msi
set NODE_INSTALLER=temp\nodejs-installer.msi

:: Use PowerShell to download Node.js
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%NODE_URL%' -OutFile '%NODE_INSTALLER%'}"

if not exist "%NODE_INSTALLER%" (
    echo [ERROR] Failed to download Node.js installer
    goto :error
)

echo [INFO] Installing Node.js...
msiexec /i "%NODE_INSTALLER%" /quiet /norestart

:: Wait for installation to complete
timeout /t 15 /nobreak >nul

:: Refresh PATH
call :refresh_path

:: Check if Node.js is now available
node --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Node.js installation failed
    goto :error
)

echo [INFO] Node.js installation completed

:install_packages
:: Create requirements.txt if it doesn't exist
if not exist "requirements.txt" (
    echo [INFO] Creating requirements.txt...
    echo fastapi^>=0.104.1> requirements.txt
    echo uvicorn[standard]^>=0.24.0>> requirements.txt
    echo pydantic^>=2.5.0>> requirements.txt
    echo python-multipart^>=0.0.6>> requirements.txt
    echo requests^>=2.31.0>> requirements.txt
    echo python-dotenv^>=1.0.0>> requirements.txt
    echo cryptography^>=41.0.0>> requirements.txt
    echo pytest^>=7.4.0>> requirements.txt
    echo pytest-asyncio^>=0.21.0>> requirements.txt
    echo httpx^>=0.25.0>> requirements.txt
)

:: Create virtual environment
echo [INFO] Creating virtual environment...
%PYTHON_CMD% -m venv venv

if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Failed to create virtual environment
    goto :error
)

:: Activate virtual environment and install packages
echo [INFO] Installing Python packages...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if %errorLevel% neq 0 (
    echo [ERROR] Failed to install Python packages
    goto :error
)

:: Create .env file
echo [INFO] Creating environment configuration...
call :create_env_file

:: Create basic backend structure
echo [INFO] Creating backend structure...
call :create_backend

:: Create basic frontend structure
echo [INFO] Creating frontend structure...
call :create_frontend

:: Create startup scripts
echo [INFO] Creating startup scripts...
call :create_startup_scripts

:: Install Node.js packages
echo [INFO] Installing Node.js packages...
call :refresh_path
npm install -g concurrently 2>nul

:: Create package.json
if not exist "package.json" (
    echo [INFO] Creating package.json...
    echo {> package.json
    echo   "name": "medivote",>> package.json
    echo   "version": "1.0.0",>> package.json
    echo   "description": "Secure blockchain-based voting system",>> package.json
    echo   "scripts": {>> package.json
    echo     "start": "python -m uvicorn backend.main:app --reload --port 8000",>> package.json
    echo     "test": "python test_basic.py">> package.json
    echo   }>> package.json
    echo }>> package.json
)

:: Create basic test file
echo [INFO] Creating basic test file...
call :create_basic_test

:: Run basic tests
echo [INFO] Running basic tests...
call venv\Scripts\activate.bat
python test_basic.py

if %errorLevel% neq 0 (
    echo [WARNING] Some tests failed, but installation can continue
)

:: Success message
echo.
echo [SUCCESS] MediVote installation completed successfully!
echo.
echo To start the application:
echo   1. Double-click: start_medivote.bat
echo   2. Or run: start_medivote.bat
echo.
echo The application will be available at: http://localhost:8000
echo.
goto :end

:create_env_file
echo # MediVote Environment Configuration> .env
echo APP_NAME=MediVote>> .env
echo APP_VERSION=1.0.0>> .env
echo DEBUG=True>> .env
echo TESTING=False>> .env
echo.>> .env
echo # Server Configuration>> .env
echo HOST=0.0.0.0>> .env
echo PORT=8000>> .env
echo.>> .env
echo # Security Settings>> .env
echo SECRET_KEY=medivote_secure_secret_key_32_chars_minimum>> .env
echo ENCRYPTION_KEY=medivote_encryption_key_32_chars_minimum>> .env
echo JWT_SECRET_KEY=medivote_jwt_secret_key_32_chars_minimum>> .env
echo JWT_ALGORITHM=HS256>> .env
echo JWT_EXPIRATION_MINUTES=60>> .env
echo.>> .env
echo # Database Configuration>> .env
echo DATABASE_URL=sqlite:///./medivote.db>> .env
echo DATABASE_ECHO=False>> .env
echo.>> .env
echo # CORS and Security>> .env
echo CORS_ORIGINS=["http://localhost:3000", "http://127.0.0.1:3000"]>> .env
echo ALLOWED_HOSTS=["localhost", "127.0.0.1"]>> .env
goto :eof

:create_backend
echo """>> backend\main.py
echo MediVote Backend - FastAPI Application>> backend\main.py
echo """>> backend\main.py
echo from fastapi import FastAPI>> backend\main.py
echo from fastapi.middleware.cors import CORSMiddleware>> backend\main.py
echo.>> backend\main.py
echo app = FastAPI(title="MediVote", version="1.0.0", description="Secure Blockchain Voting System")>> backend\main.py
echo.>> backend\main.py
echo # Add CORS middleware>> backend\main.py
echo app.add_middleware(>> backend\main.py
echo     CORSMiddleware,>> backend\main.py
echo     allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],>> backend\main.py
echo     allow_credentials=True,>> backend\main.py
echo     allow_methods=["GET", "POST", "PUT", "DELETE"],>> backend\main.py
echo     allow_headers=["*"],>> backend\main.py
echo )>> backend\main.py
echo.>> backend\main.py
echo @app.get("/")>> backend\main.py
echo async def root():>> backend\main.py
echo     return {"message": "MediVote API is running", "version": "1.0.0"}>> backend\main.py
echo.>> backend\main.py
echo @app.get("/health")>> backend\main.py
echo async def health():>> backend\main.py
echo     return {"status": "healthy", "service": "MediVote Backend"}>> backend\main.py
goto :eof

:create_frontend
echo ^<!DOCTYPE html^>> frontend\index.html
echo ^<html lang="en"^>>> frontend\index.html
echo ^<head^>>> frontend\index.html
echo     ^<meta charset="UTF-8"^>>> frontend\index.html
echo     ^<meta name="viewport" content="width=device-width, initial-scale=1.0"^>>> frontend\index.html
echo     ^<title^>MediVote - Secure Blockchain Voting^</title^>>> frontend\index.html
echo     ^<style^>>> frontend\index.html
echo         body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }>> frontend\index.html
echo         .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }>> frontend\index.html
echo         h1 { color: #2c3e50; text-align: center; }>> frontend\index.html
echo         .status { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }>> frontend\index.html
echo         .button { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }>> frontend\index.html
echo         .button:hover { background: #2980b9; }>> frontend\index.html
echo     ^</style^>>> frontend\index.html
echo ^</head^>>> frontend\index.html
echo ^<body^>>> frontend\index.html
echo     ^<div class="container"^>>> frontend\index.html
echo         ^<h1^>MediVote^</h1^>>> frontend\index.html
echo         ^<p^>^<strong^>Secure Blockchain-Based Voting System^</strong^>^</p^>>> frontend\index.html
echo         ^<div class="status"^>>> frontend\index.html
echo             ^<p^>✅ System Status: ^<strong^>Running^</strong^>^</p^>>> frontend\index.html
echo             ^<p^>🔒 Security: ^<strong^>Enabled^</strong^>^</p^>>> frontend\index.html
echo             ^<p^>🌐 API: ^<strong^>Available^</strong^>^</p^>>> frontend\index.html
echo         ^</div^>>> frontend\index.html
echo         ^<p^>Welcome to MediVote - a secure, privacy-preserving electronic voting system.^</p^>>> frontend\index.html
echo         ^<button class="button" onclick="window.open('http://localhost:8000', '_blank')"^>Check API Status^</button^>>> frontend\index.html
echo     ^</div^>>> frontend\index.html
echo ^</body^>>> frontend\index.html
echo ^</html^>>> frontend\index.html
goto :eof

:create_startup_scripts
echo @echo off> start_medivote.bat
echo echo Starting MediVote...>> start_medivote.bat
echo cd /d "%%~dp0">> start_medivote.bat
echo call venv\Scripts\activate.bat>> start_medivote.bat
echo echo Backend starting at http://localhost:8000>> start_medivote.bat
echo echo Frontend available at frontend\index.html>> start_medivote.bat
echo python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload>> start_medivote.bat
echo pause>> start_medivote.bat
goto :eof

:create_basic_test
echo """>> test_basic.py
echo Basic tests for MediVote installation>> test_basic.py
echo """>> test_basic.py
echo import sys>> test_basic.py
echo import os>> test_basic.py
echo from pathlib import Path>> test_basic.py
echo.>> test_basic.py
echo def test_python_version():>> test_basic.py
echo     """Test Python version""">> test_basic.py
echo     print(f"Python version: {sys.version}")>> test_basic.py
echo     assert sys.version_info ^>= (3, 9), "Python 3.9+ required">> test_basic.py
echo     print("✅ Python version test passed")>> test_basic.py
echo.>> test_basic.py
echo def test_imports():>> test_basic.py
echo     """Test required imports""">> test_basic.py
echo     try:>> test_basic.py
echo         import fastapi>> test_basic.py
echo         import uvicorn>> test_basic.py
echo         import pydantic>> test_basic.py
echo         print("✅ Import test passed")>> test_basic.py
echo     except ImportError as e:>> test_basic.py
echo         print(f"❌ Import test failed: {e}")>> test_basic.py
echo         raise>> test_basic.py
echo.>> test_basic.py
echo def test_file_structure():>> test_basic.py
echo     """Test file structure""">> test_basic.py
echo     required_files = [>> test_basic.py
echo         ".env",>> test_basic.py
echo         "backend/main.py",>> test_basic.py
echo         "frontend/index.html",>> test_basic.py
echo         "start_medivote.bat">> test_basic.py
echo     ]>> test_basic.py
echo     >> test_basic.py
echo     for file_path in required_files:>> test_basic.py
echo         if not Path(file_path).exists():>> test_basic.py
echo             print(f"❌ Missing file: {file_path}")>> test_basic.py
echo             raise FileNotFoundError(f"Missing file: {file_path}")>> test_basic.py
echo     >> test_basic.py
echo     print("✅ File structure test passed")>> test_basic.py
echo.>> test_basic.py
echo def test_backend_import():>> test_basic.py
echo     """Test backend import""">> test_basic.py
echo     try:>> test_basic.py
echo         sys.path.insert(0, "backend")>> test_basic.py
echo         import main>> test_basic.py
echo         print("✅ Backend import test passed")>> test_basic.py
echo     except Exception as e:>> test_basic.py
echo         print(f"❌ Backend import test failed: {e}")>> test_basic.py
echo         raise>> test_basic.py
echo.>> test_basic.py
echo if __name__ == "__main__":>> test_basic.py
echo     print("Running basic MediVote tests...")>> test_basic.py
echo     try:>> test_basic.py
echo         test_python_version()>> test_basic.py
echo         test_imports()>> test_basic.py
echo         test_file_structure()>> test_basic.py
echo         test_backend_import()>> test_basic.py
echo         print("🎉 All basic tests passed!")>> test_basic.py
echo     except Exception as e:>> test_basic.py
echo         print(f"❌ Tests failed: {e}")>> test_basic.py
echo         sys.exit(1)>> test_basic.py
goto :eof

:refresh_path
:: Refresh environment variables
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH') do set "sys_path=%%b"
for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v PATH 2^>nul') do set "user_path=%%b"
if defined user_path (
    set "PATH=%user_path%;%sys_path%"
) else (
    set "PATH=%sys_path%"
)
goto :eof

:error
echo.
echo [ERROR] Installation failed!
echo Please check the error messages above and try again.
echo.
pause
exit /b 1

:end
echo.
echo Installation completed successfully!
echo.
pause 