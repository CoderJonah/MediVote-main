#!/usr/bin/env python3
"""
MediVote Deployment Script
Deploys the secure blockchain-based voting system across different environments
"""

import os
import sys
import platform
import subprocess
import json
import time
import argparse
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
    """Print the deployment header"""
    header = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        MediVote Deployment Script                            ║
║                    Secure Blockchain Voting System                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(f"{Colors.BLUE}{header}{Colors.NC}")

class MediVoteDeployer:
    """Comprehensive deployment manager for MediVote"""
    
    def __init__(self, environment: str = "development"):
        self.environment = environment
        self.platform = platform.system()
        self.deployment_config = self.load_deployment_config()
        
    def load_deployment_config(self) -> Dict[str, Any]:
        """Load deployment configuration"""
        config_file = Path(f"deployment_config_{self.environment}.json")
        
        if config_file.exists():
            return json.loads(config_file.read_text())
        
        # Default configuration
        return {
            "environment": self.environment,
            "services": {
                "backend": {
                    "port": 8000,
                    "host": "0.0.0.0",
                    "workers": 4
                },
                "frontend": {
                    "port": 3000,
                    "host": "0.0.0.0"
                },
                "database": {
                    "type": "postgresql",
                    "host": "localhost",
                    "port": 5432,
                    "name": "medivote"
                },
                "redis": {
                    "host": "localhost",
                    "port": 6379
                }
            },
            "security": {
                "https_enabled": False,
                "ssl_cert_path": None,
                "ssl_key_path": None
            },
            "monitoring": {
                "enabled": True,
                "prometheus_port": 9090,
                "grafana_port": 3001
            }
        }
    
    def check_prerequisites(self) -> bool:
        """Check deployment prerequisites"""
        print_status("Checking deployment prerequisites...")
        
        # Check Python
        if sys.version_info < (3, 9):
            print_error("Python 3.9+ required")
            return False
        
        # Check Node.js
        try:
            result = subprocess.run(['node', '--version'], 
                                  capture_output=True, text=True, check=True)
            print_status(f"Node.js version: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print_error("Node.js not found")
            return False
        
        # Check Docker (optional)
        try:
            subprocess.run(['docker', '--version'], 
                          capture_output=True, check=True)
            print_status("Docker available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print_warning("Docker not available - some features may not work")
        
        print_status("Prerequisites check completed")
        return True
    
    def setup_environment(self) -> bool:
        """Setup deployment environment"""
        print_status(f"Setting up {self.environment} environment...")
        
        try:
            # Create necessary directories
            directories = [
                'logs', 'uploads', 'temp', 'ssl', 'backups'
            ]
            
            for directory in directories:
                Path(directory).mkdir(exist_ok=True)
            
            # Setup virtual environment if not exists
            venv_path = Path("venv")
            if not venv_path.exists():
                print_status("Creating virtual environment...")
                subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)
            
            # Install dependencies
            pip_cmd = "venv\\Scripts\\pip" if self.platform == "Windows" else "venv/bin/pip"
            subprocess.run([pip_cmd, "install", "-r", "requirements.txt"], check=True)
            
            print_status("Environment setup completed")
            return True
            
        except Exception as e:
            print_error(f"Environment setup failed: {e}")
            return False
    
    def setup_database(self) -> bool:
        """Setup database"""
        print_status("Setting up database...")
        
        try:
            if self.deployment_config["services"]["database"]["type"] == "postgresql":
                # Check if PostgreSQL is available
                try:
                    subprocess.run(['psql', '--version'], 
                                  capture_output=True, check=True)
                    print_status("PostgreSQL available")
                except (subprocess.CalledProcessError, FileNotFoundError):
                    print_warning("PostgreSQL not available - using SQLite")
                    self.deployment_config["services"]["database"]["type"] = "sqlite"
            
            # Initialize database
            db_init_script = Path("database/init.sql")
            if db_init_script.exists():
                print_status("Database initialization script found")
            
            print_status("Database setup completed")
            return True
            
        except Exception as e:
            print_error(f"Database setup failed: {e}")
            return False
    
    def setup_security(self) -> bool:
        """Setup security configurations"""
        print_status("Setting up security configurations...")
        
        try:
            # Generate SSL certificates if needed
            if self.deployment_config["security"]["https_enabled"]:
                ssl_dir = Path("ssl")
                ssl_dir.mkdir(exist_ok=True)
                
                # Generate self-signed certificate for development
                if self.environment == "development":
                    subprocess.run([
                        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
                        '-keyout', 'ssl/key.pem', '-out', 'ssl/cert.pem',
                        '-days', '365', '-nodes', '-subj', '/CN=localhost'
                    ], check=True)
                    
                    self.deployment_config["security"]["ssl_cert_path"] = "ssl/cert.pem"
                    self.deployment_config["security"]["ssl_key_path"] = "ssl/key.pem"
            
            # Generate cryptographic keys
            keys_dir = Path("keys")
            keys_dir.mkdir(exist_ok=True)
            
            # Generate environment-specific keys
            import secrets
            secret_key = secrets.token_hex(32)
            encryption_key = secrets.token_hex(32)
            jwt_secret = secrets.token_hex(32)
            
            # Update .env file
            env_file = Path(".env")
            if env_file.exists():
                env_content = env_file.read_text()
                env_content = env_content.replace("SECRET_KEY=medivote_super_secure_secret_key_32_characters_minimum_length_for_production_use", f"SECRET_KEY={secret_key}")
                env_content = env_content.replace("ENCRYPTION_KEY=medivote_encryption_key_32_characters_minimum_length_for_secure_operations", f"ENCRYPTION_KEY={encryption_key}")
                env_content = env_content.replace("JWT_SECRET_KEY=medivote_jwt_secret_key_32_characters_minimum_length_for_token_security", f"JWT_SECRET_KEY={jwt_secret}")
                env_file.write_text(env_content)
            
            print_status("Security setup completed")
            return True
            
        except Exception as e:
            print_error(f"Security setup failed: {e}")
            return False
    
    def deploy_backend(self) -> bool:
        """Deploy backend service"""
        print_status("Deploying backend service...")
        
        try:
            # Start backend service
            if self.platform == "Windows":
                activate_cmd = "venv\\Scripts\\activate"
                python_cmd = "venv\\Scripts\\python"
            else:
                activate_cmd = "venv/bin/activate"
                python_cmd = "venv/bin/python"
            
            # Start backend in background
            backend_cmd = [
                python_cmd, "-m", "uvicorn", "backend.main:app",
                "--host", self.deployment_config["services"]["backend"]["host"],
                "--port", str(self.deployment_config["services"]["backend"]["port"]),
                "--workers", str(self.deployment_config["services"]["backend"]["workers"])
            ]
            
            # For Windows, we'll use a different approach
            if self.platform == "Windows":
                # Create a batch file to start the backend
                batch_content = f"""@echo off
cd /d "%~dp0"
call {activate_cmd}
{python_cmd} -m uvicorn backend.main:app --host {self.deployment_config["services"]["backend"]["host"]} --port {self.deployment_config["services"]["backend"]["port"]}
pause
"""
                Path("start_backend.bat").write_text(batch_content)
                print_status("Backend startup script created: start_backend.bat")
            else:
                # Create a shell script for Unix systems
                shell_content = f"""#!/bin/bash
cd "$(dirname "$0")"
source {activate_cmd}
{python_cmd} -m uvicorn backend.main:app --host {self.deployment_config["services"]["backend"]["host"]} --port {self.deployment_config["services"]["backend"]["port"]}
"""
                start_script = Path("start_backend.sh")
                start_script.write_text(shell_content)
                start_script.chmod(0o755)
                print_status("Backend startup script created: start_backend.sh")
            
            print_status("Backend deployment completed")
            return True
            
        except Exception as e:
            print_error(f"Backend deployment failed: {e}")
            return False
    
    def deploy_frontend(self) -> bool:
        """Deploy frontend service"""
        print_status("Deploying frontend service...")
        
        try:
            # Install frontend dependencies
            subprocess.run(['npm', 'install'], check=True)
            
            # Build frontend for production
            if self.environment == "production":
                subprocess.run(['npm', 'run', 'build'], check=True)
                print_status("Frontend built for production")
            
            # Start frontend development server
            if self.environment == "development":
                frontend_cmd = [
                    'npm', 'start'
                ]
                
                if self.platform == "Windows":
                    batch_content = f"""@echo off
cd /d "%~dp0"
npm start
pause
"""
                    Path("start_frontend.bat").write_text(batch_content)
                    print_status("Frontend startup script created: start_frontend.bat")
                else:
                    shell_content = f"""#!/bin/bash
cd "$(dirname "$0")"
npm start
"""
                    start_script = Path("start_frontend.sh")
                    start_script.write_text(shell_content)
                    start_script.chmod(0o755)
                    print_status("Frontend startup script created: start_frontend.sh")
            
            print_status("Frontend deployment completed")
            return True
            
        except Exception as e:
            print_error(f"Frontend deployment failed: {e}")
            return False
    
    def deploy_with_docker(self) -> bool:
        """Deploy using Docker"""
        print_status("Deploying with Docker...")
        
        try:
            # Build Docker images
            subprocess.run(['docker-compose', 'build'], check=True)
            
            # Start services
            subprocess.run(['docker-compose', 'up', '-d'], check=True)
            
            # Wait for services to be ready
            time.sleep(30)
            
            # Check service status
            subprocess.run(['docker-compose', 'ps'], check=True)
            
            print_status("Docker deployment completed")
            return True
            
        except Exception as e:
            print_error(f"Docker deployment failed: {e}")
            return False
    
    def run_tests(self) -> bool:
        """Run deployment tests"""
        print_status("Running deployment tests...")
        
        try:
            # Run cross-platform tests
            subprocess.run([sys.executable, 'test_cross_platform.py'], check=True)
            
            # Run security tests
            subprocess.run([sys.executable, 'production_security_test.py'], check=True)
            
            print_status("Deployment tests completed")
            return True
            
        except Exception as e:
            print_error(f"Deployment tests failed: {e}")
            return False
    
    def create_startup_scripts(self) -> None:
        """Create platform-specific startup scripts"""
        print_status("Creating startup scripts...")
        
        if self.platform == "Windows":
            # Windows batch file
            main_script = f"""@echo off
echo Starting MediVote {self.environment} environment...
echo.

echo Starting backend...
start "MediVote Backend" cmd /k "start_backend.bat"

echo Starting frontend...
start "MediVote Frontend" cmd /k "start_frontend.bat"

echo.
echo MediVote is starting up...
echo Backend will be available at: http://localhost:{self.deployment_config["services"]["backend"]["port"]}
echo Frontend will be available at: http://localhost:{self.deployment_config["services"]["frontend"]["port"]}
echo.
pause
"""
            Path("start_medivote.bat").write_text(main_script)
            print_status("Windows startup script created: start_medivote.bat")
            
        else:
            # Unix shell script
            main_script = f"""#!/bin/bash
echo "Starting MediVote {self.environment} environment..."

# Start backend in background
echo "Starting backend..."
./start_backend.sh &
BACKEND_PID=$!

# Start frontend in background
echo "Starting frontend..."
./start_frontend.sh &
FRONTEND_PID=$!

echo ""
echo "MediVote is starting up..."
echo "Backend will be available at: http://localhost:{self.deployment_config["services"]["backend"]["port"]}"
echo "Frontend will be available at: http://localhost:{self.deployment_config["services"]["frontend"]["port"]}"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for user interrupt
trap "echo 'Stopping services...'; kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait
"""
            start_script = Path("start_medivote.sh")
            start_script.write_text(main_script)
            start_script.chmod(0o755)
            print_status("Unix startup script created: start_medivote.sh")
    
    def deploy(self, use_docker: bool = False) -> bool:
        """Main deployment method"""
        print_header()
        
        print_status(f"Starting MediVote deployment for {self.environment} environment")
        
        # Check prerequisites
        if not self.check_prerequisites():
            return False
        
        # Setup environment
        if not self.setup_environment():
            return False
        
        # Setup database
        if not self.setup_database():
            return False
        
        # Setup security
        if not self.setup_security():
            return False
        
        # Deploy services
        if use_docker:
            if not self.deploy_with_docker():
                return False
        else:
            if not self.deploy_backend():
                return False
            
            if not self.deploy_frontend():
                return False
        
        # Run tests
        if not self.run_tests():
            return False
        
        # Create startup scripts
        self.create_startup_scripts()
        
        print_status("Deployment completed successfully!")
        print_status("To start the application:")
        
        if use_docker:
            print_status("  docker-compose up -d")
        else:
            if self.platform == "Windows":
                print_status("  start_medivote.bat")
            else:
                print_status("  ./start_medivote.sh")
        
        return True

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="MediVote Deployment Script")
    parser.add_argument("--environment", "-e", default="development", 
                       choices=["development", "staging", "production"],
                       help="Deployment environment")
    parser.add_argument("--docker", "-d", action="store_true",
                       help="Use Docker for deployment")
    
    args = parser.parse_args()
    
    deployer = MediVoteDeployer(args.environment)
    success = deployer.deploy(use_docker=args.docker)
    
    if success:
        print_status("🎉 Deployment successful!")
        sys.exit(0)
    else:
        print_error("❌ Deployment failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 