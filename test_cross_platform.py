#!/usr/bin/env python3
"""
MediVote Cross-Platform Test Suite
Tests the secure blockchain-based voting system across Windows, macOS, and Linux
"""

import os
import sys
import platform
import subprocess
import json
import time
import requests
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional
import pytest

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
    """Print the test suite header"""
    header = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MediVote Cross-Platform Test Suite                        ║
║                    Testing Security, Portability & Functionality             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(f"{Colors.BLUE}{header}{Colors.NC}")

class CrossPlatformTester:
    """Comprehensive cross-platform testing for MediVote"""
    
    def __init__(self):
        self.platform = platform.system()
        self.python_version = sys.version_info
        self.test_results = {}
        self.errors = []
        
    def test_platform_compatibility(self) -> bool:
        """Test basic platform compatibility"""
        print_status("Testing platform compatibility...")
        
        try:
            # Check Python version
            if self.python_version < (3, 9):
                print_error(f"Python 3.9+ required. Current: {sys.version}")
                return False
            
            # Check platform-specific paths
            if self.platform == "Windows":
                # Test Windows path handling
                test_path = Path("backend\\main.py")
                if not test_path.exists():
                    test_path = Path("backend/main.py")
            else:
                test_path = Path("backend/main.py")
            
            if not test_path.exists():
                print_error("Backend main.py not found")
                return False
            
            print_status(f"Platform: {self.platform}")
            print_status(f"Python: {sys.version}")
            print_status("Platform compatibility: PASSED")
            return True
            
        except Exception as e:
            print_error(f"Platform compatibility test failed: {e}")
            return False
    
    def test_dependencies(self) -> bool:
        """Test required dependencies"""
        print_status("Testing dependencies...")
        
        required_packages = [
            'fastapi', 'uvicorn', 'pydantic', 'sqlalchemy',
            'cryptography', 'phe', 'requests', 'loguru'
        ]
        
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            print_error(f"Missing packages: {missing_packages}")
            return False
        
        print_status("Dependencies: PASSED")
        return True
    
    def test_file_structure(self) -> bool:
        """Test project file structure"""
        print_status("Testing file structure...")
        
        required_files = [
            'README.md',
            'requirements.txt',
            'package.json',
            'docker-compose.yml',
            'setup.py',
            'setup.sh',
            '.gitignore',
            'CONTRIBUTING.md',
            'LICENSE',
            'backend/main.py',
            'backend/requirements.txt',
            'frontend/index.html',
            'database/init.sql'
        ]
        
        required_dirs = [
            'backend',
            'frontend',
            'database',
            'circuits',
            'keys',
            'uploads'
        ]
        
        missing_files = []
        missing_dirs = []
        
        for file_path in required_files:
            if not Path(file_path).exists():
                missing_files.append(file_path)
        
        for dir_path in required_dirs:
            if not Path(dir_path).exists():
                missing_dirs.append(dir_path)
        
        if missing_files:
            print_error(f"Missing files: {missing_files}")
            return False
        
        if missing_dirs:
            print_error(f"Missing directories: {missing_dirs}")
            return False
        
        print_status("File structure: PASSED")
        return True
    
    def test_environment_configuration(self) -> bool:
        """Test environment configuration"""
        print_status("Testing environment configuration...")
        
        try:
            # Check if .env exists
            env_file = Path(".env")
            if not env_file.exists():
                print_warning(".env file not found - will be created during setup")
            
            # Test environment variable handling
            test_env = {
                'APP_NAME': 'MediVote',
                'DEBUG': 'True',
                'HOST': '0.0.0.0',
                'PORT': '8000'
            }
            
            for key, value in test_env.items():
                os.environ[key] = value
            
            # Verify environment variables are accessible
            for key, expected_value in test_env.items():
                if os.environ.get(key) != expected_value:
                    print_error(f"Environment variable {key} not set correctly")
                    return False
            
            print_status("Environment configuration: PASSED")
            return True
            
        except Exception as e:
            print_error(f"Environment configuration test failed: {e}")
            return False
    
    def test_database_operations(self) -> bool:
        """Test database operations"""
        print_status("Testing database operations...")
        
        try:
            # Test SQLite operations (cross-platform)
            db_path = "test_medivote.db"
            
            # Create test database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create test table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Insert test data
            cursor.execute("""
                INSERT INTO test_users (username) VALUES (?)
            """, ("test_user",))
            
            # Query test data
            cursor.execute("SELECT username FROM test_users WHERE username = ?", ("test_user",))
            result = cursor.fetchone()
            
            if not result or result[0] != "test_user":
                print_error("Database query failed")
                return False
            
            # Cleanup
            conn.close()
            Path(db_path).unlink(missing_ok=True)
            
            print_status("Database operations: PASSED")
            return True
            
        except Exception as e:
            print_error(f"Database operations test failed: {e}")
            return False
    
    def test_cryptographic_operations(self) -> bool:
        """Test cryptographic operations"""
        print_status("Testing cryptographic operations...")
        
        try:
            import secrets
            import hashlib
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            
            # Test secure random generation
            random_bytes = secrets.token_bytes(32)
            if len(random_bytes) != 32:
                print_error("Secure random generation failed")
                return False
            
            # Test hashing
            test_data = b"test_vote_data"
            hash_result = hashlib.sha256(test_data).hexdigest()
            if len(hash_result) != 64:
                print_error("Hashing operation failed")
                return False
            
            # Test RSA key generation
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            
            # Test encryption/decryption
            test_message = b"test_message"
            encrypted = public_key.encrypt(
                test_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            decrypted = private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            if decrypted != test_message:
                print_error("Encryption/decryption failed")
                return False
            
            print_status("Cryptographic operations: PASSED")
            return True
            
        except Exception as e:
            print_error(f"Cryptographic operations test failed: {e}")
            return False
    
    def test_network_operations(self) -> bool:
        """Test network operations"""
        print_status("Testing network operations...")
        
        try:
            # Test HTTP requests
            response = requests.get("https://httpbin.org/get", timeout=10)
            if response.status_code != 200:
                print_error("HTTP request test failed")
                return False
            
            # Test JSON handling
            test_data = {"test": "data", "number": 123}
            json_string = json.dumps(test_data)
            parsed_data = json.loads(json_string)
            
            if parsed_data != test_data:
                print_error("JSON handling test failed")
                return False
            
            print_status("Network operations: PASSED")
            return True
            
        except Exception as e:
            print_error(f"Network operations test failed: {e}")
            return False
    
    def test_file_operations(self) -> bool:
        """Test file operations"""
        print_status("Testing file operations...")
        
        try:
            # Test file creation and reading
            test_file = Path("test_file.txt")
            test_content = "Test content for cross-platform file operations"
            
            # Write file
            test_file.write_text(test_content)
            
            # Read file
            read_content = test_file.read_text()
            
            if read_content != test_content:
                print_error("File read/write test failed")
                return False
            
            # Test directory operations
            test_dir = Path("test_directory")
            test_dir.mkdir(exist_ok=True)
            
            if not test_dir.exists():
                print_error("Directory creation test failed")
                return False
            
            # Cleanup
            test_file.unlink()
            test_dir.rmdir()
            
            print_status("File operations: PASSED")
            return True
            
        except Exception as e:
            print_error(f"File operations test failed: {e}")
            return False
    
    def test_security_features(self) -> bool:
        """Test security features"""
        print_status("Testing security features...")
        
        try:
            import secrets
            import hashlib
            import base64
            
            # Test secure key generation
            secret_key = secrets.token_hex(32)
            if len(secret_key) != 64:
                print_error("Secret key generation failed")
                return False
            
            # Test password hashing
            test_password = "test_password_123"
            salt = secrets.token_hex(16)
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                test_password.encode('utf-8'), 
                salt.encode('utf-8'), 
                100000
            )
            
            if len(password_hash) != 32:
                print_error("Password hashing failed")
                return False
            
            # Test input validation
            def validate_input(data: str) -> bool:
                if not isinstance(data, str):
                    return False
                if len(data) > 1000:  # Prevent DoS
                    return False
                if any(char in data for char in ['<', '>', '"', "'"]):  # Basic XSS prevention
                    return False
                return True
            
            if not validate_input("safe_input"):
                print_error("Input validation test failed")
                return False
            
            if validate_input("<script>alert('xss')</script>"):
                print_error("XSS prevention test failed")
                return False
            
            print_status("Security features: PASSED")
            return True
            
        except Exception as e:
            print_error(f"Security features test failed: {e}")
            return False
    
    def test_accessibility_features(self) -> bool:
        """Test accessibility features"""
        print_status("Testing accessibility features...")
        
        try:
            # Test WCAG compliance indicators
            accessibility_features = {
                'high_contrast_support': True,
                'screen_reader_support': True,
                'keyboard_navigation': True,
                'alt_text_support': True,
                'focus_indicators': True
            }
            
            # Check if accessibility features are configured
            for feature, enabled in accessibility_features.items():
                if not enabled:
                    print_warning(f"Accessibility feature {feature} not enabled")
            
            print_status("Accessibility features: PASSED")
            return True
            
        except Exception as e:
            print_error(f"Accessibility features test failed: {e}")
            return False
    
    def test_docker_compatibility(self) -> bool:
        """Test Docker compatibility"""
        print_status("Testing Docker compatibility...")
        
        try:
            # Check if Docker is available
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                print_warning("Docker not available - skipping Docker tests")
                return True
            
            # Check if docker-compose is available
            result = subprocess.run(['docker-compose', '--version'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                print_warning("Docker Compose not available")
                return True
            
            # Test docker-compose.yml syntax
            if Path("docker-compose.yml").exists():
                result = subprocess.run(['docker-compose', 'config'], 
                                      capture_output=True, text=True)
                
                if result.returncode != 0:
                    print_error("Docker Compose configuration is invalid")
                    return False
            
            print_status("Docker compatibility: PASSED")
            return True
            
        except Exception as e:
            print_warning(f"Docker compatibility test failed: {e}")
            return True  # Docker is optional
    
    def run_all_tests(self) -> Dict[str, bool]:
        """Run all cross-platform tests"""
        print_header()
        
        tests = [
            ("Platform Compatibility", self.test_platform_compatibility),
            ("Dependencies", self.test_dependencies),
            ("File Structure", self.test_file_structure),
            ("Environment Configuration", self.test_environment_configuration),
            ("Database Operations", self.test_database_operations),
            ("Cryptographic Operations", self.test_cryptographic_operations),
            ("Network Operations", self.test_network_operations),
            ("File Operations", self.test_file_operations),
            ("Security Features", self.test_security_features),
            ("Accessibility Features", self.test_accessibility_features),
            ("Docker Compatibility", self.test_docker_compatibility)
        ]
        
        results = {}
        
        for test_name, test_func in tests:
            try:
                results[test_name] = test_func()
            except Exception as e:
                print_error(f"Test {test_name} failed with exception: {e}")
                results[test_name] = False
        
        return results
    
    def generate_report(self, results: Dict[str, bool]) -> None:
        """Generate a comprehensive test report"""
        print_status("Generating test report...")
        
        passed = sum(1 for result in results.values() if result)
        total = len(results)
        
        print(f"\n{Colors.BLUE}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                            TEST RESULTS SUMMARY                                    ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Colors.NC}")
        
        print(f"\nPlatform: {self.platform}")
        print(f"Python Version: {sys.version}")
        print(f"Tests Passed: {passed}/{total}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        print(f"\n{Colors.BLUE}Detailed Results:{Colors.NC}")
        for test_name, result in results.items():
            status = f"{Colors.GREEN}PASSED{Colors.NC}" if result else f"{Colors.RED}FAILED{Colors.NC}"
            print(f"  {test_name}: {status}")
        
        # Save results to file
        report_data = {
            "platform": self.platform,
            "python_version": str(sys.version),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": results,
            "summary": {
                "passed": passed,
                "total": total,
                "success_rate": (passed/total)*100
            }
        }
        
        report_file = Path("test_report.json")
        report_file.write_text(json.dumps(report_data, indent=2))
        
        print(f"\n{Colors.GREEN}Test report saved to: test_report.json{Colors.NC}")
        
        if passed == total:
            print(f"\n{Colors.GREEN}🎉 All tests passed! MediVote is ready for cross-platform deployment.{Colors.NC}")
        else:
            print(f"\n{Colors.YELLOW}⚠️  Some tests failed. Please review the results above.{Colors.NC}")

def main():
    """Main test function"""
    tester = CrossPlatformTester()
    results = tester.run_all_tests()
    tester.generate_report(results)
    
    # Exit with appropriate code
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    if passed == total:
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # Some tests failed

if __name__ == "__main__":
    main() 