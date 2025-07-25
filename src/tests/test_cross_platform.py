"""
Cross-Platform Compatibility Tests for MediVote

Tests that MediVote functions correctly across different operating systems
and Python versions. Referenced in CI configuration.
"""

import os
import sys
import platform
import json
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime


def generate_test_report():
    """Generate a test report for CI artifacts"""
    report = {
        "test_run_id": f"cross_platform_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "timestamp": datetime.now().isoformat(),
        "platform_info": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation()
        },
        "tests": []
    }
    return report


def test_python_version_compatibility():
    """Test Python version compatibility"""
    test_result = {
        "test_name": "python_version_compatibility",
        "status": "PASS",
        "message": "",
        "details": {}
    }
    
    python_version = sys.version_info
    
    # MediVote requires Python 3.9+
    if python_version >= (3, 9):
        test_result["status"] = "PASS"
        test_result["message"] = f"Python {python_version.major}.{python_version.minor}.{python_version.micro} is supported"
    else:
        test_result["status"] = "FAIL"
        test_result["message"] = f"Python {python_version.major}.{python_version.minor}.{python_version.micro} is not supported (requires 3.9+)"
    
    test_result["details"] = {
        "version": f"{python_version.major}.{python_version.minor}.{python_version.micro}",
        "implementation": platform.python_implementation(),
        "required_minimum": "3.9.0"
    }
    
    return test_result


def test_file_system_operations():
    """Test file system operations across platforms"""
    test_result = {
        "test_name": "file_system_operations",
        "status": "PASS",
        "message": "",
        "details": {}
    }
    
    try:
        # Test directory creation
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir) / "medivote_test"
            test_dir.mkdir(parents=True, exist_ok=True)
            
            # Test file creation and writing
            test_file = test_dir / "test_data.json"
            test_data = {"test": "cross_platform", "platform": platform.system()}
            
            with open(test_file, 'w', encoding='utf-8') as f:
                json.dump(test_data, f, indent=2)
            
            # Test file reading
            with open(test_file, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)
            
            assert loaded_data == test_data
            
            # Test file permissions (Unix-like systems only)
            if platform.system() != "Windows":
                test_file.chmod(0o600)  # Owner read/write only
                file_stats = test_file.stat()
                permissions = oct(file_stats.st_mode)[-3:]
                test_result["details"]["permissions_test"] = permissions
            
            test_result["status"] = "PASS"
            test_result["message"] = "File system operations successful"
            test_result["details"]["temp_dir"] = str(temp_dir)
            test_result["details"]["test_file_size"] = test_file.stat().st_size
            
    except Exception as e:
        test_result["status"] = "FAIL"
        test_result["message"] = f"File system operations failed: {str(e)}"
        test_result["details"]["error"] = str(e)
    
    return test_result


def test_path_handling():
    """Test cross-platform path handling"""
    test_result = {
        "test_name": "path_handling",
        "status": "PASS",
        "message": "",
        "details": {}
    }
    
    try:
        # Test Path operations
        current_dir = Path.cwd()
        backend_path = current_dir / "backend"
        frontend_path = current_dir / "frontend"
        
        # Test path resolution
        resolved_backend = backend_path.resolve()
        resolved_frontend = frontend_path.resolve()
        
        # Test path existence checks
        paths_exist = {
            "backend": backend_path.exists(),
            "frontend": frontend_path.exists(),
            "logs": (current_dir / "logs").exists() or True,  # May not exist yet
            "keys": (current_dir / "keys").exists() or True   # May not exist yet
        }
        
        test_result["status"] = "PASS"
        test_result["message"] = "Path handling successful"
        test_result["details"] = {
            "current_dir": str(current_dir),
            "path_separator": os.sep,
            "paths_exist": paths_exist,
            "backend_path": str(resolved_backend),
            "frontend_path": str(resolved_frontend)
        }
        
    except Exception as e:
        test_result["status"] = "FAIL"
        test_result["message"] = f"Path handling failed: {str(e)}"
        test_result["details"]["error"] = str(e)
    
    return test_result


def test_process_execution():
    """Test process execution across platforms"""
    test_result = {
        "test_name": "process_execution",
        "status": "PASS",
        "message": "",
        "details": {}
    }
    
    try:
        # Test Python execution
        python_cmd = [sys.executable, "--version"]
        result = subprocess.run(python_cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            test_result["status"] = "PASS"
            test_result["message"] = "Process execution successful"
            test_result["details"] = {
                "python_version_output": result.stdout.strip(),
                "return_code": result.returncode,
                "executable": sys.executable
            }
        else:
            test_result["status"] = "FAIL"
            test_result["message"] = f"Python execution failed with return code {result.returncode}"
            test_result["details"] = {
                "return_code": result.returncode,
                "stderr": result.stderr
            }
        
    except subprocess.TimeoutExpired:
        test_result["status"] = "FAIL"
        test_result["message"] = "Process execution timed out"
        test_result["details"]["error"] = "Timeout after 10 seconds"
    except Exception as e:
        test_result["status"] = "FAIL"
        test_result["message"] = f"Process execution failed: {str(e)}"
        test_result["details"]["error"] = str(e)
    
    return test_result


def test_encoding_compatibility():
    """Test text encoding compatibility"""
    test_result = {
        "test_name": "encoding_compatibility",
        "status": "PASS",
        "message": "",
        "details": {}
    }
    
    try:
        # Test UTF-8 encoding/decoding
        test_strings = [
            "Standard ASCII text",
            "UTF-8 with special characters: áéíóú",
            "Emoji support: 🗳️ 🔐 ✅",
            "Mixed languages: Hello 世界 مرحبا"
        ]
        
        encoding_results = {}
        
        for i, test_string in enumerate(test_strings):
            # Encode to bytes and back
            encoded = test_string.encode('utf-8')
            decoded = encoded.decode('utf-8')
            
            assert decoded == test_string
            encoding_results[f"test_{i}"] = {
                "original": test_string,
                "encoded_length": len(encoded),
                "success": True
            }
        
        test_result["status"] = "PASS"
        test_result["message"] = "Text encoding compatibility successful"
        test_result["details"] = {
            "default_encoding": sys.getdefaultencoding(),
            "filesystem_encoding": sys.getfilesystemencoding(),
            "test_results": encoding_results
        }
        
    except Exception as e:
        test_result["status"] = "FAIL"
        test_result["message"] = f"Encoding compatibility failed: {str(e)}"
        test_result["details"]["error"] = str(e)
    
    return test_result


def test_network_compatibility():
    """Test basic network operations"""
    test_result = {
        "test_name": "network_compatibility",
        "status": "PASS",
        "message": "",
        "details": {}
    }
    
    try:
        import socket
        
        # Test socket creation
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Test binding to localhost (should work on all platforms)
        test_socket.bind(('127.0.0.1', 0))  # 0 = let OS choose port
        bound_address = test_socket.getsockname()
        
        test_socket.close()
        
        test_result["status"] = "PASS"
        test_result["message"] = "Network compatibility successful"
        test_result["details"] = {
            "localhost_binding": True,
            "bound_address": bound_address,
            "socket_family": "AF_INET",
            "socket_type": "SOCK_STREAM"
        }
        
    except Exception as e:
        test_result["status"] = "FAIL"
        test_result["message"] = f"Network compatibility failed: {str(e)}"
        test_result["details"]["error"] = str(e)
    
    return test_result


def main():
    """Run all cross-platform tests and generate report"""
    print("🌐 MediVote Cross-Platform Compatibility Tests")
    print("=" * 60)
    
    # Generate test report
    report = generate_test_report()
    
    # Run all tests
    tests = [
        test_python_version_compatibility,
        test_file_system_operations,
        test_path_handling,
        test_process_execution,
        test_encoding_compatibility,
        test_network_compatibility
    ]
    
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {platform.python_version()} ({platform.python_implementation()})")
    print()
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        print(f"Running {test_func.__name__}...", end=" ")
        
        result = test_func()
        report["tests"].append(result)
        
        if result["status"] == "PASS":
            print("✅ PASS")
            passed += 1
        else:
            print("❌ FAIL")
            print(f"   Error: {result['message']}")
            failed += 1
    
    print()
    print(f"Results: {passed} passed, {failed} failed")
    
    # Save test report
    report["summary"] = {
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests) if tests else 0
    }
    
    with open("test_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"Test report saved to: test_report.json")
    
    # Exit with error code if any tests failed
    sys.exit(failed)


if __name__ == "__main__":
    main() 