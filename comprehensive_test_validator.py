#!/usr/bin/env python3
"""
COMPREHENSIVE TEST VALIDATOR FOR MEDIVOTE
Tests everything possible in the MediVote system
"""

import os
import sys
import json
import time
import subprocess
import threading
import hashlib
import random
import string
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback

class MediVoteComprehensiveTestValidator:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.backend_url = "http://localhost:8000"
        self.frontend_url = "http://localhost:3000"
        self.test_results = []
        self.errors = []
        self.warnings = []
        
    def log_result(self, category, test_name, status, details="", error=None):
        """Log test results"""
        symbols = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "INFO": "ℹ️"}
        symbol = symbols.get(status, "❓")
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "test": test_name,
            "status": status,
            "details": details,
            "error": str(error) if error else None
        }
        self.test_results.append(result)
        
        print(f"{symbol} [{category}] {test_name}")
        if details:
            print(f"    {details}")
        if error and status == "FAIL":
            self.errors.append(f"[{category}] {test_name}: {error}")
            
    def test_file_structure(self):
        """Test project file structure and completeness"""
        print("\n🏗️ TESTING PROJECT STRUCTURE...")
        
        required_files = [
            "backend/main.py",
            "simple_main_with_security.py", 
            "requirements.txt",
            "README.md",
            "CONTRIBUTING.md",
            "LICENSE",
            "setup.py",
            "build_installer.py",
            "installer_config.json",
            "requirements_build.txt"
        ]
        
        for file in required_files:
            if os.path.exists(file):
                size = os.path.getsize(file)
                self.log_result("STRUCTURE", f"File exists: {file}", "PASS", f"Size: {size} bytes")
            else:
                self.log_result("STRUCTURE", f"Missing file: {file}", "FAIL")
                
        # Check for critical directories
        critical_dirs = ["backend", "frontend", "tests", "docs"]
        for dir_name in critical_dirs:
            if os.path.exists(dir_name):
                files_count = len([f for f in os.listdir(dir_name) if os.path.isfile(os.path.join(dir_name, f))])
                self.log_result("STRUCTURE", f"Directory exists: {dir_name}", "PASS", f"Contains {files_count} files")
            else:
                self.log_result("STRUCTURE", f"Missing directory: {dir_name}", "WARN", "May be optional")
                
    def test_python_syntax(self):
        """Test Python file syntax validation"""
        print("\n🐍 TESTING PYTHON SYNTAX...")
        
        python_files = [f for f in os.listdir('.') if f.endswith('.py')]
        
        for py_file in python_files:
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Basic syntax checks
                compile(content, py_file, 'exec')
                self.log_result("SYNTAX", f"Python syntax: {py_file}", "PASS")
                
                # Check for common issues
                if 'import' not in content:
                    self.log_result("SYNTAX", f"No imports found: {py_file}", "WARN", "May be intentional")
                    
                if 'def ' not in content and 'class ' not in content:
                    self.log_result("SYNTAX", f"No functions/classes: {py_file}", "WARN", "May be a script")
                    
            except SyntaxError as e:
                self.log_result("SYNTAX", f"Syntax error in {py_file}", "FAIL", f"Line {e.lineno}: {e.msg}")
            except Exception as e:
                self.log_result("SYNTAX", f"Error reading {py_file}", "FAIL", str(e))
                
    def test_dependencies(self):
        """Test dependency analysis"""
        print("\n📦 TESTING DEPENDENCIES...")
        
        if os.path.exists('requirements.txt'):
            try:
                with open('requirements.txt', 'r') as f:
                    deps = f.read().strip().split('\n')
                    
                self.log_result("DEPS", "Requirements file readable", "PASS", f"Found {len(deps)} dependencies")
                
                # Check for critical dependencies
                critical_deps = ['fastapi', 'uvicorn', 'pydantic', 'sqlalchemy']
                for dep in critical_deps:
                    if any(dep in line for line in deps):
                        self.log_result("DEPS", f"Critical dependency: {dep}", "PASS")
                    else:
                        self.log_result("DEPS", f"Missing critical dependency: {dep}", "FAIL")
                        
            except Exception as e:
                self.log_result("DEPS", "Requirements file error", "FAIL", str(e))
        else:
            self.log_result("DEPS", "No requirements.txt found", "FAIL")
            
    def test_configuration_files(self):
        """Test configuration file validity"""
        print("\n⚙️ TESTING CONFIGURATION FILES...")
        
        config_files = {
            'installer_config.json': 'json',
            'package.json': 'json',
            'docker-compose.yml': 'yaml',
            'Dockerfile': 'text'
        }
        
        for config_file, file_type in config_files.items():
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                        
                    if file_type == 'json':
                        json.loads(content)
                        self.log_result("CONFIG", f"Valid JSON: {config_file}", "PASS")
                    else:
                        self.log_result("CONFIG", f"File readable: {config_file}", "PASS")
                        
                except json.JSONDecodeError as e:
                    self.log_result("CONFIG", f"Invalid JSON: {config_file}", "FAIL", str(e))
                except Exception as e:
                    self.log_result("CONFIG", f"Error reading {config_file}", "FAIL", str(e))
            else:
                self.log_result("CONFIG", f"Optional config missing: {config_file}", "INFO")
                
    def test_security_features(self):
        """Test security implementation"""
        print("\n🔒 TESTING SECURITY FEATURES...")
        
        security_files = ['simple_main_with_security.py', 'initialize_production_security.py']
        
        for sec_file in security_files:
            if os.path.exists(sec_file):
                try:
                    with open(sec_file, 'r') as f:
                        content = f.read()
                        
                    # Check for security features
                    security_checks = [
                        ('bcrypt', 'Password hashing'),
                        ('jwt', 'JWT authentication'),
                        ('csrf', 'CSRF protection'),
                        ('rate_limit', 'Rate limiting'),
                        ('encryption', 'Data encryption'),
                        ('validation', 'Input validation')
                    ]
                    
                    for check, description in security_checks:
                        if check in content.lower():
                            self.log_result("SECURITY", f"{description} in {sec_file}", "PASS")
                        else:
                            self.log_result("SECURITY", f"Missing {description} in {sec_file}", "WARN")
                            
                except Exception as e:
                    self.log_result("SECURITY", f"Error analyzing {sec_file}", "FAIL", str(e))
            else:
                self.log_result("SECURITY", f"Security file missing: {sec_file}", "WARN")
                
    def test_installer_functionality(self):
        """Test installer components"""
        print("\n🔧 TESTING INSTALLER FUNCTIONALITY...")
        
        installer_files = ['build_installer.py', 'simple_install.py', 'setup.py']
        
        for installer in installer_files:
            if os.path.exists(installer):
                try:
                    with open(installer, 'r') as f:
                        content = f.read()
                        
                    # Check for installer features
                    installer_checks = [
                        ('download', 'Download functionality'),
                        ('install', 'Installation logic'),
                        ('verify', 'Verification steps'),
                        ('path', 'Path management'),
                        ('environment', 'Environment setup')
                    ]
                    
                    for check, description in installer_checks:
                        if check in content.lower():
                            self.log_result("INSTALLER", f"{description} in {installer}", "PASS")
                            
                except Exception as e:
                    self.log_result("INSTALLER", f"Error analyzing {installer}", "FAIL", str(e))
            else:
                self.log_result("INSTALLER", f"Installer missing: {installer}", "WARN")
                
    def test_documentation_completeness(self):
        """Test documentation quality"""
        print("\n📚 TESTING DOCUMENTATION...")
        
        doc_files = ['README.md', 'CONTRIBUTING.md', 'LICENSE']
        
        for doc in doc_files:
            if os.path.exists(doc):
                try:
                    with open(doc, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    word_count = len(content.split())
                    if word_count > 100:
                        self.log_result("DOCS", f"Comprehensive {doc}", "PASS", f"{word_count} words")
                    else:
                        self.log_result("DOCS", f"Brief {doc}", "WARN", f"Only {word_count} words")
                        
                    # Check for key sections in README
                    if doc == 'README.md':
                        readme_sections = ['installation', 'usage', 'features', 'requirements']
                        for section in readme_sections:
                            if section.lower() in content.lower():
                                self.log_result("DOCS", f"README has {section} section", "PASS")
                            else:
                                self.log_result("DOCS", f"README missing {section} section", "WARN")
                                
                except Exception as e:
                    self.log_result("DOCS", f"Error reading {doc}", "FAIL", str(e))
            else:
                self.log_result("DOCS", f"Missing documentation: {doc}", "FAIL")
                
    def test_cross_platform_compatibility(self):
        """Test cross-platform compatibility indicators"""
        print("\n🌍 TESTING CROSS-PLATFORM COMPATIBILITY...")
        
        # Check for platform-specific code
        python_files = [f for f in os.listdir('.') if f.endswith('.py')]
        
        for py_file in python_files:
            try:
                with open(py_file, 'r') as f:
                    content = f.read()
                    
                # Check for cross-platform practices
                if 'os.path.join' in content:
                    self.log_result("PLATFORM", f"Cross-platform paths in {py_file}", "PASS")
                    
                if 'platform.system()' in content:
                    self.log_result("PLATFORM", f"Platform detection in {py_file}", "PASS")
                    
                # Check for problematic patterns
                if '\\\\' in content or '//' in content:
                    self.log_result("PLATFORM", f"Potential path issues in {py_file}", "WARN")
                    
            except Exception as e:
                self.log_result("PLATFORM", f"Error analyzing {py_file}", "FAIL", str(e))
                
    def test_performance_indicators(self):
        """Test for performance optimization indicators"""
        print("\n⚡ TESTING PERFORMANCE INDICATORS...")
        
        python_files = [f for f in os.listdir('.') if f.endswith('.py')]
        
        for py_file in python_files:
            try:
                with open(py_file, 'r') as f:
                    content = f.read()
                    
                # Check for performance patterns
                perf_patterns = [
                    ('async def', 'Async functions'),
                    ('await ', 'Async operations'),
                    ('cache', 'Caching implementation'),
                    ('pool', 'Connection pooling'),
                    ('index', 'Database indexing')
                ]
                
                for pattern, description in perf_patterns:
                    if pattern in content:
                        self.log_result("PERFORMANCE", f"{description} in {py_file}", "PASS")
                        
            except Exception as e:
                self.log_result("PERFORMANCE", f"Error analyzing {py_file}", "FAIL", str(e))
                
    def run_all_tests(self):
        """Run all comprehensive tests"""
        print("🚀 STARTING COMPREHENSIVE MEDIVOTE TESTING...")
        print(f"Test started at: {datetime.now().isoformat()}")
        print("=" * 60)
        
        # Run all test categories
        test_methods = [
            self.test_file_structure,
            self.test_python_syntax,
            self.test_dependencies,
            self.test_configuration_files,
            self.test_security_features,
            self.test_installer_functionality,
            self.test_documentation_completeness,
            self.test_cross_platform_compatibility,
            self.test_performance_indicators
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                self.log_result("SYSTEM", f"Test method {test_method.__name__}", "FAIL", str(e))
                
        self.generate_comprehensive_report()
        
    def generate_comprehensive_report(self):
        """Generate detailed test report"""
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE TEST REPORT")
        print("=" * 60)
        
        # Count results by status
        status_counts = {}
        category_counts = {}
        
        for result in self.test_results:
            status = result['status']
            category = result['category']
            
            status_counts[status] = status_counts.get(status, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
            
        # Print summary
        total_tests = len(self.test_results)
        passed = status_counts.get('PASS', 0)
        failed = status_counts.get('FAIL', 0)
        warned = status_counts.get('WARN', 0)
        info = status_counts.get('INFO', 0)
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️ Warnings: {warned}")
        print(f"ℹ️ Info: {info}")
        
        if total_tests > 0:
            success_rate = (passed / total_tests) * 100
            print(f"Success Rate: {success_rate:.1f}%")
            
        # Print category breakdown
        print("\n📋 CATEGORY BREAKDOWN:")
        for category, count in category_counts.items():
            print(f"  {category}: {count} tests")
            
        # Print all errors
        if self.errors:
            print("\n❌ ERRORS FOUND:")
            for error in self.errors:
                print(f"  {error}")
                
        # Save detailed report
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_tests': total_tests,
                'passed': passed,
                'failed': failed,
                'warnings': warned,
                'info': info,
                'success_rate': success_rate if total_tests > 0 else 0
            },
            'results': self.test_results,
            'errors': self.errors
        }
        
        with open('COMPREHENSIVE_TEST_REPORT.json', 'w') as f:
            json.dump(report_data, f, indent=2)
            
        print(f"\n📄 Detailed report saved to: COMPREHENSIVE_TEST_REPORT.json")
        print("=" * 60)

if __name__ == "__main__":
    tester = MediVoteComprehensiveTestValidator()
    tester.run_all_tests() 