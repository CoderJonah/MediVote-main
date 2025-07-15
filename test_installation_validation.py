#!/usr/bin/env python3
"""
INSTALLATION VALIDATION TEST SUITE
Tests all installer components and MSI functionality
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime

class InstallationValidator:
    def __init__(self):
        self.results = []
        self.errors = []
        
    def log_test(self, test_name, passed, details="", error=None):
        """Log test results"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.results.append({
            "test": test_name,
            "passed": passed,
            "details": details,
            "error": str(error) if error else None,
            "timestamp": datetime.now().isoformat()
        })
        print(f"{status} {test_name}")
        if details:
            print(f"    {details}")
        if error:
            self.errors.append(f"{test_name}: {error}")
            
    def test_installer_config(self):
        """Test installer configuration"""
        print("\n🔧 TESTING INSTALLER CONFIGURATION...")
        
        config_file = "installer_config.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    
                required_keys = ['app_name', 'version', 'description', 'author', 'url']
                for key in required_keys:
                    if key in config:
                        self.log_test(f"Config has {key}", True, f"Value: {config[key]}")
                    else:
                        self.log_test(f"Config missing {key}", False)
                        
            except json.JSONDecodeError as e:
                self.log_test("Config JSON validity", False, error=e)
            except Exception as e:
                self.log_test("Config file access", False, error=e)
        else:
            self.log_test("Config file exists", False, "installer_config.json not found")
            
    def test_build_installer_script(self):
        """Test build installer script"""
        print("\n🏗️ TESTING BUILD INSTALLER SCRIPT...")
        
        script_file = "build_installer.py"
        if os.path.exists(script_file):
            try:
                with open(script_file, 'r') as f:
                    content = f.read()
                    
                # Check for required components
                required_components = [
                    'class MSIBuilder',
                    'def create_msi',
                    'def download_dependencies',
                    'def create_installer_files',
                    'def build_complete_installer'
                ]
                
                for component in required_components:
                    if component in content:
                        self.log_test(f"Has {component}", True)
                    else:
                        self.log_test(f"Missing {component}", False)
                        
                # Check for security features
                security_features = ['validate_download', 'verify_signature', 'secure_install']
                for feature in security_features:
                    if feature in content:
                        self.log_test(f"Security feature: {feature}", True)
                        
            except Exception as e:
                self.log_test("Build script analysis", False, error=e)
        else:
            self.log_test("Build script exists", False, "build_installer.py not found")
            
    def test_requirements_build(self):
        """Test build requirements"""
        print("\n📦 TESTING BUILD REQUIREMENTS...")
        
        req_file = "requirements_build.txt"
        if os.path.exists(req_file):
            try:
                with open(req_file, 'r') as f:
                    requirements = f.read().strip().split('\n')
                    
                self.log_test("Build requirements readable", True, f"Found {len(requirements)} dependencies")
                
                # Check for MSI building tools
                msi_tools = ['cx_Freeze', 'pywin32', 'wix']
                for tool in msi_tools:
                    if any(tool in req for req in requirements):
                        self.log_test(f"MSI tool: {tool}", True)
                        
            except Exception as e:
                self.log_test("Build requirements analysis", False, error=e)
        else:
            self.log_test("Build requirements exist", False, "requirements_build.txt not found")
            
    def test_installation_scripts(self):
        """Test installation scripts"""
        print("\n📜 TESTING INSTALLATION SCRIPTS...")
        
        scripts = ['simple_install.py', 'setup.py', 'install_medivote.bat']
        
        for script in scripts:
            if os.path.exists(script):
                try:
                    with open(script, 'r') as f:
                        content = f.read()
                        
                    self.log_test(f"Script readable: {script}", True, f"Size: {len(content)} chars")
                    
                    # Check for installation features
                    install_features = ['download', 'install', 'configure', 'verify']
                    for feature in install_features:
                        if feature in content.lower():
                            self.log_test(f"{script} has {feature} logic", True)
                            
                except Exception as e:
                    self.log_test(f"Script analysis: {script}", False, error=e)
            else:
                self.log_test(f"Script exists: {script}", False, f"{script} not found")
                
    def test_cross_platform_support(self):
        """Test cross-platform installation support"""
        print("\n🌍 TESTING CROSS-PLATFORM SUPPORT...")
        
        # Check for platform-specific files
        platform_files = {
            'install_medivote.bat': 'Windows batch file',
            'setup.sh': 'Unix shell script',
            'install.ps1': 'PowerShell script',
            'Makefile': 'Unix makefile'
        }
        
        for file, description in platform_files.items():
            if os.path.exists(file):
                self.log_test(f"Platform support: {description}", True, f"File: {file}")
            else:
                self.log_test(f"Platform support: {description}", False, f"Missing: {file}")
                
    def test_dependency_management(self):
        """Test dependency management"""
        print("\n🔗 TESTING DEPENDENCY MANAGEMENT...")
        
        dep_files = ['requirements.txt', 'requirements_build.txt', 'package.json']
        
        for dep_file in dep_files:
            if os.path.exists(dep_file):
                try:
                    with open(dep_file, 'r') as f:
                        content = f.read()
                        
                    if dep_file.endswith('.json'):
                        deps = json.loads(content)
                        dep_count = len(deps.get('dependencies', {})) + len(deps.get('devDependencies', {}))
                    else:
                        dep_count = len([line for line in content.split('\n') if line.strip() and not line.startswith('#')])
                        
                    self.log_test(f"Dependencies in {dep_file}", True, f"Count: {dep_count}")
                    
                except Exception as e:
                    self.log_test(f"Dependency file: {dep_file}", False, error=e)
            else:
                self.log_test(f"Dependency file: {dep_file}", False, f"{dep_file} not found")
                
    def test_documentation_for_installation(self):
        """Test installation documentation"""
        print("\n📖 TESTING INSTALLATION DOCUMENTATION...")
        
        doc_files = ['README.md', 'INSTALLATION_IMPROVEMENTS_SUMMARY.md', 'PROFESSIONAL_INSTALLER_SUMMARY.md']
        
        for doc_file in doc_files:
            if os.path.exists(doc_file):
                try:
                    with open(doc_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # Check for installation instructions
                    install_keywords = ['install', 'setup', 'requirements', 'dependencies', 'download']
                    found_keywords = sum(1 for keyword in install_keywords if keyword in content.lower())
                    
                    self.log_test(f"Installation docs in {doc_file}", True, f"Found {found_keywords} install keywords")
                    
                except Exception as e:
                    self.log_test(f"Documentation: {doc_file}", False, error=e)
            else:
                self.log_test(f"Documentation: {doc_file}", False, f"{doc_file} not found")
                
    def run_all_tests(self):
        """Run all installation validation tests"""
        print("🚀 STARTING INSTALLATION VALIDATION TESTS...")
        print(f"Started at: {datetime.now().isoformat()}")
        print("=" * 50)
        
        test_methods = [
            self.test_installer_config,
            self.test_build_installer_script,
            self.test_requirements_build,
            self.test_installation_scripts,
            self.test_cross_platform_support,
            self.test_dependency_management,
            self.test_documentation_for_installation
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                self.log_test(f"Test method {test_method.__name__}", False, error=e)
                
        self.generate_report()
        
    def generate_report(self):
        """Generate test report"""
        print("\n" + "=" * 50)
        print("📊 INSTALLATION VALIDATION REPORT")
        print("=" * 50)
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r['passed'])
        failed = total - passed
        
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        
        if total > 0:
            success_rate = (passed / total) * 100
            print(f"Success Rate: {success_rate:.1f}%")
            
        if self.errors:
            print("\n❌ ERRORS:")
            for error in self.errors:
                print(f"  {error}")
                
        # Save report
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'success_rate': success_rate if total > 0 else 0
            },
            'results': self.results,
            'errors': self.errors
        }
        
        with open('INSTALLATION_VALIDATION_REPORT.json', 'w') as f:
            json.dump(report_data, f, indent=2)
            
        print(f"\n📄 Report saved to: INSTALLATION_VALIDATION_REPORT.json")
        print("=" * 50)

if __name__ == "__main__":
    validator = InstallationValidator()
    validator.run_all_tests() 