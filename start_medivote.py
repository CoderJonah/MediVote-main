#!/usr/bin/env python3
"""
MediVote Startup Script
Simple script to start the complete MediVote system
"""

import os
import sys
import time
import subprocess
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'fastapi',
        'uvicorn',
        'requests',
        'aiofiles'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} - missing")
    
    if missing_packages:
        print(f"\n⚠️ Missing packages: {', '.join(missing_packages)}")
        print("Please install them using: pip install " + " ".join(missing_packages))
        return False
    
    print("✅ All dependencies are installed")
    return True

def check_files():
    """Check if required files exist"""
    print("\n🔍 Checking required files...")
    
    required_files = [
        'backend/main.py',
        'blockchain_node.py',
        'network_coordinator.py',
        'node_incentive_system.py',
        'network_dashboard.py',
        'frontend/index.html'
    ]
    
    missing_files = []
    
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            missing_files.append(file_path)
            print(f"❌ {file_path} - missing")
    
    if missing_files:
        print(f"\n⚠️ Missing files: {', '.join(missing_files)}")
        return False
    
    print("✅ All required files are present")
    return True

def install_dependencies():
    """Install missing dependencies"""
    print("\n📦 Installing dependencies...")
    
    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", 
            "fastapi", "uvicorn", "requests", "aiofiles"
        ], check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def main():
    """Main startup function"""
    print("🚀 MediVote Startup Script")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("backend").exists():
        print("❌ Please run this script from the MediVote root directory")
        return
    
    # Check dependencies
    if not check_dependencies():
        print("\nWould you like to install missing dependencies? (y/n): ", end="")
        response = input().lower()
        if response == 'y':
            if not install_dependencies():
                return
        else:
            print("❌ Cannot start without required dependencies")
            return
    
    # Check files
    if not check_files():
        print("❌ Cannot start without required files")
        return
    
    print("\n🎉 All checks passed! Starting MediVote system...")
    print("=" * 50)
    
    # Start the integrated system
    try:
        from integrated_medivote_system import MediVoteIntegratedSystem
        
        system = MediVoteIntegratedSystem()
        system.run()
        
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        print(f"\n❌ Error starting system: {e}")
        print("Please check the logs for more details")

if __name__ == "__main__":
    main() 