#!/usr/bin/env python3
"""
MediVote Test Runner

Convenient script to run different categories of tests.
Can be run from within the tests directory.
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path


def setup_python_path():
    """Add project root to Python path"""
    test_dir = Path(__file__).parent
    project_root = test_dir.parent
    sys.path.insert(0, str(project_root))


def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"\n🧪 {description}")
    print("=" * 60)
    
    try:
        result = subprocess.run(cmd, shell=True, check=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed with exit code {e.returncode}")
        return False


def main():
    """Main test runner function"""
    setup_python_path()
    
    parser = argparse.ArgumentParser(description="MediVote Test Runner")
    parser.add_argument(
        "test_type", 
        choices=["all", "unit", "integration", "security", "performance", "cross-platform"],
        help="Type of tests to run"
    )
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true", 
        help="Verbose output"
    )
    parser.add_argument(
        "--coverage", "-c", 
        action="store_true", 
        help="Generate coverage report"
    )
    parser.add_argument(
        "--parallel", "-p", 
        action="store_true", 
        help="Run tests in parallel"
    )
    
    args = parser.parse_args()
    
    # Build pytest command
    base_cmd = "python -m pytest"
    
    if args.verbose:
        base_cmd += " -v"
    
    if args.coverage:
        base_cmd += " --cov=backend --cov-report=html --cov-report=term"
    
    if args.parallel:
        base_cmd += " -n auto"
    
    # Determine test paths based on test type
            test_commands = {
            "all": f"{base_cmd} .",
            "unit": f"{base_cmd} unit/ -m unit",
            "integration": f"{base_cmd} integration/ -m integration",
            "security": f"{base_cmd} security/ -m security",
            "performance": "python performance/locustfile.py",
            "cross-platform": "python test_cross_platform.py"
    }
    
    print("🗳️  MediVote Test Suite Runner")
    print("=" * 60)
    print(f"Running: {args.test_type} tests")
    
    if args.test_type == "performance":
        print("\n⚠️  Performance tests require Locust to be installed:")
        print("   pip install locust")
        print("\n💡 To run performance tests against running backend:")
        print("   locust -f performance/locustfile.py --host=http://localhost:8000")
        
        # Just show the locust file content as reference
        success = run_command(test_commands[args.test_type], "Performance Test Reference")
        
    elif args.test_type == "cross-platform":
        success = run_command(test_commands[args.test_type], "Cross-Platform Compatibility Tests")
        
    else:
        # Run pytest-based tests
        success = run_command(test_commands[args.test_type], f"{args.test_type.title()} Tests")
    
    if success:
        print(f"\n🎉 All {args.test_type} tests completed successfully!")
        sys.exit(0)
    else:
        print(f"\n💥 Some {args.test_type} tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main() 