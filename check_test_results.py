#!/usr/bin/env python3
"""Simple script to run tests and capture results"""

import subprocess
import sys
import re

# Run the test suite
print("Running MediVote Service Manager Test Suite...")
result = subprocess.run(
    [sys.executable, "test_service_manager_full_suite.py"],
    capture_output=True,
    text=True
)

# Extract test summary from output
output = result.stderr + result.stdout

# Find the "Ran X tests" line
ran_match = re.search(r"Ran (\d+) tests", output)
if ran_match:
    total_tests = int(ran_match.group(1))
    
    # Check if OK or FAILED
    if "OK" in output and "FAILED" not in output:
        print(f"\nSUCCESS: All {total_tests} tests passed!")
    else:
        # Count failures and errors
        failure_match = re.search(r"failures=(\d+)", output)
        error_match = re.search(r"errors=(\d+)", output)
        
        failures = int(failure_match.group(1)) if failure_match else 0
        errors = int(error_match.group(1)) if error_match else 0
        passed = total_tests - failures - errors
        
        print(f"\nFAILED:")
        print(f"  Total Tests: {total_tests}")
        print(f"  Passed: {passed}")
        print(f"  Failed: {failures}")
        print(f"  Errors: {errors}")
else:
    print("\nCould not parse test results")
    
# Exit with same code as test suite
sys.exit(result.returncode) 