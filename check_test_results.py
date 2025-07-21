#!/usr/bin/env python3
import json
import os

# Check if the test report exists
if os.path.exists('service_manager_test_report.json'):
    with open('service_manager_test_report.json', 'r') as f:
        data = json.load(f)
    
    summary = data['summary']
    print(f"Test Results:")
    print(f"  Total Tests: {summary['total_tests']}")
    print(f"  Passed: {summary['passed_tests']}")
    print(f"  Failed: {summary['failed_tests']}")
    print(f"  Success Rate: {summary['success_rate']:.1f}%")
    print(f"  Assessment: {summary['assessment']}")
    
    # Show failed tests
    failed_tests = [r for r in data['results'] if not r['passed']]
    if failed_tests:
        print(f"\nFailed Tests:")
        for test in failed_tests:
            print(f"  • {test['category']}: {test['test']}")
            if test['details']:
                print(f"    Details: {test['details']}")
else:
    print("No test report found") 