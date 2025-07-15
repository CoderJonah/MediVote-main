#!/usr/bin/env python3
"""
Debug script to test frontend connectivity
"""

import requests
import time

def test_frontend():
    print("🔍 DEBUGGING FRONTEND CONNECTIVITY")
    print("=" * 50)
    
    frontend_url = "http://localhost:3000"
    
    # Test main page
    try:
        print(f"Testing {frontend_url}/")
        response = requests.get(f"{frontend_url}/", timeout=10)
        print(f"  Status: {response.status_code}")
        print(f"  Has MediVote: {'MediVote' in response.text}")
        print(f"  Content length: {len(response.text)}")
        print(f"  First 200 chars: {response.text[:200]}")
    except Exception as e:
        print(f"  Error: {e}")
    
    print()
    
    # Test individual pages
    pages = [
        ("register.html", "Registration Page"),
        ("vote.html", "Voting Page"), 
        ("verify.html", "Verification Page"),
        ("results.html", "Results Page"),
        ("admin.html", "Admin Page")
    ]
    
    for page, name in pages:
        try:
            print(f"Testing {name} ({page})")
            response = requests.get(f"{frontend_url}/{page}", timeout=10)
            has_medivote = "MediVote" in response.text
            print(f"  Status: {response.status_code}")
            print(f"  Has MediVote: {has_medivote}")
            print(f"  Test Result: {'✅ PASS' if response.status_code == 200 and has_medivote else '❌ FAIL'}")
        except Exception as e:
            print(f"  Error: {e}")
            print(f"  Test Result: ❌ FAIL")
        print()

if __name__ == "__main__":
    test_frontend() 