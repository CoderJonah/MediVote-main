#!/usr/bin/env python3
"""
Simple MediVote Test Script
"""

import requests
import json
import time

def test_application():
    print("🗳️  Testing MediVote Application")
    print("=" * 50)
    
    # Test 1: Health Check
    try:
        print("Testing health endpoint...")
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check: PASSED")
            try:
                data = response.json()
                print(f"   Response: {json.dumps(data, indent=2)}")
            except:
                print(f"   Raw response: {response.text}")
        else:
            print(f"❌ Health check: FAILED (Status: {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"❌ Health check: CONNECTION ERROR - {e}")
    
    print()
    
    # Test 2: API Documentation
    try:
        print("Testing API documentation...")
        response = requests.get("http://localhost:8000/docs", timeout=5)
        if response.status_code == 200:
            print("✅ API documentation: ACCESSIBLE")
            print(f"   Content length: {len(response.text)} characters")
        else:
            print(f"❌ API documentation: FAILED (Status: {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"❌ API documentation: CONNECTION ERROR - {e}")
    
    print()
    
    # Test 3: Basic endpoints
    endpoints = [
        "/",
        "/api/auth/register",
        "/api/voting/ballots",
        "/api/verification/status"
    ]
    
    for endpoint in endpoints:
        try:
            print(f"Testing {endpoint}...")
            response = requests.get(f"http://localhost:8000{endpoint}", timeout=5)
            if response.status_code in [200, 404, 405]:  # 405 is OK for GET on POST endpoints
                print(f"✅ {endpoint}: ACCESSIBLE")
            else:
                print(f"❌ {endpoint}: Status {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"❌ {endpoint}: CONNECTION ERROR - {e}")
    
    print()
    print("🎉 Basic test completed!")

if __name__ == "__main__":
    test_application() 