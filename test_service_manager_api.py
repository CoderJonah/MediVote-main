#!/usr/bin/env python3
"""Test script for MediVote Service Manager API"""

import requests
import json
import time

BASE_URL = "http://localhost:8090"

def test_status():
    """Test the /status endpoint"""
    print("Testing /status endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/status")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_stop_service(service_id):
    """Test stopping a service"""
    print(f"\nTesting /stop/{service_id} endpoint...")
    try:
        response = requests.post(f"{BASE_URL}/stop/{service_id}")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Error: {data.get('error')}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_start_service(service_id):
    """Test starting a service"""
    print(f"\nTesting /start/{service_id} endpoint...")
    try:
        response = requests.post(f"{BASE_URL}/start/{service_id}")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        if response.status_code == 200:
            data = response.json()
            print(f"Success: {data.get('success')}")
            print(f"Error: {data.get('error')}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    print("MediVote Service Manager API Test")
    print("=" * 50)
    
    # Test status endpoint
    if test_status():
        print("\nStatus endpoint working!")
    
    # Wait a moment
    time.sleep(1)
    
    # Test stopping backend service
    test_stop_service("backend")
    
    # Wait for operation to complete
    time.sleep(3)
    
    # Check status again
    print("\nChecking status after stop...")
    test_status()
    
    # Test starting backend service
    test_start_service("backend")
    
    # Wait for operation to complete
    time.sleep(3)
    
    # Final status check
    print("\nFinal status check...")
    test_status()

if __name__ == "__main__":
    main() 