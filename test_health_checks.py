#!/usr/bin/env python3
"""
Test Health Checks for MediVote System
Simple script to verify all services are responding
"""

import requests
import time
import sys

def test_health_endpoint(url, name):
    """Test a health endpoint"""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            print(f"✅ {name}: {url} - OK")
            return True
        else:
            print(f"❌ {name}: {url} - Status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ {name}: {url} - Error: {e}")
        return False

def main():
    """Test all health endpoints"""
    print("🔍 Testing MediVote System Health Checks...")
    print("=" * 50)
    
    endpoints = [
        ("Backend", "http://localhost:8001/health"),
        ("Frontend", "http://localhost:8080/"),
        ("Incentive System", "http://localhost:8082/status"),
        ("Blockchain Node", "http://localhost:8081/status"),
        ("Network Coordinator", "http://localhost:8083/status"),
        ("Network Dashboard", "http://localhost:8084/"),
    ]
    
    results = []
    for name, url in endpoints:
        result = test_health_endpoint(url, name)
        results.append((name, result))
        time.sleep(1)  # Small delay between tests
    
    print("=" * 50)
    working = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"📊 Results: {working}/{total} services responding")
    
    if working == total:
        print("🎉 All services are healthy!")
        return 0
    else:
        print("⚠️ Some services are not responding")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 