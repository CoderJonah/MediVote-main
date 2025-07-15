#!/usr/bin/env python3
"""
Test MediVote System Components
"""

import requests
import time

def test_backend():
    """Test backend API"""
    try:
        response = requests.get("http://localhost:8001/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend API is working")
            return True
        else:
            print(f"❌ Backend API returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Backend API error: {e}")
        return False

def test_frontend():
    """Test frontend server"""
    try:
        response = requests.get("http://localhost:8080/", timeout=5)
        if response.status_code == 200:
            print("✅ Frontend server is working")
            return True
        else:
            print(f"❌ Frontend server returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Frontend server error: {e}")
        return False

def test_incentive_system():
    """Test incentive system"""
    try:
        response = requests.get("http://localhost:8082/status", timeout=5)
        if response.status_code == 200:
            print("✅ Incentive system is working")
            return True
        else:
            print(f"❌ Incentive system returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Incentive system error: {e}")
        return False

def test_blockchain_node():
    """Test blockchain node"""
    try:
        response = requests.get("http://localhost:8081/status", timeout=5)
        if response.status_code == 200:
            print("✅ Blockchain node is working")
            return True
        else:
            print(f"❌ Blockchain node returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Blockchain node error: {e}")
        return False

def main():
    """Test all components"""
    print("🧪 Testing MediVote System Components")
    print("=" * 40)
    
    tests = [
        ("Backend API", test_backend),
        ("Frontend Server", test_frontend),
        ("Incentive System", test_incentive_system),
        ("Blockchain Node", test_blockchain_node)
    ]
    
    results = []
    for name, test_func in tests:
        print(f"\nTesting {name}...")
        result = test_func()
        results.append((name, result))
    
    print("\n" + "=" * 40)
    print("📊 Test Results:")
    
    working = 0
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name}: {status}")
        if result:
            working += 1
    
    print(f"\nOverall: {working}/{len(results)} components working")
    
    if working >= 2:  # At least backend and frontend
        print("\n🎉 System is ready!")
        print("Open http://localhost:8080 in your browser to use MediVote")
    else:
        print("\n⚠️ Some components are not working properly")

if __name__ == "__main__":
    main() 