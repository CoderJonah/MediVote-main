#!/usr/bin/env python3
"""
Test Concurrent Operations
Tests the concurrent operation handling to prevent race conditions
"""

import requests
import threading
import time
import json
from datetime import datetime

def test_concurrent_operations():
    """Test concurrent operations on the same service"""
    print("🧪 TESTING CONCURRENT OPERATIONS")
    print("=" * 50)
    
    base_url = "http://localhost:8090"
    
    # Test concurrent restart operations on backend
    print("🔍 Testing concurrent restart operations on backend...")
    
    def make_restart_request():
        try:
            response = requests.post(f"{base_url}/restart/backend", timeout=30)
            return response.status_code == 200
        except Exception as e:
            print(f"❌ Restart request failed: {e}")
            return False
    
    # Start multiple concurrent restart operations
    threads = []
    results = []
    
    print("📡 Starting 5 concurrent restart operations...")
    for i in range(5):
        thread = threading.Thread(target=lambda: results.append(make_restart_request()))
        threads.append(thread)
        thread.start()
        time.sleep(0.1)  # Small delay between starts
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    success_count = sum(results)
    print(f"✅ Concurrent operations completed: {success_count}/5 successful")
    
    # Check if service is still running
    time.sleep(5)  # Wait for operations to complete
    try:
        response = requests.get(f"{base_url}/status", timeout=10)
        if response.status_code == 200:
            data = response.json()
            backend_status = data.get('backend', {}).get('status', 'unknown')
            print(f"📊 Backend status after concurrent operations: {backend_status}")
            
            if backend_status == 'running':
                print("✅ Service is running after concurrent operations")
            else:
                print("⚠️ Service is not running after concurrent operations")
        else:
            print(f"❌ Failed to get status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error checking status: {e}")
    
    # Test concurrent stop/start operations
    print("\n🔍 Testing concurrent stop/start operations on frontend...")
    
    def make_stop_request():
        try:
            response = requests.post(f"{base_url}/stop/frontend", timeout=30)
            return response.status_code == 200
        except Exception as e:
            print(f"❌ Stop request failed: {e}")
            return False
    
    def make_start_request():
        try:
            response = requests.post(f"{base_url}/start/frontend", timeout=30)
            return response.status_code == 200
        except Exception as e:
            print(f"❌ Start request failed: {e}")
            return False
    
    # Start concurrent stop and start operations
    stop_results = []
    start_results = []
    
    print("📡 Starting concurrent stop and start operations...")
    
    # Start stop operations
    stop_threads = []
    for i in range(3):
        thread = threading.Thread(target=lambda: stop_results.append(make_stop_request()))
        stop_threads.append(thread)
        thread.start()
        time.sleep(0.1)
    
    # Start start operations
    start_threads = []
    for i in range(3):
        thread = threading.Thread(target=lambda: start_results.append(make_start_request()))
        start_threads.append(thread)
        thread.start()
        time.sleep(0.1)
    
    # Wait for all threads to complete
    for thread in stop_threads + start_threads:
        thread.join()
    
    stop_success = sum(stop_results)
    start_success = sum(start_results)
    print(f"✅ Stop operations: {stop_success}/3 successful")
    print(f"✅ Start operations: {start_success}/3 successful")
    
    # Check final status
    time.sleep(5)
    try:
        response = requests.get(f"{base_url}/status", timeout=10)
        if response.status_code == 200:
            data = response.json()
            frontend_status = data.get('frontend', {}).get('status', 'unknown')
            print(f"📊 Frontend status after concurrent operations: {frontend_status}")
            
            if frontend_status == 'running':
                print("✅ Frontend is running after concurrent operations")
            else:
                print("⚠️ Frontend is not running after concurrent operations")
        else:
            print(f"❌ Failed to get status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error checking status: {e}")
    
    print("\n🎯 CONCURRENT OPERATIONS TEST COMPLETE")
    print("=" * 50)
    
    # Summary
    total_operations = len(results) + len(stop_results) + len(start_results)
    total_success = success_count + stop_success + start_success
    success_rate = (total_success / total_operations * 100) if total_operations > 0 else 0
    
    print(f"📊 SUMMARY:")
    print(f"   Total Operations: {total_operations}")
    print(f"   Successful: {total_success}")
    print(f"   Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 80:
        print("✅ CONCURRENT OPERATIONS HANDLING: EXCELLENT")
    elif success_rate >= 60:
        print("⚠️ CONCURRENT OPERATIONS HANDLING: GOOD")
    else:
        print("❌ CONCURRENT OPERATIONS HANDLING: NEEDS IMPROVEMENT")

if __name__ == "__main__":
    test_concurrent_operations() 