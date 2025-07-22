#!/usr/bin/env python3
"""
Test script to verify dashboard pages load quickly without hanging
"""

import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor

def test_dashboard_loading(port, service_name):
    """Test loading a dashboard page and measure response time"""
    try:
        start_time = time.time()
        
        # Make request with timeout to prevent hanging
        response = requests.get(f'http://localhost:{port}/', timeout=10)
        
        end_time = time.time()
        response_time = end_time - start_time
        
        if response.status_code == 200:
            content_length = len(response.content)
            print(f"✅ {service_name:25} | Port: {port} | Time: {response_time:.3f}s | Size: {content_length} bytes")
            return True
        else:
            print(f"❌ {service_name:25} | Port: {port} | Status: {response.status_code}")
            return False
            
    except requests.exceptions.Timeout:
        print(f"⏰ {service_name:25} | Port: {port} | TIMEOUT (>10s)")
        return False
    except requests.exceptions.ConnectionError:
        print(f"🔌 {service_name:25} | Port: {port} | CONNECTION ERROR")
        return False
    except Exception as e:
        print(f"💥 {service_name:25} | Port: {port} | ERROR: {e}")
        return False

def test_head_request(port, service_name):
    """Test HEAD request handling - this is the key fix for dashboard hanging"""
    try:
        start_time = time.time()
        
        # Make HEAD request (this is what openDashboard() does)
        response = requests.head(f'http://localhost:{port}/', timeout=5)
        
        end_time = time.time()
        response_time = end_time - start_time
        
        if response.status_code == 200:
            print(f"✅ {service_name:25} | HEAD: {response_time:.3f}s | Status: {response.status_code}")
            return True
        else:
            print(f"❌ {service_name:25} | HEAD: Status {response.status_code}")
            return False
    except requests.exceptions.Timeout:
        print(f"⏰ {service_name:25} | HEAD: TIMEOUT (>5s) - THIS WAS THE ISSUE!")
        return False
    except Exception as e:
        print(f"💥 {service_name:25} | HEAD ERROR: {e}")
        return False

def test_favicon(port, service_name):
    """Test favicon handling"""
    try:
        response = requests.get(f'http://localhost:{port}/favicon.ico', timeout=5)
        if response.status_code == 204:
            print(f"✅ {service_name:25} | Favicon: 204 No Content")
            return True
        else:
            print(f"❌ {service_name:25} | Favicon: {response.status_code}")
            return False
    except Exception as e:
        print(f"💥 {service_name:25} | Favicon ERROR: {e}")
        return False

def test_multiple_requests(port, service_name, num_requests=3):
    """Test multiple concurrent requests to check for hanging"""
    print(f"🔄 Testing {num_requests} concurrent requests to {service_name}...")
    
    def single_request():
        try:
            start_time = time.time()
            response = requests.get(f'http://localhost:{port}/', timeout=5)
            end_time = time.time()
            return response.status_code == 200, end_time - start_time
        except:
            return False, float('inf')
    
    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [executor.submit(single_request) for _ in range(num_requests)]
        results = [future.result() for future in futures]
    
    successful = sum(1 for success, _ in results if success)
    avg_time = sum(time for _, time in results if time != float('inf')) / len(results)
    
    print(f"   {successful}/{num_requests} successful, avg time: {avg_time:.3f}s")
    return successful == num_requests

def main():
    """Main test function"""
    print("Dashboard Loading Test")
    print("=" * 60)
    
    # Dashboard ports to test
    dashboard_ports = {
        8091: "Backend Dashboard",
        8093: "Blockchain Node Dashboard", 
        8095: "Incentive System Dashboard",
        8096: "Network Coordinator Dashboard",
        8097: "Network Dashboard Dashboard",
        8098: "Frontend Dashboard"
    }
    
    # Test basic loading
    print("\n🚀 Testing Basic Dashboard Loading:")
    print("-" * 60)
    success_count = 0
    
    for port, service_name in dashboard_ports.items():
        if test_dashboard_loading(port, service_name):
            success_count += 1
    
    # Test HEAD request handling (key fix)
    print(f"\n🔍 Testing HEAD Request Handling (Dashboard Hanging Fix):")
    print("-" * 60)
    head_success = 0
    
    for port, service_name in dashboard_ports.items():
        if test_head_request(port, service_name):
            head_success += 1
    
    # Test favicon handling
    print(f"\n🖼️  Testing Favicon Handling:")
    print("-" * 60)
    favicon_success = 0
    
    for port, service_name in dashboard_ports.items():
        if test_favicon(port, service_name):
            favicon_success += 1
    
    # Test concurrent requests
    print(f"\n⚡ Testing Concurrent Requests (Anti-Hang Test):")
    print("-" * 60)
    concurrent_success = 0
    
    for port, service_name in list(dashboard_ports.items())[:2]:  # Test first 2 services
        if test_multiple_requests(port, service_name):
            concurrent_success += 1
    
    # Final results
    print(f"\n📊 Test Results:")
    print("=" * 60)
    print(f"Basic Loading:      {success_count}/{len(dashboard_ports)} ({'✅ PASS' if success_count == len(dashboard_ports) else '❌ FAIL'})")
    print(f"HEAD Requests:      {head_success}/{len(dashboard_ports)} ({'✅ PASS' if head_success == len(dashboard_ports) else '❌ FAIL'}) - KEY FIX")
    print(f"Favicon Handling:   {favicon_success}/{len(dashboard_ports)} ({'✅ PASS' if favicon_success == len(dashboard_ports) else '❌ FAIL'})")
    print(f"Concurrent Requests: {concurrent_success}/2 ({'✅ PASS' if concurrent_success == 2 else '❌ FAIL'})")
    
    overall_success = (success_count == len(dashboard_ports) and 
                      head_success == len(dashboard_ports) and
                      favicon_success == len(dashboard_ports) and 
                      concurrent_success == 2)
    
    print(f"\n🏆 Overall Result: {'✅ ALL TESTS PASSED' if overall_success else '❌ SOME TESTS FAILED'}")
    
    if overall_success:
        print("🎉 Dashboard hanging issues should be resolved!")
        print("✨ HEAD request handling fix implemented successfully!")
    else:
        print("⚠️  Some issues remain - check failed tests above.")
        if head_success != len(dashboard_ports):
            print("🔍 HEAD request handling may still be causing dashboard hanging!")

if __name__ == "__main__":
    main() 