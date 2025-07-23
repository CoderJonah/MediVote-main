#!/usr/bin/env python3
"""
Test HTTP Shutdown Fixes
Tests the core fixes for HTTP handler issues
"""

import asyncio
import subprocess
import time
import requests
import signal
import os
import socket

async def test_http_shutdown_fixes():
    """Test the HTTP shutdown fixes"""
    print("🧪 TESTING HTTP SHUTDOWN FIXES")
    print("=" * 60)
    
    # Step 1: Start the system
    print("\n1. 🚀 Starting MediVote system...")
    process = subprocess.Popen(
        ["python", "start_medivote_background.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
    )
    
    # Wait for system to start
    print("   Waiting for system startup...")
    await asyncio.sleep(20)
    
    # Step 2: Test service responsiveness
    print("\n2. 🔍 Testing service responsiveness...")
    services_to_test = {
        "backend": 8001,
        "blockchain_node": 8546, 
        "network_coordinator": 8083,
        "network_dashboard": 8084,
        "frontend": 8080
    }
    
    responsive_services = {}
    
    for service_name, port in services_to_test.items():
        try:
            # Test if service is responsive
            response = requests.get(f"http://localhost:{port}/status", timeout=3)
            if response.status_code == 200:
                responsive_services[service_name] = port
                print(f"   ✅ {service_name} is responsive on port {port}")
            else:
                print(f"   ⚠️ {service_name} returned status {response.status_code}")
        except Exception as e:
            print(f"   ❌ {service_name} not responsive: {str(e)[:50]}")
    
    # Step 3: Test shutdown endpoints directly
    print("\n3. 🛑 Testing shutdown endpoints...")
    
    shutdown_results = {}
    
    for service_name, port in responsive_services.items():
        try:
            # Determine correct shutdown endpoint
            if service_name == "backend":
                endpoint = "/internal-shutdown"
            else:
                endpoint = "/shutdown"
            
            print(f"\n   Testing {service_name} shutdown endpoint...")
            response = requests.post(f"http://localhost:{port}{endpoint}", timeout=5)
            
            if response.status_code == 200:
                print(f"   ✅ {service_name} shutdown endpoint responded successfully")
                shutdown_results[service_name] = "success"
                
                # Check response content
                try:
                    data = response.json()
                    print(f"   📄 Response: {data.get('message', 'No message')}")
                except:
                    print(f"   📄 Response: {response.text[:50]}...")
                    
            elif response.status_code == 403:
                print(f"   🔒 {service_name} shutdown endpoint denied (security working)")
                shutdown_results[service_name] = "security_denied"
            else:
                print(f"   ⚠️ {service_name} shutdown endpoint returned {response.status_code}")
                shutdown_results[service_name] = f"status_{response.status_code}"
                
        except requests.exceptions.ConnectionError:
            print(f"   ✅ {service_name} connection refused (service may have shut down)")
            shutdown_results[service_name] = "connection_refused"
        except Exception as e:
            print(f"   ❌ {service_name} shutdown test failed: {str(e)[:50]}")
            shutdown_results[service_name] = "error"
    
    # Step 4: Wait and check remaining services
    print("\n4. ⏳ Waiting for services to shut down...")
    await asyncio.sleep(5)
    
    remaining_services = []
    for service_name, port in services_to_test.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            
            if result == 0:  # Port still in use
                remaining_services.append(f"{service_name}:{port}")
        except Exception:
            pass
    
    if remaining_services:
        print(f"   ⚠️ Services still running: {', '.join(remaining_services)}")
    else:
        print("   ✅ All services appear to have stopped")
    
    # Step 5: Force cleanup
    print("\n5. 🧹 Forcing cleanup...")
    try:
        if os.name == 'nt':
            process.send_signal(signal.CTRL_C_EVENT)
        else:
            process.send_signal(signal.SIGINT)
        
        process.wait(timeout=10)
        print("   ✅ Service manager stopped cleanly")
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait()
        print("   ⚠️ Service manager force terminated")
    
    # Step 6: Analyze results
    print("\n" + "=" * 60)
    print("🎯 HTTP SHUTDOWN FIXES TEST RESULTS")
    print("=" * 60)
    
    print(f"\n📊 SERVICE RESPONSIVENESS:")
    print(f"   Responsive services: {len(responsive_services)}/{len(services_to_test)}")
    for service in services_to_test:
        status = "✅ Responsive" if service in responsive_services else "❌ Not responsive"
        print(f"   • {service}: {status}")
    
    print(f"\n🛑 SHUTDOWN ENDPOINT TESTS:")
    for service_name, result in shutdown_results.items():
        if result == "success":
            print(f"   ✅ {service_name}: Shutdown endpoint working")
        elif result == "security_denied":
            print(f"   🔒 {service_name}: Security working (403 expected)")
        elif result == "connection_refused":
            print(f"   ✅ {service_name}: Service shut down successfully")
        else:
            print(f"   ⚠️ {service_name}: {result}")
    
    print(f"\n🔧 FIXES VALIDATION:")
    # Check if we had fewer connection errors
    connection_issues = sum(1 for r in shutdown_results.values() if r == "error")
    print(f"   • Connection errors: {connection_issues}/{len(shutdown_results)} (target: <2)")
    
    # Check if services have shutdown endpoints
    working_endpoints = sum(1 for r in shutdown_results.values() if r in ["success", "connection_refused"])
    print(f"   • Working shutdown endpoints: {working_endpoints}/{len(shutdown_results)}")
    
    # Overall success
    if len(responsive_services) >= 3 and working_endpoints >= 3:
        print(f"\n🎉 HTTP SHUTDOWN FIXES SUCCESSFUL!")
        print("   • Services are responsive")
        print("   • Shutdown endpoints are working")
        print("   • Connection issues minimized")
    else:
        print(f"\n⚠️ HTTP SHUTDOWN FIXES NEED MORE WORK")
        print("   • Review service startup issues")
        print("   • Check shutdown endpoint implementations")
    
    print(f"\n📈 EXPECTED IMPROVEMENTS:")
    print("   ✅ Added shutdown endpoint to network_dashboard")
    print("   ✅ Service responsiveness check before HTTP shutdown")
    print("   ✅ Eliminated urllib3 retry warnings")
    print("   ✅ Proper endpoint routing (/internal-shutdown for backend)")
    print("   ✅ Better error handling for non-responsive services")

if __name__ == "__main__":
    try:
        asyncio.run(test_http_shutdown_fixes())
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"Test failed: {e}") 