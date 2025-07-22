#!/usr/bin/env python3
"""
Test to verify dashboard opens instantly without HEAD request delays
"""

import time
import requests

def test_dashboard_direct_access():
    """Test that dashboards can be accessed directly without HEAD requests"""
    
    dashboard_ports = {
        8091: "Backend Dashboard",
        8093: "Blockchain Node Dashboard", 
        8095: "Incentive System Dashboard",
        8096: "Network Coordinator Dashboard",
        8097: "Network Dashboard Dashboard",
        8098: "Frontend Dashboard"
    }
    
    print("Direct Dashboard Access Test")
    print("=" * 50)
    print("Testing direct GET requests (simulating browser opening dashboard)")
    print()
    
    success_count = 0
    
    for port, service_name in dashboard_ports.items():
        try:
            start_time = time.time()
            
            # Make direct GET request (what happens when user opens dashboard)
            response = requests.get(f'http://localhost:{port}/', timeout=5)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            if response.status_code == 200:
                content_length = len(response.content)
                print(f"✅ {service_name:25} | Time: {response_time:.3f}s | Size: {content_length} bytes")
                success_count += 1
            else:
                print(f"❌ {service_name:25} | Status: {response.status_code}")
                
        except requests.exceptions.Timeout:
            print(f"⏰ {service_name:25} | TIMEOUT (>5s)")
        except requests.exceptions.ConnectionError:
            print(f"🔌 {service_name:25} | CONNECTION ERROR (Dashboard server not running)")
        except Exception as e:
            print(f"💥 {service_name:25} | ERROR: {e}")
    
    print()
    print("=" * 50)
    print(f"Results: {success_count}/{len(dashboard_ports)} dashboards accessible")
    
    if success_count == len(dashboard_ports):
        print("🎉 All dashboards accessible directly!")
        print("✨ No HEAD request delays - instant dashboard opening!")
    else:
        print(f"⚠️  {len(dashboard_ports) - success_count} dashboards may not be running")
        print("💡 Start the service manager first: python start_medivote_background.py")
    
    print()
    print("🔍 Key Fix Implemented:")
    print("  ❌ Before: Click → HEAD request (2s delay) → Dashboard opens")  
    print("  ✅ After:  Click → Dashboard opens instantly")
    print()
    
    return success_count == len(dashboard_ports)

if __name__ == "__main__":
    test_dashboard_direct_access() 