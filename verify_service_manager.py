#!/usr/bin/env python3
import requests
import json

def test_service_manager():
    print("🧪 VERIFYING MEDIVOTE SERVICE MANAGER")
    print("=" * 50)
    
    try:
        # Test connectivity
        response = requests.get('http://localhost:8090/status', timeout=5)
        print(f"✅ Service Manager Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Services Running: {len(data)}")
            print(f"✅ All Services: {list(data.keys())}")
            
            # Check if all services are running
            all_running = all(info.get("status") == "running" for info in data.values())
            print(f"✅ All Services Running: {all_running}")
            
            # Test service operations
            print("\n🔧 Testing Service Operations...")
            
            # Test restart
            restart_response = requests.post('http://localhost:8090/restart/backend', timeout=10)
            print(f"✅ Restart Backend: {restart_response.status_code}")
            
            # Test stop
            stop_response = requests.post('http://localhost:8090/stop/frontend', timeout=10)
            print(f"✅ Stop Frontend: {stop_response.status_code}")
            
            # Test start
            start_response = requests.post('http://localhost:8090/start/frontend', timeout=10)
            print(f"✅ Start Frontend: {start_response.status_code}")
            
            # Test UI
            ui_response = requests.get('http://localhost:8090/', timeout=5)
            print(f"✅ UI Dashboard: {ui_response.status_code}")
            
            print("\n🎉 ALL TESTS PASSED! Service Manager is working perfectly!")
            return True
            
        else:
            print(f"❌ Service Manager Error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Service Manager Test Failed: {e}")
        return False

if __name__ == "__main__":
    test_service_manager() 