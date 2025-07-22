#!/usr/bin/env python3
"""
Test Auto-Recovery Control Functionality
"""

import requests
import time
import json

def test_auto_recovery_control():
    """Test auto-recovery enable/disable functionality"""
    print("🧪 TESTING AUTO-RECOVERY CONTROL")
    print("=" * 50)
    
    base_url = "http://localhost:8090"
    
    # Test 1: Get initial auto-recovery status
    print("\n1. Testing GET /auto-recovery endpoint...")
    try:
        response = requests.get(f"{base_url}/auto-recovery", timeout=10)
        if response.status_code == 200:
            status = response.json()
            print(f"✅ Auto-recovery status retrieved: {len(status)} services")
            for service_id, enabled in status.items():
                print(f"   • {service_id}: {'ON' if enabled else 'OFF'}")
        else:
            print(f"❌ Failed to get auto-recovery status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error getting auto-recovery status: {e}")
        return False
    
    # Test 2: Enable auto-recovery for backend
    print("\n2. Testing enable auto-recovery for backend...")
    try:
        response = requests.post(f"{base_url}/auto-recovery/enable/backend", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("✅ Auto-recovery enabled for backend")
            else:
                print(f"❌ Failed to enable auto-recovery: {data.get('error')}")
                return False
        else:
            print(f"❌ Failed to enable auto-recovery: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error enabling auto-recovery: {e}")
        return False
    
    # Test 3: Verify auto-recovery is enabled
    print("\n3. Verifying auto-recovery is enabled...")
    try:
        response = requests.get(f"{base_url}/auto-recovery", timeout=10)
        if response.status_code == 200:
            status = response.json()
            if status.get('backend', False):
                print("✅ Auto-recovery confirmed enabled for backend")
            else:
                print("❌ Auto-recovery not enabled for backend")
                return False
        else:
            print(f"❌ Failed to verify auto-recovery status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error verifying auto-recovery status: {e}")
        return False
    
    # Test 4: Disable auto-recovery for backend
    print("\n4. Testing disable auto-recovery for backend...")
    try:
        response = requests.post(f"{base_url}/auto-recovery/disable/backend", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("✅ Auto-recovery disabled for backend")
            else:
                print(f"❌ Failed to disable auto-recovery: {data.get('error')}")
                return False
        else:
            print(f"❌ Failed to disable auto-recovery: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error disabling auto-recovery: {e}")
        return False
    
    # Test 5: Verify auto-recovery is disabled
    print("\n5. Verifying auto-recovery is disabled...")
    try:
        response = requests.get(f"{base_url}/auto-recovery", timeout=10)
        if response.status_code == 200:
            status = response.json()
            if not status.get('backend', True):
                print("✅ Auto-recovery confirmed disabled for backend")
            else:
                print("❌ Auto-recovery still enabled for backend")
                return False
        else:
            print(f"❌ Failed to verify auto-recovery status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error verifying auto-recovery status: {e}")
        return False
    
    # Test 6: Test invalid service
    print("\n6. Testing invalid service...")
    try:
        response = requests.post(f"{base_url}/auto-recovery/enable/invalid_service", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if not data.get('success'):
                print("✅ Invalid service correctly rejected")
            else:
                print("❌ Invalid service should have been rejected")
                return False
        else:
            print(f"❌ Unexpected response for invalid service: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error testing invalid service: {e}")
        return False
    
    print("\n🎯 AUTO-RECOVERY CONTROL TEST: ✅ PASS")
    return True

if __name__ == "__main__":
    success = test_auto_recovery_control()
    exit(0 if success else 1) 