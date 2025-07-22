#!/usr/bin/env python3
"""
Simple test script to check if the service manager is working
"""

import requests
import time
import sys

def test_service_manager():
    """Test if the service manager is responding"""
    print("Testing MediVote Service Manager...")
    
    # Wait a moment for the service manager to start
    time.sleep(2)
    
    try:
        # Test basic connectivity
        print("Testing connectivity...")
        response = requests.get('http://localhost:8090/', timeout=5)
        print(f"Dashboard response: {response.status_code}")
        
        # Test status endpoint
        print("Testing status endpoint...")
        response = requests.get('http://localhost:8090/status', timeout=5)
        print(f"Status response: {response.status_code}")
        
        if response.status_code == 200:
            status_data = response.json()
            print("Service Status:")
            for service_id, info in status_data.items():
                print(f"  {service_id}: {info.get('status', 'unknown')} (PID: {info.get('pid', 'N/A')})")
            return True
        else:
            print(f"Status endpoint returned {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")
        return False
    except requests.exceptions.Timeout as e:
        print(f"Timeout error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = test_service_manager()
    if success:
        print("✅ Service manager is working!")
        sys.exit(0)
    else:
        print("❌ Service manager is not responding")
        sys.exit(1) 