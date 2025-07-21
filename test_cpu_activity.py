#!/usr/bin/env python3
"""Test CPU monitoring by generating activity"""

import time
import requests
import json

def generate_cpu_activity():
    """Generate some CPU activity"""
    print("Generating CPU activity for 10 seconds...")
    start_time = time.time()
    
    # Generate CPU activity
    while time.time() - start_time < 10:
        # Do some CPU-intensive work
        result = 0
        for i in range(1000000):
            result += i * i
        time.sleep(0.1)  # Small delay to prevent 100% CPU
    
    print("CPU activity generation complete!")

def check_cpu_usage():
    """Check CPU usage of services"""
    try:
        data = requests.get('http://localhost:8090/status').json()
        print("\nCurrent CPU usage:")
        for service_id, info in data.items():
            cpu = info.get('cpu_percent', 'N/A')
            memory = info.get('memory_mb', 'N/A')
            print(f"  {info['name']}: {cpu}% CPU, {memory} MB")
    except Exception as e:
        print(f"Error checking status: {e}")

if __name__ == "__main__":
    print("Testing CPU monitoring...")
    
    # Check initial status
    print("\n1. Initial status:")
    check_cpu_usage()
    
    # Generate CPU activity
    print("\n2. Generating CPU activity...")
    generate_cpu_activity()
    
    # Check status after activity
    print("\n3. Status after CPU activity:")
    check_cpu_usage()
    
    print("\n✅ CPU monitoring test complete!") 