#!/usr/bin/env python3
"""Test CPU monitoring with actual CPU activity"""

import time
import requests
import json
import subprocess
import threading

def create_cpu_intensive_process():
    """Create a CPU-intensive Python process"""
    print("Creating CPU-intensive process...")
    
    # Create a simple CPU-intensive script
    cpu_script = """
import time
import sys

print("CPU-intensive process started")
start_time = time.time()

# Run for 30 seconds
while time.time() - start_time < 30:
    # CPU-intensive calculation
    result = 0
    for i in range(100000):
        result += i * i * i
    print(f"CPU activity: {result}")
    time.sleep(0.1)

print("CPU-intensive process finished")
"""
    
    # Write script to file
    with open("cpu_test.py", "w") as f:
        f.write(cpu_script)
    
    # Start the process
    process = subprocess.Popen([sys.executable, "cpu_test.py"], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
    
    return process

def check_cpu_usage():
    """Check CPU usage of services"""
    try:
        data = requests.get('http://localhost:8090/status').json()
        print("\nCurrent CPU usage:")
        for service_id, info in data.items():
            cpu = info.get('cpu_percent', 'N/A')
            memory = info.get('memory_mb', 'N/A')
            print(f"  {info['name']}: {cpu}% CPU, {memory} MB")
        return data
    except Exception as e:
        print(f"Error checking status: {e}")
        return None

def monitor_cpu_changes():
    """Monitor CPU changes over time"""
    print("Monitoring CPU usage changes...")
    
    # Check initial status
    print("\n1. Initial status:")
    initial_data = check_cpu_usage()
    
    # Create CPU-intensive process
    print("\n2. Starting CPU-intensive process...")
    cpu_process = create_cpu_intensive_process()
    
    # Monitor for 15 seconds
    print("\n3. Monitoring CPU usage for 15 seconds...")
    start_time = time.time()
    while time.time() - start_time < 15:
        check_cpu_usage()
        time.sleep(2)
    
    # Stop the CPU-intensive process
    print("\n4. Stopping CPU-intensive process...")
    cpu_process.terminate()
    cpu_process.wait()
    
    # Check final status
    print("\n5. Final status:")
    final_data = check_cpu_usage()
    
    # Clean up
    try:
        import os
        os.remove("cpu_test.py")
    except:
        pass
    
    print("\n✅ CPU monitoring test complete!")

if __name__ == "__main__":
    print("Testing CPU monitoring with actual CPU activity...")
    monitor_cpu_changes() 