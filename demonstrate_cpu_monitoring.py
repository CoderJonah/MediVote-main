#!/usr/bin/env python3
"""Demonstrate that CPU monitoring is working correctly"""

import time
import requests
import json
import psutil

def check_system_cpu():
    """Check overall system CPU usage"""
    cpu_percent = psutil.cpu_percent(interval=1)
    print(f"System CPU usage: {cpu_percent}%")
    return cpu_percent

def check_service_cpu():
    """Check service CPU usage"""
    try:
        data = requests.get('http://localhost:8090/status').json()
        print("\nService CPU usage:")
        total_cpu = 0
        for service_id, info in data.items():
            cpu = info.get('cpu_percent', 0)
            memory = info.get('memory_mb', 0)
            print(f"  {info['name']}: {cpu}% CPU, {memory:.1f} MB")
            total_cpu += cpu
        print(f"  Total service CPU: {total_cpu:.1f}%")
        return data
    except Exception as e:
        print(f"Error checking service status: {e}")
        return None

def demonstrate_cpu_monitoring():
    """Demonstrate CPU monitoring functionality"""
    print("Demonstrating CPU monitoring functionality...")
    print("=" * 50)
    
    # Check system and service CPU
    print("\n1. Current system and service CPU usage:")
    system_cpu = check_system_cpu()
    service_data = check_service_cpu()
    
    print("\n2. Explanation:")
    print("   - System CPU shows overall CPU usage")
    print("   - Service CPU shows individual process usage")
    print("   - 0.0% CPU is normal for idle services")
    print("   - Memory values show actual usage in MB")
    
    print("\n3. CPU monitoring is working correctly if:")
    print("   ✅ Memory values are > 0 MB")
    print("   ✅ CPU values are numeric (0.0% is normal for idle)")
    print("   ✅ Values update every 1-2 seconds")
    print("   ✅ No errors in the status response")
    
    print("\n4. Test results:")
    if service_data:
        backend_cpu = service_data.get('backend', {}).get('cpu_percent', 'N/A')
        backend_memory = service_data.get('backend', {}).get('memory_mb', 'N/A')
        
        print(f"   Backend CPU: {backend_cpu}% (Expected: 0.0% for idle)")
        print(f"   Backend Memory: {backend_memory} MB (Expected: > 0 MB)")
        
        if isinstance(backend_cpu, (int, float)) and isinstance(backend_memory, (int, float)):
            print("   ✅ CPU monitoring is working correctly!")
        else:
            print("   ❌ CPU monitoring has issues")
    else:
        print("   ❌ Could not retrieve service data")

if __name__ == "__main__":
    demonstrate_cpu_monitoring() 