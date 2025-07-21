#!/usr/bin/env python3
"""Test blockchain node stop operations"""

import requests
import json
import time

print("Testing Blockchain Node Stop Operations")
print("=" * 50)

# Test stopping blockchain_node_1
print("\n1. Testing STOP for blockchain_node_1...")
response = requests.post("http://localhost:8090/stop/blockchain_node_1", timeout=20)
result = response.json()
print(f"   Result: {result}")
time.sleep(3)

# Test stopping blockchain_node_2
print("\n2. Testing STOP for blockchain_node_2...")
response = requests.post("http://localhost:8090/stop/blockchain_node_2", timeout=20)
result = response.json()
print(f"   Result: {result}")
time.sleep(3)

# Check final status
print("\n3. Final Status:")
response = requests.get("http://localhost:8090/status")
status = response.json()
for service_id in ['blockchain_node_1', 'blockchain_node_2']:
    if service_id in status:
        print(f"   {status[service_id]['name']}: {status[service_id]['status']}")

print("\n✅ Blockchain stop tests completed!") 