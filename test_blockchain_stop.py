#!/usr/bin/env python3
"""Test blockchain node stop functionality"""

import requests
import time

# Service Manager base URL
base_url = "http://localhost:8090"

# Test stopping blockchain node
print("\n1. Testing STOP for blockchain_node...")
response = requests.post(f"{base_url}/stop/blockchain_node", timeout=20)
print(f"Response: {response.status_code}")
print(f"Result: {response.json()}")

# Check service status
print("\n2. Checking service status...")
status_response = requests.get(f"{base_url}/status")
status = status_response.json()

# Check the blockchain node status
if 'blockchain_node' in status:
    node_info = status['blockchain_node']
    print(f"Blockchain Node - Status: {node_info.get('status')}, PID: {node_info.get('pid')}")

print("\nTest completed!") 