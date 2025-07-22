#!/usr/bin/env python3
"""
Test Network Discovery Fix
Verifies that network coordinator discovers blockchain nodes and network dashboard shows them
"""

import requests
import json
import time
from datetime import datetime

def test_blockchain_node_status():
    """Test that blockchain node status endpoint is working"""
    print("🔍 Testing blockchain node status...")
    try:
        response = requests.get("http://localhost:8546/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Blockchain node responding:")
            print(f"   - Node ID: {data.get('node_id', 'N/A')}")
            print(f"   - Is Running: {data.get('is_running', 'N/A')}")
            print(f"   - Blocks Processed: {data.get('blocks_processed', 0)}")
            print(f"   - Votes Processed: {data.get('votes_processed', 0)}")
            return True
        else:
            print(f"❌ Blockchain node returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Blockchain node error: {e}")
        return False

def test_network_coordinator_discovery():
    """Test that network coordinator discovers the blockchain node"""
    print("\n🔍 Testing network coordinator discovery...")
    try:
        response = requests.get("http://localhost:8083/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            nodes = data.get("nodes", [])
            active_nodes = [n for n in nodes if n.get("is_active", False)]
            
            print(f"✅ Network coordinator responding:")
            print(f"   - Total nodes discovered: {len(nodes)}")
            print(f"   - Active nodes: {len(active_nodes)}")
            
            for node in nodes:
                status = "🟢 Active" if node.get("is_active", False) else "🔴 Inactive"
                print(f"   - {node.get('node_id', 'Unknown')}: {status}")
                print(f"     Address: {node.get('address', 'N/A')}:{node.get('rpc_port', 'N/A')}")
                print(f"     Last seen: {node.get('last_seen', 'Never')}")
            
            return len(active_nodes) > 0
        else:
            print(f"❌ Network coordinator returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Network coordinator error: {e}")
        return False

def test_network_dashboard_nodes():
    """Test that network dashboard shows discovered nodes"""
    print("\n🔍 Testing network dashboard node display...")
    try:
        response = requests.get("http://localhost:8084/api/nodes", timeout=5)
        if response.status_code == 200:
            nodes = response.json()
            active_nodes = [n for n in nodes if n.get("is_active", False)]
            
            print(f"✅ Network dashboard responding:")
            print(f"   - Dashboard showing {len(nodes)} total nodes")
            print(f"   - Active nodes displayed: {len(active_nodes)}")
            
            for node in nodes:
                status = "🟢 Active" if node.get("is_active", False) else "🔴 Inactive"
                print(f"   - {node.get('node_id', 'Unknown')}: {status}")
            
            return len(active_nodes) > 0
        else:
            print(f"❌ Network dashboard returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Network dashboard error: {e}")
        return False

def test_backend_server_interface():
    """Test that backend server interface opens without delay"""
    print("\n🔍 Testing backend server interface...")
    try:
        start_time = time.time()
        response = requests.get("http://localhost:8001/api/status", timeout=5)
        response_time = time.time() - start_time
        
        if response.status_code == 200:
            print(f"✅ Backend server interface responding in {response_time:.2f}s")
            if response_time < 2.0:
                print("✅ Response time is fast (< 2 seconds)")
                return True
            else:
                print("⚠️ Response time is slow (>= 2 seconds)")
                return False
        else:
            print(f"❌ Backend server returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Backend server error: {e}")
        return False

def main():
    """Run all network discovery tests"""
    print("🧪 TESTING NETWORK DISCOVERY FIX")
    print("=" * 50)
    
    results = []
    
    # Test 1: Blockchain node status
    results.append(test_blockchain_node_status())
    
    # Test 2: Network coordinator discovery
    results.append(test_network_coordinator_discovery())
    
    # Test 3: Network dashboard showing nodes
    results.append(test_network_dashboard_nodes())
    
    # Test 4: Backend server interface speed
    results.append(test_backend_server_interface())
    
    # Summary
    passed = sum(results)
    total = len(results)
    success_rate = (passed / total) * 100
    
    print(f"\n📊 RESULTS SUMMARY:")
    print(f"   Tests passed: {passed}/{total}")
    print(f"   Success rate: {success_rate:.1f}%")
    
    if success_rate == 100:
        print("🎉 ALL TESTS PASSED! Network discovery fix successful!")
        print("🍪 Cookie earned!")
    elif success_rate >= 75:
        print("✅ Most tests passed. Network discovery mostly working.")
    else:
        print("❌ Network discovery needs more work.")
    
    return success_rate == 100

if __name__ == "__main__":
    main() 