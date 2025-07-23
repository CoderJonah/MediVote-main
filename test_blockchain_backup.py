#!/usr/bin/env python3
"""
Test script for MediVote blockchain backup and restoration system
"""

import requests
import json
import time

def test_blockchain_backup():
    """Test the complete blockchain backup cycle"""
    base_url = "http://localhost:8001"
    
    print("🔗 TESTING BLOCKCHAIN BACKUP SYSTEM")
    print("=" * 50)
    
    # Step 1: Authenticate
    print("1. Authenticating...")
    login_data = {
        "username": "admin",
        "password": "medivote_admin_2024"
    }
    
    try:
        response = requests.post(f"{base_url}/api/auth/login", json=login_data)
        if response.status_code == 200:
            token = response.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            print("✅ Authentication successful")
        else:
            print(f"❌ Authentication failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return
    
    # Step 2: Check current system status
    print("\n2. Checking system status...")
    try:
        response = requests.get(f"{base_url}/api/system/sync-status", headers=headers)
        if response.status_code == 200:
            status = response.json()
            print(f"   Current ballots: {status['sync_status']['memory_storage']['ballots']}")
            print(f"   Current votes: {status['sync_status']['memory_storage']['votes']}")
            print(f"   Cache health: {status['sync_status']['cache_status']['cache_health']}")
            print(f"   Pending blockchain sync: {status['sync_status']['cache_status']['pending_votes']}")
        else:
            print(f"❌ Status check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Status check error: {e}")
    
    # Step 3: Create test ballot
    print("\n3. Creating blockchain test ballot...")
    ballot_data = {
        "title": "Blockchain Backup Test 2024",
        "description": "Testing blockchain vote backup and restoration system",
        "candidates": ["Alice", "Bob", "Charlie"],
        "start_time": "2025-01-01T00:00:00Z",
        "end_time": "2025-12-31T23:59:59Z"
    }
    
    try:
        response = requests.post(f"{base_url}/api/admin/create-ballot", json=ballot_data, headers=headers)
        if response.status_code == 200:
            ballot_id = response.json()["ballot_id"]
            print(f"✅ Ballot created: {ballot_id}")
        else:
            print(f"❌ Ballot creation failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Ballot creation error: {e}")
        return
    
    # Step 4: Cast test votes
    print("\n4. Casting votes for blockchain backup...")
    votes = [
        {"ballot_id": ballot_id, "choice": "Alice"},
        {"ballot_id": ballot_id, "choice": "Bob"}, 
        {"ballot_id": ballot_id, "choice": "Alice"},
        {"ballot_id": ballot_id, "choice": "Charlie"}
    ]
    
    vote_count = 0
    for vote in votes:
        try:
            response = requests.post(f"{base_url}/api/voting/cast-vote", json=vote, headers=headers)
            if response.status_code == 200:
                vote_count += 1
                print(f"   ✅ Vote {vote_count} cast: {vote['choice']}")
            else:
                print(f"   ❌ Vote failed: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Vote error: {e}")
    
    print(f"✅ {vote_count} votes cast successfully")
    
    # Step 5: Wait for blockchain sync
    print("\n5. Waiting for blockchain sync...")
    print("   (Background sync runs every 30 seconds)")
    time.sleep(35)  # Wait for sync cycle
    
    # Step 6: Check sync status
    print("\n6. Checking blockchain sync status...")
    try:
        response = requests.get(f"{base_url}/api/system/sync-status", headers=headers)
        if response.status_code == 200:
            status = response.json()
            cache_status = status['sync_status']['cache_status']
            print(f"   Total votes in cache: {cache_status['total_votes']}")
            print(f"   Synced votes: {cache_status['synced_votes']}")
            print(f"   Pending votes: {cache_status['pending_votes']}")
            print(f"   Last sync: {cache_status['last_sync']}")
            
            if cache_status['synced_votes'] > 0:
                print("🎉 BLOCKCHAIN BACKUP SUCCESS!")
                print("✅ Votes successfully synced to blockchain")
            else:
                print("⚠️ No votes synced to blockchain yet")
                print("   This may indicate blockchain service isn't fully initialized")
        else:
            print(f"❌ Status check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Status check error: {e}")
    
    print("\n" + "=" * 50)
    print("Blockchain backup test completed!")

if __name__ == "__main__":
    test_blockchain_backup() 