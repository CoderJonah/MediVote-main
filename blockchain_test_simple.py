#!/usr/bin/env python3
"""
Simple blockchain backup test for MediVote
Tests the complete blockchain backup and sync functionality
"""

import requests
import json
import time
import sys

def log(message):
    """Simple logging function"""
    print(f"[{time.strftime('%H:%M:%S')}] {message}")

def test_blockchain_backup():
    """Test blockchain backup functionality"""
    base_url = "http://localhost:8001"
    
    log("🔗 BLOCKCHAIN BACKUP TEST STARTED")
    log("=" * 50)
    
    # Step 1: Test backend connection
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            log("✅ Backend is responsive")
        else:
            log(f"❌ Backend health check failed: {response.status_code}")
            return False
    except Exception as e:
        log(f"❌ Backend connection failed: {e}")
        return False
    
    # Step 2: Authenticate
    try:
        login_data = {"username": "admin", "password": "medivote_admin_2024"}
        response = requests.post(f"{base_url}/api/auth/login", json=login_data, timeout=10)
        
        if response.status_code != 200:
            log(f"❌ Authentication failed: {response.status_code} - {response.text}")
            return False
            
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        log("✅ Authentication successful")
        
    except Exception as e:
        log(f"❌ Authentication error: {e}")
        return False
    
    # Step 3: Check initial state
    try:
        response = requests.get(f"{base_url}/api/system/sync-status", headers=headers, timeout=10)
        
        if response.status_code == 200:
            status = response.json()["sync_status"]
            log(f"📊 Initial State:")
            log(f"   Ballots: {status['memory_storage']['ballots']}")
            log(f"   Votes: {status['memory_storage']['votes']}")
            log(f"   Cache pending: {status['cache_status']['pending_votes']}")
        else:
            log(f"⚠️ Status check failed: {response.status_code}")
            
    except Exception as e:
        log(f"⚠️ Status check error: {e}")
    
    # Step 4: Create test ballot
    ballot_data = {
        "title": "Blockchain Test 2024",
        "description": "Testing blockchain backup system",
        "candidates": ["Alpha", "Beta", "Gamma"],
        "start_time": "2025-01-01T00:00:00Z",
        "end_time": "2025-12-31T23:59:59Z"
    }
    
    try:
        response = requests.post(f"{base_url}/api/admin/create-ballot", 
                               json=ballot_data, headers=headers, timeout=10)
        
        if response.status_code == 200:
            ballot_id = response.json()["ballot_id"]
            log(f"✅ Test ballot created: {ballot_id}")
        else:
            log(f"❌ Ballot creation failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        log(f"❌ Ballot creation error: {e}")
        return False
    
    # Step 5: Cast test votes
    test_votes = [
        {"ballot_id": ballot_id, "choice": "Alpha"},
        {"ballot_id": ballot_id, "choice": "Beta"},
        {"ballot_id": ballot_id, "choice": "Alpha"},
    ]
    
    vote_count = 0
    for i, vote in enumerate(test_votes, 1):
        try:
            response = requests.post(f"{base_url}/api/voting/cast-vote", 
                                   json=vote, headers=headers, timeout=10)
            
            if response.status_code == 200:
                vote_count += 1
                log(f"✅ Vote {i} cast: {vote['choice']}")
            else:
                log(f"❌ Vote {i} failed: {response.status_code} - {response.text}")
                
        except Exception as e:
            log(f"❌ Vote {i} error: {e}")
    
    log(f"📊 Successfully cast {vote_count}/{len(test_votes)} votes")
    
    # Step 6: Check data is cached
    try:
        response = requests.get(f"{base_url}/api/system/sync-status", headers=headers, timeout=10)
        
        if response.status_code == 200:
            status = response.json()["sync_status"]
            log(f"📊 After Vote Casting:")
            log(f"   Memory ballots: {status['memory_storage']['ballots']}")
            log(f"   Memory votes: {status['memory_storage']['votes']}")
            log(f"   Cache total: {status['cache_status']['total_votes']}")
            log(f"   Cache pending: {status['cache_status']['pending_votes']}")
            log(f"   Cache synced: {status['cache_status']['synced_votes']}")
            
            if status['cache_status']['total_votes'] > 0:
                log("✅ Votes are cached and ready for blockchain sync")
            else:
                log("❌ No votes in cache - blockchain sync won't work")
        else:
            log(f"❌ Status check failed: {response.status_code}")
            
    except Exception as e:
        log(f"❌ Status check error: {e}")
    
    # Step 7: Wait for blockchain sync attempt
    log("⏳ Waiting for blockchain sync cycle (30 seconds)...")
    time.sleep(35)
    
    # Step 8: Check blockchain sync results
    try:
        response = requests.get(f"{base_url}/api/system/sync-status", headers=headers, timeout=10)
        
        if response.status_code == 200:
            status = response.json()["sync_status"]
            log(f"📊 After Blockchain Sync:")
            log(f"   Cache total: {status['cache_status']['total_votes']}")
            log(f"   Cache synced: {status['cache_status']['synced_votes']}")
            log(f"   Cache pending: {status['cache_status']['pending_votes']}")
            log(f"   Last sync: {status['cache_status']['last_sync']}")
            
            synced_votes = int(status['cache_status']['synced_votes'])
            if synced_votes > 0:
                log("🎉 BLOCKCHAIN BACKUP SUCCESS!")
                log(f"✅ {synced_votes} votes synced to blockchain")
                return True
            else:
                log("⚠️ No votes synced to blockchain")
                log("   This may indicate blockchain service initialization issues")
                return False
                
        else:
            log(f"❌ Final status check failed: {response.status_code}")
            return False
            
    except Exception as e:
        log(f"❌ Final status check error: {e}")
        return False

if __name__ == "__main__":
    success = test_blockchain_backup()
    log("=" * 50)
    if success:
        log("🎉 BLOCKCHAIN BACKUP TEST PASSED")
        sys.exit(0)
    else:
        log("❌ BLOCKCHAIN BACKUP TEST FAILED")
        sys.exit(1) 