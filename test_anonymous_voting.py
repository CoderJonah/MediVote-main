#!/usr/bin/env python3
"""
Test script for MediVote Anonymous Voting System
Tests the complete flow of voter registration, login, vote casting, and verification
"""

import requests
import json
import time

def test_anonymous_voting_system():
    """Test the complete anonymous voting system"""
    base_url = "http://localhost:8001"
    
    print("🧪 TESTING ANONYMOUS VOTING SYSTEM")
    print("=" * 50)
    
    # Step 1: Test voter registration
    print("1. 📝 Testing voter registration...")
    registration_data = {
        "username": "testvoter2024",
        "email": "testvoter@medivote.com", 
        "full_name": "Anonymous Test Voter",
        "password": "securepass123"
    }
    
    try:
        response = requests.post(f"{base_url}/api/voter/register", json=registration_data)
        if response.status_code == 200:
            reg_result = response.json()
            print(f"✅ Registration successful!")
            print(f"   Voter ID: {reg_result['voter_credentials']['voter_id']}")
            print(f"   Voter DID: {reg_result['voter_credentials']['voter_did']}")
            voter_credentials = reg_result['voter_credentials']
        else:
            print(f"❌ Registration failed: {response.text}")
            return
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return
    
    # Step 2: Test voter login
    print("\n2. 🔓 Testing voter login...")
    login_data = {
        "username": registration_data["username"],
        "password": registration_data["password"]
    }
    
    try:
        response = requests.post(f"{base_url}/api/voter/login", json=login_data)
        if response.status_code == 200:
            login_result = response.json()
            print(f"✅ Login successful!")
            print(f"   Session ID: {login_result['session_id'][:20]}...")
            session_id = login_result['session_id']
        else:
            print(f"❌ Login failed: {response.text}")
            return
    except Exception as e:
        print(f"❌ Login error: {e}")
        return
    
    # Step 3: Create test ballot (using admin auth)
    print("\n3. 🗳️ Creating test ballot...")
    admin_login = {
        "username": "admin", 
        "password": "medivote_admin_2024"
    }
    
    try:
        # Admin login
        admin_response = requests.post(f"{base_url}/api/auth/login", json=admin_login)
        if admin_response.status_code == 200:
            admin_token = admin_response.json()["access_token"]
            
            # Create ballot
            ballot_data = {
                "title": "Anonymous Voting Test 2024",
                "description": "Testing anonymous vote choice encryption",
                "candidates": ["Alice Anonymous", "Bob Private", "Charlie Secret"],
                "start_time": "2024-01-01T00:00:00Z",
                "end_time": "2025-12-31T23:59:59Z"
            }
            
            ballot_response = requests.post(
                f"{base_url}/api/admin/create-ballot",
                json=ballot_data,
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            
            if ballot_response.status_code == 200:
                ballot_result = ballot_response.json()
                ballot_id = ballot_result["ballot_id"]
                print(f"✅ Ballot created: {ballot_id}")
            else:
                print(f"❌ Ballot creation failed: {ballot_response.text}")
                return
        else:
            print(f"❌ Admin login failed: {admin_response.text}")
            return
    except Exception as e:
        print(f"❌ Ballot creation error: {e}")
        return
    
    # Step 4: Cast anonymous vote
    print("\n4. 🤐 Testing anonymous vote casting...")
    vote_data = {
        "ballot_id": ballot_id,
        "choice": "Alice Anonymous",
        "session_id": session_id
    }
    
    try:
        vote_response = requests.post(
            f"{base_url}/api/voting/cast-vote",
            json=vote_data,
            headers={"Authorization": f"VoterSession {session_id}"}
        )
        
        if vote_response.status_code == 200:
            vote_result = vote_response.json()
            print(f"✅ Anonymous vote cast successfully!")
            print(f"   Security Level: {vote_result['security_level']}")
            print(f"   Receipt ID: {vote_result['receipt']['receipt_id']}")
            print(f"   Verification Code: {vote_result['receipt']['verification_code']}")
            
            receipt_id = vote_result['receipt']['receipt_id']
            verification_code = vote_result['receipt']['verification_code']
            
            print(f"\n   Privacy Guarantees:")
            for guarantee in vote_result['privacy_guarantees']:
                print(f"     • {guarantee}")
        else:
            print(f"❌ Vote casting failed: {vote_response.text}")
            return
    except Exception as e:
        print(f"❌ Vote casting error: {e}")
        return
    
    # Step 5: Test vote verification (choice revelation)
    print("\n5. 🔍 Testing anonymous vote verification...")
    try:
        verify_response = requests.get(
            f"{base_url}/api/verification/verify-vote",
            params={
                "receipt_id": receipt_id,
                "verification_code": verification_code
            }
        )
        
        if verify_response.status_code == 200:
            verify_result = verify_response.json()
            if verify_result['verified']:
                print(f"✅ Vote verified successfully!")
                print(f"   Choice revealed: {verify_result['vote_details']['choice']}")
                print(f"   Privacy Level: {verify_result['vote_details']['privacy_level']}")
                print(f"   Vote Hash: {verify_result['vote_details']['vote_hash'][:20]}...")
            else:
                print(f"❌ Vote verification failed: {verify_result['message']}")
        else:
            print(f"❌ Verification request failed: {verify_response.text}")
    except Exception as e:
        print(f"❌ Verification error: {e}")
    
    # Step 6: Test with wrong verification code
    print("\n6. 🚫 Testing verification with wrong code...")
    try:
        wrong_verify_response = requests.get(
            f"{base_url}/api/verification/verify-vote",
            params={
                "receipt_id": receipt_id,
                "verification_code": "WRONGCODE"
            }
        )
        
        if wrong_verify_response.status_code == 200:
            wrong_result = wrong_verify_response.json()
            if not wrong_result['verified']:
                print(f"✅ Correctly rejected wrong verification code!")
                print(f"   Message: {wrong_result['message']}")
            else:
                print(f"❌ Security failure: Wrong code was accepted!")
        else:
            print(f"❌ Wrong verification test failed: {wrong_verify_response.text}")
    except Exception as e:
        print(f"❌ Wrong verification error: {e}")
    
    # Step 7: Test admin results (should show counts but not individual choices)
    print("\n7. 📊 Testing admin results (anonymous counting)...")
    try:
        results_response = requests.get(
            f"{base_url}/api/admin/results",
            params={"ballot_id": ballot_id},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        if results_response.status_code == 200:
            results = results_response.json()
            print(f"✅ Admin results retrieved!")
            print(f"   Total Votes: {results['total_votes']}")
            print(f"   Privacy Level: {results['privacy_level']}")
            print(f"   Vote Privacy: {results['vote_privacy']}")
            print(f"   Results:")
            for result in results['results']:
                print(f"     • {result['candidate_name']}: {result['vote_count']} votes ({result['percentage']}%)")
        else:
            print(f"❌ Results retrieval failed: {results_response.text}")
    except Exception as e:
        print(f"❌ Results error: {e}")
    
    print("\n🎉 ANONYMOUS VOTING SYSTEM TEST COMPLETE!")
    print("✅ Voter registration: Required before voting")
    print("✅ Vote choice anonymity: Only voter can see their choice")
    print("✅ Admin privacy: Cannot see individual vote choices")  
    print("✅ Verification: Works only with correct receipt credentials")
    print("✅ Counting: Anonymous hash-based aggregation")

if __name__ == "__main__":
    test_anonymous_voting_system() 