#!/usr/bin/env python3
"""
Create demo ballot data for testing the MediVote web interface
"""

import requests
import json
from datetime import datetime, timedelta

API_BASE_URL = 'http://localhost:8000'

def create_demo_ballot():
    """Create a demo ballot for testing"""
    
    # Calculate times: start now, end in 2 hours
    start_time = datetime.now()
    end_time = start_time + timedelta(hours=2)
    
    ballot_data = {
        "title": "2024 Presidential Election Demo",
        "description": "A demonstration of the MediVote secure voting system with sample candidates for testing purposes.",
        "candidates": [
            {
                "name": "Candidate A",
                "party": "Democratic Party"
            },
            {
                "name": "Bob Smith",
                "party": "Republican Party"
            },
            {
                "name": "Carol Davis",
                "party": "Green Party"
            },
            {
                "name": "David Wilson",
                "party": "Independent"
            }
        ],
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat()
    }
    
    try:
        print("🗳️  Creating demo ballot...")
        response = requests.post(f"{API_BASE_URL}/api/admin/create-ballot", json=ballot_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Demo ballot created successfully!")
            print(f"📋 Ballot ID: {result['ballot_id']}")
            print(f"📝 Title: {result['title']}")
            print(f"🗳️  Candidates: {result['candidates_count']}")
            print(f"⏰ Voting Period: {start_time.strftime('%Y-%m-%d %H:%M')} - {end_time.strftime('%Y-%m-%d %H:%M')}")
            return result
        else:
            print(f"❌ Failed to create ballot: {response.status_code}")
            print(f"Error: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend API. Make sure the backend is running on port 8000.")
        print("Please start the backend first: python backend/main.py")
        return None
    except Exception as e:
        print(f"❌ Error creating ballot: {e}")
        return None

def register_demo_voter():
    """Register a demo voter for testing"""
    
    voter_data = {
        "full_name": "Demo User",
        "email": "john.doe@example.com",
        "password": "password123",
        "phone": "(555) 123-4567",
        "address": "123 Main St, Anytown, USA 12345",
        "date_of_birth": "1990-01-01",
        "identity_document": "DL123456789"
    }
    
    try:
        print("👤 Registering demo voter...")
        response = requests.post(f"{API_BASE_URL}/api/auth/register", json=voter_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Demo voter registered successfully!")
            print(f"🆔 Voter ID: {result['voter_id']}")
            print(f"👤 Name: {voter_data['full_name']}")
            print(f"📧 Email: {voter_data['email']}")
            return result
        else:
            print(f"❌ Failed to register voter: {response.status_code}")
            print(f"Error: {response.text}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend API. Make sure the backend is running on port 8000.")
        return None
    except Exception as e:
        print(f"❌ Error registering voter: {e}")
        return None

def check_system_status():
    """Check if the backend system is running"""
    
    try:
        print("🔍 Checking system status...")
        response = requests.get(f"{API_BASE_URL}/api/status")
        
        if response.status_code == 200:
            status = response.json()
            print("✅ Backend system is running!")
            print(f"🗄️  Database: {status.get('database', 'Unknown')}")
            print(f"⛓️  Blockchain: {status.get('blockchain', 'Unknown')}")
            print(f"🔄 Cache: {status.get('cache', 'Unknown')}")
            return True
        else:
            print(f"❌ Backend system check failed: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Backend system is not running!")
        print("Please start the backend first: python backend/main.py")
        return False
    except Exception as e:
        print(f"❌ Error checking system status: {e}")
        return False

def main():
    """Main function to set up demo data"""
    
    print("🚀 MediVote Demo Setup")
    print("=" * 50)
    
    # Check system status
    if not check_system_status():
        print("\n❌ Please start the backend system first and try again.")
        return
    
    print("\n📋 Creating demo election data...")
    
    # Create demo ballot
    ballot_result = create_demo_ballot()
    if not ballot_result:
        print("\n❌ Failed to create demo ballot. Please check the backend logs.")
        return
    
    # Register demo voter
    voter_result = register_demo_voter()
    if not voter_result:
        print("\n⚠️  Failed to register demo voter, but ballot was created successfully.")
    
    print("\n🎉 Demo setup complete!")
    print("\nNext steps:")
    print("1. Start the frontend server: cd frontend && python serve.py")
    print("2. Open your browser to: http://localhost:3000")
    print("3. Try the voting interface with the demo ballot")
    print("4. Use the admin panel to create additional ballots")
    
    print("\n📊 Demo ballot details:")
    print(f"   • Title: {ballot_result['title']}")
    print(f"   • Candidates: {ballot_result['candidates_count']}")
    print(f"   • Status: {ballot_result['status']}")
    
    if voter_result:
        print(f"\n👤 Demo voter details:")
        print(f"   • Name: Demo User")
        print(f"   • Email: john.doe@example.com")
        print(f"   • Voter ID: {voter_result['voter_id']}")

if __name__ == "__main__":
    main() 