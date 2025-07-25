"""
Performance and Load Tests for MediVote API

Uses Locust for load testing and performance benchmarking.
Referenced in CI configuration for automated performance testing.
"""

from locust import HttpUser, task, between
import json
import random
import string
from datetime import datetime, timedelta


class MediVoteAPIUser(HttpUser):
    """Simulated user for MediVote API load testing"""
    
    wait_time = between(1, 3)  # Wait 1-3 seconds between requests
    
    def on_start(self):
        """Initialize user session"""
        self.auth_token = None
        self.session_id = None
        self.user_credentials = self.generate_test_credentials()
        
        # Try to authenticate if possible
        self.authenticate_admin()
    
    def generate_test_credentials(self):
        """Generate random test credentials"""
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return {
            "username": f"test_user_{random_suffix}",
            "password": "TestPassword123!@#",
            "email": f"test_{random_suffix}@example.com",
            "device_fingerprint": {
                "browser": "LoadTest",
                "os": "TestOS",
                "screen": "1920x1080"
            }
        }
    
    def authenticate_admin(self):
        """Attempt admin authentication"""
        try:
            login_data = {
                "username": "admin",
                "password": "TempAdmin123!@#",
                "device_fingerprint": self.user_credentials["device_fingerprint"]
            }
            
            response = self.client.post(
                "/api/admin/auth/login",
                json=login_data,
                name="admin_login"
            )
            
            if response.status_code == 200:
                session_data = response.json()
                self.auth_token = session_data.get("access_token")
                self.session_id = session_data.get("session_id")
        except Exception:
            # Authentication failed, continue without auth
            pass
    
    @task(1)
    def health_check(self):
        """Test health check endpoint"""
        self.client.get("/health", name="health_check")
    
    @task(2)
    def api_status(self):
        """Test API status endpoint"""
        self.client.get("/api/status", name="api_status")
    
    @task(3)
    def get_ballots(self):
        """Test ballot retrieval"""
        self.client.get("/api/voting/ballots", name="get_ballots")
    
    @task(2)
    def voter_registration(self):
        """Test voter registration endpoint"""
        registration_data = {
            **self.user_credentials,
            "full_name": f"Test User {random.randint(1000, 9999)}",
            "date_of_birth": "1990-01-01",
            "address": "123 Test Street, Test City"
        }
        
        self.client.post(
            "/api/auth/register",
            json=registration_data,
            name="voter_registration"
        )
    
    @task(1)
    def admin_system_stats(self):
        """Test admin system statistics (requires authentication)"""
        if self.auth_token:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            self.client.get(
                "/api/admin/system/stats",
                headers=headers,
                name="admin_system_stats"
            )
        else:
            # Test unauthenticated access (should return 401)
            self.client.get(
                "/api/admin/system/stats",
                name="admin_system_stats_unauth"
            )
    
    @task(2)
    def vote_verification(self):
        """Test vote verification endpoint"""
        # Generate fake receipt data for testing
        fake_receipt_id = f"receipt_{random.randint(100000, 999999)}"
        fake_verification_code = f"verify_{random.randint(1000, 9999)}"
        
        self.client.get(
            f"/api/verification/verify-vote?receipt_id={fake_receipt_id}&verification_code={fake_verification_code}",
            name="vote_verification"
        )
    
    @task(1)
    def ballot_creation(self):
        """Test ballot creation (admin only)"""
        if self.auth_token:
            ballot_data = {
                "title": f"Test Election {random.randint(1000, 9999)}",
                "description": "Load test election ballot",
                "candidates": [
                    {"name": "Candidate A", "description": "First test candidate"},
                    {"name": "Candidate B", "description": "Second test candidate"}
                ],
                "start_date": datetime.now().isoformat(),
                "end_date": (datetime.now() + timedelta(days=7)).isoformat()
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            self.client.post(
                "/api/admin/create-ballot",
                json=ballot_data,
                headers=headers,
                name="ballot_creation"
            )
    
    @task(1)
    def cast_vote(self):
        """Test vote casting"""
        vote_data = {
            "ballot_id": f"test_ballot_{random.randint(1, 100)}",
            "choices": {
                f"candidate_{random.choice(['a', 'b', 'c'])}": 1
            },
            "voter_proof": "test_proof_data"
        }
        
        self.client.post(
            "/api/voting/cast-vote",
            json=vote_data,
            name="cast_vote"
        )


class MediVoteVoterUser(HttpUser):
    """Simulated voter user for realistic voting scenarios"""
    
    wait_time = between(5, 15)  # Voters take more time between actions
    
    def on_start(self):
        """Initialize voter session"""
        self.voter_credentials = None
        self.session_token = None
        self.register_and_login()
    
    def register_and_login(self):
        """Register as a voter and login"""
        # Generate unique voter credentials
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        registration_data = {
            "username": f"voter_{random_suffix}",
            "password": "VoterPass123!",
            "email": f"voter_{random_suffix}@example.com",
            "full_name": f"Voter {random_suffix.upper()}",
            "date_of_birth": f"19{random.randint(60, 99)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
        }
        
        # Register
        register_response = self.client.post(
            "/api/voter/register",
            json=registration_data,
            name="voter_register"
        )
        
        if register_response.status_code == 200:
            self.voter_credentials = registration_data
            
            # Login
            login_data = {
                "username": registration_data["username"],
                "password": registration_data["password"]
            }
            
            login_response = self.client.post(
                "/api/voter/login",
                json=login_data,
                name="voter_login"
            )
            
            if login_response.status_code == 200:
                session_data = login_response.json()
                self.session_token = session_data.get("session_token")
    
    @task(3)
    def browse_ballots(self):
        """Browse available ballots"""
        self.client.get("/api/voting/ballots", name="voter_browse_ballots")
    
    @task(2)
    def view_ballot_details(self):
        """View detailed ballot information"""
        ballot_id = f"ballot_{random.randint(1, 10)}"
        self.client.get(
            f"/api/voting/ballots/{ballot_id}",
            name="voter_view_ballot_details"
        )
    
    @task(1)
    def cast_vote_realistic(self):
        """Cast a vote with realistic voter behavior"""
        if self.session_token:
            # Simulate voter thinking time
            import time
            time.sleep(random.uniform(2, 8))  # 2-8 seconds to "read" ballot
            
            vote_data = {
                "ballot_id": f"ballot_{random.randint(1, 5)}",
                "choices": {
                    f"candidate_{random.choice(['a', 'b', 'c'])}": 1
                },
                "session_token": self.session_token
            }
            
            self.client.post(
                "/api/voting/cast-vote",
                json=vote_data,
                name="voter_cast_vote"
            )
    
    @task(1)
    def verify_vote(self):
        """Verify cast vote"""
        if self.session_token:
            # Generate verification request
            verification_data = {
                "receipt_id": f"receipt_{random.randint(100000, 999999)}",
                "verification_code": f"code_{random.randint(1000, 9999)}"
            }
            
            self.client.post(
                "/api/verification/verify-vote",
                json=verification_data,
                name="voter_verify_vote"
            )


class MediVoteAdminUser(HttpUser):
    """Simulated admin user for administrative operations"""
    
    wait_time = between(2, 8)  # Admins work at medium pace
    
    def on_start(self):
        """Initialize admin session"""
        self.auth_token = None
        self.authenticate()
    
    def authenticate(self):
        """Authenticate as admin"""
        login_data = {
            "username": "admin",
            "password": "TempAdmin123!@#",
            "device_fingerprint": {
                "browser": "AdminBrowser",
                "os": "AdminOS"
            }
        }
        
        response = self.client.post(
            "/api/admin/auth/login",
            json=login_data,
            name="admin_authenticate"
        )
        
        if response.status_code == 200:
            session_data = response.json()
            self.auth_token = session_data.get("access_token")
    
    @task(3)
    def monitor_system_stats(self):
        """Monitor system statistics"""
        if self.auth_token:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            self.client.get(
                "/api/admin/system/stats",
                headers=headers,
                name="admin_monitor_stats"
            )
    
    @task(2)
    def view_audit_logs(self):
        """View system audit logs"""
        if self.auth_token:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            self.client.get(
                "/api/admin/system/audit-logs",
                headers=headers,
                name="admin_view_audit_logs"
            )
    
    @task(1)
    def manage_elections(self):
        """Manage elections and ballots"""
        if self.auth_token:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            
            # List elections
            self.client.get(
                "/api/admin/elections",
                headers=headers,
                name="admin_list_elections"
            )
            
            # Create new election (occasionally)
            if random.random() < 0.1:  # 10% chance
                election_data = {
                    "name": f"Load Test Election {random.randint(1000, 9999)}",
                    "description": "Performance test election",
                    "start_date": datetime.now().isoformat(),
                    "end_date": (datetime.now() + timedelta(days=1)).isoformat(),
                    "candidates": [
                        {"name": "Test Candidate A", "description": "First candidate"},
                        {"name": "Test Candidate B", "description": "Second candidate"}
                    ]
                }
                
                self.client.post(
                    "/api/admin/elections/create",
                    json=election_data,
                    headers=headers,
                    name="admin_create_election"
                )


# Custom test scenarios for specific load patterns
class PeakVotingUser(HttpUser):
    """Simulates peak voting hours with high concurrent load"""
    
    wait_time = between(0.5, 2)  # Very active users during peak hours
    weight = 3  # Higher weight = more of these users
    
    @task(5)
    def rapid_vote_casting(self):
        """Rapid vote casting during peak hours"""
        vote_data = {
            "ballot_id": f"peak_ballot_{random.randint(1, 3)}",
            "choices": {f"candidate_{random.choice(['x', 'y'])}": 1}
        }
        
        self.client.post(
            "/api/voting/cast-vote",
            json=vote_data,
            name="peak_voting"
        )
    
    @task(2)
    def check_results(self):
        """Check election results frequently"""
        ballot_id = f"peak_ballot_{random.randint(1, 3)}"
        self.client.get(
            f"/api/elections/{ballot_id}/results",
            name="peak_results_check"
        )


if __name__ == "__main__":
    import os
    import sys
    
    # Add parent directory to Python path for imports
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    
    # This file can be run directly for testing individual components
    print("MediVote Performance Test Suite")
    print("Use 'locust -f locustfile.py' to run load tests")
    print("Example: locust -f locustfile.py --headless --users 10 --spawn-rate 1 --run-time 60s") 