#!/usr/bin/env python3
"""
MediVote Node Incentive System
Encourages users to run nodes by granting ballot creation privileges

Users can only create ballots if they're running a node, with clever
mechanisms to prevent abuse and encourage long-term participation.
"""

import asyncio
import json
import logging
import os
import sys
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import aiohttp
from aiohttp import web
import aiofiles
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('node_incentive.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class NodeCredential:
    """Node credential for ballot creation"""
    node_id: str
    public_key: str
    node_address: str
    node_port: int
    created_at: datetime
    last_verified: datetime
    ballot_count: int = 0
    total_uptime_hours: float = 0.0
    is_active: bool = True
    reputation_score: float = 100.0

@dataclass
class BallotRequest:
    """Ballot creation request"""
    request_id: str
    node_id: str
    ballot_data: Dict[str, Any]
    timestamp: datetime
    status: str = "pending"
    verification_attempts: int = 0

class NodeIncentiveSystem:
    """Incentive system for encouraging node participation"""
    
    def __init__(self, config_path: str = "incentive_config.json"):
        self.config_path = config_path
        self.node_credentials: Dict[str, NodeCredential] = {}
        self.ballot_requests: Dict[str, BallotRequest] = {}
        self.app = web.Application()
        self.is_running = False
        
        # Load configuration
        self.config = self._load_config()
        
        # Setup routes
        self._setup_routes()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load incentive system configuration"""
        default_config = {
            "incentive": {
                "name": "MediVote Node Incentive System",
                "port": 8082,
                "host": "0.0.0.0",
                "verification_interval": 300,  # 5 minutes
                "max_ballots_per_node": 10,
                "min_uptime_hours": 24,
                "reputation_decay_rate": 0.1,
                "reputation_boost_rate": 0.2
            },
            "verification": {
                "timeout": 10,
                "max_attempts": 3,
                "cooldown_period": 3600,  # 1 hour
                "grace_period": 1800  # 30 minutes
            },
            "reputation": {
                "min_score": 50.0,
                "max_score": 1000.0,
                "penalty_for_disconnect": 10.0,
                "bonus_for_uptime": 5.0,
                "bonus_for_ballots": 2.0
            },
            "storage": {
                "data_dir": "./incentive_data",
                "backup_interval": 3600
            }
        }
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                return default_config
        else:
            # Create default config
            with open(self.config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            return default_config
    
    def _setup_routes(self):
        """Setup web routes for the incentive system"""
        self.app.router.add_get('/', self._status_handler)
        self.app.router.add_get('/status', self._status_handler)
        self.app.router.add_post('/api/register-node', self._register_node_handler)
        self.app.router.add_post('/api/verify-node', self._verify_node_handler)
        self.app.router.add_post('/api/request-ballot', self._request_ballot_handler)
        self.app.router.add_get('/api/node-status/{node_id}', self._node_status_handler)
        self.app.router.add_get('/api/ballot-requests', self._ballot_requests_handler)
        self.app.router.add_post('/api/approve-ballot', self._approve_ballot_handler)
        self.app.router.add_get('/api/incentive-stats', self._incentive_stats_handler)
    
    async def _register_node_handler(self, request):
        """Handle node registration"""
        try:
            data = await request.json()
            
            node_id = data.get("node_id")
            public_key = data.get("public_key")
            node_address = data.get("node_address")
            node_port = data.get("node_port")
            
            if not all([node_id, public_key, node_address, node_port]):
                return web.json_response(
                    {"error": "Missing required fields"}, status=400
                )
            
            # Verify node is actually running
            if not await self._verify_node_running(node_address, node_port):
                return web.json_response(
                    {"error": "Node is not running or not accessible"}, status=400
                )
            
            # Create node credential
            credential = NodeCredential(
                node_id=node_id,
                public_key=public_key,
                node_address=node_address,
                node_port=node_port,
                created_at=datetime.utcnow(),
                last_verified=datetime.utcnow(),
                is_active=True
            )
            
            self.node_credentials[node_id] = credential
            
            # Save credentials
            await self._save_credentials()
            
            logger.info(f"Registered node: {node_id}")
            
            return web.json_response({
                "success": True,
                "node_id": node_id,
                "message": "Node registered successfully",
                "ballot_limit": self.config["incentive"]["max_ballots_per_node"],
                "min_uptime": self.config["incentive"]["min_uptime_hours"]
            })
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _verify_node_handler(self, request):
        """Handle node verification"""
        try:
            data = await request.json()
            node_id = data.get("node_id")
            
            if not node_id or node_id not in self.node_credentials:
                return web.json_response(
                    {"error": "Invalid node ID"}, status=400
                )
            
            credential = self.node_credentials[node_id]
            
            # Verify node is still running
            if not await self._verify_node_running(credential.node_address, credential.node_port):
                credential.is_active = False
                credential.reputation_score = max(
                    credential.reputation_score - self.config["reputation"]["penalty_for_disconnect"],
                    self.config["reputation"]["min_score"]
                )
                await self._save_credentials()
                
                return web.json_response({
                    "verified": False,
                    "message": "Node is not running",
                    "reputation_score": credential.reputation_score
                })
            
            # Update verification time and uptime
            now = datetime.utcnow()
            uptime_hours = (now - credential.last_verified).total_seconds() / 3600
            credential.last_verified = now
            credential.total_uptime_hours += uptime_hours
            credential.is_active = True
            
            # Boost reputation for uptime
            if uptime_hours >= 1:  # Boost for each hour of uptime
                credential.reputation_score = min(
                    credential.reputation_score + self.config["reputation"]["bonus_for_uptime"],
                    self.config["reputation"]["max_score"]
                )
            
            await self._save_credentials()
            
            return web.json_response({
                "verified": True,
                "uptime_hours": credential.total_uptime_hours,
                "reputation_score": credential.reputation_score,
                "ballots_remaining": self._calculate_ballots_remaining(credential)
            })
            
        except Exception as e:
            logger.error(f"Verification error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _request_ballot_handler(self, request):
        """Handle ballot creation request"""
        try:
            data = await request.json()
            
            node_id = data.get("node_id")
            ballot_data = data.get("ballot_data", {})
            
            if not node_id or node_id not in self.node_credentials:
                return web.json_response(
                    {"error": "Invalid node ID"}, status=400
                )
            
            credential = self.node_credentials[node_id]
            
            # Check if node meets requirements
            if not await self._check_ballot_eligibility(credential):
                return web.json_response({
                    "error": "Node does not meet ballot creation requirements",
                    "requirements": {
                        "min_uptime": self.config["incentive"]["min_uptime_hours"],
                        "min_reputation": self.config["reputation"]["min_score"],
                        "ballots_remaining": self._calculate_ballots_remaining(credential)
                    }
                }, status=400)
            
            # Create ballot request
            request_id = f"ballot_{secrets.token_hex(8)}"
            ballot_request = BallotRequest(
                request_id=request_id,
                node_id=node_id,
                ballot_data=ballot_data,
                timestamp=datetime.utcnow()
            )
            
            self.ballot_requests[request_id] = ballot_request
            
            # Verify node is still running
            if not await self._verify_node_running(credential.node_address, credential.node_port):
                return web.json_response({
                    "error": "Node must be running to create ballots"
                }, status=400)
            
            # Increment ballot count
            credential.ballot_count += 1
            
            # Boost reputation for ballot creation
            credential.reputation_score = min(
                credential.reputation_score + self.config["reputation"]["bonus_for_ballots"],
                self.config["reputation"]["max_score"]
            )
            
            await self._save_credentials()
            
            logger.info(f"Ballot request created: {request_id} by node {node_id}")
            
            return web.json_response({
                "success": True,
                "request_id": request_id,
                "message": "Ballot request created successfully",
                "reputation_score": credential.reputation_score,
                "ballots_remaining": self._calculate_ballots_remaining(credential)
            })
            
        except Exception as e:
            logger.error(f"Ballot request error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _node_status_handler(self, request):
        """Handle node status requests"""
        try:
            node_id = request.match_info['node_id']
            
            if node_id not in self.node_credentials:
                return web.json_response(
                    {"error": "Node not found"}, status=404
                )
            
            credential = self.node_credentials[node_id]
            
            # Check if node is currently running
            is_currently_running = await self._verify_node_running(
                credential.node_address, credential.node_port
            )
            
            return web.json_response({
                "node_id": node_id,
                "is_registered": True,
                "is_currently_running": is_currently_running,
                "uptime_hours": credential.total_uptime_hours,
                "reputation_score": credential.reputation_score,
                "ballot_count": credential.ballot_count,
                "ballots_remaining": self._calculate_ballots_remaining(credential),
                "created_at": credential.created_at.isoformat(),
                "last_verified": credential.last_verified.isoformat(),
                "meets_requirements": await self._check_ballot_eligibility(credential)
            })
            
        except Exception as e:
            logger.error(f"Node status error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _ballot_requests_handler(self, request):
        """Handle ballot requests listing"""
        try:
            requests_data = []
            for request_id, ballot_request in self.ballot_requests.items():
                requests_data.append({
                    "request_id": request_id,
                    "node_id": ballot_request.node_id,
                    "status": ballot_request.status,
                    "timestamp": ballot_request.timestamp.isoformat(),
                    "verification_attempts": ballot_request.verification_attempts
                })
            
            return web.json_response({
                "requests": requests_data,
                "total_requests": len(requests_data)
            })
            
        except Exception as e:
            logger.error(f"Ballot requests error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _approve_ballot_handler(self, request):
        """Handle ballot approval"""
        try:
            data = await request.json()
            request_id = data.get("request_id")
            approved = data.get("approved", False)
            
            if request_id not in self.ballot_requests:
                return web.json_response(
                    {"error": "Ballot request not found"}, status=404
                )
            
            ballot_request = self.ballot_requests[request_id]
            
            if approved:
                # Verify node is still running before approval
                node_id = ballot_request.node_id
                if node_id in self.node_credentials:
                    credential = self.node_credentials[node_id]
                    
                    if not await self._verify_node_running(credential.node_address, credential.node_port):
                        return web.json_response({
                            "error": "Cannot approve ballot - node is not running"
                        }, status=400)
                
                ballot_request.status = "approved"
                logger.info(f"Ballot request approved: {request_id}")
                
                return web.json_response({
                    "success": True,
                    "message": "Ballot request approved",
                    "ballot_data": ballot_request.ballot_data
                })
            else:
                ballot_request.status = "rejected"
                logger.info(f"Ballot request rejected: {request_id}")
                
                return web.json_response({
                    "success": True,
                    "message": "Ballot request rejected"
                })
            
        except Exception as e:
            logger.error(f"Ballot approval error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _status_handler(self, request):
        """Handle status endpoint"""
        try:
            total_nodes = len(self.node_credentials)
            active_nodes = len([c for c in self.node_credentials.values() if c.is_active])
            total_ballots = sum(c.ballot_count for c in self.node_credentials.values())
            
            return web.json_response({
                "status": "operational",
                "service": "MediVote Node Incentive System",
                "total_nodes": total_nodes,
                "active_nodes": active_nodes,
                "total_ballots_created": total_ballots,
                "timestamp": datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Status error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _incentive_stats_handler(self, request):
        """Handle incentive statistics"""
        try:
            total_nodes = len(self.node_credentials)
            active_nodes = len([c for c in self.node_credentials.values() if c.is_active])
            total_ballots = sum(c.ballot_count for c in self.node_credentials.values())
            avg_reputation = sum(c.reputation_score for c in self.node_credentials.values()) / max(total_nodes, 1)
            
            return web.json_response({
                "total_nodes": total_nodes,
                "active_nodes": active_nodes,
                "total_ballots_created": total_ballots,
                "average_reputation": round(avg_reputation, 2),
                "pending_requests": len([r for r in self.ballot_requests.values() if r.status == "pending"])
            })
            
        except Exception as e:
            logger.error(f"Incentive stats error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _verify_node_running(self, address: str, port: int) -> bool:
        """Verify that a node is actually running"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://{address}:{port}/status",
                    timeout=self.config["verification"]["timeout"]
                ) as response:
                    return response.status == 200
        except Exception:
            return False
    
    async def _check_ballot_eligibility(self, credential: NodeCredential) -> bool:
        """Check if a node is eligible to create ballots"""
        # Check minimum uptime
        if credential.total_uptime_hours < self.config["incentive"]["min_uptime_hours"]:
            return False
        
        # Check minimum reputation
        if credential.reputation_score < self.config["reputation"]["min_score"]:
            return False
        
        # Check ballot limit
        if credential.ballot_count >= self.config["incentive"]["max_ballots_per_node"]:
            return False
        
        # Check if node is currently running
        if not await self._verify_node_running(credential.node_address, credential.node_port):
            return False
        
        return True
    
    def _calculate_ballots_remaining(self, credential: NodeCredential) -> int:
        """Calculate how many ballots a node can still create"""
        return max(0, self.config["incentive"]["max_ballots_per_node"] - credential.ballot_count)
    
    async def _save_credentials(self):
        """Save node credentials to storage"""
        try:
            data_dir = Path(self.config["storage"]["data_dir"])
            data_dir.mkdir(exist_ok=True)
            
            credentials_file = data_dir / "node_credentials.json"
            credentials_data = []
            
            for credential in self.node_credentials.values():
                credential_dict = asdict(credential)
                credential_dict["created_at"] = credential.created_at.isoformat()
                credential_dict["last_verified"] = credential.last_verified.isoformat()
                credentials_data.append(credential_dict)
            
            async with aiofiles.open(credentials_file, 'w') as f:
                await f.write(json.dumps(credentials_data, indent=2))
                
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
    
    async def _load_credentials(self):
        """Load node credentials from storage"""
        try:
            data_dir = Path(self.config["storage"]["data_dir"])
            credentials_file = data_dir / "node_credentials.json"
            
            if credentials_file.exists():
                async with aiofiles.open(credentials_file, 'r') as f:
                    content = await f.read()
                    credentials_data = json.loads(content)
                    
                    for credential_data in credentials_data:
                        credential = NodeCredential(
                            node_id=credential_data["node_id"],
                            public_key=credential_data["public_key"],
                            node_address=credential_data["node_address"],
                            node_port=credential_data["node_port"],
                            created_at=datetime.fromisoformat(credential_data["created_at"]),
                            last_verified=datetime.fromisoformat(credential_data["last_verified"]),
                            ballot_count=credential_data.get("ballot_count", 0),
                            total_uptime_hours=credential_data.get("total_uptime_hours", 0.0),
                            is_active=credential_data.get("is_active", True),
                            reputation_score=credential_data.get("reputation_score", 100.0)
                        )
                        self.node_credentials[credential.node_id] = credential
                    
                    logger.info(f"Loaded {len(self.node_credentials)} node credentials")
                    
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
    
    async def start(self):
        """Start the incentive system"""
        try:
            logger.info("Starting MediVote Node Incentive System...")
            
            # Load existing credentials
            await self._load_credentials()
            
            # Start web server
            runner = web.AppRunner(self.app)
            await runner.setup()
            
            site = web.TCPSite(
                runner,
                self.config["incentive"]["host"],
                self.config["incentive"]["port"]
            )
            
            await site.start()
            
            self.is_running = True
            logger.info(f"Incentive system started on http://{self.config['incentive']['host']}:{self.config['incentive']['port']}")
            
            # Start background tasks
            asyncio.create_task(self._background_verification())
            asyncio.create_task(self._reputation_management())
            
            # Keep running
            while True:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Failed to start incentive system: {e}")
            return False
    
    async def _background_verification(self):
        """Background task to verify nodes periodically"""
        while self.is_running:
            try:
                for credential in self.node_credentials.values():
                    is_running = await self._verify_node_running(
                        credential.node_address, credential.node_port
                    )
                    
                    if is_running:
                        credential.is_active = True
                        # Boost reputation for staying online
                        credential.reputation_score = min(
                            credential.reputation_score + 0.1,
                            self.config["reputation"]["max_score"]
                        )
                    else:
                        credential.is_active = False
                        # Penalize for going offline
                        credential.reputation_score = max(
                            credential.reputation_score - self.config["reputation"]["penalty_for_disconnect"],
                            self.config["reputation"]["min_score"]
                        )
                
                await self._save_credentials()
                await asyncio.sleep(self.config["incentive"]["verification_interval"])
                
            except Exception as e:
                logger.error(f"Background verification error: {e}")
                await asyncio.sleep(60)
    
    async def _reputation_management(self):
        """Background task to manage reputation scores"""
        while self.is_running:
            try:
                for credential in self.node_credentials.values():
                    # Gradual reputation decay for inactive nodes
                    if not credential.is_active:
                        credential.reputation_score = max(
                            credential.reputation_score - self.config["reputation"]["reputation_decay_rate"],
                            self.config["reputation"]["min_score"]
                        )
                
                await self._save_credentials()
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Reputation management error: {e}")
                await asyncio.sleep(300)
    
    async def stop(self):
        """Stop the incentive system"""
        logger.info("Stopping MediVote Node Incentive System...")
        self.is_running = False
        await self._save_credentials()

async def main():
    """Main function to run the incentive system"""
    print("MediVote Node Incentive System")
    print("=" * 50)
    print("Encouraging users to run nodes for ballot creation")
    print("=" * 50)
    
    # Create and start the incentive system
    incentive_system = NodeIncentiveSystem()
    
    try:
        # Start the incentive system
        if await incentive_system.start():
            print("Incentive system started successfully!")
            print(f"URL: http://localhost:{incentive_system.config['incentive']['port']}")
            print("\nPress Ctrl+C to stop the incentive system")
            
            # Keep the incentive system running
            while True:
                await asyncio.sleep(1)
                
        else:
            print("Failed to start incentive system")
            return 1
            
    except KeyboardInterrupt:
        print("\nStopping incentive system...")
        await incentive_system.stop()
        print("Incentive system stopped")
        return 0
        
    except Exception as e:
        print(f"Error running incentive system: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 