#!/usr/bin/env python3
"""
MediVote Blockchain Node
Standalone blockchain node for decentralized voting network

Users can download and run this to participate in the MediVote network,
making the network more powerful and decentralized.
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import hashlib
import secrets
import threading
from pathlib import Path
import aiohttp
from aiohttp import web

# Add the backend/core directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend', 'core'))

try:
    from blockchain import BlockchainService, BlockchainTransaction, VoteTransaction
    from config import get_settings
    BLOCKCHAIN_AVAILABLE = True
    print("SUCCESS: Blockchain dependencies imported successfully")
except ImportError as e:
    BLOCKCHAIN_AVAILABLE = False
    print(f"Warning: Blockchain dependencies not available. Using mock mode. ImportError: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('blockchain_node.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class NodeInfo:
    """Information about this blockchain node"""
    node_id: str
    version: str = "1.0.0"
    network_id: str = "medivote_mainnet"
    node_type: str = "full_node"
    last_sync: Optional[datetime] = None
    peers_connected: int = 0
    blocks_processed: int = 0
    votes_processed: int = 0

@dataclass
class NetworkPeer:
    """Information about a network peer"""
    peer_id: str
    address: str
    port: int
    last_seen: datetime
    is_active: bool = True
    node_type: str = "full_node"

class MediVoteBlockchainNode:
    """Standalone blockchain node for MediVote network"""
    
    def __init__(self, config_path: str = "node_config.json"):
        self.config_path = config_path
        self.node_info = NodeInfo(
            node_id=self._generate_node_id(),
            last_sync=datetime.utcnow()
        )
        self.peers: Dict[str, NetworkPeer] = {}
        self.blockchain_service: Optional[BlockchainService] = None
        self.is_running = False
        self.sync_thread: Optional[threading.Thread] = None
        self.start_time = datetime.utcnow()
        
        # Load or create configuration
        self.config = self._load_config()
        
        # Initialize blockchain service
        if BLOCKCHAIN_AVAILABLE:
            self.blockchain_service = BlockchainService()
        else:
            logger.warning("Blockchain service not available. Running in mock mode.")
    
    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        return f"node_{secrets.token_hex(8)}"
    
    def _load_config(self) -> Dict[str, Any]:
        """Load or create node configuration"""
        default_config = {
            "node": {
                "name": f"MediVote Node {self.node_info.node_id[:8]}",
                "port": 8545,
                "rpc_port": 8546,
                "max_peers": 50,
                "sync_interval": 30,
                "block_time": 15,
                "register_with_incentive_system": False,
                "incentive_system_url": "http://localhost:8082"
            },
            "network": {
                "bootstrap_nodes": [
                    "node1.medivote.net:8545",
                    "node2.medivote.net:8545",
                    "node3.medivote.net:8545"
                ],
                "network_id": "medivote_mainnet",
                "genesis_block": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "blockchain": {
                "rpc_url": "http://localhost:8545",
                "private_key": None,  # Will be generated if not provided
                "gas_limit": 3000000,
                "gas_price": "20 gwei"
            },
            "storage": {
                "data_dir": "./blockchain_data",
                "backup_interval": 3600,
                "max_storage_gb": 10
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
    
    async def initialize(self):
        """Initialize the blockchain node"""
        try:
            logger.info(f"Initializing MediVote Blockchain Node: {self.node_info.node_id}")
            
            # Create data directory
            data_dir = Path(self.config["storage"]["data_dir"])
            data_dir.mkdir(exist_ok=True)
            
            # Initialize blockchain service
            if self.blockchain_service:
                await self.blockchain_service.initialize()
                logger.info("Blockchain service initialized")
            
            # Initialize peer discovery
            await self._initialize_peer_discovery()
            
            # Start sync process
            await self._start_sync_process()
            
            logger.info("Blockchain node initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize blockchain node: {e}")
            return False
    
    async def _initialize_peer_discovery(self):
        """Initialize peer discovery and connection"""
        logger.info("Initializing peer discovery...")
        
        # Connect to bootstrap nodes
        for bootstrap_node in self.config["network"]["bootstrap_nodes"]:
            try:
                host, port = bootstrap_node.split(":")
                peer = NetworkPeer(
                    peer_id=f"bootstrap_{host}",
                    address=host,
                    port=int(port),
                    last_seen=datetime.utcnow()
                )
                self.peers[peer.peer_id] = peer
                logger.info(f"Added bootstrap peer: {bootstrap_node}")
            except Exception as e:
                logger.warning(f"Failed to add bootstrap peer {bootstrap_node}: {e}")
    
    async def _start_sync_process(self):
        """Start blockchain synchronization process"""
        self.sync_thread = threading.Thread(target=self._sync_worker, daemon=True)
        self.sync_thread.start()
        logger.info("Blockchain sync process started")
    
    def _sync_worker(self):
        """Background worker for blockchain synchronization"""
        while self.is_running:
            try:
                # Sync with peers
                self._sync_with_peers()
                
                # Process new blocks
                self._process_new_blocks()
                
                # Update node info
                self.node_info.last_sync = datetime.utcnow()
                self.node_info.peers_connected = len([p for p in self.peers.values() if p.is_active])
                
                time.sleep(self.config["node"]["sync_interval"])
                
            except Exception as e:
                logger.error(f"Sync worker error: {e}")
                time.sleep(10)
    
    def _sync_with_peers(self):
        """Sync blockchain state with peers"""
        # This would implement actual peer-to-peer synchronization
        # For now, we'll simulate the process
        logger.debug("Syncing with peers...")
    
    def _process_new_blocks(self):
        """Process new blocks from the blockchain"""
        # This would implement actual block processing
        # For now, we'll simulate the process
        logger.debug("Processing new blocks...")
    
    async def start(self):
        """Start the blockchain node"""
        try:
            logger.info("Starting MediVote Blockchain Node...")
            
            # Initialize the node
            if not await self.initialize():
                return False
            
            self.is_running = True
            
            # Start RPC server as background task and store reference
            self.rpc_task = asyncio.create_task(self._start_rpc_server())
            
            # Register with incentive system if configured
            if self.config.get("node", {}).get("register_with_incentive_system", False):
                asyncio.create_task(self._register_with_incentive_system())
            
            logger.info("Blockchain node started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start blockchain node: {e}")
            return False
    
    async def _start_rpc_server(self):
        """Start RPC server for node communication"""
        try:
            app = web.Application()
            
            async def status_handler(request):
                return web.json_response(self.get_node_status())
            
            async def peers_handler(request):
                peers_data = []
                for peer in self.peers.values():
                    peers_data.append({
                        "peer_id": peer.peer_id,
                        "address": peer.address,
                        "port": peer.port,
                        "is_active": peer.is_active,
                        "last_seen": peer.last_seen.isoformat() if peer.last_seen else None,
                        "node_type": peer.node_type
                    })
                return web.json_response(peers_data)
        
            async def shutdown_handler(request):
                """Handle graceful shutdown request"""
                try:
                    # Check if this is a local request (for security)
                    client_ip = request.remote
                    if client_ip not in ["127.0.0.1", "localhost", "::1"]:
                        return web.json_response({"error": "Unauthorized"}, status=403)
                    
                    logger.warning("Received shutdown request - Node will lose credibility points!")
                    
                    # Return warning about credibility loss
                    response_data = {
                        "message": "Blockchain node shutdown initiated",
                        "status": "shutting_down",
                        "warning": "Shutting down this node will result in loss of credibility points and network participation rewards.",
                        "credibility_impact": "You will lose accumulated credibility points and may need to re-establish trust in the network.",
                        "recommendation": "Consider running the node continuously to maintain network participation and earn rewards.",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    # Send response immediately
                    response = web.json_response(response_data, status=200)
                    
                    # Schedule graceful shutdown after response is sent
                    async def delayed_shutdown():
                        await asyncio.sleep(0.3)  # Brief delay to ensure response is sent
                        await self._graceful_shutdown()
                        # Signal shutdown via SIGTERM
                        import os
                        import signal
                        os.kill(os.getpid(), signal.SIGTERM)
                    
                    # Schedule shutdown
                    asyncio.create_task(delayed_shutdown())
                    
                    return response
                    
                except Exception as e:
                    logger.error(f"Error in shutdown handler: {e}")
                    return web.json_response({"error": str(e)}, status=500)
            
            async def root_handler(request):
                """Root handler that displays node information"""
                status = self.get_node_status()
                # Calculate uptime
                uptime_seconds = int((datetime.utcnow() - self.start_time).total_seconds()) if hasattr(self, 'start_time') else 0
                running_status = "Running" if status.get('is_running', False) else "Stopped"
                html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>MediVote Blockchain Node</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 10px; }}
        h1 {{ color: #667eea; }}
        .info {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .status {{ color: #28a745; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>MediVote Blockchain Node</h1>
        <div class="info">
            <h2>Node Information</h2>
            <p><strong>Node ID:</strong> {status.get('node_id', 'N/A')}</p>
            <p><strong>Network:</strong> {status.get('network_id', 'N/A')}</p>
            <p><strong>Status:</strong> <span class="status">{running_status}</span></p>
            <p><strong>Connected Peers:</strong> {status.get('peers_connected', 0)}</p>
            <p><strong>Uptime:</strong> {uptime_seconds} seconds</p>
            <p><strong>Blocks Processed:</strong> {status.get('blocks_processed', 0)}</p>
            <p><strong>Votes Processed:</strong> {status.get('votes_processed', 0)}</p>
        </div>
        <div class="info">
            <h2>Available Endpoints</h2>
            <ul>
                <li><a href="/status">/status</a> - Get node status (JSON)</li>
                <li><a href="/peers">/peers</a> - Get connected peers (JSON)</li>
            </ul>
        </div>
    </div>
</body>
</html>
                """
                return web.Response(text=html, content_type='text/html')
            
            async def favicon_handler(request):
                """Return empty favicon to prevent 404"""
                return web.Response(status=204)  # No Content
            
            app.router.add_get('/', root_handler)
            app.router.add_get('/favicon.ico', favicon_handler)
            app.router.add_get('/status', status_handler)
            app.router.add_get('/peers', peers_handler)
            app.router.add_post('/shutdown', shutdown_handler)
            
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, '0.0.0.0', self.config['node']['rpc_port'])
            await site.start()
            logger.info(f"RPC server started on port {self.config['node']['rpc_port']}")
        except Exception as e:
            logger.error(f"Failed to start RPC server: {e}")
            raise

    async def _graceful_shutdown(self):
        """Perform graceful shutdown with credibility loss warning"""
        try:
            logger.warning("=== CREDIBILITY LOSS WARNING ===")
            logger.warning("Shutting down this node will result in:")
            logger.warning("- Loss of accumulated credibility points")
            logger.warning("- Disconnection from the MediVote network")
            logger.warning("- Need to re-establish trust when restarting")
            logger.warning("- Loss of potential rewards and incentives")
            logger.warning("================================")
            
            # Shorter wait to ensure HTTP request doesn't timeout
            await asyncio.sleep(0.5)
            
            # Stop the node gracefully
            await self.stop()
            
            logger.info("Node shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during graceful shutdown: {e}")
    
    async def stop(self):
        """Stop the blockchain node"""
        logger.info("Stopping MediVote Blockchain Node...")
        self.is_running = False
        
        if self.blockchain_service:
            await self.blockchain_service.close()
        
        logger.info("Blockchain node stopped")
    
    def get_node_status(self) -> Dict[str, Any]:
        """Get current node status"""
        return {
            "node_id": self.node_info.node_id,
            "version": self.node_info.version,
            "network_id": self.node_info.network_id,
            "node_type": self.node_info.node_type,
            "is_running": self.is_running,
            "last_sync": self.node_info.last_sync.isoformat() if self.node_info.last_sync else None,
            "peers_connected": self.node_info.peers_connected,
            "blocks_processed": self.node_info.blocks_processed,
            "votes_processed": self.node_info.votes_processed,
            "config": {
                "name": self.config["node"]["name"],
                "port": self.config["node"]["port"],
                "rpc_port": self.config["node"]["rpc_port"]
            }
        }
    
    async def process_vote(self, vote_data: Dict[str, Any]) -> bool:
        """Process a vote transaction"""
        try:
            if not self.blockchain_service:
                logger.error("Blockchain service not available")
                return False
            
            # Create vote transaction
            vote_tx = VoteTransaction(
                vote_id=vote_data.get("vote_id"),
                election_id=vote_data.get("election_id"),
                encrypted_vote=vote_data.get("encrypted_vote"),
                blind_signature=vote_data.get("blind_signature"),
                timestamp=int(time.time()),
                voter_proof=vote_data.get("voter_proof", "")
            )
            
            # Post to blockchain
            tx = await self.blockchain_service.post_ballot(
                vote_tx.election_id,
                vote_tx.encrypted_vote,
                vote_tx.blind_signature
            )
            
            if tx:
                self.node_info.votes_processed += 1
                logger.info(f"Vote processed successfully: {vote_tx.vote_id}")
                return True
            else:
                logger.error(f"Failed to process vote: {vote_tx.vote_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error processing vote: {e}")
            return False
    
    async def get_election_data(self, election_id: str) -> Optional[Dict[str, Any]]:
        """Get election data from blockchain"""
        try:
            if not self.blockchain_service:
                return None
            
            election_info = await self.blockchain_service.get_election_info(election_id)
            ballots = await self.blockchain_service.get_ballots(election_id)
            
            return {
                "election_id": election_id,
                "election_info": election_info,
                "ballots": ballots,
                "total_votes": len(ballots) if ballots else 0
            }
            
        except Exception as e:
            logger.error(f"Error getting election data: {e}")
            return None

    async def _register_with_incentive_system(self):
        """Register this node with the incentive system"""
        try:
            # Wait a moment for the RPC server to be fully ready
            await asyncio.sleep(3)
            
            incentive_url = self.config.get("node", {}).get("incentive_system_url", "http://localhost:8082")
            
            # Generate a simple public key for demo purposes
            public_key = f"pk_{secrets.token_hex(16)}"
            
            registration_data = {
                "node_id": self.node_info.node_id,
                "public_key": public_key,
                "node_address": "localhost",
                "node_port": self.config["node"]["rpc_port"]
            }
            
            logger.info(f"Registering with incentive system at {incentive_url}...")
            
            # Make up to 3 attempts to register
            for attempt in range(3):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            f"{incentive_url}/api/register-node",
                            json=registration_data,
                            timeout=10
                        ) as response:
                            
                            if response.status == 200:
                                data = await response.json()
                                logger.info(f"Successfully registered with incentive system: {data.get('message', 'Registered')}")
                                logger.info(f"Ballot limit: {data.get('ballot_limit', 'N/A')}, Min uptime: {data.get('min_uptime', 'N/A')} hours")
                                return True
                            else:
                                error_data = await response.json()
                                logger.warning(f"Failed to register with incentive system (attempt {attempt + 1}): {error_data.get('error', 'Unknown error')}")
                                
                except Exception as e:
                    logger.warning(f"Registration attempt {attempt + 1} failed: {e}")
                
                # Wait before retry
                if attempt < 2:
                    await asyncio.sleep(5)
            
            logger.error("Failed to register with incentive system after 3 attempts")
            return False
            
        except Exception as e:
            logger.error(f"Error registering with incentive system: {e}")
            return False

async def main():
    """Main function to run the blockchain node"""
    import argparse
    
    parser = argparse.ArgumentParser(description="MediVote Blockchain Node")
    parser.add_argument("--config", default="node_config.json", help="Path to configuration file")
    args = parser.parse_args()
    
    print("MediVote Blockchain Node")
    print("=" * 50)
    print("Decentralized voting network node")
    print("Download and run to participate in the network")
    print("=" * 50)
    
    # Create and start the node with specified config
    node = MediVoteBlockchainNode(args.config)
    
    try:
        # Start the node
        if await node.start():
            print("Blockchain node started successfully!")
            print(f"Node ID: {node.node_info.node_id}")
            print(f"Network: {node.node_info.network_id}")
            print(f"RPC Port: {node.config['node']['rpc_port']}")
            print("\nPress Ctrl+C to stop the node")
            
            # Wait forever, but allow background tasks to run
            await asyncio.Event().wait()
                
        else:
            print("Failed to start blockchain node")
            return 1
            
    except KeyboardInterrupt:
        print("\nStopping blockchain node...")
        await node.stop()
        print("Blockchain node stopped")
        return 0
        
    except Exception as e:
        print(f"Error running blockchain node: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 