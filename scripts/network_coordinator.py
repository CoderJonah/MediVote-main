#!/usr/bin/env python3
"""
MediVote Network Coordinator
Manages the decentralized voting network and node discovery

This service helps blockchain nodes discover each other and maintain
network connectivity for the decentralized MediVote network.
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
import aiohttp
import aiofiles
from pathlib import Path
from aiohttp import web
import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Any, List
import hashlib
import time
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_coordinator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class NetworkNode:
    """Information about a network node"""
    node_id: str
    address: str
    port: int
    rpc_port: int
    node_type: str = "full_node"
    version: str = "1.0.0"
    last_seen: datetime = None
    is_active: bool = True
    votes_processed: int = 0
    blocks_processed: int = 0

@dataclass
class NetworkStats:
    """Network statistics"""
    total_nodes: int = 0
    active_nodes: int = 0
    total_votes_processed: int = 0
    total_blocks_processed: int = 0
    network_uptime: timedelta = timedelta(0)
    last_updated: datetime = None

class MediVoteNetworkCoordinator:
    """MediVote Network Coordinator for decentralized node management"""
    
    def __init__(self, config_path: str = "network_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.nodes: Dict[str, NetworkNode] = {}
        self.network_stats = NetworkStats()
        self.is_running = False
        self.start_time = datetime.utcnow()
        
        # Bootstrap nodes (seed nodes)
        self.bootstrap_nodes = [
            {"address": "node1.medivote.net", "port": 8545, "rpc_port": 8546},
            {"address": "node2.medivote.net", "port": 8545, "rpc_port": 8546},
            {"address": "node3.medivote.net", "port": 8545, "rpc_port": 8546}
        ]
        
        # Security enhancements
        self.request_counts = defaultdict(int)
        self.last_request_reset = time.time()
        self.rate_limit_window = 60  # 1 minute
        self.max_requests_per_window = 100
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_coordinator.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load or create network configuration"""
        default_config = {
            "network": {
                "name": "MediVote Mainnet",
                "network_id": "medivote_mainnet",
                "coordinator_port": 8083,
                "discovery_interval": 60,
                "node_timeout": 300,
                "max_nodes": 1000
            },
            "api": {
                "enabled": True,
                "port": 8083,
                "rate_limit": 100
            },
            "storage": {
                "data_dir": "./network_data",
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
    
    async def start(self):
        """Start the network coordinator"""
        try:
            logger.info("Starting MediVote Network Coordinator...")
            
            # Create data directory
            data_dir = Path(self.config["storage"]["data_dir"])
            data_dir.mkdir(exist_ok=True)
            
            # Load existing nodes
            await self._load_nodes()
            
            # Start discovery service
            await self._start_discovery_service()
            
            # Start API server
            if self.config["api"]["enabled"]:
                # Start API server as a background task
                asyncio.create_task(self._start_api_server())
            
            self.is_running = True
            self.network_stats.last_updated = datetime.utcnow()
            
            logger.info("Network coordinator started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start network coordinator: {e}")
            return False
    
    async def _load_nodes(self):
        """Load existing nodes from storage"""
        nodes_file = Path(self.config["storage"]["data_dir"]) / "nodes.json"
        if nodes_file.exists():
            try:
                async with aiofiles.open(nodes_file, 'r') as f:
                    content = await f.read()
                    nodes_data = json.loads(content)
                    
                    for node_data in nodes_data:
                        node = NetworkNode(**node_data)
                        node.last_seen = datetime.fromisoformat(node_data["last_seen"])
                        self.nodes[node.node_id] = node
                    
                    logger.info(f"Loaded {len(self.nodes)} existing nodes")
            except Exception as e:
                logger.error(f"Failed to load nodes: {e}")
    
    async def _save_nodes(self):
        """Save nodes to storage"""
        nodes_file = Path(self.config["storage"]["data_dir"]) / "nodes.json"
        try:
            nodes_data = []
            for node in self.nodes.values():
                node_dict = asdict(node)
                node_dict["last_seen"] = node.last_seen.isoformat()
                nodes_data.append(node_dict)
            
            async with aiofiles.open(nodes_file, 'w') as f:
                await f.write(json.dumps(nodes_data, indent=2))
                
        except Exception as e:
            logger.error(f"Failed to save nodes: {e}")
    
    async def _start_discovery_service(self):
        """Start node discovery service"""
        logger.info("Starting node discovery service...")
        
        # Start discovery loop
        asyncio.create_task(self._discovery_loop())
        
        # Start cleanup loop
        asyncio.create_task(self._cleanup_loop())
        
        # Start stats update loop
        asyncio.create_task(self._stats_update_loop())
    
    async def _discovery_loop(self):
        """Main discovery loop"""
        while self.is_running:
            try:
                # Discover new nodes
                await self._discover_nodes()
                
                # Update node status
                await self._update_node_status()
                
                # Save nodes periodically
                await self._save_nodes()
                
                await asyncio.sleep(self.config["network"]["discovery_interval"])
                
            except Exception as e:
                logger.error(f"Discovery loop error: {e}")
                await asyncio.sleep(10)
    
    async def _discover_nodes(self):
        """Discover new nodes in the network"""
        logger.debug("Discovering new nodes...")
        
        # Check bootstrap nodes
        for bootstrap in self.bootstrap_nodes:
            try:
                # Try to connect to bootstrap node
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{bootstrap['address']}:{bootstrap['rpc_port']}/status", timeout=5) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Add bootstrap node if not already present
                            node_id = data.get("node_id", f"bootstrap_{bootstrap['address']}")
                            if node_id not in self.nodes:
                                node = NetworkNode(
                                    node_id=node_id,
                                    address=bootstrap["address"],
                                    port=bootstrap["port"],
                                    rpc_port=bootstrap["rpc_port"],
                                    node_type="bootstrap",
                                    last_seen=datetime.utcnow()
                                )
                                self.nodes[node_id] = node
                                logger.info(f"Discovered bootstrap node: {bootstrap['address']}")
                
            except Exception as e:
                logger.debug(f"Failed to connect to bootstrap node {bootstrap['address']}: {e}")
        
        # Check for local blockchain node with improved error handling
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("http://localhost:8546/status", timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        node_id = data.get("node_id", "local_blockchain_node")
                        
                        if node_id not in self.nodes:
                            node = NetworkNode(
                                node_id=node_id,
                                address="localhost",
                                port=8545,
                                rpc_port=8546,
                                node_type="full_node",
                                last_seen=datetime.utcnow(),
                                is_active=True  # Mark as active since we just got a response
                            )
                            self.nodes[node_id] = node
                            logger.info(f"Discovered local blockchain node: {node_id} - Status: {data.get('is_running', 'unknown')}")
                        else:
                            # Update existing local node - ensure it's marked as active
                            node = self.nodes[node_id]
                            node.last_seen = datetime.utcnow()
                            node.is_active = True
                            node.votes_processed = data.get("votes_processed", 0)
                            node.blocks_processed = data.get("blocks_processed", 0)
                            logger.debug(f"Updated local blockchain node: {node_id} - Active: True")
                            
        except Exception as e:
            logger.info(f"Local blockchain node not available yet: {e}")
            # Don't mark existing nodes as inactive just because we can't connect right now
            # Only mark as inactive if they haven't been seen for a while (handled in cleanup)
        
        # Check existing nodes for new peers
        for node in list(self.nodes.values()):
            if not node.is_active:
                continue
                
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{node.address}:{node.rpc_port}/peers", timeout=5) as response:
                        if response.status == 200:
                            peers_data = await response.json()
                            
                            # Add new peers
                            for peer_data in peers_data.get("peers", []):
                                peer_id = peer_data.get("node_id")
                                if peer_id and peer_id not in self.nodes:
                                    peer_node = NetworkNode(
                                        node_id=peer_id,
                                        address=peer_data["address"],
                                        port=peer_data["port"],
                                        rpc_port=peer_data["rpc_port"],
                                        node_type=peer_data.get("node_type", "full_node"),
                                        last_seen=datetime.utcnow()
                                    )
                                    self.nodes[peer_id] = peer_node
                                    logger.info(f"Discovered new peer: {peer_id}")
                
            except Exception as e:
                logger.debug(f"Failed to get peers from node {node.node_id}: {e}")
    
    async def _update_node_status(self):
        """Update status of existing nodes"""
        for node in self.nodes.values():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{node.address}:{node.rpc_port}/status", timeout=8) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Update node status
                            node.last_seen = datetime.utcnow()
                            node.is_active = True
                            node.votes_processed = data.get("votes_processed", 0)
                            node.blocks_processed = data.get("blocks_processed", 0)
                            node.version = data.get("version", node.version)
                            logger.debug(f"Updated node {node.node_id}: Active=True, Votes={node.votes_processed}, Blocks={node.blocks_processed}")
                        else:
                            logger.info(f"Node {node.node_id} returned HTTP {response.status}, marking as inactive")
                            node.is_active = False
                
            except Exception as e:
                logger.info(f"Failed to update status for node {node.node_id}: {e}")
                # Only mark as inactive after a few failed attempts
                # For now, just log the error but don't immediately mark as inactive
                # The cleanup loop will handle nodes that haven't been seen for a while
                if node.last_seen and (datetime.utcnow() - node.last_seen).total_seconds() > 120:  # 2 minutes
                    logger.warning(f"Node {node.node_id} hasn't responded for 2+ minutes, marking as inactive")
                    node.is_active = False
    
    async def _cleanup_loop(self):
        """Clean up inactive nodes"""
        while self.is_running:
            try:
                timeout = timedelta(seconds=self.config["network"]["node_timeout"])
                current_time = datetime.utcnow()
                
                # Remove inactive nodes
                inactive_nodes = []
                for node_id, node in self.nodes.items():
                    if node.last_seen and (current_time - node.last_seen) > timeout:
                        inactive_nodes.append(node_id)
                
                for node_id in inactive_nodes:
                    del self.nodes[node_id]
                    logger.info(f"Removed inactive node: {node_id}")
                
                await asyncio.sleep(60)  # Cleanup every minute
                
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(10)
    
    async def _stats_update_loop(self):
        """Update network statistics"""
        while self.is_running:
            try:
                active_nodes = [node for node in self.nodes.values() if node.is_active]
                
                self.network_stats.total_nodes = len(self.nodes)
                self.network_stats.active_nodes = len(active_nodes)
                self.network_stats.total_votes_processed = sum(node.votes_processed for node in active_nodes)
                self.network_stats.total_blocks_processed = sum(node.blocks_processed for node in active_nodes)
                self.network_stats.network_uptime = datetime.utcnow() - self.start_time
                self.network_stats.last_updated = datetime.utcnow()
                
                await asyncio.sleep(30)  # Update stats every 30 seconds
                
            except Exception as e:
                logger.error(f"Stats update error: {e}")
                await asyncio.sleep(10)
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client has exceeded rate limit"""
        current_time = time.time()
        
        # Reset counters if window has passed
        if current_time - self.last_request_reset > self.rate_limit_window:
            self.request_counts.clear()
            self.last_request_reset = current_time
        
        # Check rate limit
        if self.request_counts[client_ip] >= self.max_requests_per_window:
            self.logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return False
        
        self.request_counts[client_ip] += 1
        return True

    def _log_security_event(self, event_type: str, client_ip: str, details: str = ""):
        """Log security events for monitoring"""
        self.logger.info(f"SECURITY_EVENT: {event_type} from {client_ip} - {details}")

    async def _start_api_server(self):
        """Start API server for network information with security enhancements"""
        app = web.Application()
        
        async def status_handler(request):
            # Security: Rate limiting
            client_ip = request.remote
            if not self._check_rate_limit(client_ip):
                self._log_security_event("RATE_LIMIT_EXCEEDED", client_ip)
                return web.json_response({"error": "Rate limit exceeded"}, status=429)
            
            # Security: Log access
            self._log_security_event("API_ACCESS", client_ip, "status endpoint")
            
            # Return sanitized data (no sensitive info)
            status_data = self.get_network_status()
            
            # Security: Remove detailed node info for public access
            if not self._is_trusted_client(client_ip):
                # Only return aggregate stats, not individual node details
                status_data = {
                    "network_name": status_data["network_name"],
                    "network_id": status_data["network_id"],
                    "is_running": status_data["is_running"],
                    "stats": status_data["stats"],
                    "node_count": len(status_data["nodes"]),
                    "active_node_count": len([n for n in status_data["nodes"] if n["is_active"]])
                }
            
            return web.json_response(status_data)
        
        async def admin_handler(request):
            # Security: Admin endpoint with IP restriction
            client_ip = request.remote
            if not self._is_admin_client(client_ip):
                self._log_security_event("UNAUTHORIZED_ADMIN_ACCESS", client_ip)
                return web.json_response({"error": "Unauthorized"}, status=403)
            
            self._log_security_event("ADMIN_ACCESS", client_ip, "admin endpoint")
            return web.json_response(self.get_network_status())
        
        async def shutdown_handler(request):
            """Handle graceful shutdown requests"""
            try:
                # Security: Only allow shutdown from trusted/admin clients
                client_ip = request.remote
                if not self._is_admin_client(client_ip):
                    self._log_security_event("UNAUTHORIZED_SHUTDOWN_ATTEMPT", client_ip)
                    return web.json_response({"error": "Unauthorized"}, status=403)
                
                self._log_security_event("SHUTDOWN_REQUEST", client_ip, "shutdown endpoint")
                logger.info("Shutdown request received via HTTP endpoint")
                
                # Immediate response to confirm shutdown initiation
                response_data = {
                    "message": "Network coordinator graceful shutdown initiated",
                    "status": "shutting_down",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                # Send response immediately
                response = web.json_response(response_data, status=200)
                
                # Schedule shutdown after response is sent
                async def delayed_shutdown():
                    await asyncio.sleep(0.5)  # Brief delay to ensure response is sent
                    logger.info("Executing graceful shutdown...")
                    self.is_running = False
                    # Save network state
                    await self._save_nodes()
                    # Signal shutdown
                    import os
                    import signal
                    os.kill(os.getpid(), signal.SIGTERM)
                
                # Schedule shutdown
                asyncio.create_task(delayed_shutdown())
                
                return response
                
            except Exception as e:
                logger.error(f"Shutdown handler error: {e}")
                return web.json_response({"error": "Shutdown failed", "details": str(e)}, status=500)
        
        app.router.add_get('/', status_handler)
        app.router.add_get('/admin', admin_handler)
        app.router.add_post('/shutdown', shutdown_handler)  # Add shutdown endpoint
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.config['api']['port'])
        await site.start()
        self.logger.info(f"API server started on port {self.config['api']['port']}")

    def _is_trusted_client(self, client_ip: str) -> bool:
        """Check if client is trusted (internal network)"""
        trusted_ips = self.config.get("security", {}).get("trusted_ips", ["127.0.0.1", "localhost"])
        return client_ip in trusted_ips or client_ip.startswith("192.168.") or client_ip.startswith("10.")

    def _is_admin_client(self, client_ip: str) -> bool:
        """Check if client has admin access"""
        admin_ips = self.config.get("security", {}).get("admin_ips", ["127.0.0.1", "localhost"])
        return client_ip in admin_ips
    
    async def register_node(self, node_data: Dict[str, Any]) -> bool:
        """Register a new node in the network"""
        try:
            node_id = node_data.get("node_id")
            if not node_id:
                return False
            
            if node_id in self.nodes:
                # Update existing node
                node = self.nodes[node_id]
                node.address = node_data.get("address", node.address)
                node.port = node_data.get("port", node.port)
                node.rpc_port = node_data.get("rpc_port", node.rpc_port)
                node.last_seen = datetime.utcnow()
                node.is_active = True
            else:
                # Add new node
                node = NetworkNode(
                    node_id=node_id,
                    address=node_data.get("address"),
                    port=node_data.get("port"),
                    rpc_port=node_data.get("rpc_port"),
                    node_type=node_data.get("node_type", "full_node"),
                    version=node_data.get("version", "1.0.0"),
                    last_seen=datetime.utcnow()
                )
                self.nodes[node_id] = node
            
            logger.info(f"Registered node: {node_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register node: {e}")
            return False
    
    def _format_uptime(self, uptime: timedelta) -> str:
        """Format uptime without microseconds"""
        total_seconds = int(uptime.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def get_network_status(self) -> Dict[str, Any]:
        """Get current network status"""
        return {
            "network_name": self.config["network"]["name"],
            "network_id": self.config["network"]["network_id"],
            "is_running": self.is_running,
            "start_time": self.start_time.isoformat(),
            "stats": {
                "total_nodes": self.network_stats.total_nodes,
                "active_nodes": self.network_stats.active_nodes,
                "total_votes_processed": self.network_stats.total_votes_processed,
                "total_blocks_processed": self.network_stats.total_blocks_processed,
                "network_uptime": self._format_uptime(self.network_stats.network_uptime),
                "last_updated": self.network_stats.last_updated.isoformat() if self.network_stats.last_updated else None
            },
            "nodes": [
                {
                    "node_id": node.node_id,
                    "address": node.address,
                    "port": node.port,
                    "rpc_port": node.rpc_port,
                    "node_type": node.node_type,
                    "version": node.version,
                    "is_active": node.is_active,
                    "votes_processed": node.votes_processed,
                    "blocks_processed": node.blocks_processed,
                    "last_seen": node.last_seen.isoformat() if node.last_seen else None
                }
                for node in self.nodes.values()
            ]
        }
    
    async def stop(self):
        """Stop the network coordinator"""
        logger.info("Stopping MediVote Network Coordinator...")
        self.is_running = False
        
        # Save nodes
        await self._save_nodes()
        
        logger.info("Network coordinator stopped")

async def main():
    """Main function to run the network coordinator"""
    print("MediVote Network Coordinator")
    print("=" * 50)
    print("Decentralized network management")
    print("Helps nodes discover each other")
    print("=" * 50)
    
    # Create and start the coordinator
    coordinator = MediVoteNetworkCoordinator()
    
    try:
        # Start the coordinator
        if await coordinator.start():
            print("Network coordinator started successfully!")
            print(f"Network: {coordinator.config['network']['name']}")
            print(f"API Port: {coordinator.config['api']['port']}")
            print("\nPress Ctrl+C to stop the coordinator")
            
            # Wait forever, but allow background tasks to run
            await asyncio.Event().wait()
            
        else:
            print("Failed to start network coordinator")
            return 1
            
    except KeyboardInterrupt:
        print("\nStopping network coordinator...")
        await coordinator.stop()
        print("Network coordinator stopped")
        return 0
        
    except Exception as e:
        print(f"Error running network coordinator: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 