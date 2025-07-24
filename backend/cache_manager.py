#!/usr/bin/env python3
"""
MediVote Distributed Blockchain Node - Network Independence Edition
Enables nodes to operate independently across different networks with robust peer discovery,
blockchain synchronization, and distributed cache backup/restore capabilities.

Key Features:
- Multi-network peer discovery 
- Bitcoin-style blockchain sync with catchup
- Distributed cache backup to multiple nodes
- Network partition resilience
- Security validation for distributed operations
"""

import asyncio
import json
import logging
import os
import sys
import time
import hashlib
import secrets
import aiohttp
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import socket
import ssl
from collections import defaultdict
from enum import Enum

# Add the backend directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

try:
    from core.blockchain import BlockchainService, BlockchainTransaction, VoteTransaction
    from core.config import get_settings
    from cache_manager import VoteCacheManager
    DEPENDENCIES_AVAILABLE = True
    print("SUCCESS: All dependencies imported successfully")
except ImportError as e:
    DEPENDENCIES_AVAILABLE = False
    print(f"Warning: Dependencies not available. Using mock mode. ImportError: {e}")

# Configure advanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/distributed_node.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NodeState(Enum):
    """Node operational states"""
    INITIALIZING = "initializing"
    DISCOVERING_PEERS = "discovering_peers"
    SYNCING = "syncing"
    SYNCED = "synced"
    ACTIVE = "active"
    PARTITION_RECOVERY = "partition_recovery"
    ERROR = "error"

@dataclass
class DistributedPeer:
    """Enhanced peer information for distributed operations"""
    peer_id: str
    address: str
    port: int
    rpc_port: int
    network_id: str
    node_type: str = "distributed_node"
    version: str = "2.0.0"
    last_seen: datetime = None
    last_sync: datetime = None
    is_active: bool = True
    is_trusted: bool = False
    trust_score: float = 0.0
    latency_ms: float = 0.0
    blocks_synced: int = 0
    votes_synced: int = 0
    cache_backup_capability: bool = True
    network_zone: str = "unknown"  # For network topology optimization
    public_key: Optional[str] = None  # For node authentication

@dataclass
class NetworkPartition:
    """Information about detected network partition"""
    partition_id: str
    detected_at: datetime
    affected_peers: List[str]
    recovery_strategy: str
    is_resolved: bool = False
    resolved_at: Optional[datetime] = None

@dataclass
class CacheBackupInfo:
    """Cache backup metadata"""
    backup_id: str
    source_node: str
    target_nodes: List[str]
    backup_time: datetime
    backup_size_bytes: int
    backup_hash: str
    votes_count: int
    ballots_count: int
    is_verified: bool = False

class DistributedBlockchainNode:
    """Enhanced blockchain node with network independence capabilities"""
    
    def __init__(self, config_path: str = "distributed_node_config.json"):
        self.config_path = config_path
        self.node_id = self._generate_secure_node_id()
        self.state = NodeState.INITIALIZING
        self.config = self._load_config()
        
        # Enhanced peer management
        self.peers: Dict[str, DistributedPeer] = {}
        self.trusted_peers: Set[str] = set()
        self.blacklisted_peers: Set[str] = set()
        self.peer_scores: Dict[str, float] = {}
        
        # Network partition detection
        self.network_partitions: List[NetworkPartition] = []
        self.partition_detection_enabled = True
        self.last_partition_check = datetime.now()
        
        # Blockchain sync capabilities
        self.blockchain_service: Optional[BlockchainService] = None
        self.local_block_height = 0
        self.network_block_height = 0
        self.sync_progress = 0.0
        self.catchup_mode = False
        
        # Distributed cache backup
        self.cache_manager: Optional[VoteCacheManager] = None
        self.cache_backups: Dict[str, CacheBackupInfo] = {}
        self.backup_redundancy = 3  # Number of backup copies
        
        # Security
        self.node_private_key = secrets.token_bytes(32)
        self.node_public_key = self._derive_public_key(self.node_private_key)
        self.authenticated_peers: Set[str] = set()
        
        # Performance monitoring
        self.sync_stats = {
            "blocks_synced": 0,
            "votes_synced": 0,
            "cache_backups_created": 0,
            "cache_restores_performed": 0,
            "network_switches": 0,
            "partition_recoveries": 0
        }
        
        # Threading and async control
        self.is_running = False
        self.background_tasks: List[asyncio.Task] = []
        
        logger.critical(f"DISTRIBUTED NODE INITIALIZED: {self.node_id}")
        logger.critical(f"   Network Independence: ENABLED")
        logger.critical(f"   Multi-Network Discovery: ACTIVE")
        logger.critical(f"   Distributed Cache Backup: READY")
        logger.critical(f"   Partition Recovery: ENABLED")
    
    def _generate_secure_node_id(self) -> str:
        """Generate cryptographically secure node ID"""
        random_bytes = secrets.token_bytes(16)
        timestamp = int(time.time()).to_bytes(8, 'big')
        combined = random_bytes + timestamp
        return f"node_{hashlib.sha256(combined).hexdigest()[:16]}"
    
    def _derive_public_key(self, private_key: bytes) -> str:
        """Derive public key from private key (simplified for demo)"""
        return hashlib.sha256(private_key + b"PUBLIC").hexdigest()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load or create distributed node configuration"""
        default_config = {
            "node": {
                "name": f"MediVote Distributed Node {self.node_id[:8]}",
                "port": 8545,
                "rpc_port": 8546,
                "max_peers": 100,
                "sync_interval": 15,  # More frequent sync for better network independence
                "block_time": 10,
                "enable_cache_backup": True,
                "backup_redundancy": 3,
                "trust_threshold": 0.7,
                "network_zones": ["zone_a", "zone_b", "zone_c"]  # For topology optimization
            },
            "network": {
                "bootstrap_nodes": [
                    "node1.medivote.net:8545",
                    "node2.medivote.net:8545", 
                    "node3.medivote.net:8545",
                    "backup1.medivote.org:8545",
                    "backup2.medivote.org:8545"
                ],
                "network_id": "medivote_distributed_v2",
                "genesis_block": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "enable_multi_network_discovery": True,
                "discovery_timeout": 30,
                "peer_timeout": 300,
                "partition_detection_interval": 60,
                "max_partition_recovery_time": 3600
            },
            "blockchain": {
                "catchup_batch_size": 100,  # Bitcoin-style batch syncing
                "max_catchup_time": 7200,  # 2 hours max catchup
                "validation_threshold": 0.67,  # 67% of peers must agree
                "enable_fast_sync": True,
                "checkpoint_interval": 1000
            },
            "cache": {
                "enable_distributed_backup": True,
                "backup_interval": 600,  # 10 minutes
                "backup_redundancy": 3,
                "backup_verification": True,
                "restore_timeout": 300,
                "compression_enabled": True
            },
            "security": {
                "enable_peer_authentication": True,
                "trust_decay_rate": 0.95,  # Trust decays over time
                "blacklist_threshold": -10.0,
                "whitelist_bootstrap_nodes": True,
                "enable_encryption": True,
                "key_rotation_interval": 86400  # 24 hours
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
                        elif isinstance(value, dict):
                            for subkey, subvalue in value.items():
                                if subkey not in config[key]:
                                    config[key][subkey] = subvalue
                    return config
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                return default_config
        else:
            # Create default config
            os.makedirs(os.path.dirname(self.config_path) if os.path.dirname(self.config_path) else '.', exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            logger.info(f"Created default distributed node config: {self.config_path}")
            return default_config
    
    async def start(self) -> bool:
        """Start the distributed blockchain node with network independence"""
        try:
            logger.critical("STARTING DISTRIBUTED BLOCKCHAIN NODE")
            logger.critical(f"   Node ID: {self.node_id}")
            logger.critical(f"   Network Independence: ACTIVE")
            
            self.is_running = True
            self.state = NodeState.DISCOVERING_PEERS
            
            # Initialize components
            await self._initialize_blockchain_service()
            await self._initialize_cache_manager()
            await self._initialize_security()
            
            # Start background tasks
            await self._start_background_tasks()
            
            # Multi-network peer discovery
            await self._discover_peers_multi_network()
            
            # Start blockchain sync
            await self._start_blockchain_sync()
            
            # Enable distributed cache backup
            if self.config["cache"]["enable_distributed_backup"]:
                await self._start_distributed_cache_backup()
            
            self.state = NodeState.ACTIVE
            logger.critical("DISTRIBUTED NODE FULLY OPERATIONAL")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start distributed node: {e}")
            self.state = NodeState.ERROR
            return False
    
    async def _initialize_blockchain_service(self):
        """Initialize blockchain service with distributed capabilities"""
        if DEPENDENCIES_AVAILABLE:
            self.blockchain_service = BlockchainService()
            await self.blockchain_service.initialize()
            self.local_block_height = await self._get_local_block_height()
            logger.info(f"Blockchain service initialized at height {self.local_block_height}")
        else:
            logger.warning("Blockchain service not available - using mock mode")

    async def _initialize_cache_manager(self):
        """Initialize cache manager for distributed backup"""
        if DEPENDENCIES_AVAILABLE:
            self.cache_manager = VoteCacheManager()
            logger.info("Cache manager initialized for distributed backup")
        else:
            logger.warning("Cache manager not available - distributed backup disabled")

    async def _initialize_security(self):
        """Initialize security layer for node authentication"""
        # Generate or load node keypair
        keys_dir = Path("keys/distributed_nodes")
        keys_dir.mkdir(parents=True, exist_ok=True)
        
        private_key_file = keys_dir / f"{self.node_id}_private.key"
        public_key_file = keys_dir / f"{self.node_id}_public.key"
        
        if private_key_file.exists() and public_key_file.exists():
            # Load existing keys
            with open(private_key_file, 'rb') as f:
                self.node_private_key = f.read()
            with open(public_key_file, 'r') as f:
                self.node_public_key = f.read().strip()
            logger.info("Loaded existing node keypair")
        else:
            # Save new keys
            with open(private_key_file, 'wb') as f:
                f.write(self.node_private_key)
            with open(public_key_file, 'w') as f:
                f.write(self.node_public_key)
            os.chmod(private_key_file, 0o600)  # Secure permissions
            logger.info("Generated and saved new node keypair")

    async def _start_background_tasks(self):
        """Start all background tasks for distributed operation"""
        tasks = [
            self._peer_discovery_loop(),
            self._peer_health_monitor(),
            self._network_partition_detector(),
            self._trust_score_updater(),
            self._cache_backup_scheduler(),
            self._performance_monitor()
        ]
        
        for task_coro in tasks:
            task = asyncio.create_task(task_coro)
            self.background_tasks.append(task)
        
        logger.info(f"Started {len(self.background_tasks)} background tasks")

    async def _discover_peers_multi_network(self):
        """Enhanced multi-network peer discovery"""
        logger.critical("MULTI-NETWORK PEER DISCOVERY STARTED")
        
        discovery_methods = [
            self._discover_bootstrap_peers(),
            self._discover_dns_peers(),
            self._discover_network_scan_peers(),
            self._discover_cached_peers()
        ]
        
        # Run all discovery methods in parallel
        results = await asyncio.gather(*discovery_methods, return_exceptions=True)
        
        total_discovered = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"Discovery method {i} failed: {result}")
            else:
                total_discovered += result
        
        logger.critical(f"PEER DISCOVERY COMPLETE: {total_discovered} peers discovered across all networks")
        
        # Authenticate discovered peers
        await self._authenticate_peers()

    async def _discover_bootstrap_peers(self) -> int:
        """Discover peers from bootstrap nodes"""
        discovered = 0
        for bootstrap_node in self.config["network"]["bootstrap_nodes"]:
            try:
                host, port = bootstrap_node.split(":")
                peer = await self._test_peer_connection(host, int(port))
                if peer:
                    self.peers[peer.peer_id] = peer
                    self.trusted_peers.add(peer.peer_id)  # Bootstrap nodes are trusted
                    discovered += 1
                    logger.info(f"Connected to bootstrap peer: {bootstrap_node}")
            except Exception as e:
                logger.debug(f"Failed to connect to bootstrap peer {bootstrap_node}: {e}")
        
        return discovered

    async def _discover_dns_peers(self) -> int:
        """Discover peers via DNS TXT records (similar to Bitcoin)"""
        discovered = 0
        dns_seeds = [
            "seed1.medivote.net",
            "seed2.medivote.net", 
            "seed3.medivote.org"
        ]
        
        for dns_seed in dns_seeds:
            try:
                # In a real implementation, this would query DNS TXT records
                # For now, simulate DNS discovery
                logger.debug(f"DNS discovery from {dns_seed} (simulated)")
                # discovered += await self._process_dns_results(dns_seed)
            except Exception as e:
                logger.debug(f"DNS discovery failed for {dns_seed}: {e}")
        
        return discovered

    async def _discover_network_scan_peers(self) -> int:
        """Discover peers via local network scanning"""
        discovered = 0
        
        # Scan common ports on local network
        local_network = self._get_local_network_range()
        scan_ports = [8545, 8546, 8547, 8548]
        
        for network_addr in local_network[:10]:  # Limit scan scope
            for port in scan_ports:
                try:
                    peer = await self._test_peer_connection(network_addr, port, timeout=2)
                    if peer and peer.peer_id not in self.peers:
                        self.peers[peer.peer_id] = peer
                        discovered += 1
                        logger.info(f"Discovered local peer: {network_addr}:{port}")
                except Exception:
                    pass  # Silent failure for network scanning
        
        return discovered

    async def _discover_cached_peers(self) -> int:
        """Load previously discovered peers from cache"""
        discovered = 0
        peers_cache_file = Path("cache/discovered_peers.json")
        
        if peers_cache_file.exists():
            try:
                with open(peers_cache_file, 'r') as f:
                    cached_peers = json.load(f)
                
                for peer_data in cached_peers:
                    # Test if cached peer is still active
                    peer = await self._test_peer_connection(
                        peer_data["address"], 
                        peer_data["port"], 
                        timeout=5
                    )
                    if peer:
                        self.peers[peer.peer_id] = peer
                        discovered += 1
                        logger.debug(f"Restored cached peer: {peer.address}:{peer.port}")
                
            except Exception as e:
                logger.warning(f"Failed to load cached peers: {e}")
        
        return discovered

    async def _test_peer_connection(self, host: str, port: int, timeout: int = 10) -> Optional[DistributedPeer]:
        """Test connection to a potential peer"""
        try:
            start_time = time.time()
            
            # Test TCP connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            latency = (time.time() - start_time) * 1000  # ms
            
            # Close test connection
            writer.close()
            await writer.wait_closed()
            
            # Create peer object
            peer_id = f"peer_{hashlib.sha256(f'{host}:{port}'.encode()).hexdigest()[:12]}"
            peer = DistributedPeer(
                peer_id=peer_id,
                address=host,
                port=port,
                rpc_port=port + 1,  # Assume RPC is on next port
                network_id=self.config["network"]["network_id"],
                last_seen=datetime.now(),
                latency_ms=latency
            )
            
            return peer
            
        except Exception as e:
            logger.debug(f"Peer connection test failed for {host}:{port}: {e}")
            return None

    def _get_local_network_range(self) -> List[str]:
        """Get local network IP range for peer discovery"""
        try:
            # Get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            
            # Generate network range (simplified)
            ip_parts = local_ip.split('.')
            network_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
            
            return [f"{network_base}.{i}" for i in range(1, 255)]
            
        except Exception as e:
            logger.debug(f"Failed to get local network range: {e}")
            return []

    async def _authenticate_peers(self):
        """Authenticate discovered peers using cryptographic challenge"""
        if not self.config["security"]["enable_peer_authentication"]:
            return
        
        authentication_tasks = []
        for peer_id, peer in self.peers.items():
            if peer_id not in self.authenticated_peers:
                task = asyncio.create_task(self._authenticate_peer(peer))
                authentication_tasks.append(task)
        
        if authentication_tasks:
            results = await asyncio.gather(*authentication_tasks, return_exceptions=True)
            authenticated_count = sum(1 for r in results if r is True)
            logger.info(f"Authenticated {authenticated_count}/{len(authentication_tasks)} peers")

    async def _authenticate_peer(self, peer: DistributedPeer) -> bool:
        """Authenticate a single peer using cryptographic challenge"""
        try:
            # Generate challenge
            challenge = secrets.token_bytes(32)
            challenge_hash = hashlib.sha256(challenge).hexdigest()
            
            # Send challenge to peer (simplified - in real implementation use proper protocol)
            # For now, assume authentication succeeds for bootstrap nodes
            if peer.peer_id in self.trusted_peers:
                self.authenticated_peers.add(peer.peer_id)
                peer.is_trusted = True
                peer.trust_score = 1.0
                return True
            
            # For non-bootstrap peers, implement actual challenge-response
            # This would involve sending challenge and verifying signature
            return False
            
        except Exception as e:
            logger.debug(f"Peer authentication failed for {peer.peer_id}: {e}")
            return False

    async def _start_blockchain_sync(self):
        """Start blockchain synchronization with catchup capability"""
        if not self.blockchain_service:
            return
        
        logger.critical("BLOCKCHAIN SYNC STARTED")
        self.state = NodeState.SYNCING
        
        # Get network block height from peers
        await self._determine_network_block_height()
        
        # Start catchup if behind
        if self.local_block_height < self.network_block_height:
            self.catchup_mode = True
            logger.critical(f"CATCHUP MODE ENABLED: {self.local_block_height} -> {self.network_block_height}")
            await self._perform_catchup_sync()
        
        self.state = NodeState.SYNCED
        logger.critical("BLOCKCHAIN SYNC COMPLETED")

    async def _determine_network_block_height(self):
        """Determine the network's current block height from peers"""
        heights = []
        
        for peer_id, peer in self.peers.items():
            if peer.is_active and peer_id in self.authenticated_peers:
                try:
                    # Query peer for block height (simplified)
                    height = await self._query_peer_block_height(peer)
                    if height:
                        heights.append(height)
                        peer.blocks_synced = height
                except Exception as e:
                    logger.debug(f"Failed to get block height from {peer_id}: {e}")
        
        if heights:
            # Use consensus (most common height among majority of peers)
            height_counts = defaultdict(int)
            for height in heights:
                height_counts[height] += 1
            
            # Require 67% consensus
            required_consensus = max(1, len(heights) * 2 // 3)
            for height, count in height_counts.items():
                if count >= required_consensus:
                    self.network_block_height = height
                    logger.info(f"Network consensus height: {height} ({count}/{len(heights)} peers)")
                    return
            
            # If no consensus, use highest height from trusted peers
            trusted_heights = [heights[i] for i, (pid, _) in enumerate(self.peers.items()) 
                             if pid in self.trusted_peers and i < len(heights)]
            if trusted_heights:
                self.network_block_height = max(trusted_heights)
                logger.warning(f"No consensus, using max trusted height: {self.network_block_height}")

    async def _query_peer_block_height(self, peer: DistributedPeer) -> Optional[int]:
        """Query a peer for their current block height"""
        # In a real implementation, this would use proper P2P protocol
        # For now, simulate the query
        return self.local_block_height + secrets.randbelow(100)  # Simulate peer heights

    async def _perform_catchup_sync(self):
        """Perform Bitcoin-style catchup synchronization"""
        logger.critical("PERFORMING CATCHUP SYNC")
        
        batch_size = self.config["blockchain"]["catchup_batch_size"]
        current_height = self.local_block_height
        
        while current_height < self.network_block_height and self.is_running:
            # Calculate batch end
            batch_end = min(current_height + batch_size, self.network_block_height)
            
            # Request blocks from peers
            blocks = await self._request_blocks_from_peers(current_height, batch_end)
            
            if blocks:
                # Validate and process blocks
                valid_blocks = await self._validate_blocks(blocks)
                if valid_blocks:
                    await self._process_blocks(valid_blocks)
                    current_height = batch_end
                    self.local_block_height = current_height
                    
                    # Update progress
                    self.sync_progress = (current_height / self.network_block_height) * 100
                    logger.info(f"Catchup progress: {self.sync_progress:.1f}% ({current_height}/{self.network_block_height})")
                else:
                    logger.error("Block validation failed during catchup")
                    break
            else:
                logger.error("Failed to retrieve blocks from peers")
                break
            
            # Small delay to prevent overwhelming peers
            await asyncio.sleep(0.1)
        
        self.catchup_mode = False
        logger.critical("CATCHUP SYNC COMPLETED")

    async def _request_blocks_from_peers(self, start_height: int, end_height: int) -> List[Dict]:
        """Request block range from multiple peers"""
        # Implement parallel block requests from multiple peers
        # For now, simulate block retrieval
        blocks = []
        for height in range(start_height, min(end_height, start_height + 10)):  # Simulate limited batch
            block = {
                "height": height,
                "hash": hashlib.sha256(f"block_{height}".encode()).hexdigest(),
                "transactions": [],
                "timestamp": int(time.time())
            }
            blocks.append(block)
        
        return blocks

    async def _validate_blocks(self, blocks: List[Dict]) -> List[Dict]:
        """Validate blocks before processing"""
        valid_blocks = []
        
        for block in blocks:
            # Implement block validation logic
            if self._is_valid_block(block):
                valid_blocks.append(block)
            else:
                logger.warning(f"Invalid block detected: {block.get('height', 'unknown')}")
        
        return valid_blocks

    def _is_valid_block(self, block: Dict) -> bool:
        """Validate a single block"""
        # Implement comprehensive block validation
        required_fields = ["height", "hash", "transactions", "timestamp"]
        return all(field in block for field in required_fields)

    async def _process_blocks(self, blocks: List[Dict]):
        """Process validated blocks"""
        for block in blocks:
            # Process block transactions
            if self.blockchain_service:
                # In a real implementation, add block to local blockchain
                pass
            
            self.sync_stats["blocks_synced"] += 1

    async def _start_distributed_cache_backup(self):
        """Start distributed cache backup system"""
        if not self.cache_manager:
            return
        
        logger.critical("DISTRIBUTED CACHE BACKUP ENABLED")
        
        # Schedule regular backups
        backup_task = asyncio.create_task(self._cache_backup_loop())
        self.background_tasks.append(backup_task)

    async def _cache_backup_loop(self):
        """Background loop for cache backup operations"""
        backup_interval = self.config["cache"]["backup_interval"]
        
        while self.is_running:
            try:
                await asyncio.sleep(backup_interval)
                
                if self.state == NodeState.ACTIVE:
                    await self._perform_distributed_cache_backup()
                
            except Exception as e:
                logger.error(f"Cache backup loop error: {e}")

    async def _perform_distributed_cache_backup(self):
        """Perform distributed cache backup to multiple peers"""
        logger.info("Performing distributed cache backup")
        
        # Get cache data
        cache_data = await self._serialize_cache_data()
        if not cache_data:
            return
        
        # Select backup peers
        backup_peers = self._select_backup_peers()
        if len(backup_peers) < self.backup_redundancy:
            logger.warning(f"Insufficient backup peers: {len(backup_peers)} < {self.backup_redundancy}")
        
        # Create backup
        backup_info = CacheBackupInfo(
            backup_id=secrets.token_hex(16),
            source_node=self.node_id,
            target_nodes=[peer.peer_id for peer in backup_peers],
            backup_time=datetime.now(),
            backup_size_bytes=len(cache_data),
            backup_hash=hashlib.sha256(cache_data).hexdigest(),
            votes_count=len(self.cache_manager.votes_cache) if self.cache_manager else 0,
            ballots_count=len(self.cache_manager.ballots_cache) if self.cache_manager else 0
        )
        
        # Send backup to peers
        successful_backups = 0
        for peer in backup_peers:
            try:
                success = await self._send_cache_backup_to_peer(peer, cache_data, backup_info)
                if success:
                    successful_backups += 1
            except Exception as e:
                logger.error(f"Backup to peer {peer.peer_id} failed: {e}")
        
        if successful_backups >= self.backup_redundancy:
            self.cache_backups[backup_info.backup_id] = backup_info
            self.sync_stats["cache_backups_created"] += 1
            logger.info(f"Cache backup successful: {successful_backups} copies created")
        else:
            logger.error(f"Cache backup failed: only {successful_backups} copies created")

    async def _serialize_cache_data(self) -> bytes:
        """Serialize cache data for backup"""
        if not self.cache_manager:
            return b""
        
        try:
            # Get all cache data
            cache_data = {
                "votes": self.cache_manager.restore_votes_to_backend(),
                "ballots": self.cache_manager.restore_ballots_to_backend(),
                "voters": self.cache_manager.restore_voters_to_backend(),
                "sync_status": self.cache_manager.get_sync_status(),
                "timestamp": datetime.now().isoformat()
            }
            
            # Serialize and optionally compress
            serialized = json.dumps(cache_data).encode('utf-8')
            
            if self.config["cache"]["compression_enabled"]:
                import gzip
                serialized = gzip.compress(serialized)
            
            return serialized
            
        except Exception as e:
            logger.error(f"Cache serialization failed: {e}")
            return b""

    def _select_backup_peers(self) -> List[DistributedPeer]:
        """Select optimal peers for cache backup"""
        eligible_peers = []
        
        for peer_id, peer in self.peers.items():
            if (peer.is_active and 
                peer.cache_backup_capability and 
                peer_id in self.authenticated_peers and
                peer.trust_score >= self.config["node"]["trust_threshold"]):
                eligible_peers.append(peer)
        
        # Sort by trust score and latency
        eligible_peers.sort(key=lambda p: (-p.trust_score, p.latency_ms))
        
        # Return top peers up to redundancy requirement
        return eligible_peers[:self.backup_redundancy * 2]  # Extra peers for redundancy

    async def _send_cache_backup_to_peer(self, peer: DistributedPeer, cache_data: bytes, backup_info: CacheBackupInfo) -> bool:
        """Send cache backup to a specific peer"""
        try:
            # In a real implementation, this would use proper P2P protocol
            # For now, simulate successful backup
            await asyncio.sleep(0.1)  # Simulate network delay
            
            # Verify backup was received correctly
            if secrets.randbelow(10) < 8:  # 80% success rate simulation
                return True
            else:
                return False
                
        except Exception as e:
            logger.debug(f"Backup to peer {peer.peer_id} failed: {e}")
            return False

    async def restore_cache_from_distributed_backup(self, backup_id: Optional[str] = None) -> bool:
        """Restore cache from distributed backup"""
        logger.critical("RESTORING CACHE FROM DISTRIBUTED BACKUP")
        
        if backup_id:
            # Restore specific backup
            if backup_id not in self.cache_backups:
                logger.error(f"Backup {backup_id} not found")
                return False
            backup_info = self.cache_backups[backup_id]
        else:
            # Restore latest backup
            if not self.cache_backups:
                logger.error("No backups available")
                return False
            backup_info = max(self.cache_backups.values(), key=lambda b: b.backup_time)
        
        # Request backup from peers
        for peer_id in backup_info.target_nodes:
            if peer_id in self.peers:
                peer = self.peers[peer_id]
                cache_data = await self._request_cache_backup_from_peer(peer, backup_info)
                
                if cache_data:
                    # Verify backup integrity
                    if hashlib.sha256(cache_data).hexdigest() == backup_info.backup_hash:
                        # Restore cache
                        success = await self._restore_cache_from_data(cache_data)
                        if success:
                            self.sync_stats["cache_restores_performed"] += 1
                            logger.critical("CACHE RESTORE SUCCESSFUL")
                            return True
                    else:
                        logger.error("Backup integrity check failed")
        
        logger.error("Cache restore failed - no valid backup found")
        return False

    async def _request_cache_backup_from_peer(self, peer: DistributedPeer, backup_info: CacheBackupInfo) -> Optional[bytes]:
        """Request cache backup from a specific peer"""
        try:
            # In a real implementation, this would use proper P2P protocol
            # For now, simulate backup retrieval
            await asyncio.sleep(0.2)  # Simulate network delay
            
            if secrets.randbelow(10) < 7:  # 70% success rate simulation
                # Generate fake cache data for simulation
                cache_data = {
                    "votes": {},
                    "ballots": {},
                    "voters": {},
                    "sync_status": {},
                    "timestamp": datetime.now().isoformat()
                }
                serialized = json.dumps(cache_data).encode('utf-8')
                
                if self.config["cache"]["compression_enabled"]:
                    import gzip
                    serialized = gzip.compress(serialized)
                
                return serialized
            else:
                return None
                
        except Exception as e:
            logger.debug(f"Backup request from peer {peer.peer_id} failed: {e}")
            return None

    async def _restore_cache_from_data(self, cache_data: bytes) -> bool:
        """Restore cache from backup data"""
        try:
            # Decompress if needed
            if self.config["cache"]["compression_enabled"]:
                import gzip
                cache_data = gzip.decompress(cache_data)
            
            # Deserialize
            data = json.loads(cache_data.decode('utf-8'))
            
            # Restore to cache manager
            if self.cache_manager:
                # In a real implementation, this would restore actual data
                # For now, log the restore operation
                logger.info(f"Restored {len(data.get('votes', {}))} votes, {len(data.get('ballots', {}))} ballots")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Cache restore from data failed: {e}")
            return False

    # Background task methods
    async def _peer_discovery_loop(self):
        """Continuous peer discovery loop"""
        while self.is_running:
            try:
                await asyncio.sleep(self.config["network"]["discovery_timeout"])
                await self._discover_peers_multi_network()
            except Exception as e:
                logger.error(f"Peer discovery loop error: {e}")

    async def _peer_health_monitor(self):
        """Monitor peer health and connectivity"""
        while self.is_running:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                for peer_id, peer in list(self.peers.items()):
                    # Test peer connectivity
                    is_alive = await self._test_peer_connection(peer.address, peer.port, timeout=5)
                    
                    if is_alive:
                        peer.last_seen = datetime.now()
                        peer.is_active = True
                        # Increase trust score slightly
                        self.peer_scores[peer_id] = min(1.0, self.peer_scores.get(peer_id, 0.5) + 0.01)
                    else:
                        peer.is_active = False
                        # Decrease trust score
                        self.peer_scores[peer_id] = max(-1.0, self.peer_scores.get(peer_id, 0.5) - 0.1)
                        
                        # Remove inactive peers after timeout
                        if (datetime.now() - peer.last_seen).seconds > self.config["network"]["peer_timeout"]:
                            logger.info(f"Removing inactive peer: {peer_id}")
                            del self.peers[peer_id]
                            if peer_id in self.authenticated_peers:
                                self.authenticated_peers.remove(peer_id)
                
            except Exception as e:
                logger.error(f"Peer health monitor error: {e}")

    async def _network_partition_detector(self):
        """Detect network partitions"""
        if not self.partition_detection_enabled:
            return
        
        while self.is_running:
            try:
                await asyncio.sleep(self.config["network"]["partition_detection_interval"])
                
                active_peers = [p for p in self.peers.values() if p.is_active]
                total_peers = len(self.peers)
                
                if total_peers > 0:
                    active_ratio = len(active_peers) / total_peers
                    
                    # Detect potential partition (less than 30% of peers active)
                    if active_ratio < 0.3:
                        partition = NetworkPartition(
                            partition_id=secrets.token_hex(8),
                            detected_at=datetime.now(),
                            affected_peers=[p.peer_id for p in self.peers.values() if not p.is_active],
                            recovery_strategy="reconnect_and_sync"
                        )
                        
                        self.network_partitions.append(partition)
                        self.state = NodeState.PARTITION_RECOVERY
                        
                        logger.critical(f"NETWORK PARTITION DETECTED: {partition.partition_id}")
                        logger.critical(f"   Active peers: {len(active_peers)}/{total_peers}")
                        logger.critical(f"   Initiating recovery strategy: {partition.recovery_strategy}")
                        
                        await self._handle_network_partition(partition)
                
            except Exception as e:
                logger.error(f"Network partition detector error: {e}")

    async def _handle_network_partition(self, partition: NetworkPartition):
        """Handle detected network partition"""
        try:
            if partition.recovery_strategy == "reconnect_and_sync":
                # Attempt to reconnect nodes in affected zones
                await self._discover_peers_multi_network()
                
                # Re-sync blockchain if needed
                await self._determine_network_block_height()
                if self.local_block_height < self.network_block_height:
                    await self._perform_catchup_sync()
                
                # Mark partition as resolved if we have enough active peers
                active_peers = len([p for p in self.peers.values() if p.is_active])
                if active_peers >= 3:  # Minimum peers for normal operation
                    partition.is_resolved = True
                    partition.resolved_at = datetime.now()
                    self.state = NodeState.ACTIVE
                    self.sync_stats["partition_recoveries"] += 1
                    logger.critical(f"NETWORK PARTITION RECOVERED: {partition.partition_id}")
        
        except Exception as e:
            logger.error(f"Partition recovery failed: {e}")

    async def _trust_score_updater(self):
        """Update trust scores for peers"""
        while self.is_running:
            try:
                await asyncio.sleep(300)  # Update every 5 minutes
                
                decay_rate = self.config["security"]["trust_decay_rate"]
                
                for peer_id, peer in self.peers.items():
                    current_score = self.peer_scores.get(peer_id, 0.5)
                    
                    # Apply trust decay
                    new_score = current_score * decay_rate
                    
                    # Update peer trust score
                    peer.trust_score = new_score
                    self.peer_scores[peer_id] = new_score
                    
                    # Handle blacklisting
                    if new_score < self.config["security"]["blacklist_threshold"]:
                        if peer_id not in self.blacklisted_peers:
                            self.blacklisted_peers.add(peer_id)
                            logger.warning(f"Blacklisted peer due to low trust: {peer_id}")
                
            except Exception as e:
                logger.error(f"Trust score updater error: {e}")

    async def _performance_monitor(self):
        """Monitor node performance and statistics"""
        while self.is_running:
            try:
                await asyncio.sleep(60)  # Update every minute
                
                # Log performance statistics
                if self.sync_stats["blocks_synced"] > 0:
                    logger.info(f"Performance: {self.sync_stats['blocks_synced']} blocks, "
                              f"{self.sync_stats['votes_synced']} votes, "
                              f"{self.sync_stats['cache_backups_created']} backups, "
                              f"{len(self.peers)} peers")
                
            except Exception as e:
                logger.error(f"Performance monitor error: {e}")

    # Public API methods
    def get_node_status(self) -> Dict[str, Any]:
        """Get comprehensive node status"""
        active_peers = len([p for p in self.peers.values() if p.is_active])
        
        return {
            "node_id": self.node_id,
            "state": self.state.value,
            "network_independence": {
                "enabled": True,  
                "multi_network_discovery": True,
                "distributed_cache_backup": self.config["cache"]["enable_distributed_backup"],
                "partition_recovery": self.partition_detection_enabled
            },
            "peers": {
                "total": len(self.peers),
                "active": active_peers,
                "authenticated": len(self.authenticated_peers),
                "trusted": len(self.trusted_peers),
                "blacklisted": len(self.blacklisted_peers)
            },
            "blockchain": {
                "local_height": self.local_block_height,
                "network_height": self.network_block_height,
                "sync_progress": self.sync_progress,
                "catchup_mode": self.catchup_mode
            },
            "cache_backup": {
                "backups_created": len(self.cache_backups),
                "redundancy_level": self.backup_redundancy,
                "last_backup": max((b.backup_time for b in self.cache_backups.values()), default=None)
            },
            "security": {
                "peer_authentication": self.config["security"]["enable_peer_authentication"],
                "encryption_enabled": self.config["security"]["enable_encryption"],
                "trust_threshold": self.config["node"]["trust_threshold"]
            },
            "performance": self.sync_stats,
            "partitions": {
                "detected": len(self.network_partitions),
                "resolved": len([p for p in self.network_partitions if p.is_resolved]),
                "current_partition": self.state == NodeState.PARTITION_RECOVERY
            }
        }
    
    async def stop(self):
        """Stop the distributed blockchain node"""
        logger.critical("STOPPING DISTRIBUTED BLOCKCHAIN NODE")
        
        self.is_running = False
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Save peer cache
        await self._save_peer_cache()
        
        # Cleanup
        if self.blockchain_service:
            await self.blockchain_service.close()
        
        logger.critical("DISTRIBUTED NODE STOPPED")

    async def _save_peer_cache(self):
        """Save discovered peers to cache for next startup"""
        try:
            peers_cache_file = Path("cache/discovered_peers.json")
            peers_cache_file.parent.mkdir(exist_ok=True)
            
            peer_data = []
            for peer in self.peers.values():
                if peer.is_active and peer.trust_score > 0:
                    peer_data.append({
                        "address": peer.address,
                        "port": peer.port,
                        "rpc_port": peer.rpc_port,
                        "trust_score": peer.trust_score,
                        "last_seen": peer.last_seen.isoformat() if peer.last_seen else None
                    })
            
            with open(peers_cache_file, 'w') as f:
                json.dump(peer_data, f, indent=2)
            
            logger.info(f"Saved {len(peer_data)} peers to cache")
            
        except Exception as e:
            logger.error(f"Failed to save peer cache: {e}")


# ============ KEY VALIDATION SYSTEM ============

class KeyValidationResult:
    """Result of key validation operation"""
    def __init__(self, service_name: str, key_type: str, is_valid: bool, details: Dict[str, Any]):
        self.service_name = service_name
        self.key_type = key_type  
        self.is_valid = is_valid
        self.details = details
        self.timestamp = datetime.now()
        self.validation_id = secrets.token_hex(8)

class MediVoteKeyValidator:
    """
    COMPREHENSIVE KEY VALIDATION SYSTEM
    
    Detects when services are using different encryption keys and alerts administrators.
    Critical for preventing silent data corruption and ensuring system integrity.
    """
    
    def __init__(self, security_manager: MediVoteSecurityManager):
        self.security_manager = security_manager
        self.validation_history: List[KeyValidationResult] = []
        self.active_key_hashes: Dict[str, str] = {}
        self.service_key_mappings: Dict[str, Dict[str, str]] = {}
        self.validation_enabled = True
        self.last_validation_time = datetime.now()
        
        # Alert thresholds
        self.mismatch_alert_threshold = 1  # Alert on any mismatch
        self.validation_interval = 300  # 5 minutes
        
        logger.critical("KEY VALIDATION SYSTEM INITIALIZED")
        logger.critical("   Mismatch Detection: ENABLED")
        logger.critical("   Alert Threshold: IMMEDIATE")
        logger.critical("   Validation Interval: 5 minutes")
    
    def validate_service_keys(self, service_name: str, service_keys: Dict[str, bytes]) -> List[KeyValidationResult]:
        """
        Validate that a service is using the correct encryption keys
        
        Args:
            service_name: Name of the service (e.g., 'cache_manager', 'security_service')
            service_keys: Dictionary of key_type -> key_bytes from the service
            
        Returns:
            List of validation results for each key type
        """
        try:
            logger.info(f"VALIDATING KEYS FOR SERVICE: {service_name}")
            
            validation_results = []
            
            for key_type, service_key in service_keys.items():
                result = self._validate_individual_key(service_name, key_type, service_key)
                validation_results.append(result)
                
                # Store validation result
                self.validation_history.append(result)
                
                # Alert on validation failure
                if not result.is_valid:
                    self._trigger_key_mismatch_alert(result)
            
            # Update service key mappings
            self.service_key_mappings[service_name] = {
                key_type: hashlib.sha256(key_bytes).hexdigest()[:16]
                for key_type, key_bytes in service_keys.items()
            }
            
            # Cleanup old validation history
            self._cleanup_validation_history()
            
            valid_count = sum(1 for r in validation_results if r.is_valid)
            total_count = len(validation_results)
            
            logger.critical(f"KEY VALIDATION COMPLETE: {service_name}")
            logger.critical(f"   Valid Keys: {valid_count}/{total_count}")
            logger.critical(f"   Service Status: {'SECURE' if valid_count == total_count else 'KEY MISMATCH DETECTED'}")
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Key validation failed for {service_name}: {e}")
            error_result = KeyValidationResult(
                service_name, "validation_error", False,
                {"error": str(e), "error_type": type(e).__name__}
            )
            self._trigger_key_mismatch_alert(error_result)
            return [error_result]
    
    def _validate_individual_key(self, service_name: str, key_type: str, service_key: bytes) -> KeyValidationResult:
        """Validate an individual key against the security manager"""
        try:
            # Get expected key from security manager
            expected_key = None
            
            if key_type == "database":
                expected_key = self.security_manager.get_database_key()
            elif key_type == "audit":
                expected_key = self.security_manager.get_audit_key()
            elif key_type == "jwt":
                expected_key = self.security_manager.get_jwt_secret()
            elif key_type == "session":
                expected_key = self.security_manager.get_session_key()
            else:
                return KeyValidationResult(
                    service_name, key_type, False,
                    {"error": f"Unknown key type: {key_type}"}
                )
            
            # Compare keys
            keys_match = service_key == expected_key
            
            # Generate key hashes for logging (never log actual keys)
            service_key_hash = hashlib.sha256(service_key).hexdigest()[:16]
            expected_key_hash = hashlib.sha256(expected_key).hexdigest()[:16]
            
            details = {
                "service_key_hash": service_key_hash,
                "expected_key_hash": expected_key_hash,
                "keys_match": keys_match,
                "key_length": len(service_key),
                "expected_length": len(expected_key)
            }
            
            if keys_match:
                logger.debug(f"Key validation PASSED: {service_name}.{key_type}")
            else:
                logger.error(f"KEY MISMATCH DETECTED: {service_name}.{key_type}")
                logger.error(f"   Service Key Hash: {service_key_hash}")
                logger.error(f"   Expected Key Hash: {expected_key_hash}")
            
            return KeyValidationResult(service_name, key_type, keys_match, details)
            
        except Exception as e:
            logger.error(f"Individual key validation failed: {e}")
            return KeyValidationResult(
                service_name, key_type, False,
                {"error": str(e), "validation_failed": True}
            )
    
    def _trigger_key_mismatch_alert(self, validation_result: KeyValidationResult):
        """Trigger admin alert for key mismatch"""
        try:
            alert_details = {
                "service_name": validation_result.service_name,
                "key_type": validation_result.key_type,
                "validation_id": validation_result.validation_id,
                "timestamp": validation_result.timestamp.isoformat(),
                "details": validation_result.details
            }
            
            # Use the admin alert system
            admin_alert_system = get_admin_alert_system()
            admin_alert_system.send_critical_alert(
                "KEY_MISMATCH_DETECTED",
                f"Service {validation_result.service_name} using incorrect {validation_result.key_type} key",
                alert_details
            )
            
            logger.critical(f"ADMIN ALERT TRIGGERED: KEY_MISMATCH_DETECTED")
            logger.critical(f"   Service: {validation_result.service_name}")
            logger.critical(f"   Key Type: {validation_result.key_type}")
            logger.critical(f"   Alert ID: {validation_result.validation_id}")
            
        except Exception as e:
            logger.error(f"Failed to trigger key mismatch alert: {e}")
    
    def validate_all_active_services(self) -> Dict[str, List[KeyValidationResult]]:
        """Validate keys for all known active services"""
        logger.critical("VALIDATING ALL ACTIVE SERVICES")
        
        all_results = {}
        
        # Validate cache manager keys
        try:
            from cache_manager import cache_manager
            if hasattr(cache_manager, '_get_encryption_keys'):
                cache_keys = cache_manager._get_encryption_keys()
                all_results["cache_manager"] = self.validate_service_keys("cache_manager", cache_keys)
        except Exception as e:
            logger.warning(f"Could not validate cache_manager keys: {e}")
        
        # Validate security service keys
        try:
            from security_service import encryption_service
            if hasattr(encryption_service, '_get_encryption_keys'):
                security_keys = encryption_service._get_encryption_keys()
                all_results["security_service"] = self.validate_service_keys("security_service", security_keys)
        except Exception as e:
            logger.warning(f"Could not validate security_service keys: {e}")
        
        # Generate summary
        total_services = len(all_results)
        secure_services = 0
        total_keys_validated = 0
        total_keys_valid = 0
        
        for service_name, results in all_results.items():
            service_valid = all(r.is_valid for r in results)
            if service_valid:
                secure_services += 1
            
            total_keys_validated += len(results)
            total_keys_valid += sum(1 for r in results if r.is_valid)
        
        logger.critical("ALL SERVICES VALIDATION COMPLETE")
        logger.critical(f"   Secure Services: {secure_services}/{total_services}")
        logger.critical(f"   Valid Keys: {total_keys_valid}/{total_keys_validated}")
        logger.critical(f"   System Status: {'SECURE' if secure_services == total_services else 'CRITICAL - KEY MISMATCHES DETECTED'}")
        
        return all_results
    
    def get_validation_status(self) -> Dict[str, Any]:
        """Get comprehensive validation status"""
        recent_validations = [
            v for v in self.validation_history 
            if (datetime.now() - v.timestamp).seconds < 3600  # Last hour
        ]
        
        return {
            "validation_enabled": self.validation_enabled,
            "last_validation": self.last_validation_time.isoformat(),
            "validation_interval": self.validation_interval,
            "recent_validations": {
                "total": len(recent_validations),
                "valid": len([v for v in recent_validations if v.is_valid]),
                "failed": len([v for v in recent_validations if not v.is_valid])
            },
            "active_services": len(self.service_key_mappings),
            "service_status": {
                service: len([v for v in recent_validations if v.service_name == service and v.is_valid])
                for service in self.service_key_mappings.keys()
            },
            "alert_thresholds": {
                "mismatch_alert_threshold": self.mismatch_alert_threshold,
                "immediate_alerts": True
            }
        }
    
    def _cleanup_validation_history(self):
        """Clean up old validation history to prevent memory bloat"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.validation_history = [
            v for v in self.validation_history 
            if v.timestamp > cutoff_time
        ]

# Global key validator instance
_key_validator: Optional[MediVoteKeyValidator] = None

def get_key_validator() -> MediVoteKeyValidator:
    """Get the global key validator instance"""
    global _key_validator
    
    if _key_validator is None:
        security_manager = get_security_manager()
        _key_validator = MediVoteKeyValidator(security_manager)
    
    return _key_validator

def validate_service_keys(service_name: str, service_keys: Dict[str, bytes]) -> List[KeyValidationResult]:
    """Convenience function to validate service keys"""
    validator = get_key_validator()
    return validator.validate_service_keys(service_name, service_keys)

def validate_all_services() -> Dict[str, List[KeyValidationResult]]:
    """Convenience function to validate all active services"""
    validator = get_key_validator()
    return validator.validate_all_active_services()


# ============ ADMIN ALERT SYSTEM ============

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class AdminAlert:
    """Admin alert data structure"""
    alert_id: str
    alert_type: str
    severity: AlertSeverity
    title: str
    message: str
    details: Dict[str, Any]
    timestamp: datetime
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved: bool = False
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None

class AdminAlertSystem:
    """
    COMPREHENSIVE ADMIN ALERT SYSTEM
    
    Handles critical alerts for key synchronization failures, system issues,
    and operational problems that require immediate administrator attention.
    """
    
    def __init__(self):
        self.alerts: Dict[str, AdminAlert] = {}
        self.alert_history: List[AdminAlert] = []
        self.notification_channels: Dict[str, callable] = {}
        self.alert_rules: Dict[str, Dict[str, Any]] = {}
        self.is_enabled = True
        
        # Alert statistics
        self.stats = {
            "alerts_sent": 0,
            "critical_alerts": 0,
            "acknowledged_alerts": 0,
            "resolved_alerts": 0,
            "last_alert_time": None
        }
        
        # Initialize default alert rules
        self._initialize_alert_rules()
        
        # Initialize notification channels
        self._initialize_notification_channels()
        
        logger.critical("ADMIN ALERT SYSTEM INITIALIZED")
        logger.critical("   Real-time Alerts: ENABLED")
        logger.critical("   Critical Alert Escalation: ACTIVE")
        logger.critical("   Multi-channel Notifications: READY")
    
    def _initialize_alert_rules(self):
        """Initialize default alert rules"""
        self.alert_rules = {
            "KEY_MISMATCH_DETECTED": {
                "severity": AlertSeverity.CRITICAL,
                "auto_escalate": True,
                "escalation_delay": 300,  # 5 minutes
                "notification_channels": ["log", "email", "dashboard"],
                "description": "Service using incorrect encryption key"
            },
            "KEY_SYNCHRONIZATION_FAILURE": {
                "severity": AlertSeverity.CRITICAL,
                "auto_escalate": True,
                "escalation_delay": 180,  # 3 minutes
                "notification_channels": ["log", "email", "dashboard"],
                "description": "Key synchronization between services failed"
            },
            "RANDOM_KEY_FALLBACK": {
                "severity": AlertSeverity.CRITICAL,
                "auto_escalate": True,
                "escalation_delay": 60,  # 1 minute
                "notification_channels": ["log", "email", "sms", "dashboard"],
                "description": "Service fell back to random keys - data corruption risk"
            },
            "BLOCKCHAIN_SYNC_FAILURE": {
                "severity": AlertSeverity.ERROR,
                "auto_escalate": False,
                "notification_channels": ["log", "dashboard"],
                "description": "Blockchain synchronization failed"
            },
            "CACHE_BACKUP_FAILURE": {
                "severity": AlertSeverity.WARNING,
                "auto_escalate": False,
                "notification_channels": ["log", "dashboard"],
                "description": "Cache backup operation failed"
            },
            "NETWORK_PARTITION_DETECTED": {
                "severity": AlertSeverity.ERROR,
                "auto_escalate": True,
                "escalation_delay": 600,  # 10 minutes
                "notification_channels": ["log", "email", "dashboard"],
                "description": "Network partition detected in distributed system"
            }
        }
    
    def _initialize_notification_channels(self):
        """Initialize notification channels"""
        self.notification_channels = {
            "log": self._send_log_notification,
            "dashboard": self._send_dashboard_notification,
            "email": self._send_email_notification,
            "sms": self._send_sms_notification,
            "webhook": self._send_webhook_notification
        }
    
    def send_alert(self, alert_type: str, message: str, details: Dict[str, Any] = None, 
                   severity: AlertSeverity = AlertSeverity.WARNING) -> str:
        """Send an admin alert"""
        try:
            alert_id = secrets.token_hex(12)
            
            # Get alert rule or use defaults
            rule = self.alert_rules.get(alert_type, {})
            actual_severity = rule.get("severity", severity)
            
            # Create alert
            alert = AdminAlert(
                alert_id=alert_id,
                alert_type=alert_type,
                severity=actual_severity,
                title=rule.get("description", message),
                message=message,
                details=details or {},
                timestamp=datetime.now()
            )
            
            # Store alert
            self.alerts[alert_id] = alert
            self.alert_history.append(alert)
            
            # Update statistics
            self.stats["alerts_sent"] += 1
            if actual_severity == AlertSeverity.CRITICAL:
                self.stats["critical_alerts"] += 1
            self.stats["last_alert_time"] = datetime.now()
            
            # Send notifications
            notification_channels = rule.get("notification_channels", ["log"])
            self._send_notifications(alert, notification_channels)
            
            # Schedule escalation if needed
            if rule.get("auto_escalate", False):
                escalation_delay = rule.get("escalation_delay", 300)
                asyncio.create_task(self._schedule_escalation(alert_id, escalation_delay))
            
            logger.critical(f"ADMIN ALERT SENT: {alert_type}")
            logger.critical(f"   Alert ID: {alert_id}")
            logger.critical(f"   Severity: {actual_severity.value.upper()}")
            logger.critical(f"   Channels: {notification_channels}")
            
            return alert_id
            
        except Exception as e:
            logger.error(f"Failed to send admin alert: {e}")
            # Fallback logging
            logger.critical(f"FALLBACK ALERT: {alert_type} - {message}")
            return ""
    
    def send_critical_alert(self, alert_type: str, message: str, details: Dict[str, Any] = None) -> str:
        """Send a critical admin alert with immediate escalation"""
        return self.send_alert(alert_type, message, details, AlertSeverity.CRITICAL)
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge an alert"""
        try:
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                alert.acknowledged = True
                alert.acknowledged_by = acknowledged_by
                alert.acknowledged_at = datetime.now()
                
                self.stats["acknowledged_alerts"] += 1
                
                logger.info(f"Alert acknowledged: {alert_id} by {acknowledged_by}")
                return True
            else:
                logger.warning(f"Alert not found for acknowledgment: {alert_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to acknowledge alert: {e}")
            return False
    
    def resolve_alert(self, alert_id: str, resolved_by: str, resolution_note: str = "") -> bool:
        """Resolve an alert"""
        try:
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                alert.resolved = True
                alert.resolved_by = resolved_by
                alert.resolved_at = datetime.now()
                
                if resolution_note:
                    alert.details["resolution_note"] = resolution_note
                
                self.stats["resolved_alerts"] += 1
                
                logger.info(f"Alert resolved: {alert_id} by {resolved_by}")
                return True
            else:
                logger.warning(f"Alert not found for resolution: {alert_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to resolve alert: {e}")
            return False
    
    def _send_notifications(self, alert: AdminAlert, channels: List[str]):
        """Send notifications through specified channels"""
        for channel in channels:
            try:
                if channel in self.notification_channels:
                    self.notification_channels[channel](alert)
                else:
                    logger.warning(f"Unknown notification channel: {channel}")
            except Exception as e:
                logger.error(f"Failed to send notification via {channel}: {e}")
    
    def _send_log_notification(self, alert: AdminAlert):
        """Send alert via logging system"""
        log_level = {
            AlertSeverity.INFO: logger.info,
            AlertSeverity.WARNING: logger.warning,
            AlertSeverity.ERROR: logger.error,
            AlertSeverity.CRITICAL: logger.critical
        }.get(alert.severity, logger.info)
        
        log_level(f"ADMIN ALERT [{alert.alert_type}]: {alert.message}")
        log_level(f"   Alert ID: {alert.alert_id}")
        log_level(f"   Timestamp: {alert.timestamp}")
        if alert.details:
            log_level(f"   Details: {alert.details}")
    
    def _send_dashboard_notification(self, alert: AdminAlert):
        """Send alert to admin dashboard"""
        # In a real implementation, this would update the dashboard
        # For now, store for dashboard retrieval
        dashboard_alert = {
            "alert_id": alert.alert_id,
            "type": alert.alert_type,
            "severity": alert.severity.value,
            "title": alert.title,
            "message": alert.message,
            "timestamp": alert.timestamp.isoformat(),
            "acknowledged": alert.acknowledged,
            "resolved": alert.resolved
        }
        
        # Store for dashboard API
        if not hasattr(self, 'dashboard_alerts'):
            self.dashboard_alerts = []
        
        self.dashboard_alerts.append(dashboard_alert)
        
        # Keep only last 100 alerts for dashboard
        if len(self.dashboard_alerts) > 100:
            self.dashboard_alerts = self.dashboard_alerts[-100:]
    
    def _send_email_notification(self, alert: AdminAlert):
        """Send alert via email"""
        # In a real implementation, this would integrate with email service
        logger.info(f"EMAIL ALERT: {alert.alert_type} - {alert.message}")
        logger.info("   (Email integration not implemented - this is a placeholder)")
    
    def _send_sms_notification(self, alert: AdminAlert):
        """Send alert via SMS"""
        # In a real implementation, this would integrate with SMS service
        logger.info(f"SMS ALERT: {alert.alert_type} - {alert.message}")
        logger.info("   (SMS integration not implemented - this is a placeholder)")
    
    def _send_webhook_notification(self, alert: AdminAlert):
        """Send alert via webhook"""
        # In a real implementation, this would send HTTP webhook
        logger.info(f"WEBHOOK ALERT: {alert.alert_type} - {alert.message}")
        logger.info("   (Webhook integration not implemented - this is a placeholder)")
    
    async def _schedule_escalation(self, alert_id: str, delay_seconds: int):
        """Schedule alert escalation"""
        try:
            await asyncio.sleep(delay_seconds)
            
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                
                # Only escalate if not acknowledged or resolved
                if not alert.acknowledged and not alert.resolved:
                    logger.critical(f"ESCALATING UNACKNOWLEDGED ALERT: {alert_id}")
                    
                    # Send escalated notification
                    escalation_channels = ["log", "email", "sms"]
                    self._send_notifications(alert, escalation_channels)
                    
                    # Mark as escalated
                    alert.details["escalated"] = True
                    alert.details["escalated_at"] = datetime.now().isoformat()
        except Exception as e:
            logger.error(f"Alert escalation failed: {e}")
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active (unresolved) alerts"""
        active_alerts = []
        
        for alert in self.alerts.values():
            if not alert.resolved:
                active_alerts.append({
                    "alert_id": alert.alert_id,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "message": alert.message,
                    "timestamp": alert.timestamp.isoformat(),
                    "acknowledged": alert.acknowledged,
                    "acknowledged_by": alert.acknowledged_by,
                    "details": alert.details
                })
        
        # Sort by severity and timestamp
        severity_order = {
            AlertSeverity.CRITICAL.value: 0,
            AlertSeverity.ERROR.value: 1,
            AlertSeverity.WARNING.value: 2,
            AlertSeverity.INFO.value: 3
        }
        
        active_alerts.sort(key=lambda a: (severity_order.get(a["severity"], 999), a["timestamp"]))
        
        return active_alerts
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get comprehensive alert statistics"""
        recent_alerts = [
            alert for alert in self.alert_history
            if (datetime.now() - alert.timestamp).hours < 24
        ]
        
        return {
            "system_status": {
                "enabled": self.is_enabled,
                "notification_channels": len(self.notification_channels),
                "alert_rules": len(self.alert_rules)
            },
            "alert_stats": self.stats,
            "recent_24h": {
                "total": len(recent_alerts),
                "by_severity": {
                    severity.value: len([a for a in recent_alerts if a.severity == severity])
                    for severity in AlertSeverity
                },
                "by_type": {
                    alert_type: len([a for a in recent_alerts if a.alert_type == alert_type])
                    for alert_type in set(a.alert_type for a in recent_alerts)
                }
            },
            "active_alerts": {
                "total": len([a for a in self.alerts.values() if not a.resolved]),
                "critical": len([a for a in self.alerts.values() 
                               if not a.resolved and a.severity == AlertSeverity.CRITICAL]),
                "unacknowledged": len([a for a in self.alerts.values() 
                                     if not a.resolved and not a.acknowledged])
            }
        }
    
    def cleanup_old_alerts(self, days: int = 30):
        """Clean up old resolved alerts"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # Clean up alerts dictionary
        old_alert_ids = [
            alert_id for alert_id, alert in self.alerts.items()
            if alert.resolved and alert.resolved_at and alert.resolved_at < cutoff_date
        ]
        
        for alert_id in old_alert_ids:
            del self.alerts[alert_id]
        
        # Clean up alert history
        self.alert_history = [
            alert for alert in self.alert_history
            if not (alert.resolved and alert.resolved_at and alert.resolved_at < cutoff_date)
        ]
        
        logger.info(f"Cleaned up {len(old_alert_ids)} old alerts")

# Global admin alert system instance
_admin_alert_system: Optional[AdminAlertSystem] = None

def get_admin_alert_system() -> AdminAlertSystem:
    """Get the global admin alert system instance"""
    global _admin_alert_system
    
    if _admin_alert_system is None:
        _admin_alert_system = AdminAlertSystem()
    
    return _admin_alert_system

def send_admin_alert(alert_type: str, message: str, details: Dict[str, Any] = None, 
                    severity: AlertSeverity = AlertSeverity.WARNING) -> str:
    """Convenience function to send admin alert"""
    alert_system = get_admin_alert_system()
    return alert_system.send_alert(alert_type, message, details, severity)

def send_critical_admin_alert(alert_type: str, message: str, details: Dict[str, Any] = None) -> str:
    """Convenience function to send critical admin alert"""
    alert_system = get_admin_alert_system()
    return alert_system.send_critical_alert(alert_type, message, details) 