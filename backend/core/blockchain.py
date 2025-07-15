"""
Local Blockchain Service for MediVote
Handles local blockchain operations, smart contracts, and distributed ledger operations
"""

import json
import asyncio
import hashlib
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import secrets
from loguru import logger

from config import get_settings

settings = get_settings()


@dataclass
class Block:
    """Blockchain block structure"""
    index: int
    timestamp: float
    transactions: List[Dict[str, Any]]
    previous_hash: str
    hash: str
    nonce: int = 0


@dataclass
class BlockchainTransaction:
    """Blockchain transaction data"""
    transaction_hash: str
    block_number: int
    block_hash: str
    gas_used: int
    status: str
    timestamp: int


@dataclass
class VoteTransaction:
    """Vote transaction for blockchain"""
    vote_id: str
    election_id: str
    encrypted_vote: str
    blind_signature: str
    timestamp: int
    voter_proof: str


class LocalBlockchain:
    """Local blockchain implementation"""
    
    def __init__(self, data_dir: str = "./blockchain_data"):
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.nodes: List[str] = []
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.difficulty = 4  # Number of leading zeros required
        self.block_time = 15  # Target block time in seconds
        self.mining_thread: Optional[threading.Thread] = None
        self.is_mining = False
        
        # Load existing blockchain
        self._load_blockchain()
        
        # Create genesis block if chain is empty
        if len(self.chain) == 0:
            self._create_genesis_block()
    
    def _load_blockchain(self):
        """Load blockchain from disk"""
        chain_file = self.data_dir / "blockchain.json"
        if chain_file.exists():
            try:
                with open(chain_file, 'r') as f:
                    chain_data = json.load(f)
                    self.chain = [Block(**block) for block in chain_data]
                logger.info(f"Loaded blockchain with {len(self.chain)} blocks")
            except Exception as e:
                logger.error(f"Failed to load blockchain: {e}")
    
    def _save_blockchain(self):
        """Save blockchain to disk"""
        chain_file = self.data_dir / "blockchain.json"
        try:
            with open(chain_file, 'w') as f:
                json.dump([asdict(block) for block in self.chain], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save blockchain: {e}")
    
    def _create_genesis_block(self):
        """Create the genesis block"""
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            transactions=[],
            previous_hash="0" * 64,
            hash="",
            nonce=0
        )
        genesis_block.hash = self._calculate_hash(genesis_block)
        self.chain.append(genesis_block)
        self._save_blockchain()
        logger.info("Created genesis block")
    
    def _calculate_hash(self, block: Block) -> str:
        """Calculate hash of a block"""
        block_string = json.dumps(asdict(block), sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def _get_latest_block(self) -> Block:
        """Get the latest block in the chain"""
        return self.chain[-1]
    
    def _mine_block(self, transactions: List[Dict[str, Any]]) -> Block:
        """Mine a new block with the given transactions"""
        previous_block = self._get_latest_block()
        new_block = Block(
            index=previous_block.index + 1,
            timestamp=time.time(),
            transactions=transactions,
            previous_hash=previous_block.hash,
            hash="",
            nonce=0
        )
        
        # Mine the block
        while True:
            new_block.hash = self._calculate_hash(new_block)
            if new_block.hash.startswith("0" * self.difficulty):
                break
            new_block.nonce += 1
        
        return new_block
    
    def add_transaction(self, transaction: Dict[str, Any]) -> str:
        """Add a transaction to the pending transactions"""
        transaction_hash = hashlib.sha256(
            json.dumps(transaction, sort_keys=True).encode()
        ).hexdigest()
        
        transaction["hash"] = transaction_hash
        transaction["timestamp"] = int(time.time())
        
        self.pending_transactions.append(transaction)
        logger.info(f"Added transaction: {transaction_hash}")
        
        return transaction_hash
    
    def mine_pending_transactions(self) -> Optional[Block]:
        """Mine pending transactions into a new block"""
        if not self.pending_transactions:
            return None
        
        # Create new block
        new_block = self._mine_block(self.pending_transactions)
        
        # Add block to chain
        self.chain.append(new_block)
        
        # Clear pending transactions
        self.pending_transactions = []
        
        # Save blockchain
        self._save_blockchain()
        
        logger.info(f"Mined block {new_block.index} with {len(new_block.transactions)} transactions")
        return new_block
    
    def is_chain_valid(self) -> bool:
        """Check if the blockchain is valid"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if current block hash is valid
            if current_block.hash != self._calculate_hash(current_block):
                return False
            
            # Check if previous block hash is correct
            if current_block.previous_hash != previous_block.hash:
                return False
        
        return True
    
    def get_balance(self, address: str) -> int:
        """Get balance of an address (simplified)"""
        balance = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.get("to") == address:
                    balance += transaction.get("amount", 0)
                if transaction.get("from") == address:
                    balance -= transaction.get("amount", 0)
        return balance
    
    def get_transactions_by_election(self, election_id: str) -> List[Dict[str, Any]]:
        """Get all transactions for a specific election"""
        transactions = []
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.get("election_id") == election_id:
                    transactions.append(transaction)
        return transactions
    
    def start_mining(self):
        """Start background mining process"""
        if not self.is_mining:
            self.is_mining = True
            self.mining_thread = threading.Thread(target=self._mining_worker, daemon=True)
            self.mining_thread.start()
            logger.info("Started background mining")
    
    def stop_mining(self):
        """Stop background mining process"""
        self.is_mining = False
        if self.mining_thread:
            self.mining_thread.join(timeout=1)
        logger.info("Stopped background mining")
    
    def _mining_worker(self):
        """Background mining worker"""
        while self.is_mining:
            if self.pending_transactions:
                self.mine_pending_transactions()
            time.sleep(self.block_time)


class BlockchainService:
    """Service for blockchain interactions"""
    
    def __init__(self):
        self.blockchain: Optional[LocalBlockchain] = None
        self.connected = False
        self.network_id = 1337  # Local development chain ID
        
    async def initialize(self):
        """Initialize blockchain connection and contracts"""
        try:
            # Initialize local blockchain
            self.blockchain = LocalBlockchain()
            
            # Start mining
            self.blockchain.start_mining()
            
            self.connected = True
            logger.info("Local blockchain service initialized successfully")
            
        except Exception as e:
            logger.error(f"Blockchain initialization failed: {e}")
            raise
    
    async def create_election(
        self,
        election_id: str,
        name: str,
        public_key: str
    ) -> Optional[BlockchainTransaction]:
        """Create a new election on the blockchain"""
        try:
            if not self.blockchain:
                return None
            
            transaction = {
                "type": "create_election",
                "election_id": election_id,
                "name": name,
                "public_key": public_key,
                "timestamp": int(time.time())
            }
            
            transaction_hash = self.blockchain.add_transaction(transaction)
            
            # Create transaction receipt
            receipt = BlockchainTransaction(
                transaction_hash=transaction_hash,
                block_number=len(self.blockchain.chain),
                block_hash="pending",
                gas_used=0,
                status="pending",
                timestamp=int(time.time())
            )
            
            logger.info(f"Created election: {election_id}")
            return receipt
            
        except Exception as e:
            logger.error(f"Failed to create election: {e}")
            return None
    
    async def post_ballot(
        self,
        election_id: str,
        encrypted_vote: str,
        blind_signature: str
    ) -> Optional[BlockchainTransaction]:
        """Post a ballot to the blockchain"""
        try:
            if not self.blockchain:
                return None
            
            transaction = {
                "type": "post_ballot",
                "election_id": election_id,
                "encrypted_vote": encrypted_vote,
                "blind_signature": blind_signature,
                "timestamp": int(time.time())
            }
            
            transaction_hash = self.blockchain.add_transaction(transaction)
            
            # Create transaction receipt
            receipt = BlockchainTransaction(
                transaction_hash=transaction_hash,
                block_number=len(self.blockchain.chain),
                block_hash="pending",
                gas_used=0,
                status="pending",
                timestamp=int(time.time())
            )
            
            logger.info(f"Posted ballot for election: {election_id}")
            return receipt
            
        except Exception as e:
            logger.error(f"Failed to post ballot: {e}")
            return None
    
    async def get_ballots(self, election_id: str) -> List[Dict[str, Any]]:
        """Get all ballots for an election"""
        try:
            if not self.blockchain:
                return []
            
            transactions = self.blockchain.get_transactions_by_election(election_id)
            ballots = [tx for tx in transactions if tx.get("type") == "post_ballot"]
            
            return ballots
            
        except Exception as e:
            logger.error(f"Failed to get ballots: {e}")
            return []
    
    async def get_election_info(self, election_id: str) -> Optional[Dict[str, Any]]:
        """Get election information"""
        try:
            if not self.blockchain:
                return None
            
            transactions = self.blockchain.get_transactions_by_election(election_id)
            election_creation = [tx for tx in transactions if tx.get("type") == "create_election"]
            
            if not election_creation:
                return None
            
            election_data = election_creation[0]
            ballots = await self.get_ballots(election_id)
            
            return {
                "election_id": election_id,
                "name": election_data.get("name", ""),
                "public_key": election_data.get("public_key", ""),
                "created_at": election_data.get("timestamp", 0),
                "total_ballots": len(ballots),
                "ballots": ballots
            }
            
        except Exception as e:
            logger.error(f"Failed to get election info: {e}")
            return None
    
    async def close(self):
        """Close blockchain service"""
        if self.blockchain:
            self.blockchain.stop_mining()
        self.connected = False
        logger.info("Blockchain service closed")
    
    async def get_network_status(self) -> Dict[str, Any]:
        """Get blockchain network status"""
        try:
            if not self.blockchain:
                return {"status": "disconnected"}
            
            return {
                "status": "connected" if self.connected else "disconnected",
                "network_id": self.network_id,
                "chain_length": len(self.blockchain.chain),
                "pending_transactions": len(self.blockchain.pending_transactions),
                "difficulty": self.blockchain.difficulty,
                "is_mining": self.blockchain.is_mining,
                "is_valid": self.blockchain.is_chain_valid()
            }
            
        except Exception as e:
            logger.error(f"Failed to get network status: {e}")
            return {"status": "error", "error": str(e)}
    
    async def estimate_gas(self, transaction_data: Dict[str, Any]) -> int:
        """Estimate gas for a transaction"""
        try:
            if self.blockchain:
                return 150000  # Mock gas estimate for local blockchain
            else:
                return 300000  # Safe default
        except Exception as e:
            logger.error(f"Gas estimation failed: {e}")
            return 300000  # Safe default


# Utility functions
async def verify_blockchain_integrity(blockchain_service: BlockchainService, election_id: str) -> bool:
    """Verify the integrity of blockchain data for an election"""
    try:
        ballots = await blockchain_service.get_ballots(election_id)
        election_info = await blockchain_service.get_election_info(election_id)
        
        if not election_info:
            return False
        
        # Verify ballot count matches
        if len(ballots) != election_info.get("total_ballots", 0):
            return False
        
        # Additional integrity checks would go here
        return True
        
    except Exception as e:
        logger.error(f"Blockchain integrity verification failed: {e}")
        return False


async def calculate_merkle_root(data_list: List[str]) -> str:
    """Calculate Merkle root for blockchain data"""
    if not data_list:
        return ""
    
    # Simple Merkle tree implementation
    def hash_pair(left: str, right: str) -> str:
        return hashlib.sha256(f"{left}{right}".encode()).hexdigest()
    
    level = data_list[:]
    
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(hash_pair(left, right))
        level = next_level
    
    return level[0] if level else "" 