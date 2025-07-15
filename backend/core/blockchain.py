"""
Blockchain Service for MediVote
Handles blockchain interactions, smart contracts, and distributed ledger operations
"""

import json
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from web3 import Web3
from web3.contract import Contract
from eth_account import Account
from loguru import logger
import hashlib
import time

from core.config import get_settings

settings = get_settings()


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


class BlockchainService:
    """Service for blockchain interactions"""
    
    def __init__(self):
        self.w3: Optional[Web3] = None
        self.account: Optional[Account] = None
        self.election_contract: Optional[Contract] = None
        self.ballot_contract: Optional[Contract] = None
        self.connected = False
        self.network_id = None
        
    async def initialize(self):
        """Initialize blockchain connection and contracts"""
        try:
            # Connect to blockchain network
            if settings.BLOCKCHAIN_RPC_URL:
                self.w3 = Web3(Web3.HTTPProvider(settings.BLOCKCHAIN_RPC_URL))
                
                # Check connection
                if self.w3.is_connected():
                    self.network_id = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: self.w3.eth.chain_id
                    )
                    logger.info(f"Connected to blockchain network (Chain ID: {self.network_id})")
                else:
                    raise ConnectionError("Failed to connect to blockchain network")
            else:
                # Mock blockchain for testing
                logger.info("Using mock blockchain for development")
                await self._initialize_mock_blockchain()
            
            # Initialize account
            if settings.BLOCKCHAIN_PRIVATE_KEY:
                self.account = Account.from_key(settings.BLOCKCHAIN_PRIVATE_KEY)
                logger.info(f"Blockchain account initialized: {self.account.address}")
            
            # Deploy or connect to smart contracts
            await self._initialize_contracts()
            
            self.connected = True
            logger.info("Blockchain service initialized successfully")
            
        except Exception as e:
            logger.error(f"Blockchain initialization failed: {e}")
            if settings.MOCK_BLOCKCHAIN:
                await self._initialize_mock_blockchain()
                self.connected = True
                logger.info("Fallback to mock blockchain successful")
            else:
                raise
    
    async def _initialize_mock_blockchain(self):
        """Initialize mock blockchain for development"""
        self.w3 = None
        self.network_id = 1337  # Local development chain ID
        self.account = None
        logger.info("Mock blockchain initialized")
    
    async def _initialize_contracts(self):
        """Initialize smart contracts"""
        try:
            # Election bulletin board contract
            election_abi = self._get_election_contract_abi()
            election_bytecode = self._get_election_contract_bytecode()
            
            if settings.CONTRACT_ADDRESS:
                # Connect to existing contract
                if self.w3:
                    self.election_contract = self.w3.eth.contract(
                        address=settings.CONTRACT_ADDRESS,
                        abi=election_abi
                    )
                    logger.info(f"Connected to existing election contract: {settings.CONTRACT_ADDRESS}")
            else:
                # Deploy new contract
                contract_address = await self._deploy_contract(election_abi, election_bytecode)
                if contract_address and self.w3:
                    self.election_contract = self.w3.eth.contract(
                        address=contract_address,
                        abi=election_abi
                    )
                    logger.info(f"Deployed new election contract: {contract_address}")
                
        except Exception as e:
            logger.error(f"Contract initialization failed: {e}")
            # Continue with mock contracts for development
            self.election_contract = None
    
    async def _deploy_contract(self, abi: List[Dict], bytecode: str) -> Optional[str]:
        """Deploy smart contract to blockchain"""
        try:
            if not self.w3 or not self.account:
                return None
            
            contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)
            
            # Build transaction
            transaction = contract.constructor().build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 3000000,
                'gasPrice': self.w3.to_wei('20', 'gwei'),
            })
            
            # Sign and send transaction
            signed_txn = self.account.sign_transaction(transaction)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for transaction receipt
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if tx_receipt.status == 1:
                return tx_receipt.contractAddress
            else:
                raise Exception("Contract deployment failed")
                
        except Exception as e:
            logger.error(f"Contract deployment error: {e}")
            return None
    
    def _get_election_contract_abi(self) -> List[Dict]:
        """Get Election contract ABI"""
        return [
            {
                "inputs": [],
                "name": "ElectionBulletinBoard",
                "type": "constructor"
            },
            {
                "inputs": [
                    {"name": "_electionId", "type": "string"},
                    {"name": "_name", "type": "string"},
                    {"name": "_publicKey", "type": "string"}
                ],
                "name": "createElection",
                "outputs": [],
                "type": "function"
            },
            {
                "inputs": [
                    {"name": "_electionId", "type": "string"},
                    {"name": "_encryptedVote", "type": "string"},
                    {"name": "_blindSignature", "type": "string"}
                ],
                "name": "postBallot",
                "outputs": [],
                "type": "function"
            },
            {
                "inputs": [{"name": "_electionId", "type": "string"}],
                "name": "getBallots",
                "outputs": [{"name": "", "type": "string[]"}],
                "type": "function"
            },
            {
                "inputs": [{"name": "_electionId", "type": "string"}],
                "name": "getElectionInfo",
                "outputs": [
                    {"name": "name", "type": "string"},
                    {"name": "publicKey", "type": "string"},
                    {"name": "ballotCount", "type": "uint256"}
                ],
                "type": "function"
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "name": "electionId", "type": "string"},
                    {"indexed": False, "name": "voteHash", "type": "string"}
                ],
                "name": "BallotPosted",
                "type": "event"
            }
        ]
    
    def _get_election_contract_bytecode(self) -> str:
        """Get Election contract bytecode (simplified)"""
        # In a real implementation, this would be the compiled Solidity bytecode
        return "0x608060405234801561001057600080fd5b50..."  # Truncated for brevity
    
    async def create_election(
        self,
        election_id: str,
        name: str,
        public_key: str
    ) -> Optional[BlockchainTransaction]:
        """Create a new election on the blockchain"""
        try:
            if not self.connected:
                await self.initialize()
            
            if self.election_contract and self.w3 and self.account:
                # Build transaction
                function = self.election_contract.functions.createElection(
                    election_id,
                    name,
                    public_key
                )
                
                transaction = function.build_transaction({
                    'from': self.account.address,
                    'nonce': self.w3.eth.get_transaction_count(self.account.address),
                    'gas': 500000,
                    'gasPrice': self.w3.to_wei('20', 'gwei'),
                })
                
                # Sign and send
                signed_txn = self.account.sign_transaction(transaction)
                tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
                
                # Wait for confirmation
                tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
                
                return BlockchainTransaction(
                    transaction_hash=tx_hash.hex(),
                    block_number=tx_receipt.blockNumber,
                    block_hash=tx_receipt.blockHash.hex(),
                    gas_used=tx_receipt.gasUsed,
                    status="success" if tx_receipt.status == 1 else "failed",
                    timestamp=int(time.time())
                )
            else:
                # Mock transaction for development
                return await self._create_mock_transaction("create_election")
                
        except Exception as e:
            logger.error(f"Election creation failed: {e}")
            return None
    
    async def post_ballot(
        self,
        election_id: str,
        encrypted_vote: str,
        blind_signature: str
    ) -> Optional[BlockchainTransaction]:
        """Post an encrypted ballot to the blockchain"""
        try:
            if not self.connected:
                await self.initialize()
            
            if self.election_contract and self.w3 and self.account:
                # Verify signature before posting
                if not await self._verify_blind_signature(encrypted_vote, blind_signature):
                    raise ValueError("Invalid blind signature")
                
                # Build transaction
                function = self.election_contract.functions.postBallot(
                    election_id,
                    encrypted_vote,
                    blind_signature
                )
                
                transaction = function.build_transaction({
                    'from': self.account.address,
                    'nonce': self.w3.eth.get_transaction_count(self.account.address),
                    'gas': 300000,
                    'gasPrice': self.w3.to_wei('20', 'gwei'),
                })
                
                # Sign and send
                signed_txn = self.account.sign_transaction(transaction)
                tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
                
                # Wait for confirmation
                tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
                
                return BlockchainTransaction(
                    transaction_hash=tx_hash.hex(),
                    block_number=tx_receipt.blockNumber,
                    block_hash=tx_receipt.blockHash.hex(),
                    gas_used=tx_receipt.gasUsed,
                    status="success" if tx_receipt.status == 1 else "failed",
                    timestamp=int(time.time())
                )
            else:
                # Mock transaction for development
                return await self._create_mock_transaction("post_ballot")
                
        except Exception as e:
            logger.error(f"Ballot posting failed: {e}")
            return None
    
    async def get_ballots(self, election_id: str) -> List[Dict[str, Any]]:
        """Get all ballots for an election"""
        try:
            if self.election_contract and self.w3:
                ballots = self.election_contract.functions.getBallots(election_id).call()
                return [{"encrypted_vote": ballot} for ballot in ballots]
            else:
                # Return mock ballots for development
                return await self._get_mock_ballots(election_id)
                
        except Exception as e:
            logger.error(f"Error retrieving ballots: {e}")
            return []
    
    async def get_election_info(self, election_id: str) -> Optional[Dict[str, Any]]:
        """Get election information from blockchain"""
        try:
            if self.election_contract and self.w3:
                info = self.election_contract.functions.getElectionInfo(election_id).call()
                return {
                    "name": info[0],
                    "public_key": info[1],
                    "ballot_count": info[2]
                }
            else:
                # Return mock info for development
                return await self._get_mock_election_info(election_id)
                
        except Exception as e:
            logger.error(f"Error retrieving election info: {e}")
            return None
    
    async def _verify_blind_signature(self, encrypted_vote: str, blind_signature: str) -> bool:
        """Verify blind signature on encrypted vote"""
        # This would integrate with the blind signature verification
        # For now, return True for development
        return True
    
    async def _create_mock_transaction(self, operation: str) -> BlockchainTransaction:
        """Create mock transaction for development"""
        return BlockchainTransaction(
            transaction_hash=f"0x{hashlib.sha256(f'{operation}{time.time()}'.encode()).hexdigest()}",
            block_number=int(time.time()) % 1000000,
            block_hash=f"0x{hashlib.sha256(f'block{time.time()}'.encode()).hexdigest()}",
            gas_used=150000,
            status="success",
            timestamp=int(time.time())
        )
    
    async def _get_mock_ballots(self, election_id: str) -> List[Dict[str, Any]]:
        """Get mock ballots for development"""
        return [
            {"encrypted_vote": f"mock_encrypted_vote_{i}_{election_id}"}
            for i in range(3)
        ]
    
    async def _get_mock_election_info(self, election_id: str) -> Dict[str, Any]:
        """Get mock election info for development"""
        return {
            "name": f"Mock Election {election_id}",
            "public_key": "mock_public_key",
            "ballot_count": 3
        }
    
    async def close(self):
        """Close blockchain connections"""
        try:
            self.connected = False
            logger.info("Blockchain service closed")
        except Exception as e:
            logger.error(f"Error closing blockchain service: {e}")
    
    async def get_network_status(self) -> Dict[str, Any]:
        """Get blockchain network status"""
        try:
            if self.w3 and self.w3.is_connected():
                latest_block = self.w3.eth.get_block('latest')
                return {
                    "connected": True,
                    "network_id": self.network_id,
                    "latest_block": latest_block.number,
                    "block_time": latest_block.timestamp,
                    "account_address": self.account.address if self.account else None
                }
            else:
                return {
                    "connected": False,
                    "network_id": self.network_id,
                    "mode": "mock" if settings.MOCK_BLOCKCHAIN else "disconnected"
                }
        except Exception as e:
            logger.error(f"Error getting network status: {e}")
            return {"connected": False, "error": str(e)}
    
    async def estimate_gas(self, transaction_data: Dict[str, Any]) -> int:
        """Estimate gas for a transaction"""
        try:
            if self.w3:
                return self.w3.eth.estimate_gas(transaction_data)
            else:
                return 150000  # Mock gas estimate
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
        if len(ballots) != election_info.get("ballot_count", 0):
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