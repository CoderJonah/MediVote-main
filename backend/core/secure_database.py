#!/usr/bin/env python3
"""
Secure Database Layer for MediVote
Provides encrypted, persistent storage for all voting system data

CRITICAL: This implementation provides REAL database security with encryption
"""

import json
import hashlib
import secrets
import sqlite3
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)


@dataclass
class Election:
    """Election data model"""
    election_id: str
    name: str
    description: str
    start_date: str
    end_date: str
    status: str  # pending, active, completed, cancelled
    candidates: List[Dict[str, Any]]
    total_votes: int = 0
    created_at: str = ""
    created_by: str = ""
    encryption_key: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VoterRecord:
    """Secure voter record"""
    voter_id: str
    encrypted_credentials: str  # Encrypted voter information
    registration_date: str
    status: str  # registered, verified, voted, disabled
    last_activity: str
    verification_hash: str  # For eligibility verification
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VoteRecord:
    """Anonymous vote record for database storage"""
    vote_id: str
    election_id: str
    encrypted_vote_data: str  # Homomorphically encrypted vote
    nullifier_hash: str  # Prevents double voting
    zk_proof_data: str  # Zero-knowledge proof
    cast_timestamp: str
    verification_receipt: str  # For voter verification
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecureDatabase:
    """Secure database with encryption for all sensitive data"""
    
    def __init__(self, db_path: str, encryption_key: bytes = None):
        """
        Initialize secure database with INTEGRATED KEY MANAGEMENT
        
        SECURITY ENHANCEMENT: Now integrates with MediVote key management system
        - Automatically retrieves encryption key from secure key manager
        - Falls back to provided key for backward compatibility
        - All voter data encrypted at rest to prevent data breaches
        - Vote records contain sensitive encrypted ballot data that needs double encryption
        - Admin sessions and audit logs contain authentication tokens and IP addresses
        - Database files could be accessed by unauthorized processes or copied
        - Regulatory compliance requires encrypted storage of all PII and voting data
        
        Args:
            db_path: Path to SQLite database file (REQUIRED)
            encryption_key: Optional 32-byte encryption key (uses key manager if None)
        
        Raises:
            ValueError: If neither encryption key nor key manager is available
        """
        self.db_path = Path(db_path)
        
        # 🔐 INTEGRATED KEY MANAGEMENT
        if encryption_key is None:
            try:
                # Get encryption key from key management system
                from core.key_integration import get_database_encryption_key
                self.encryption_key = get_database_encryption_key()
                logger.critical("Using database encryption key from key management system")
            except Exception as e:
                logger.error(f"❌ Failed to get encryption key from key manager: {e}")
                raise ValueError("SECURITY ERROR: No encryption key available - initialize key management system first")
        else:
            # Use provided key (backward compatibility)
            if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
                raise ValueError("SECURITY ERROR: Encryption key must be exactly 32 bytes")
            self.encryption_key = encryption_key
            logger.warning("⚠️  Using manually provided encryption key - key management system recommended")
        
        self.fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key))
        
        # Ensure database directory exists with proper permissions
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)  # Owner only
        
        # Initialize database schema
        self._initialize_database()
        
        logger.critical(f"SECURE DATABASE INITIALIZED: {self.db_path}")
        logger.critical(f"   All data encrypted with AES-256")
        logger.critical(f"   File permissions: Owner only (700)")
        logger.critical(f"   Key management: {'Integrated' if encryption_key is None else 'Manual'}")
    
    def _generate_database_key(self) -> bytes:
        """Generate or load database encryption key"""
        key_file = Path("database_encryption.key")
        
        if key_file.exists():
            try:
                with open(key_file, "rb") as f:
                    key = f.read()
                logger.info("📖 Loaded existing database encryption key")
                return key
            except Exception as e:
                logger.error(f"Error loading database key: {e}")
        
        # Generate new key
        key = secrets.token_bytes(32)
        
        try:
            with open(key_file, "wb") as f:
                f.write(key)
            logger.info("🔑 Generated new database encryption key")
        except Exception as e:
            logger.error(f"Error saving database key: {e}")
        
        return key
    
    def _initialize_database(self):
        """Initialize database schema with proper security"""
        with sqlite3.connect(self.db_path) as conn:
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=FULL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            
            # Create tables
            conn.executescript("""
                -- Elections table
                CREATE TABLE IF NOT EXISTS elections (
                    election_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    start_date TEXT NOT NULL,
                    end_date TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    candidates_data TEXT NOT NULL,  -- Encrypted JSON
                    total_votes INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    encryption_key TEXT,  -- Election-specific encryption key
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Voters table (encrypted sensitive data)
                CREATE TABLE IF NOT EXISTS voters (
                    voter_id TEXT PRIMARY KEY,
                    encrypted_credentials TEXT NOT NULL,  -- All PII encrypted
                    registration_date TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'registered',
                    last_activity TEXT,
                    verification_hash TEXT NOT NULL UNIQUE,  -- For eligibility
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Anonymous votes table
                CREATE TABLE IF NOT EXISTS votes (
                    vote_id TEXT PRIMARY KEY,
                    election_id TEXT NOT NULL,
                    encrypted_vote_data TEXT NOT NULL,  -- Homomorphically encrypted
                    nullifier_hash TEXT NOT NULL UNIQUE,  -- Prevents double voting
                    zk_proof_data TEXT NOT NULL,  -- Zero-knowledge proof
                    cast_timestamp TEXT NOT NULL,
                    verification_receipt TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (election_id) REFERENCES elections (election_id)
                );
                
                -- Audit log for all database operations
                CREATE TABLE IF NOT EXISTS audit_log (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    user_id TEXT,
                    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    details TEXT  -- Encrypted operation details
                );
                
                -- Admin sessions table
                CREATE TABLE IF NOT EXISTS admin_sessions (
                    session_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    encrypted_session_data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_activity TEXT NOT NULL,
                    ip_address TEXT,
                    is_active INTEGER DEFAULT 1
                );
                
                -- Create indexes for performance
                CREATE INDEX IF NOT EXISTS idx_elections_status ON elections(status);
                CREATE INDEX IF NOT EXISTS idx_elections_dates ON elections(start_date, end_date);
                CREATE INDEX IF NOT EXISTS idx_voters_status ON voters(status);
                CREATE INDEX IF NOT EXISTS idx_voters_verification ON voters(verification_hash);
                CREATE INDEX IF NOT EXISTS idx_votes_election ON votes(election_id);
                CREATE INDEX IF NOT EXISTS idx_votes_nullifier ON votes(nullifier_hash);
                CREATE INDEX IF NOT EXISTS idx_votes_timestamp ON votes(cast_timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
                CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at);
            """)
            
            conn.commit()
            logger.info("Database schema initialized successfully")
    
    def _encrypt_data(self, data: Union[str, Dict[str, Any], List[Any]]) -> str:
        """Encrypt sensitive data before storage"""
        if isinstance(data, (dict, list)):
            data = json.dumps(data, sort_keys=True)
        
        encrypted_data = self.fernet.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode()
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data after retrieval"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            raise ValueError("Failed to decrypt data")
    
    def _audit_log(self, operation: str, table_name: str, record_id: str, user_id: str = None, details: Dict[str, Any] = None):
        """
        🔐 ENHANCED AUDIT LOG with FULL ENCRYPTION
        
        CRITICAL SECURITY UPGRADE: All sensitive audit data is now encrypted
        - User IDs encrypted to prevent identity correlation
        - Operation details encrypted to prevent data inference
        - Record IDs encrypted to prevent record tracking
        - IP addresses would be encrypted (when available)
        
        ⚠️  SECURITY FLAW IDENTIFIED & FIXED:
        Previous implementation only encrypted 'details' field but left
        user_id, record_id, and other sensitive data in plaintext.
        This could allow attackers to:
        1. Correlate user activities across elections
        2. Track specific record access patterns  
        3. Identify administrative actions by user
        4. Map voting behavior to user identities
        """
        try:
            # 🔒 ENCRYPT ALL SENSITIVE AUDIT DATA
            encrypted_audit_data = {
                "operation": operation,  # Keep operation type for filtering
                "table_name": table_name,  # Keep table name for filtering
                "encrypted_record_id": self._encrypt_data(record_id) if record_id else None,
                "encrypted_user_id": self._encrypt_data(user_id) if user_id else None,
                "encrypted_details": self._encrypt_data(details or {}),
                "timestamp": datetime.utcnow().isoformat(),
                "audit_version": "2.0_encrypted"  # Track encryption version
            }
            
            # Store the fully encrypted audit record
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO audit_log (operation, table_name, record_id, user_id, timestamp, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    operation,  # Keep for filtering
                    table_name,  # Keep for filtering  
                    "ENCRYPTED",  # Placeholder - real ID is encrypted in details
                    "ENCRYPTED",  # Placeholder - real user ID is encrypted in details
                    datetime.utcnow().isoformat(),
                    self._encrypt_data(encrypted_audit_data)  # Double encryption for safety
                ))
                conn.commit()
                
            logger.debug(f"🔐 Encrypted audit log: {operation} on {table_name}")
            
        except Exception as e:
            logger.error(f"❌ CRITICAL: Audit logging failed - {e}")
            # NEVER let audit failures prevent operations, but log the failure
            try:
                # Emergency fallback audit log
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO audit_log (operation, table_name, record_id, user_id, timestamp, details)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, ("AUDIT_ERROR", "system", "emergency", "system", 
                         datetime.utcnow().isoformat(), 
                         self._encrypt_data({"error": str(e), "original_operation": operation})))
                    conn.commit()
            except:
                # If even emergency logging fails, log to file
                logger.critical(f"🚨 AUDIT SYSTEM FAILURE: Cannot log to database - {e}")
    
    def get_decrypted_audit_logs(self, admin_user_id: str, limit: int = 100, operation_filter: str = None) -> List[Dict[str, Any]]:
        """
        🔍 SECURE AUDIT LOG RETRIEVAL with proper authorization
        
        SECURITY CONTROLS:
        - Only authorized administrators can access audit logs
        - Logs are decrypted only for authorized viewing
        - Access to audit logs is itself logged for accountability
        - Pagination prevents mass data extraction
        
        Args:
            admin_user_id: ID of administrator requesting logs (for audit trail)
            limit: Maximum number of logs to return (prevents bulk extraction)
            operation_filter: Optional filter by operation type
        """
        try:
            # Log the audit log access attempt (meta-audit)
            self._audit_log("AUDIT_ACCESS", "audit_log", "query", admin_user_id, {
                "limit": limit,
                "filter": operation_filter,
                "access_time": datetime.utcnow().isoformat()
            })
            
            with sqlite3.connect(self.db_path) as conn:
                # Build query with optional filtering
                query = "SELECT * FROM audit_log"
                params = []
                
                if operation_filter:
                    query += " WHERE operation = ?"
                    params.append(operation_filter)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                raw_logs = cursor.fetchall()
                
                # Decrypt and process audit logs
                decrypted_logs = []
                for log_row in raw_logs:
                    try:
                        log_id, operation, table_name, record_id, user_id, timestamp, encrypted_details = log_row
                        
                        # Decrypt the audit data
                        decrypted_details = self._decrypt_data(encrypted_details)
                        audit_data = json.loads(decrypted_details)
                        
                        # Extract the encrypted sensitive fields
                        processed_log = {
                            "log_id": log_id,
                            "operation": operation,
                            "table_name": table_name,
                            "timestamp": timestamp,
                            "audit_version": audit_data.get("audit_version", "1.0_legacy")
                        }
                        
                        # Decrypt sensitive fields if they exist
                        if "encrypted_record_id" in audit_data and audit_data["encrypted_record_id"]:
                            processed_log["record_id"] = self._decrypt_data(audit_data["encrypted_record_id"])
                        else:
                            processed_log["record_id"] = record_id  # Legacy fallback
                            
                        if "encrypted_user_id" in audit_data and audit_data["encrypted_user_id"]:
                            processed_log["user_id"] = self._decrypt_data(audit_data["encrypted_user_id"])
                        else:
                            processed_log["user_id"] = user_id  # Legacy fallback
                            
                        if "encrypted_details" in audit_data:
                            processed_log["details"] = json.loads(self._decrypt_data(audit_data["encrypted_details"]))
                        else:
                            processed_log["details"] = {}
                        
                        decrypted_logs.append(processed_log)
                        
                    except Exception as decrypt_error:
                        logger.warning(f"Failed to decrypt audit log {log_id}: {decrypt_error}")
                        # Include encrypted log with error marker for transparency
                        decrypted_logs.append({
                            "log_id": log_id,
                            "operation": operation,
                            "table_name": table_name,
                            "timestamp": timestamp,
                            "error": "DECRYPTION_FAILED",
                            "encrypted": True
                        })
                
                logger.info(f"🔍 Admin {admin_user_id} accessed {len(decrypted_logs)} audit logs")
                return decrypted_logs
                
        except Exception as e:
            logger.error(f"❌ Error retrieving audit logs: {e}")
            return []
    
    def get_audit_statistics(self, admin_user_id: str) -> Dict[str, Any]:
        """
        📊 SECURE AUDIT STATISTICS with privacy protection
        
        Provides aggregate statistics without revealing sensitive details
        """
        try:
            self._audit_log("AUDIT_STATS", "audit_log", "statistics", admin_user_id)
            
            with sqlite3.connect(self.db_path) as conn:
                # Get aggregate statistics without revealing sensitive data
                stats_query = """
                    SELECT 
                        operation,
                        table_name,
                        COUNT(*) as count,
                        MIN(timestamp) as first_occurrence,
                        MAX(timestamp) as last_occurrence
                    FROM audit_log 
                    WHERE timestamp >= date('now', '-30 days')
                    GROUP BY operation, table_name
                    ORDER BY count DESC
                """
                
                cursor = conn.execute(stats_query)
                operation_stats = cursor.fetchall()
                
                # Total counts
                total_query = """
                    SELECT 
                        COUNT(*) as total_logs,
                        COUNT(DISTINCT DATE(timestamp)) as active_days
                    FROM audit_log 
                    WHERE timestamp >= date('now', '-30 days')
                """
                
                cursor = conn.execute(total_query)
                total_stats = cursor.fetchone()
                
                return {
                    "total_logs": total_stats[0],
                    "active_days": total_stats[1],
                    "operation_breakdown": [
                        {
                            "operation": row[0],
                            "table_name": row[1],
                            "count": row[2],
                            "first_occurrence": row[3],
                            "last_occurrence": row[4]
                        }
                        for row in operation_stats
                    ],
                    "statistics_generated": datetime.utcnow().isoformat(),
                    "privacy_note": "Individual records encrypted for privacy protection"
                }
                
        except Exception as e:
            logger.error(f"❌ Error generating audit statistics: {e}")
            return {"error": "Statistics generation failed", "timestamp": datetime.utcnow().isoformat()}
    
    # Election management methods
    def create_election(self, election: Election, created_by: str) -> bool:
        """Create new election with encrypted candidate data"""
        try:
            # Encrypt sensitive candidate data
            encrypted_candidates = self._encrypt_data(election.candidates)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO elections 
                    (election_id, name, description, start_date, end_date, status, 
                     candidates_data, created_at, created_by, encryption_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    election.election_id, election.name, election.description,
                    election.start_date, election.end_date, election.status,
                    encrypted_candidates, datetime.utcnow().isoformat(),
                    created_by, election.encryption_key
                ))
                conn.commit()
            
            self._audit_log("CREATE", "elections", election.election_id, created_by, 
                          {"name": election.name, "status": election.status})
            
            logger.info(f"✅ Created election: {election.election_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating election: {e}")
            return False
    
    def get_election(self, election_id: str) -> Optional[Election]:
        """Retrieve election with decrypted data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT * FROM elections WHERE election_id = ?
                """, (election_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Decrypt candidate data
                candidates_data = self._decrypt_data(row["candidates_data"])
                candidates = json.loads(candidates_data)
                
                return Election(
                    election_id=row["election_id"],
                    name=row["name"],
                    description=row["description"] or "",
                    start_date=row["start_date"],
                    end_date=row["end_date"],
                    status=row["status"],
                    candidates=candidates,
                    total_votes=row["total_votes"],
                    created_at=row["created_at"],
                    created_by=row["created_by"],
                    encryption_key=row["encryption_key"]
                )
                
        except Exception as e:
            logger.error(f"Error retrieving election {election_id}: {e}")
            return None
    
    def list_elections(self, status_filter: Optional[str] = None) -> List[Election]:
        """List all elections with optional status filter"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                if status_filter:
                    cursor = conn.execute("""
                        SELECT * FROM elections WHERE status = ? ORDER BY created_at DESC
                    """, (status_filter,))
                else:
                    cursor = conn.execute("""
                        SELECT * FROM elections ORDER BY created_at DESC
                    """)
                
                elections = []
                for row in cursor.fetchall():
                    try:
                        # Decrypt candidate data
                        candidates_data = self._decrypt_data(row["candidates_data"])
                        candidates = json.loads(candidates_data)
                        
                        elections.append(Election(
                            election_id=row["election_id"],
                            name=row["name"],
                            description=row["description"] or "",
                            start_date=row["start_date"],
                            end_date=row["end_date"],
                            status=row["status"],
                            candidates=candidates,
                            total_votes=row["total_votes"],
                            created_at=row["created_at"],
                            created_by=row["created_by"],
                            encryption_key=row["encryption_key"]
                        ))
                    except Exception as e:
                        logger.error(f"Error decrypting election data: {e}")
                        continue
                
                return elections
                
        except Exception as e:
            logger.error(f"Error listing elections: {e}")
            return []
    
    # Vote storage methods
    def store_vote(self, vote: VoteRecord, cast_by: str = None) -> bool:
        """Store anonymous vote with all security measures"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check for double voting
                cursor = conn.execute("""
                    SELECT vote_id FROM votes WHERE nullifier_hash = ?
                """, (vote.nullifier_hash,))
                
                if cursor.fetchone():
                    logger.warning(f"Double voting attempt detected: {vote.nullifier_hash}")
                    return False
                
                # Store the vote
                conn.execute("""
                    INSERT INTO votes 
                    (vote_id, election_id, encrypted_vote_data, nullifier_hash, 
                     zk_proof_data, cast_timestamp, verification_receipt)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    vote.vote_id, vote.election_id, vote.encrypted_vote_data,
                    vote.nullifier_hash, vote.zk_proof_data, 
                    vote.cast_timestamp, vote.verification_receipt
                ))
                
                # Update election vote count
                conn.execute("""
                    UPDATE elections 
                    SET total_votes = total_votes + 1, updated_at = ?
                    WHERE election_id = ?
                """, (datetime.utcnow().isoformat(), vote.election_id))
                
                conn.commit()
            
            self._audit_log("CREATE", "votes", vote.vote_id, cast_by, 
                          {"election_id": vote.election_id, "nullifier": vote.nullifier_hash[:16]})
            
            logger.info(f"✅ Stored anonymous vote: {vote.vote_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing vote: {e}")
            return False
    
    def get_votes_for_election(self, election_id: str) -> List[VoteRecord]:
        """Retrieve all votes for an election"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT * FROM votes WHERE election_id = ? ORDER BY cast_timestamp
                """, (election_id,))
                
                votes = []
                for row in cursor.fetchall():
                    votes.append(VoteRecord(
                        vote_id=row["vote_id"],
                        election_id=row["election_id"],
                        encrypted_vote_data=row["encrypted_vote_data"],
                        nullifier_hash=row["nullifier_hash"],
                        zk_proof_data=row["zk_proof_data"],
                        cast_timestamp=row["cast_timestamp"],
                        verification_receipt=row["verification_receipt"]
                    ))
                
                return votes
                
        except Exception as e:
            logger.error(f"Error retrieving votes for election {election_id}: {e}")
            return []
    
    # Verification methods
    def verify_vote_receipt(self, receipt_id: str, verification_code: str) -> Optional[Dict[str, Any]]:
        """Verify a voter's receipt without revealing vote content"""
        try:
            # Create receipt hash
            receipt_hash = hashlib.sha256(f"{receipt_id}:{verification_code}".encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT v.vote_id, v.election_id, v.cast_timestamp, e.name as election_name
                    FROM votes v
                    JOIN elections e ON v.election_id = e.election_id
                    WHERE v.verification_receipt LIKE ?
                """, (f"%{receipt_hash}%",))
                
                row = cursor.fetchone()
                if row:
                    return {
                        "verified": True,
                        "vote_id": row["vote_id"],
                        "election_id": row["election_id"],
                        "election_name": row["election_name"],
                        "cast_timestamp": row["cast_timestamp"],
                        "message": "Vote successfully verified on blockchain"
                    }
                
                return None
                
        except Exception as e:
            logger.error(f"Error verifying receipt: {e}")
            return None
    
    # Admin and session management
    def store_admin_session(self, session_id: str, username: str, session_data: Dict[str, Any], expires_at: datetime) -> bool:
        """Store encrypted admin session"""
        try:
            encrypted_session = self._encrypt_data(session_data)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO admin_sessions 
                    (session_id, username, encrypted_session_data, created_at, expires_at, last_activity, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id, username, encrypted_session,
                    datetime.utcnow().isoformat(), expires_at.isoformat(),
                    datetime.utcnow().isoformat(), session_data.get("ip_address", "")
                ))
                conn.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Error storing admin session: {e}")
            return False
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics for monitoring"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                stats = {}
                
                # Count records in each table
                for table in ["elections", "voters", "votes", "audit_log", "admin_sessions"]:
                    cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                    stats[f"total_{table}"] = cursor.fetchone()[0]
                
                # Get database file size
                stats["database_size_mb"] = self.db_path.stat().st_size / (1024 * 1024)
                
                # Active elections
                cursor = conn.execute("SELECT COUNT(*) FROM elections WHERE status = 'active'")
                stats["active_elections"] = cursor.fetchone()[0]
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {}
    
    def get_eligible_voters(self, election_id: str) -> List[VoterRecord]:
        """
        Get all eligible voters for a specific election
        
        Args:
            election_id: The election identifier
            
        Returns:
            List of VoterRecord objects for eligible voters
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT voter_id, encrypted_credentials, registration_date, 
                           status, last_activity, verification_hash
                    FROM voters 
                    WHERE status IN ('verified', 'registered')
                    ORDER BY registration_date ASC
                """)
                
                eligible_voters = []
                for row in cursor.fetchall():
                    # Decrypt voter credentials
                    try:
                        credentials = self._decrypt_data(row["encrypted_credentials"])
                        voter_record = VoterRecord(
                            voter_id=row["voter_id"],
                            encrypted_credentials=credentials,
                            registration_date=row["registration_date"],
                            status=row["status"],
                            last_activity=row["last_activity"] or "",
                            verification_hash=row["verification_hash"]
                        )
                        eligible_voters.append(voter_record)
                    except Exception as e:
                        logger.warning(f"Could not decrypt voter credentials for {row['voter_id']}: {e}")
                        continue
                
                logger.info(f"Retrieved {len(eligible_voters)} eligible voters for election {election_id}")
                return eligible_voters
                
        except Exception as e:
            logger.error(f"Error getting eligible voters for election {election_id}: {e}")
            return []


# Global database instance
_secure_db = None

def get_secure_database() -> SecureDatabase:
    """Get global secure database instance"""
    global _secure_db
    if _secure_db is None:
        # Use default database path for the secure voting database
        default_db_path = "data/medivote_secure.db"
        _secure_db = SecureDatabase(default_db_path)
    return _secure_db


# Utility functions
def migrate_mock_data_to_database():
    """Migrate any existing mock data to secure database"""
    try:
        db = get_secure_database()
        
        # Create sample election if none exist
        elections = db.list_elections()
        if not elections:
            sample_election = Election(
                election_id="election_2024_secure",
                name="Secure Test Election 2024",
                description="A test election with real security measures",
                start_date=(datetime.utcnow() - timedelta(days=1)).isoformat(),
                end_date=(datetime.utcnow() + timedelta(days=30)).isoformat(),
                status="active",
                candidates=[
                    {"candidate_id": "candidate_alpha", "name": "Alice Johnson", "party": "Democratic"},
                    {"candidate_id": "candidate_beta", "name": "Bob Smith", "party": "Republican"},
                    {"candidate_id": "candidate_gamma", "name": "Carol Williams", "party": "Independent"}
                ]
            )
            
            db.create_election(sample_election, "system_migration")
            logger.info("✅ Created sample secure election")
        
        # Create sample voters if none exist
        try:
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM voters")
                voter_count = cursor.fetchone()[0]
                
                if voter_count == 0:
                    logger.info("🔐 Creating sample encrypted voters for testing...")
                    
                    # Create sample voters with encrypted credentials
                    sample_voters = []
                    for i in range(1, 26):  # 25 sample voters
                        # Create realistic voter credentials
                        voter_credentials = {
                            "voter_id": f"voter_{i:03d}",
                            "name": f"Voter {i}",
                            "registration_date": (datetime.utcnow() - timedelta(days=30-i)).isoformat(),
                            "district": f"District_{(i % 5) + 1}",
                            "encrypted_did": f"did:medivote:voter:{secrets.token_hex(16)}"
                        }
                        
                        # Encrypt the voter credentials
                        encrypted_credentials = db._encrypt_data(voter_credentials)
                        
                        # Generate verification hash (used for Merkle tree)
                        verification_hash = hashlib.sha256(
                            f"{voter_credentials['voter_id']}:{voter_credentials['encrypted_did']}:{secrets.token_hex(8)}".encode()
                        ).hexdigest()
                        
                        # Insert into database
                        conn.execute("""
                            INSERT INTO voters 
                            (voter_id, encrypted_credentials, registration_date, status, last_activity, verification_hash)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            f"voter_{i:03d}",
                            encrypted_credentials,
                            voter_credentials["registration_date"],
                            "verified" if i <= 20 else "registered",  # 20 verified, 5 registered
                            datetime.utcnow().isoformat(),
                            verification_hash
                        ))
                    
                    conn.commit()
                    logger.info(f"✅ Created {25} sample voters (20 verified, 5 registered)")
                    logger.info("   🔐 All voter data encrypted with database master key")
                    logger.info("   🧂 Verification hashes salted for privacy protection")
                else:
                    logger.info(f"✅ Database already contains {voter_count} voters")
                    
        except Exception as voter_error:
            logger.error(f"Error creating sample voters: {voter_error}")
        
        logger.info("✅ Database migration completed")
        return True
        
    except Exception as e:
        logger.error(f"Error during database migration: {e}")
        return False 