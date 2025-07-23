# MediVote Cryptographic Keys Documentation

**⚠️  CRITICAL SECURITY NOTICE**
This document contains information about cryptographic keys used in the MediVote system. **NEVER commit actual production keys to version control.**

---

## 🔐 **Key Inventory and Management**

### **1. Database Encryption Key**
- **Purpose**: Encrypts all sensitive data at rest in SQLite database
- **Algorithm**: AES-256 via Fernet (symmetric encryption)
- **Key Length**: 32 bytes (256 bits)
- **Location**: 
  - Development: `database_encryption.key` (generated automatically)
  - Production: Secure key management system (HSM/Vault)
- **Rotation**: Every 90 days recommended
- **Generation Command**:
  ```python
  import secrets
  key = secrets.token_bytes(32)
  with open("database_encryption.key", "wb") as f:
      f.write(key)
  ```

### **2. JWT Secret Keys**
- **Purpose**: Signs and verifies authentication tokens
- **Algorithm**: HMAC-SHA256
- **Key Length**: 64 bytes (512 bits)
- **Location**: 
  - Development: Generated at runtime in `SecurityConfig.JWT_SECRET_KEY`
  - Production: Environment variable `JWT_SECRET_KEY`
- **Rotation**: Every 30 days recommended
- **Generation Command**:
  ```python
  import secrets
  jwt_secret = secrets.token_urlsafe(64)
  ```

### **3. Paillier Homomorphic Encryption Keys**
- **Purpose**: Homomorphic encryption for vote tallying without revealing individual votes
- **Algorithm**: Paillier cryptosystem
- **Key Length**: 2048-bit RSA-like keys (p, q primes)
- **Location**: 
  - Development: Generated per election in memory
  - Production: Secure key ceremony with multiple trustees
- **Components**:
  - `Public Key (n, g)`: Used for vote encryption
  - `Private Key (p, q, λ, μ)`: Used for final decryption (threshold-shared)
- **Generation**: Via `create_homomorphic_encryption().generate_keypair()`
- **Security**: Private key split using Shamir's Secret Sharing

### **4. Threshold Decryption Trustee Keys**
- **Purpose**: Enable distributed decryption without single point of failure
- **Algorithm**: Shamir's Secret Sharing of Paillier private key
- **Key Length**: Same as Paillier private key components
- **Location**: 
  - Development: Generated in `RealThresholdDecryption.generate_threshold_keys()`
  - Production: Distributed to independent trustees
- **Threshold**: Configurable (default: 3 of 5 trustees required)
- **Format**: Base64-encoded JSON with p_share, q_share, x_coordinate

### **5. Zero-Knowledge Proof Keys**
- **Purpose**: Enable anonymous voter authentication without revealing identity
- **Algorithm**: Groth16 zk-SNARKs on BN128 curve
- **Components**:
  - **Proving Key**: Used to generate proofs (kept by voters)
  - **Verification Key**: Used to verify proofs (public)
- **Location**: 
  - Development: `circuits/voter_eligibility/verification_key.json`
  - Production: Result of trusted setup ceremony
- **Generation**: Via trusted setup ceremony with multiple contributors
- **Critical**: Setup ceremony must have >3 independent contributors

### **6. Trusted Setup Ceremony Keys**
- **Purpose**: Generate zk-SNARK parameters without trusted party
- **Algorithm**: Powers of Tau ceremony + Phase 2
- **Contributor Keys**: RSA-2048 keypairs for each ceremony participant
- **Location**: 
  - Development: `trusted_setup_<ceremony_id>/`
  - Production: Distributed ceremony with public verification
- **Final Output**: `ceremony_final.ptau` file
- **Verification**: Public verification transcripts for each contribution

### **7. Admin Authentication Keys**
- **Purpose**: Secure administrator login and session management  
- **Algorithm**: bcrypt password hashing (cost factor 12)
- **Components**:
  - **Password Hashes**: bcrypt with random salt per password
  - **Session Tokens**: JWT with short expiration
  - **Refresh Tokens**: Long-lived tokens for session renewal
- **Location**: 
  - Development: `ADMIN_CREDENTIALS.txt` (initial), then in secure database
  - Production: Secure database with encrypted storage
- **Rotation**: Passwords expire every 90 days

---

## 🏭 **Production Key Generation Process**

### **Phase 1: Infrastructure Keys**
1. **Generate Database Encryption Key**:
   ```bash
   openssl rand -out database_encryption.key 32
   chmod 600 database_encryption.key
   ```

2. **Generate JWT Secret**:
   ```bash
   export JWT_SECRET_KEY=$(openssl rand -base64 64)
   ```

### **Phase 2: Cryptographic Ceremony**
1. **Trusted Setup Ceremony** (Multi-party):
   - Recruit 5+ independent contributors
   - Each generates RSA keypair for participation
   - Run Powers of Tau ceremony with `backend/core/trusted_setup.py`
   - Verify all contributions and generate final parameters

2. **Election Key Generation**:
   - Generate Paillier keypair for each election
   - Split private key using Shamir's Secret Sharing
   - Distribute shares to 5 independent trustees
   - Require 3 trustees for decryption

### **Phase 3: Verification and Backup**
1. **Key Verification**:
   - Test all cryptographic operations with test data
   - Verify threshold decryption works with minimum trustees
   - Validate zero-knowledge proofs verify correctly

2. **Secure Backup**:
   - Encrypt all keys with master key
   - Store in geographically distributed locations
   - Implement key escrow for regulatory compliance

---

## 🛡️ **Security Controls**

### **Access Controls**
- Database keys: Only accessible by database service
- JWT secrets: Only accessible by authentication service  
- Paillier private keys: Split among trustees, never assembled
- Admin credentials: Individual user access only

### **Monitoring and Auditing**
- All key operations logged to encrypted audit trail
- Key rotation events trigger security notifications
- Failed authentication attempts tracked and rate-limited
- Trustee key usage monitored for suspicious activity

### **Incident Response**
- **Key Compromise**: Immediate rotation and re-encryption
- **Trustee Compromise**: Remove trustee and regenerate shares
- **Setup Compromise**: Re-run trusted setup ceremony
- **Database Breach**: Rotate encryption key and re-encrypt data

---

## 📋 **Key Lifecycle Management**

| Key Type | Generation | Storage | Rotation | Destruction |
|----------|------------|---------|----------|-------------|
| Database | System startup | Local file/HSM | 90 days | Secure wipe |
| JWT | Runtime | Environment | 30 days | Memory clear |
| Paillier | Per election | Threshold split | Per election | Trustee ceremony |
| ZK Setup | Multi-party ceremony | Public verification | Per circuit update | N/A (public) |
| Admin | User registration | Encrypted database | 90 days | Secure hash |

---

## ⚠️ **Production Deployment Checklist**

- [ ] All keys generated with cryptographically secure randomness
- [ ] No hardcoded keys or passwords in source code
- [ ] Database encryption keys stored in secure key management system
- [ ] JWT secrets loaded from environment variables
- [ ] Paillier keys generated fresh per election
- [ ] Threshold decryption tested with minimum trustee count
- [ ] Trusted setup ceremony completed with >3 contributors
- [ ] All key operations logged and monitored
- [ ] Key rotation procedures documented and tested
- [ ] Incident response procedures in place
- [ ] Backup and recovery procedures verified

---

## 🔍 **Key Verification Commands**

### **Verify Database Encryption**:
```python
from backend.core.secure_database import SecureDatabase
db = SecureDatabase("test.db", encryption_key)
# Should initialize without errors
```

### **Verify Homomorphic Encryption**:
```python
from backend.core.crypto.homomorphic_encryption import create_homomorphic_encryption
he = create_homomorphic_encryption()
keypair = he.generate_keypair()
# Test encrypt/decrypt cycle
```

### **Verify Zero-Knowledge Proofs**:
```python
from backend.core.crypto.zero_knowledge import create_real_zk_prover
prover = create_real_zk_prover()
# Should compile circuits successfully
```

---

**Last Updated**: {current_date}  
**Version**: 1.0  
**Review Schedule**: Monthly security review required 