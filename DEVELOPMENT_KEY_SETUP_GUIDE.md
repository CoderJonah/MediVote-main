# 🔐 MediVote Development Key Setup Guide

**Welcome to the MediVote Secure Key Management System!**

This guide will help you set up and use the new integrated key management system that provides secure, centralized management of all cryptographic keys used by MediVote.

---

## 🚀 **Quick Start Setup**

### **Step 1: Initialize the Key Management System**

Add this to your application startup code (e.g., in `backend/main.py`):

```python
from backend.core.key_integration import initialize_medivote_security, Environment

# Initialize security system for development
security_manager = initialize_medivote_security(
    environment=Environment.DEVELOPMENT,
    keys_dir=Path("keys"),  # Keys will be stored in ./keys/ directory
    user_provided_keys=None  # Let system generate keys automatically
)

print("✅ MediVote security system initialized!")
```

### **Step 2: Let the System Generate Keys Automatically**

Run your application - the key management system will:
1. Create a secure `keys/` directory with proper permissions (700)
2. Generate a master key for encrypting all other keys
3. Generate all required system keys automatically
4. Log all key generation for your review

### **Step 3: Verify Key Generation**

Check the console output - you should see:
```
🔐 KEY MANAGER INITIALIZED
   🌍 Environment: development
   📁 Key Directory: keys
   🔑 Keys Loaded: 4
   ⚠️  Production Security: DEVELOPMENT MODE

🔑 GENERATED NEW KEY: database_encryption_20241215_143022_a1b2c3d4
   🏷️  Type: database_encryption
   📝 Purpose: Database record encryption
   🔐 Algorithm: AES-256
   📊 Length: 32 bytes
```

---

## 🔑 **Key Storage Locations**

The key management system stores keys in the following locations:

### **Development Environment**
- **Keys Directory**: `./keys/` (relative to your project root)
- **Master Key**: `./keys/master.key` (encrypts all other keys)
- **System Keys**: `./keys/*.key` (individual encrypted key files)

### **File Structure**
```
MediVote-main/
├── keys/                          # 🔐 SECURE KEY DIRECTORY
│   ├── master.key                 # Master encryption key (600 permissions)
│   ├── database_encryption_*.key  # Database encryption key
│   ├── audit_log_encryption_*.key # Audit log encryption key
│   ├── jwt_secret_*.key          # JWT signing key
│   └── session_encryption_*.key   # Session encryption key
├── backend/
└── frontend/
```

### **Key File Example**
Each `.key` file contains encrypted key data:
```json
{
  "metadata": {
    "key_id": "database_encryption_20241215_143022_a1b2c3d4",
    "key_type": "database_encryption",
    "environment": "development",
    "created_at": "2024-12-15T14:30:22.123456",
    "purpose": "Database record encryption",
    "algorithm": "AES-256",
    "key_length": 32
  },
  "encrypted_key_data": "gAAAAABh...",  // Encrypted with master key
  "verification_hash": "abc123..."      // SHA-256 hash for integrity
}
```

---

## 🛠️ **Manual Key Provision (Optional)**

If you want to provide your own keys for testing:

```python
from backend.core.key_integration import initialize_medivote_security, Environment
from pathlib import Path

# Provide your own keys
user_keys = {
    'database_key': 'your_database_key_here',
    'audit_key': 'your_audit_key_here', 
    'jwt_secret': 'your_jwt_secret_here',
    'session_key': 'your_session_key_here'
}

security_manager = initialize_medivote_security(
    environment=Environment.DEVELOPMENT,
    keys_dir=Path("keys"),
    user_provided_keys=user_keys
)
```

**Note**: The system will still generate secure keys - the `user_provided_keys` parameter is mainly for development testing and key naming.

---

## 🔍 **Key Management Commands**

### **Initialize Key System**
```bash
cd MediVote-main
python -m backend.core.key_management init
```

### **Provision Development Keys**
```bash
python -m backend.core.key_management provision
```

### **List All Keys**
```bash
python -m backend.core.key_management list
```

### **Get Key Statistics**
```bash
python -m backend.core.key_management stats
```

---

## 🔐 **Using the Key System in Your Code**

### **Database Encryption (Automatic)**
```python
from backend.core.secure_database import SecureDatabase

# NEW: No encryption key needed - automatically retrieved!
db = SecureDatabase("medivote.db")
# Key management system automatically provides the encryption key
```

### **Audit Log Encryption (Automatic)**
```python
from backend.core.auth_models import AuditLog

# NEW: No encryption key needed - automatically retrieved!
audit_log = AuditLog.create_encrypted_audit_log(
    event_type="login_success",
    message="User logged in successfully",
    user_id="user123",
    ip_address="192.168.1.100"
    # Encryption handled automatically by key management system
)
```

### **Manual Key Retrieval (Advanced)**
```python
from backend.core.key_integration import get_security_manager

security_manager = get_security_manager()

# Get specific keys if needed
database_key = security_manager.get_database_key()
audit_key = security_manager.get_audit_key()  
jwt_secret = security_manager.get_jwt_secret()
session_key = security_manager.get_session_key()
```

---

## 📊 **Security Status Check**

```python
from backend.core.key_integration import get_security_manager

security_manager = get_security_manager()
status = security_manager.get_security_status()

print("Security Status:")
print(json.dumps(status, indent=2))
```

**Example Output:**
```json
{
  "status": "initialized",
  "environment": "development", 
  "key_manager_stats": {
    "total_keys": 4,
    "expired_keys": 0,
    "rotation_required": 0,
    "keys_by_type": {
      "database_encryption": 1,
      "audit_log_encryption": 1,
      "jwt_secret": 1,
      "session_encryption": 1
    }
  },
  "production_ready": false
}
```

---

## 🔄 **Key Rotation (Maintenance)**

```python
from backend.core.key_integration import get_security_manager

security_manager = get_security_manager()

# Rotate all keys (creates new versions)
rotated_keys = security_manager.rotate_all_keys()
print(f"Rotated {len(rotated_keys)} keys")
```

---

## ⚠️ **Important Security Notes**

### **Development vs Production**
- **Development keys**: Automatically generated, stored in `./keys/`
- **Production keys**: Must be generated using Hardware Security Module (HSM)
- **NEVER use development keys in production!**

### **Key Security**
- All key files have 600 permissions (owner read-only)
- Master key encrypts all other keys
- Keys are never stored in plaintext
- All key operations are logged

### **Backup Strategy**
- Backup the entire `keys/` directory securely
- Store backups encrypted in multiple locations
- Test key recovery procedures regularly

---

## 🏭 **Production Deployment**

For production deployment, see the automatically generated guide:
- Run the key management system to generate `PRODUCTION_KEY_GUIDE.md`
- Follow the HSM-based key generation procedures
- Implement proper key rotation schedules
- Set up monitoring and alerting

---

## 🔧 **Integration with Existing Systems**

The new key management system is **backward compatible**:

### **Before (Manual Keys)**
```python
# OLD: Manual key management
encryption_key = secrets.token_bytes(32)
db = SecureDatabase("medivote.db", encryption_key)
```

### **After (Integrated Keys)**
```python
# NEW: Automatic key management
db = SecureDatabase("medivote.db")  # Key automatically retrieved!
```

### **Migration**
- Existing code will work unchanged (backward compatibility)
- New code automatically uses key management system
- Gradual migration to integrated system recommended

---

## 📞 **Support**

If you encounter any issues:

1. **Check Key Directory**: Ensure `./keys/` exists with proper permissions
2. **Check Logs**: Look for key management messages in console output
3. **Verify Initialization**: Ensure `initialize_medivote_security()` is called at startup
4. **Test Key Generation**: Run `python -m backend.core.key_management provision`

---

## 🎯 **Next Steps**

1. **✅ Initialize**: Add key management initialization to your startup code
2. **✅ Test**: Run your application and verify keys are generated  
3. **✅ Monitor**: Check the security status and key statistics
4. **📋 Plan**: Review production deployment requirements
5. **🔄 Maintain**: Set up key rotation procedures

**Your keys are now securely managed! 🔐**

---

**Last Updated**: December 15, 2024  
**Version**: 2.0  
**Environment**: Development Setup Guide 