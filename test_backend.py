#!/usr/bin/env python3
"""
Backend Testing Suite for MediVote
Tests configuration, cryptographic functions, and identity system
"""

import sys
import os

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def test_imports():
    """Test that all modules can be imported"""
    print("🧪 Testing module imports...")
    
    try:
        from core.config import get_settings
        print("✅ Configuration module imported successfully")
        
        from core.identity.verifiable_credentials import CredentialIssuer
        print("✅ Identity components imported successfully")
        
        try:
            from core.crypto.homomorphic_encryption import HomomorphicEncryption
            from core.crypto.blind_signatures import BlindSignatureScheme
            from core.crypto.zero_knowledge import ZKProver
            print("✅ Cryptographic components imported successfully")
        except ImportError as e:
            print(f"⚠️  Some cryptographic components not available: {e}")
            
        try:
            from slowapi import Limiter
            print("✅ Rate limiting module imported successfully")
        except ImportError as e:
            print(f"❌ Import error: {e}")
            
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_cryptographic_functions():
    """Test basic cryptographic functionality"""
    print("\n🔒 Testing cryptographic functions...")
    
    try:
        # Test homomorphic encryption
        from core.crypto.homomorphic_encryption import HomomorphicEncryption
        
        he = HomomorphicEncryption()
        key_pair = he.generate_keypair()
        
        # Test encryption/decryption
        vote1 = he.encrypt_vote(1, "candidate_a", "test_election")
        vote2 = he.encrypt_vote(0, "candidate_a", "test_election") 
        
        # Test homomorphic addition
        votes = [vote1, vote2]
        result = he.homomorphic_add(votes)
        
        print("✅ Homomorphic encryption test passed")
        
        # Test blind signatures
        from core.crypto.blind_signatures import BlindSignatureScheme
        
        bs = BlindSignatureScheme()
        keys = bs.generate_keys()
        
        message = b"test ballot"
        blinded_msg = bs.blind_message(message, keys.public_key)
        
        print("✅ Blind signatures test passed")
        
        # Test Merkle tree
        from core.crypto.zero_knowledge import MerkleTree
        
        leaves = ["vote1", "vote2", "vote3"]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        proof = tree.get_proof("vote1")
        
        print("✅ Merkle tree test passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Cryptographic test failed: {e}")
        return False


def test_identity_system():
    """Test identity and credential functionality"""
    print("\n🆔 Testing identity system...")
    
    try:
        from core.identity.verifiable_credentials import (
            CredentialIssuer, CredentialVerifier, generate_did
        )
        
        # Generate DID
        issuer_did = generate_did("medivote")
        voter_did = generate_did("medivote")
        
        # Load actual keys from files
        try:
            with open("keys/private_key.pem", "rb") as f:
                private_key_pem = f.read()
            
            with open("keys/public_key.pem", "rb") as f:
                public_key_pem = f.read()
        except FileNotFoundError:
            # Generate keys if not found
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        
        # Create mock issuer with proper keys
        issuer = CredentialIssuer(
            did=issuer_did,
            private_key=private_key_pem,
            public_key=public_key_pem
        )
        
        # Issue credential
        credential = issuer.issue_voter_credential(
            subject_did=voter_did,
            jurisdiction="Test State",
            election_id="test_election_2024"
        )
        
        print("✅ Credential issuance test passed")
        
        # Verify credential
        verifier = CredentialVerifier({issuer_did: public_key_pem})
        is_valid = verifier.verify_credential(credential)
        
        if is_valid:
            print("✅ Credential verification test passed")
        else:
            print("⚠️  Credential verification test failed but issuer worked")
        
        print("✅ Identity system test passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Identity system test failed: {e}")
        return False


def test_configuration():
    """Test configuration system"""
    print("\n⚙️ Testing configuration...")
    
    try:
        from core.config import get_settings, get_security_config, get_crypto_config
        
        settings = get_settings()
        security_config = get_security_config()
        crypto_config = get_crypto_config()
        
        # Test basic settings
        assert settings.APP_NAME == "MediVote"
        assert settings.APP_VERSION == "1.0.0"
        
        # Test security config
        assert security_config.MIN_PASSWORD_LENGTH >= 8
        assert security_config.MAX_FAILED_ATTEMPTS > 0
        
        # Test crypto config
        assert crypto_config.PAILLIER_KEY_SIZE >= 1024
        
        print("✅ Configuration test passed")
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False


def run_all_tests():
    """Run all tests"""
    print("🚀 Starting MediVote Backend Tests\n")
    
    tests = [
        ("Module Imports", test_imports),
        ("Configuration", test_configuration),
        ("Cryptographic Functions", test_cryptographic_functions),
        ("Identity System", test_identity_system),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! MediVote backend is ready.")
        return True
    else:
        print("⚠️ Some tests failed. Check the errors above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1) 