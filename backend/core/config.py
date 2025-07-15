# backend/core/config.py

"""
Configuration management for MediVote
This version uses embedded settings to avoid file path issues in the executable.
"""

import secrets
from typing import List
from pydantic import BaseModel, Field
from functools import lru_cache

class Settings(BaseModel):
    """Application settings with embedded values"""

    # Basic Application Settings
    APP_NAME: str = "MediVote"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    TESTING: bool = False
    
    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Security Settings
    SECRET_KEY: str = "medivote_auto_generated_secret_key_32_chars_minimum_length_for_security"
    ENCRYPTION_KEY: str = "medivote_auto_generated_encryption_key_32_chars_minimum_for_operations"
    JWT_SECRET_KEY: str = "medivote_auto_generated_jwt_secret_key_32_chars_minimum_for_tokens"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60
    
    # Database Configuration
    DATABASE_URL: str = "sqlite:///./medivote.db"
    DATABASE_ECHO: bool = False
    
    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379"
    
    # CORS and Security
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    
    # Blockchain Configuration
    BLOCKCHAIN_NETWORK: str = "testnet"
    BLOCKCHAIN_RPC_URL: str = "http://localhost:8545"
    
    # Logging Configuration - This is the key part
    LOG_LEVEL: str = "INFO"
    # This format is now directly in the code, avoiding file parsing errors.
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FORMATTER_NAME: str = "default"
    
    # Main application entry point  
    MAIN_APP: str = "backend/main.py"


class SecurityConfig(BaseModel):
    """Security configuration settings"""
    
    # Rate limiting
    MAX_FAILED_ATTEMPTS: int = 5
    SESSION_TIMEOUT_MINUTES: int = 30
    
    # Cryptographic settings
    KEY_SIZE: int = 2048
    HASH_ALGORITHM: str = "SHA256"
    
    # Authentication settings
    PASSWORD_MIN_LENGTH: int = 8
    REQUIRE_SPECIAL_CHARS: bool = True
    REQUIRE_NUMBERS: bool = True
    REQUIRE_UPPERCASE: bool = True


class CryptoConfig(BaseModel):
    """Cryptographic configuration settings"""
    
    # Blind signature settings
    BLIND_SIGNATURE_KEY_SIZE: int = 2048
    BLIND_SIGNATURE_AUTHORITY_ID: str = "medivote_authority_001"
    
    # Homomorphic encryption settings
    HOMOMORPHIC_KEY_SIZE: int = 2048
    THRESHOLD_DECRYPTION: int = 3
    TOTAL_TRUSTEES: int = 5
    
    # Zero-knowledge proof settings
    ZK_CIRCUIT_PATH: str = "./circuits"
    ZK_PROOF_PROTOCOL: str = "groth16"
    ZK_CURVE: str = "bn128"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


@lru_cache()
def get_security_config() -> SecurityConfig:
    """Get cached security configuration"""
    return SecurityConfig()


@lru_cache()
def get_crypto_config() -> CryptoConfig:
    """Get cached cryptographic configuration"""
    return CryptoConfig()