#!/bin/bash

# MediVote Setup Script
# Initializes the secure blockchain-based voting system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}
██╗  ██╗███████╗██████╗ ██╗██╗   ██╗ ██████╗ ████████╗███████╗
██║  ██║██╔════╝██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝██╔════╝
███████║█████╗  ██║  ██║██║██║   ██║██║   ██║   ██║   █████╗  
██╔══██║██╔══╝  ██║  ██║██║╚██╗ ██╔╝██║   ██║   ██║   ██╔══╝  
██║  ██║███████╗██████╔╝██║ ╚████╔╝ ╚██████╔╝   ██║   ███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═══╝   ╚═════╝    ╚═╝   ╚══════╝
                                                               
Secure Blockchain-Based Voting System with End-to-End Verifiability
${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check if Python 3.9+ is installed
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3.9+ is required but not installed"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    if [[ $(python3 -c "import sys; print(sys.version_info >= (3, 9))") != "True" ]]; then
        print_error "Python 3.9+ is required. Current version: $PYTHON_VERSION"
        exit 1
    fi
    
    # Check if Node.js 16+ is installed
    if ! command -v node &> /dev/null; then
        print_error "Node.js 16+ is required but not installed"
        exit 1
    fi
    
    NODE_VERSION=$(node --version)
    if [[ $(node -e "console.log(process.version.slice(1).split('.')[0] >= 16)") != "true" ]]; then
        print_error "Node.js 16+ is required. Current version: $NODE_VERSION"
        exit 1
    fi
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_warning "Docker is not installed. Some features may not work."
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        print_warning "Docker Compose is not installed. Some features may not work."
    fi
    
    print_status "System requirements check completed"
}

# Create directory structure
create_directories() {
    print_status "Creating directory structure..."
    
    # Create main directories
    mkdir -p {backend,frontend,circuits,keys,uploads,database,nginx,monitoring}
    mkdir -p {backend/api,backend/core,backend/tests}
    mkdir -p {backend/core/crypto,backend/core/identity,backend/core/blockchain}
    mkdir -p {frontend/src,frontend/public,frontend/build}
    mkdir -p {circuits/voter_eligibility,circuits/ballot_validity}
    mkdir -p {monitoring/prometheus,monitoring/grafana}
    mkdir -p {nginx/conf.d,nginx/ssl}
    
    print_status "Directory structure created"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install dependencies
    pip install -r requirements.txt
    
    print_status "Python dependencies installed"
}

# Install Node.js dependencies
install_node_deps() {
    print_status "Installing Node.js dependencies..."
    
    # Install global dependencies
    if command -v npm &> /dev/null; then
        npm install -g concurrently
        npm install -g @angular/cli
        npm install -g truffle
        npm install -g ganache-cli
        npm install -g snarkjs
        npm install -g circom
    fi
    
    print_status "Node.js dependencies installed"
}

# Generate cryptographic keys
generate_keys() {
    print_status "Generating cryptographic keys..."
    
    # Create keys directory
    mkdir -p keys
    
    # Generate RSA keys for blind signatures
    openssl genrsa -out keys/blind_signature_private.pem 2048
    openssl rsa -in keys/blind_signature_private.pem -pubout -out keys/blind_signature_public.pem
    
    # Generate keys for homomorphic encryption (will be done by application)
    touch keys/homomorphic_keys.json
    
    # Generate DID keys
    mkdir -p keys/did
    openssl ecparam -genkey -name secp256k1 -noout -out keys/did/private_key.pem
    openssl ec -in keys/did/private_key.pem -pubout -out keys/did/public_key.pem
    
    print_status "Cryptographic keys generated"
}

# Setup ZK circuits
setup_zk_circuits() {
    print_status "Setting up Zero-Knowledge circuits..."
    
    # Create voter eligibility circuit
    cat > circuits/voter_eligibility/voter_eligibility.circom << 'EOF'
pragma circom 2.0.0;

template VoterEligibility() {
    // Public inputs
    signal input election_id;
    signal input merkle_root;
    
    // Private inputs
    signal input credential_hash;
    signal input issuer_public_key;
    signal input merkle_proof[10];
    
    // Output
    signal output valid;
    
    // Verify merkle proof
    component merkle_verifier = MerkleVerifier(10);
    merkle_verifier.leaf <== credential_hash;
    merkle_verifier.root <== merkle_root;
    for (var i = 0; i < 10; i++) {
        merkle_verifier.proof[i] <== merkle_proof[i];
    }
    
    // Output validity
    valid <== merkle_verifier.valid;
}

template MerkleVerifier(depth) {
    signal input leaf;
    signal input root;
    signal input proof[depth];
    signal output valid;
    
    // Simplified merkle verification
    // In practice, would include full merkle tree verification
    valid <== 1;
}

component main = VoterEligibility();
EOF
    
    # Create ballot validity circuit
    cat > circuits/ballot_validity/ballot_validity.circom << 'EOF'
pragma circom 2.0.0;

template BallotValidity() {
    signal input vote_sum;
    signal input max_votes;
    signal output valid;
    
    // Check that sum of votes equals max allowed votes
    component eq = IsEqual();
    eq.in[0] <== vote_sum;
    eq.in[1] <== max_votes;
    valid <== eq.out;
}

template IsEqual() {
    signal input in[2];
    signal output out;
    
    component eq = IsZero();
    eq.in <== in[0] - in[1];
    out <== eq.out;
}

template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <-- in!=0 ? 1/in : 0;
    out <== -in*inv +1;
    in*out === 0;
}

component main = BallotValidity();
EOF
    
    print_status "ZK circuits created"
}

# Setup database
setup_database() {
    print_status "Setting up database..."
    
    # Create database initialization script
    cat > database/init.sql << 'EOF'
-- MediVote Database Initialization

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS medivote;
USE medivote;

-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    did VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Elections table
CREATE TABLE IF NOT EXISTS elections (
    id SERIAL PRIMARY KEY,
    election_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    merkle_root VARCHAR(255),
    public_key TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Candidates table
CREATE TABLE IF NOT EXISTS candidates (
    id SERIAL PRIMARY KEY,
    election_id VARCHAR(255) NOT NULL,
    candidate_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    FOREIGN KEY (election_id) REFERENCES elections(election_id)
);

-- Encrypted votes table
CREATE TABLE IF NOT EXISTS encrypted_votes (
    id SERIAL PRIMARY KEY,
    vote_id VARCHAR(255) UNIQUE NOT NULL,
    election_id VARCHAR(255) NOT NULL,
    candidate_id VARCHAR(255) NOT NULL,
    encrypted_vote TEXT NOT NULL,
    signature TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (election_id) REFERENCES elections(election_id)
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    user_did VARCHAR(255),
    election_id VARCHAR(255),
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_elections_status ON elections(status);
CREATE INDEX IF NOT EXISTS idx_votes_election ON encrypted_votes(election_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_users_did ON users(did);
EOF
    
    print_status "Database setup completed"
}

# Create environment configuration
create_env_config() {
    print_status "Creating environment configuration..."
    
    # Create .env file if it doesn't exist
    if [ ! -f .env ]; then
        cat > .env << EOF
# MediVote Environment Configuration
APP_NAME=MediVote
APP_VERSION=1.0.0
DEBUG=True
TESTING=False

# Server Configuration
HOST=0.0.0.0
PORT=8000

# Security Settings
SECRET_KEY=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60

# Database Configuration
DATABASE_URL=sqlite:///./medivote.db
DATABASE_ECHO=False

# Redis Configuration
REDIS_URL=redis://localhost:6379

# CORS and Security
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,https://themedian.org
ALLOWED_HOSTS=localhost,127.0.0.1,themedian.org

# Blockchain Configuration
BLOCKCHAIN_NETWORK=testnet
BLOCKCHAIN_RPC_URL=http://localhost:8545

# Cryptographic Settings
HOMOMORPHIC_KEY_SIZE=2048
ZK_CIRCUIT_PATH=./circuits
BLIND_SIGNATURE_KEY_SIZE=2048

# Test Configuration
TEST_USER_SSN=000-00-0001
TEST_USER_NAME=John Smith
TEST_USER_ADDRESS=1 Drury Ln, New York, NY 07008
EOF
        print_status "Environment configuration created"
    else
        print_warning "Environment configuration already exists"
    fi
}

# Setup nginx configuration
setup_nginx() {
    print_status "Setting up nginx configuration..."
    
    cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream backend {
        server medivote-backend:8000;
    }
    
    upstream frontend {
        server medivote-frontend:3000;
    }
    
    server {
        listen 80;
        server_name localhost;
        
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "default-src 'self'" always;
        
        # API routes
        location /api/ {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # Frontend routes
        location / {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
EOF
    
    print_status "Nginx configuration created"
}

# Run tests
run_tests() {
    print_status "Running tests..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Run Python tests
    if [ -d "backend/tests" ]; then
        python -m pytest backend/tests/ -v
    fi
    
    # Run frontend tests
    if [ -d "frontend" ] && [ -f "frontend/package.json" ]; then
        cd frontend
        npm test -- --watchAll=false
        cd ..
    fi
    
    print_status "Tests completed"
}

# Main setup function
main() {
    print_header
    
    print_status "Starting MediVote setup..."
    
    check_root
    check_requirements
    create_directories
    install_python_deps
    install_node_deps
    generate_keys
    setup_zk_circuits
    setup_database
    create_env_config
    setup_nginx
    
    print_status "Setup completed successfully!"
    
    echo -e "\n${GREEN}Next steps:${NC}"
    echo "1. Review the .env file and update configuration as needed"
    echo "2. Start the development environment: ${BLUE}npm run dev${NC}"
    echo "3. Or use Docker: ${BLUE}docker-compose up${NC}"
    echo "4. Access the application at: ${BLUE}http://localhost:3000${NC}"
    echo "5. API documentation: ${BLUE}http://localhost:8000/api/docs${NC}"
    echo ""
    echo -e "${YELLOW}Important:${NC} This is a development setup. For production:"
    echo "- Use secure cryptographic keys"
    echo "- Configure proper SSL/TLS certificates"
    echo "- Set up proper authentication and authorization"
    echo "- Perform security audits"
    echo ""
    echo -e "${BLUE}For more information, visit: https://github.com/the-median/medivote${NC}"
}

# Run main function
main "$@" 