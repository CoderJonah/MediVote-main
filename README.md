# MediVote: Secure Blockchain-Based Voting System

## Overview

MediVote is a secure, privacy-preserving electronic voting system that leverages blockchain technology, zero-knowledge proofs, and homomorphic encryption to ensure election integrity while maintaining voter anonymity. The system is designed to complement traditional voting methods, not replace them.

## Architecture

### Core Principles
- **Security**: Resilient against nation-state actors and malicious insiders
- **Privacy**: Cryptographically unlinkable voter identity from cast ballots
- **Verifiability**: End-to-end verifiable (E2E-V) with individual and universal verification
- **Accessibility**: WCAG 2.1 AA compliant, HAVA/ADA accessible
- **Equity**: Designed to reduce, not exacerbate, the digital divide

### System Components

1. **Identity Layer**: Self-Sovereign Identity (SSI) with Verifiable Credentials
2. **Voting Protocol Layer**: ZKP authentication, blind signatures, homomorphic encryption
3. **Blockchain Layer**: Permissioned consortium blockchain with PBFT consensus
4. **Client Application Layer**: Web and mobile interfaces with accessibility features

## Key Features

- **Anonymous Authentication**: Zero-knowledge proofs verify eligibility without revealing identity
- **Ballot Secrecy**: Homomorphic encryption keeps votes private during tallying
- **Coercion Resistance**: Receipt-free system prevents vote buying/intimidation
- **One-Vote-Per-Person**: Blind signatures prevent double voting while maintaining anonymity
- **Public Auditability**: Anyone can verify election integrity via blockchain bulletin board

## Technology Stack

- **Backend**: Python with FastAPI, cryptographic libraries (phe, circom, aries-cloudagent)
- **Blockchain**: Solidity smart contracts, Hyperledger Fabric with PBFT
- **Frontend**: React with TypeScript, mobile apps with React Native
- **Cryptography**: ZK-SNARKs, Paillier homomorphic encryption, RSA blind signatures
- **Identity**: W3C Verifiable Credentials, DID (Decentralized Identifiers)

## Security Model

The system defends against:
- Client-side malware (via E2E verifiability)
- Server compromise (via decentralization)
- Network attacks (via cryptographic protocols)
- Identity theft (via SSI and zero-knowledge proofs)
- Coercion/vote buying (via receipt-freeness)

## Getting Started

### Prerequisites
- No prerequisites required for professional installer
- Python 3.9+ (for development setup)
- Node.js 16+ (for development setup)
- Docker and Docker Compose (optional)
- Git (for development)

### Installation Options

#### Option 1: Professional Installer (Recommended)
**Windows:**
1. Download `MediVote-Setup.exe` from releases
2. Run as Administrator
3. Follow the installation wizard
4. Desktop shortcut created automatically
5. Find MediVote in Start Menu

**macOS:**
1. Download `MediVote-Installer.dmg` from releases
2. Open DMG and drag MediVote.app to Applications
3. Right-click and select "Open" (first time only)
4. Find MediVote in Launchpad

**Linux:**
1. Download the appropriate package (.deb or .rpm)
2. Install using your package manager:
   ```bash
   # Ubuntu/Debian
   sudo dpkg -i medivote_1.0.0_amd64.deb
   
   # CentOS/RHEL/Fedora
   sudo rpm -i medivote-1.0.0-1.x86_64.rpm
   ```
3. Run `medivote` from command line or find in Applications

#### Option 2: Build Professional Installer
```bash
# Clone the repository
git clone https://github.com/the-median/medivote.git
cd medivote

# Install build dependencies
pip install -r requirements_build.txt

# Build professional installer
python build_installer.py

# This creates:
# Windows: MediVote-Setup.exe
# macOS: MediVote.app
# Linux: install_linux.sh
```

#### Option 3: Development Setup
```bash
# Clone the repository
git clone https://github.com/the-median/medivote.git
cd medivote

# Simple development setup
python simple_install.py

# Or advanced development setup
python setup.py

# Start the application
# On Windows:
start_medivote.bat
# On Unix-like systems:
./start_medivote.sh
```

#### Option 2: Docker Deployment
```bash
# Clone the repository
git clone https://github.com/the-median/medivote.git
cd medivote

# Deploy with Docker
docker-compose up -d

# Or use the deployment script
python deploy.py --docker
```

#### Option 3: Manual Setup
```bash
# Clone the repository
git clone https://github.com/the-median/medivote.git
cd medivote

# Run the bash setup script (Unix-like systems only)
./setup.sh

# Start development environment
docker-compose up -d
```

### Development

#### Running Tests
```bash
# Run all tests
python test_cross_platform.py

# Run backend tests
python -m pytest backend/tests/

# Run security tests
python production_security_test.py

# Run comprehensive test suite
python ultra_comprehensive_test_suite.py
```

#### Development Server
```bash
# Start backend development server
python -m uvicorn backend.main:app --reload --port 8000

# Start frontend development server
cd frontend && npm start
```

#### Docker Development
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Legal Compliance

This system is designed to comply with:
- Help America Vote Act (HAVA) requirements
- Americans with Disabilities Act (ADA) accessibility standards
- NIST Cybersecurity Framework
- State-specific election laws (varies by jurisdiction)

## Important Notice

This system is intended as a **supplement** to traditional voting methods. It should not be used as the sole method of voting in any jurisdiction. Proper security audits, legal review, and pilot testing are essential before any production deployment.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## GitHub Features

### Continuous Integration/Continuous Deployment (CI/CD)
This repository includes comprehensive GitHub Actions workflows that automatically:

- **Cross-Platform Testing**: Tests on Windows, macOS, and Linux
- **Security Scanning**: Automated security vulnerability detection
- **Code Quality**: Linting and formatting checks
- **Performance Testing**: Load testing and performance validation
- **Accessibility Testing**: WCAG compliance verification
- **Docker Testing**: Container build and deployment validation

### Automated Testing
- **Unit Tests**: Comprehensive test coverage for all components
- **Integration Tests**: End-to-end testing of the complete system
- **Security Tests**: Cryptographic and security feature validation
- **Cross-Platform Tests**: Platform compatibility verification

### Quality Assurance
- **Code Coverage**: Maintains >90% test coverage
- **Security Audits**: Regular security vulnerability scanning
- **Performance Monitoring**: Continuous performance tracking
- **Accessibility Compliance**: WCAG 2.1 AA standards

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

### Development Workflow
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`python test_cross_platform.py`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Reporting Issues
- Use GitHub Issues for bug reports and feature requests
- Include detailed reproduction steps
- Provide system information (OS, Python version, etc.)
- For security issues, email security@themedian.org

## Disclaimer

This software is provided for educational and research purposes. Use in production elections requires extensive security auditing, legal review, and compliance with local election laws. 