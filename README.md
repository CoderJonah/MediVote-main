# 🗳️ MediVote - Secure Blockchain Voting System

A secure, accessible, and verifiable blockchain-based voting system with end-to-end encryption, zero-knowledge proofs, and homomorphic encryption.

## 🏗️ Project Structure

```
medivote/
├── 📁 src/                          # Source code
│   ├── 📁 backend/                  # Python FastAPI backend
│   │   ├── 📁 api/                  # API endpoints
│   │   ├── 📁 core/                 # Core business logic
│   │   │   ├── 📁 crypto/           # Cryptographic modules
│   │   │   └── 📁 identity/         # Identity management
│   │   ├── 📄 main.py               # Application entry point
│   │   └── 📄 requirements.txt      # Python dependencies
│   ├── 📁 frontend/                 # HTML/CSS/JS frontend
│   │   ├── 📁 js/                   # JavaScript modules
│   │   ├── 📁 css/                  # Stylesheets
│   │   └── 📄 *.html                # HTML pages
│   ├── 📁 circuits/                 # Zero-knowledge circuits
│   ├── 📁 tests/                    # Test suites
│   └── 📁 shared/                   # Shared resources
│       └── 📁 static/               # Static assets
├── 📁 config/                       # Configuration files
│   ├── 📁 nginx/                    # Nginx configuration
│   └── 📄 *.json                    # Service configurations
├── 📁 data/                         # Data storage
│   └── 📁 database/                 # Database schemas
├── 📁 scripts/                      # Utility scripts
├── 📁 docs/                         # Documentation
├── 📄 start.sh                      # Quick start script
├── 📄 package.json                  # Node.js configuration
└── 📄 .gitignore                    # Git ignore rules
```

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 16+ (optional)
- Git

### 1. Clone and Setup
```bash
git clone https://github.com/the-median/medivote.git
cd medivote
```

### 2. Install System Dependencies (if needed)
```bash
# For Ubuntu/Debian systems, install build dependencies:
./install-system-deps.sh

# Or manually:
sudo apt install python3-dev python3-pip python3-venv build-essential libffi-dev libssl-dev
```

### 3. Start the Application
```bash
# Option 1: Simple start (recommended for development)
./start-simple.sh

# Option 2: With virtual environment (recommended for production)
./start.sh

# Option 3: Manual start
python3 -m pip install psutil aiohttp --break-system-packages
python3 scripts/start_medivote_background.py
```

**Troubleshooting**:
- If you get compilation errors, run `./install-system-deps.sh` first
- If virtual environment fails, use `./start-simple.sh`
- For missing dependencies, see the error messages for specific installation commands

### 3. Access the Application
- **Frontend**: http://localhost:8080
- **Backend API**: http://localhost:8001
- **Admin Dashboard**: http://localhost:8091

## 🔧 Development

### Backend Development
```bash
cd src/backend
python -m uvicorn main:app --reload --port 8000
```

### Frontend Development
```bash
cd src/frontend
python serve.py
```

### Running Tests
```bash
# All tests
cd src/tests
python run_tests.py all

# Specific test suites
python run_tests.py security
python run_tests.py unit
python run_tests.py integration
```

## 🔐 Security Features

- **End-to-End Encryption**: All data encrypted in transit and at rest
- **Zero-Knowledge Proofs**: Vote privacy without revealing choices
- **Homomorphic Encryption**: Vote tallying without decryption
- **Blind Signatures**: Anonymous voter authentication
- **Rate Limiting**: DDoS protection and abuse prevention
- **Secure Key Management**: Hardware security module integration

## 📁 Key Directories Explained

### `/src/backend/`
The Python FastAPI backend containing:
- **`api/`**: REST API endpoints for voting, authentication, admin
- **`core/`**: Business logic, cryptography, database, security
- **`main.py`**: Application entry point with middleware setup

### `/src/frontend/`
The web frontend containing:
- **`js/`**: JavaScript modules for each page/feature
- **`css/`**: Stylesheets with responsive design
- **HTML files**: Individual pages for voting, registration, results

### `/config/`
Configuration files:
- **`*.json`**: Service configurations (non-sensitive)
- **`nginx/`**: Reverse proxy configuration

### `/scripts/`
Utility scripts:
- **`start_medivote_background.py`**: Main service orchestrator
- **`initialize_*.py`**: Setup and initialization scripts
- **`*_dashboard.py`**: Monitoring dashboards

### `/data/`
Data storage (ignored by git):
- **`database/`**: Database initialization scripts
- Runtime data directories created as needed

## 🔒 Security Notes

**IMPORTANT**: The following are automatically ignored by git for security:
- Voter credentials and session data
- Cryptographic keys and certificates
- Admin passwords and API keys
- Cache and temporary files
- Environment configuration files

## 🧪 Testing

The project includes comprehensive test suites:

- **Unit Tests**: Individual component testing
- **Integration Tests**: Cross-component functionality
- **Security Tests**: Cryptographic and authentication testing
- **Performance Tests**: Load and stress testing

## 📖 Documentation

- **`docs/CONTRIBUTING.md`**: Development guidelines
- **`docs/CRYPTOGRAPHIC_KEYS_DOCUMENTATION.md`**: Key management
- **`docs/RATE_LIMITING_SECURITY_UPGRADE.md`**: Security features

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the test suite
5. Submit a pull request

See `docs/CONTRIBUTING.md` for detailed guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support, please open an issue on GitHub or contact us at contact@themedian.org.

---

**⚠️ Security Notice**: This system handles sensitive voting data. Always follow security best practices and never commit sensitive files to version control.