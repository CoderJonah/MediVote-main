# MediVote Web Interface

A modern, secure web interface for the MediVote blockchain-based voting system with advanced cryptographic security features.

## Features

### 🔐 Security Features
- **Zero-Knowledge Proofs**: Verify voter eligibility without revealing identity
- **Homomorphic Encryption**: Count votes without decrypting individual ballots
- **Blind Signatures**: Anonymous ballot authorization preventing double voting
- **Blockchain Verification**: Immutable vote storage with tamper-proof records
- **Self-Sovereign Identity**: Decentralized identity management
- **End-to-End Verification**: Mathematical proof of election integrity

### 🌐 Web Interface Components

#### 1. **Home Page** (`index.html`)
- System overview and security features
- Real-time system status monitoring
- Quick action buttons for common tasks

#### 2. **Voter Registration** (`register.html`)
- Secure voter registration with SSI integration
- Identity verification and credential generation
- Downloadable voter credentials

#### 3. **Voting Interface** (`vote.html`)
- Display available ballots and candidates
- Cryptographically secure vote casting
- Real-time vote receipts with verification codes

#### 4. **Vote Verification** (`verify.html`)
- Verify votes using receipt ID and verification code
- Display cryptographic proofs (ZK, blind signatures, homomorphic tags)
- Downloadable verification reports

#### 5. **Results Display** (`results.html`)
- Real-time election results with visual charts
- Cryptographic integrity verification
- Export and print functionality

#### 6. **Admin Panel** (`admin.html`)
- Create and manage ballots
- System monitoring and statistics
- Administrative controls

## Quick Start

### Prerequisites
- Python 3.7+
- MediVote backend running on port 8000

### Option 1: Automated Demo Setup
```bash
# Start everything with demo data
python start_demo.py
```

### Option 2: Manual Setup
```bash
# 1. Start the backend
python simple_main.py

# 2. Create demo data (optional)
python create_demo_ballot.py

# 3. Start the frontend
cd frontend
python serve.py
```

### Option 3: Custom Web Server
```bash
# Serve with any web server
cd frontend
python -m http.server 3000
# or
npx serve -p 3000
```

## Usage Guide

### For Voters

1. **Register to Vote**
   - Navigate to the Registration page
   - Fill in personal information
   - Receive SSI credentials and voter ID
   - Save your credentials securely

2. **Cast Your Vote**
   - Go to the Voting page
   - Select an active ballot
   - Choose your candidate
   - Confirm your vote
   - Save your vote receipt

3. **Verify Your Vote**
   - Use the Verify page
   - Enter your receipt ID and verification code
   - Review cryptographic proofs
   - Download verification report

4. **View Results**
   - Check the Results page
   - See real-time vote counts
   - View cryptographic integrity status

### For Administrators

1. **Create Ballots**
   - Access the Admin panel
   - Fill in ballot details
   - Add candidates
   - Set voting timeframe
   - Activate the ballot

2. **Monitor System**
   - View system health status
   - Monitor vote counts
   - Check security metrics

## API Integration

The web interface connects to the MediVote backend API:

```javascript
// Example API calls
const API_BASE_URL = 'http://localhost:8000';

// Register voter
const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(voterData)
});

// Cast vote
const voteResponse = await fetch(`${API_BASE_URL}/api/voting/cast-vote`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(voteData)
});
```

## File Structure

```
frontend/
├── index.html              # Main landing page
├── register.html           # Voter registration
├── vote.html              # Voting interface
├── verify.html            # Vote verification
├── results.html           # Results display
├── admin.html             # Admin panel
├── css/
│   └── style.css          # Main stylesheet
├── js/
│   ├── main.js            # Common functionality
│   ├── register.js        # Registration logic
│   ├── vote.js            # Voting logic
│   ├── verify.js          # Verification logic
│   ├── results.js         # Results display
│   └── admin.js           # Admin functionality
├── serve.py               # Development server
└── README.md              # This file
```

## Security Considerations

- **HTTPS**: Use HTTPS in production
- **CSP**: Implement Content Security Policy
- **CORS**: Configure proper CORS headers
- **Input Validation**: All inputs are validated client and server-side
- **Rate Limiting**: Implement rate limiting for API calls

## Demo Data

The demo includes:
- **Presidential Election Demo**: 4 sample candidates
- **Demo Voter**: John Doe (john.doe@example.com)
- **Active Ballot**: 2-hour voting window
- **Test Scenarios**: Registration, voting, verification, results

## Browser Support

- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+

## Development

### Adding New Features

1. **New Page**: Create HTML file with consistent structure
2. **Styling**: Add CSS to `css/style.css`
3. **Functionality**: Create corresponding JS file
4. **API Integration**: Use the `MediVoteAPI` class

### Code Structure

```javascript
// Example component structure
class VotingComponent {
    constructor() {
        this.initialize();
    }
    
    async initialize() {
        await this.loadData();
        this.setupEventListeners();
    }
    
    async loadData() {
        // API calls using MediVoteAPI
    }
    
    setupEventListeners() {
        // Event handling
    }
}
```

## Troubleshooting

### Common Issues

1. **Backend Connection Failed**
   - Ensure backend is running on port 8000
   - Check CORS configuration
   - Verify API endpoints

2. **Frontend Not Loading**
   - Check if port 3000 is available
   - Verify file permissions
   - Check browser console for errors

3. **Vote Verification Failed**
   - Ensure receipt ID is correct
   - Check verification code format
   - Verify backend is processing requests

### Debug Mode

Enable debug mode by setting `DEBUG = true` in `js/main.js`:

```javascript
const DEBUG = true; // Enable debug logging
```

## Support

For technical support or bug reports:
- Check the console logs
- Review the API documentation at `http://localhost:8000/docs`
- Ensure all dependencies are installed

## License

This project is part of the MediVote secure voting system. All rights reserved. 