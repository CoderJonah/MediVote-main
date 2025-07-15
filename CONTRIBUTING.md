# Contributing to MediVote

Thank you for your interest in contributing to MediVote! This document provides guidelines and information for contributors to our secure blockchain-based voting system.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Project Overview](#project-overview)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Security Guidelines](#security-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Code of Conduct

### Our Pledge

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to a positive environment for our community include:

- Using welcoming and inclusive language
- Being respectful of differing opinions and viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

Examples of unacceptable behavior include:

- The use of sexualized language or imagery, and sexual attention or advances
- Trolling, insulting or derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate

## Project Overview

MediVote is a secure, privacy-preserving electronic voting system that leverages blockchain technology, zero-knowledge proofs, and homomorphic encryption. Our mission is to provide a secure, accessible, and verifiable voting solution that complements traditional voting methods.

### Key Principles

- **Security**: Resilient against nation-state actors and malicious insiders
- **Privacy**: Cryptographically unlinkable voter identity from cast ballots
- **Verifiability**: End-to-end verifiable (E2E-V) with individual and universal verification
- **Accessibility**: WCAG 2.1 AA compliant, HAVA/ADA accessible
- **Equity**: Designed to reduce, not exacerbate, the digital divide

### Technology Stack

- **Backend**: Python with FastAPI, cryptographic libraries
- **Blockchain**: Solidity smart contracts, Hyperledger Fabric
- **Frontend**: React with TypeScript, mobile apps with React Native
- **Cryptography**: ZK-SNARKs, Paillier homomorphic encryption, RSA blind signatures
- **Identity**: W3C Verifiable Credentials, DID (Decentralized Identifiers)

## Development Setup

### Prerequisites

- Python 3.9+
- Node.js 16+
- Docker and Docker Compose (optional but recommended)
- Git

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/the-median/medivote.git
   cd medivote
   ```

2. **Run the setup script**
   ```bash
   # On Windows
   python setup.py
   
   # On Unix-like systems
   python setup.py
   # or
   ./setup.sh
   ```

3. **Start the development environment**
   ```bash
   # Using Docker (recommended)
   docker-compose up -d
   
   # Using local development
   python -m uvicorn backend.main:app --reload --port 8000
   ```

4. **Run tests**
   ```bash
   python -m pytest tests/
   ```

### Development Environment

The project uses several tools for development:

- **Pre-commit hooks**: For code formatting and linting
- **Black**: Python code formatting
- **Flake8**: Python linting
- **ESLint**: JavaScript/TypeScript linting
- **Prettier**: Code formatting

## Contributing Guidelines

### Before You Start

1. **Check existing issues**: Search for existing issues that might be related to your contribution
2. **Create an issue**: For significant changes, create an issue first to discuss the approach
3. **Fork the repository**: Create your own fork to work on
4. **Create a feature branch**: Use a descriptive branch name

### Branch Naming Convention

- `feature/description`: New features
- `bugfix/description`: Bug fixes
- `hotfix/description`: Critical bug fixes
- `docs/description`: Documentation updates
- `test/description`: Test-related changes

### Code Style Guidelines

#### Python

- Follow PEP 8 style guidelines
- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes
- Keep functions small and focused
- Use meaningful variable and function names

```python
def calculate_vote_hash(vote_data: Dict[str, Any]) -> str:
    """
    Calculate SHA-256 hash of vote data.
    
    Args:
        vote_data: Dictionary containing vote information
        
    Returns:
        Hexadecimal string representation of the hash
        
    Raises:
        ValueError: If vote_data is empty or invalid
    """
    if not vote_data:
        raise ValueError("Vote data cannot be empty")
    
    # Implementation here
    return hash_result
```

#### JavaScript/TypeScript

- Use ESLint and Prettier for formatting
- Use TypeScript for type safety
- Follow React best practices
- Use meaningful component and variable names

```typescript
interface VoteData {
  electionId: string;
  candidateId: string;
  timestamp: number;
}

const submitVote = async (voteData: VoteData): Promise<boolean> => {
  try {
    const response = await api.post('/api/voting/submit', voteData);
    return response.status === 200;
  } catch (error) {
    console.error('Failed to submit vote:', error);
    return false;
  }
};
```

### Security Guidelines

Given the sensitive nature of voting systems, security is paramount:

1. **Never commit sensitive data**: Keys, passwords, or personal information
2. **Use secure random generation**: For cryptographic operations
3. **Validate all inputs**: Prevent injection attacks
4. **Use HTTPS**: For all communications
5. **Implement rate limiting**: Prevent abuse
6. **Log security events**: For audit purposes

### Testing Guidelines

#### Unit Tests

- Write tests for all new functionality
- Aim for >90% code coverage
- Use descriptive test names
- Test both success and failure cases

```python
def test_calculate_vote_hash():
    """Test vote hash calculation with valid data."""
    vote_data = {
        "election_id": "test_election",
        "candidate_id": "candidate_1",
        "timestamp": 1234567890
    }
    
    result = calculate_vote_hash(vote_data)
    
    assert isinstance(result, str)
    assert len(result) == 64  # SHA-256 hash length
    assert result != calculate_vote_hash({})  # Different inputs produce different hashes
```

#### Integration Tests

- Test API endpoints
- Test database operations
- Test blockchain interactions
- Test cryptographic operations

#### Security Tests

- Test for common vulnerabilities
- Test cryptographic implementations
- Test access control
- Test input validation

### Documentation

- Update README.md for user-facing changes
- Update API documentation for endpoint changes
- Add inline comments for complex logic
- Update architecture diagrams if needed

## Pull Request Process

### Before Submitting

1. **Run tests**: Ensure all tests pass
2. **Check code style**: Run linters and formatters
3. **Update documentation**: If needed
4. **Test manually**: Verify functionality works as expected

### Pull Request Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No sensitive data committed

## Security Considerations
- [ ] Input validation implemented
- [ ] Cryptographic operations secure
- [ ] No hardcoded secrets
- [ ] Rate limiting considered
```

### Review Process

1. **Automated checks**: CI/CD pipeline runs tests and checks
2. **Code review**: At least one maintainer reviews the PR
3. **Security review**: Security-sensitive changes require additional review
4. **Approval**: PR requires approval from maintainers

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] Security audit completed
- [ ] Performance testing completed
- [ ] Accessibility testing completed
- [ ] Legal review completed (if needed)

### Release Notes

Include in release notes:
- New features
- Bug fixes
- Security updates
- Breaking changes
- Migration instructions

## Getting Help

- **Issues**: Use GitHub issues for bugs and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Security**: Report security issues privately to security@themedian.org
- **Documentation**: Check the docs/ directory for detailed documentation

## Recognition

Contributors will be recognized in:
- Release notes
- Contributors section of README.md
- Project documentation

Thank you for contributing to MediVote! Your contributions help make secure, accessible voting a reality. 