# MediVote Test Suite 🧪

Comprehensive test suite for the MediVote blockchain voting system, organized by functionality and testing approach.

## 📁 Test Organization

```
tests/
├── __init__.py                     # Test package initialization
├── README.md                       # This documentation
├── run_tests.py                    # Test runner script
├── test_cross_platform.py          # Cross-platform compatibility tests
│
├── unit/                           # Unit tests for individual components
│   └── __init__.py
│
├── integration/                    # Integration tests between components
│   └── __init__.py
│
├── security/                       # Security and cryptographic tests
│   ├── __init__.py
│   ├── test_authentication.py      # Authentication system tests
│   └── test_blind_signatures.py    # Blind signature crypto tests
│
└── performance/                    # Performance and load testing
    ├── __init__.py
    └── locustfile.py               # Locust load testing scenarios
```

## 🚀 Quick Start

### Run All Tests
```bash
cd tests
python run_tests.py all
```

### Run Specific Test Categories
```bash
# Security tests (authentication, cryptography)
python run_tests.py security

# Cross-platform compatibility tests
python run_tests.py cross-platform

# Performance load tests (requires Locust)
python run_tests.py performance
```

### Direct Pytest Usage
```bash
# Run all tests with coverage
pytest --cov=backend --cov-report=html

# Run only security tests
pytest tests/security/ -m security -v

# Run with parallel execution
pytest -n auto tests/
```

## 📋 Test Categories

### 🔐 Security Tests (`tests/security/`)

**Authentication Tests** (`test_authentication.py`):
- Admin user authentication
- Session token verification
- Permission-based access control
- API security integration tests
- Invalid credential handling

**Blind Signature Tests** (`test_blind_signatures.py`):
- RSA key generation for blind signatures
- Message blinding and unblinding
- Signature verification
- Ballot authorization authority tests
- Voting protocol security properties

### 🌐 Cross-Platform Tests (`test_cross_platform.py`)

Tests compatibility across different operating systems and Python versions:
- Python version compatibility (3.9+ required)
- File system operations
- Path handling across platforms
- Process execution
- Text encoding (UTF-8)
- Basic network operations

### ⚡ Performance Tests (`tests/performance/locustfile.py`)

Load testing scenarios using Locust:
- General API user simulation
- Realistic voter behavior patterns
- Admin user operations
- Peak voting hour scenarios

**User Types**:
- `MediVoteAPIUser`: General API testing
- `MediVoteVoterUser`: Realistic voter scenarios
- `MediVoteAdminUser`: Administrative operations
- `PeakVotingUser`: High-load voting scenarios

## 🛠️ Test Configuration

### Pytest Configuration (`pytest.ini`)

Key settings:
- **Test Discovery**: Finds `test_*.py` files automatically
- **Coverage**: 70% minimum coverage requirement
- **Markers**: Categorizes tests (unit, integration, security, etc.)
- **Asyncio**: Automatic async test support
- **Parallel Execution**: Automatic parallel test running

### Test Markers

Use markers to categorize and filter tests:

```python
@pytest.mark.security
def test_crypto_function():
    pass

@pytest.mark.integration
@pytest.mark.requires_backend
def test_api_integration():
    pass
```

Available markers:
- `unit`: Unit tests for individual components
- `integration`: Integration tests for component interactions
- `security`: Security and cryptographic tests
- `performance`: Performance and load tests
- `slow`: Tests that take a long time to run
- `requires_backend`: Tests that require the backend to be running
- `requires_database`: Tests that require database connection
- `requires_network`: Tests that require network access

## 📦 Dependencies

### Core Testing Dependencies
```bash
pip install pytest pytest-cov pytest-asyncio pytest-xdist
```

### Security Testing
```bash
pip install cryptography requests
```

### Performance Testing
```bash
pip install locust
```

### All Dependencies
See `backend/requirements.txt` for complete list.

## 🔄 Running Tests in CI/CD

The tests are integrated with GitHub Actions CI:

```yaml
# Run backend tests
python -m pytest backend/tests/ -v --cov=backend --cov-report=xml

# Run cross-platform tests
python test_cross_platform.py

# Run performance tests
locust -f tests/performance/locustfile.py --headless --users 10 --spawn-rate 1 --run-time 60s
```

## 🏗️ Test Development Guidelines

### Writing New Tests

1. **Choose the Right Category**:
   - `unit/`: Test individual functions/classes
   - `integration/`: Test component interactions
   - `security/`: Test cryptographic functions and security
   - `performance/`: Test system performance and load

2. **Use Descriptive Names**:
   ```python
   def test_admin_authentication_with_valid_credentials():
       pass
   
   def test_blind_signature_unlinkability_property():
       pass
   ```

3. **Add Appropriate Markers**:
   ```python
   @pytest.mark.security
   @pytest.mark.asyncio
   async def test_crypto_operation():
       pass
   ```

4. **Use Fixtures for Setup**:
   ```python
   @pytest.fixture
   async def auth_service():
       # Setup code
       return service
   ```

### Test Structure Best Practices

```python
def test_function_name():
    # Arrange - Set up test data
    input_data = {"test": "data"}
    
    # Act - Execute the function being tested
    result = function_under_test(input_data)
    
    # Assert - Verify the results
    assert result is not None
    assert result["status"] == "success"
```

## 🐛 Debugging Tests

### Verbose Output
```bash
pytest -v tests/security/test_authentication.py::TestAuthentication::test_admin_authentication
```

### Debug with Print Statements
```bash
pytest -s tests/security/  # Shows print statements
```

### Run Single Test
```bash
pytest tests/security/test_authentication.py::TestAuthentication::test_admin_authentication -v
```

### Run with Debugger
```bash
pytest --pdb tests/security/test_authentication.py  # Drops into debugger on failure
```

## 📊 Coverage Reports

### Generate HTML Coverage Report
```bash
pytest --cov=backend --cov-report=html
# View: htmlcov/index.html
```

### Terminal Coverage Report
```bash
pytest --cov=backend --cov-report=term-missing
```

### Coverage Requirements
- Minimum: 70% coverage (configured in `pytest.ini`)
- Goal: 90%+ coverage for security-critical components

## 🔧 Troubleshooting

### Common Issues

**Import Errors**:
- Make sure you're running tests from the project root
- Check that `__init__.py` files exist in test directories

**Authentication Test Failures**:
- Ensure backend is not running during unit tests
- Check that test database is accessible

**Performance Test Issues**:
- Make sure Locust is installed
- Verify backend is running on correct port for integration tests

**Cross-Platform Test Failures**:
- Check Python version (3.9+ required)
- Verify file permissions on Unix-like systems

### Getting Help

1. Check test output for specific error messages
2. Run individual tests to isolate issues
3. Use verbose mode (`-v`) for detailed output
4. Check the logs in `logs/` directory

## 🎯 Future Enhancements

### Planned Test Additions
- [ ] Unit tests for blockchain operations
- [ ] Integration tests for frontend-backend communication
- [ ] Security tests for homomorphic encryption
- [ ] Zero-knowledge proof verification tests
- [ ] Database integrity tests
- [ ] Network partition tolerance tests

### Test Infrastructure Improvements
- [ ] Automated test data generation
- [ ] Test environment containerization
- [ ] Visual test reports
- [ ] Performance regression detection
- [ ] Security vulnerability scanning

---

**Happy Testing!** 🧪✅

For questions or contributions to the test suite, see `CONTRIBUTING.md` in the project root. 