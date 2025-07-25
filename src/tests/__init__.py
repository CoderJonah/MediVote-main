"""
MediVote Test Suite

Comprehensive test suite for the MediVote blockchain voting system.
Tests are organized by component and functionality.
"""

import sys
import os
from pathlib import Path

# Add the project root to the Python path so tests can import modules
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure test environment
os.environ['TESTING'] = 'true'
os.environ['DATABASE_URL'] = 'sqlite:///test_medivote.db' 