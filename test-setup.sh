#!/bin/bash

# Test script to verify MediVote setup
echo "🧪 Testing MediVote Setup"
echo "========================"

# Test Python availability
echo "1. Testing Python..."
if command -v python3 &> /dev/null; then
    echo "✅ Python 3 found: $(python3 --version)"
else
    echo "❌ Python 3 not found"
    exit 1
fi

# Test virtual environment creation
echo "2. Testing virtual environment..."
if [ -d "venv" ]; then
    echo "✅ Virtual environment exists"
else
    echo "   Creating test virtual environment..."
    python3 -m venv test-venv
    if [ $? -eq 0 ]; then
        echo "✅ Virtual environment creation works"
        rm -rf test-venv
    else
        echo "❌ Virtual environment creation failed"
        exit 1
    fi
fi

# Test directory structure
echo "3. Testing directory structure..."
if [ -d "src/backend" ] && [ -d "src/frontend" ] && [ -d "scripts" ]; then
    echo "✅ Directory structure is correct"
else
    echo "❌ Directory structure is incorrect"
    exit 1
fi

# Test requirements files
echo "4. Testing requirements files..."
if [ -f "src/backend/requirements.txt" ]; then
    echo "✅ Backend requirements.txt found"
else
    echo "❌ Backend requirements.txt missing"
    exit 1
fi

if [ -f "requirements-system.txt" ]; then
    echo "✅ System requirements.txt found"
else
    echo "❌ System requirements.txt missing"
    exit 1
fi

# Test Python script syntax
echo "5. Testing Python script syntax..."
python3 -m py_compile scripts/start_medivote_background.py
if [ $? -eq 0 ]; then
    echo "✅ Service manager script syntax is valid"
else
    echo "❌ Service manager script has syntax errors"
    exit 1
fi

echo ""
echo "🎉 All tests passed! Setup is ready."
echo "💡 Run './start.sh' to start MediVote"