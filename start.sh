#!/bin/bash

# MediVote Startup Script
# This script starts the MediVote application with the new directory structure

echo "🗳️  Starting MediVote Secure Voting System"
echo "========================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if we're in the right directory
if [ ! -d "src/backend" ] || [ ! -d "src/frontend" ]; then
    echo "❌ Please run this script from the project root directory"
    exit 1
fi

# Install backend dependencies
echo "📦 Installing backend dependencies..."
cd src/backend
if [ ! -f "requirements.txt" ]; then
    echo "❌ Backend requirements.txt not found"
    exit 1
fi

python3 -m pip install -r requirements.txt

# Start the background service manager
echo "🚀 Starting MediVote services..."
cd ../..
python3 scripts/start_medivote_background.py

echo "✅ MediVote started successfully!"
echo "🌐 Backend: http://localhost:8001"
echo "🖥️  Frontend: http://localhost:8080"
echo "📊 Dashboard: http://localhost:8091"