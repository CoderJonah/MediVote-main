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

# Function to install dependencies without virtual environment
install_without_venv() {
    echo "⚠️  Installing dependencies without virtual environment"
    echo "   This will install packages system-wide with --break-system-packages"
    echo "   Press Ctrl+C to cancel, or wait 5 seconds to continue..."
    sleep 5
    
    echo "📦 Installing system dependencies..."
    if [ -f "requirements-system.txt" ]; then
        python3 -m pip install -r requirements-system.txt --break-system-packages
        if [ $? -ne 0 ]; then
            echo "❌ Failed to install system dependencies"
            exit 1
        fi
    fi
    
    echo "📦 Installing backend dependencies..."
    cd src/backend
    python3 -m pip install -r requirements.txt --break-system-packages
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install backend dependencies"
        exit 1
    fi
    cd ../..
    echo "✅ Dependencies installed system-wide"
}

# Try to create virtual environment
echo "🔧 Setting up Python environment..."
if [ ! -d "venv" ]; then
    echo "   Creating virtual environment..."
    python3 -m venv venv 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "⚠️  Virtual environment creation failed"
        echo "   This usually means python3-venv is not installed"
        echo ""
        echo "🔧 Available options:"
        echo "   1. Install python3-venv: sudo apt install python3-venv"
        echo "   2. Use system-wide installation (not recommended for production)"
        echo ""
        read -p "Use system-wide installation? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_without_venv
            USE_SYSTEM_PYTHON=true
        else
            echo "❌ Please install python3-venv and try again:"
            echo "   sudo apt install python3-venv"
            exit 1
        fi
    else
        echo "✅ Virtual environment created"
    fi
else
    echo "✅ Virtual environment already exists"
fi

# If we're using virtual environment, activate it and install dependencies
if [ "$USE_SYSTEM_PYTHON" != "true" ]; then
    # Activate virtual environment
    echo "   Activating virtual environment..."
    source venv/bin/activate
    if [ $? -ne 0 ]; then
        echo "❌ Failed to activate virtual environment"
        exit 1
    fi
    echo "✅ Virtual environment activated"

    # Install system-level dependencies for service manager
    echo "📦 Installing system dependencies..."
    if [ -f "requirements-system.txt" ]; then
        echo "   Installing service manager dependencies..."
        pip install -r requirements-system.txt
        if [ $? -ne 0 ]; then
            echo "❌ Failed to install system dependencies"
            exit 1
        fi
        echo "✅ System dependencies installed"
    fi

    # Install backend dependencies
    echo "📦 Installing backend dependencies..."
    cd src/backend
    if [ ! -f "requirements.txt" ]; then
        echo "❌ Backend requirements.txt not found"
        exit 1
    fi

    echo "   Installing Python packages..."
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install backend dependencies"
        exit 1
    fi
    echo "✅ Backend dependencies installed"
    cd ../..
fi

# Start the background service manager
echo "🚀 Starting MediVote services..."
if [ "$USE_SYSTEM_PYTHON" == "true" ]; then
    python3 scripts/start_medivote_background.py &
else
    python scripts/start_medivote_background.py &
fi
SERVICE_PID=$!

# Wait a moment for services to start
sleep 3

# Check if the service is still running
if kill -0 $SERVICE_PID 2>/dev/null; then
    echo "✅ MediVote started successfully!"
    echo ""
    echo "🔗 Access URLs:"
    echo "   🌐 Frontend: http://localhost:8080"
    echo "   🚀 Backend API: http://localhost:8001"
    echo "   📊 Dashboard: http://localhost:8091"
    echo ""
    echo "📝 To stop the services, press Ctrl+C or run:"
    echo "   kill $SERVICE_PID"
    echo ""
    echo "🔍 Service PID: $SERVICE_PID"
    
    # Wait for the background process
    wait $SERVICE_PID
else
    echo "❌ Failed to start MediVote services"
    exit 1
fi