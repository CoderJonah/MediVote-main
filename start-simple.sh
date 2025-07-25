#!/bin/bash

# MediVote Simple Startup Script
# This script starts MediVote using system Python (no virtual environment)

echo "🗳️  Starting MediVote (Simple Mode)"
echo "=================================="

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

echo "📦 Installing dependencies (system-wide)..."
echo "⚠️  This will install packages with --break-system-packages"

# Install system dependencies
if [ -f "requirements-system.txt" ]; then
    echo "   Installing service manager dependencies..."
    python3 -m pip install -r requirements-system.txt --break-system-packages --quiet
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install system dependencies"
        echo "💡 Try: sudo apt install python3-pip python3-dev"
        exit 1
    fi
fi

# Install backend dependencies
echo "   Installing backend dependencies..."
python3 -m pip install -r src/backend/requirements.txt --break-system-packages --quiet
if [ $? -ne 0 ]; then
    echo "❌ Failed to install backend dependencies"
    exit 1
fi

echo "✅ Dependencies installed"

# Start the service manager
echo "🚀 Starting MediVote services..."
python3 scripts/start_medivote_background.py &
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
    echo "📝 To stop the services:"
    echo "   Press Ctrl+C or run: kill $SERVICE_PID"
    echo ""
    
    # Trap Ctrl+C to clean up
    trap "echo ''; echo '🛑 Stopping MediVote...'; kill $SERVICE_PID; exit 0" INT
    
    # Wait for the background process
    wait $SERVICE_PID
else
    echo "❌ Failed to start MediVote services"
    echo "💡 Check the error messages above"
    exit 1
fi