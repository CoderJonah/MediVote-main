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

# Install system dependencies first
if [ -f "requirements-system.txt" ]; then
    echo "   Installing service manager dependencies..."
    python3 -m pip install -r requirements-system.txt --break-system-packages --quiet
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install system dependencies"
        echo "💡 Try: sudo apt install python3-pip python3-dev"
        exit 1
    fi
fi

# Function to try installing with different requirement files
install_backend_deps() {
    echo "   Trying minimal dependencies first..."
    
    # Try minimal requirements first
    if [ -f "requirements-minimal.txt" ]; then
        python3 -m pip install -r requirements-minimal.txt --break-system-packages --quiet
        if [ $? -eq 0 ]; then
            echo "✅ Minimal dependencies installed successfully"
            return 0
        fi
    fi
    
    echo "   Minimal install failed, trying full requirements..."
    echo "   This may take longer and require compilation..."
    
    # Try full requirements with no-cache to avoid issues
    python3 -m pip install -r src/backend/requirements.txt --break-system-packages --no-cache-dir --quiet --timeout 300
    if [ $? -eq 0 ]; then
        echo "✅ Full dependencies installed successfully"
        return 0
    fi
    
    echo "❌ Failed to install backend dependencies"
    echo ""
    echo "🔧 Troubleshooting suggestions:"
    echo "   1. Install build dependencies:"
    echo "      sudo apt update"
    echo "      sudo apt install python3-dev python3-pip build-essential"
    echo ""
    echo "   2. For Ubuntu/Debian, install additional packages:"
    echo "      sudo apt install libffi-dev libssl-dev"
    echo ""
    echo "   3. Try installing numpy separately:"
    echo "      python3 -m pip install numpy --break-system-packages"
    echo ""
    return 1
}

# Install backend dependencies
echo "📦 Installing backend dependencies..."
install_backend_deps
if [ $? -ne 0 ]; then
    exit 1
fi

echo "✅ Dependencies installed"

# Check if the main backend file can import
echo "🔍 Verifying backend can start..."
cd src/backend
python3 -c "import sys; sys.path.append('.'); import main" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Backend import test failed, but attempting to start anyway..."
fi
cd ../..

# Start the service manager
echo "🚀 Starting MediVote services..."
python3 scripts/start_medivote_background.py &
SERVICE_PID=$!

# Wait a moment for services to start
echo "   Waiting for services to initialize..."
sleep 5

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
    trap "echo ''; echo '🛑 Stopping MediVote...'; kill $SERVICE_PID; wait $SERVICE_PID 2>/dev/null; echo '✅ Stopped'; exit 0" INT
    
    # Wait for the background process
    echo "   MediVote is running. Press Ctrl+C to stop."
    wait $SERVICE_PID
else
    echo "❌ Failed to start MediVote services"
    echo ""
    echo "💡 Common issues and solutions:"
    echo "   • Missing dependencies: Check error messages above"
    echo "   • Port conflicts: Make sure ports 8001, 8080, 8091 are free"
    echo "   • Permission issues: Try running with different user"
    echo ""
    exit 1
fi