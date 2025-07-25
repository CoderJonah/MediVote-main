#!/bin/bash

# System Dependencies Installer for MediVote
# This script installs the system packages needed to compile Python dependencies

echo "🔧 Installing System Dependencies for MediVote"
echo "=============================================="

# Check if running as root or with sudo
if [ "$EUID" -eq 0 ]; then
    echo "✅ Running with root privileges"
    SUDO=""
else
    echo "ℹ️  Will use sudo for package installation"
    SUDO="sudo"
fi

# Detect the operating system
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "❌ Cannot detect operating system"
    exit 1
fi

echo "📋 Detected OS: $OS $VERSION"

# Install dependencies based on OS
case $OS in
    ubuntu|debian)
        echo "📦 Installing Ubuntu/Debian dependencies..."
        $SUDO apt update
        $SUDO apt install -y \
            python3-dev \
            python3-pip \
            python3-venv \
            build-essential \
            libffi-dev \
            libssl-dev \
            pkg-config \
            cmake \
            git \
            curl \
            wget
        
        if [ $? -eq 0 ]; then
            echo "✅ Ubuntu/Debian dependencies installed"
        else
            echo "❌ Failed to install dependencies"
            exit 1
        fi
        ;;
        
    centos|rhel|fedora)
        echo "📦 Installing CentOS/RHEL/Fedora dependencies..."
        if command -v dnf &> /dev/null; then
            PKG_MGR="dnf"
        else
            PKG_MGR="yum"
        fi
        
        $SUDO $PKG_MGR install -y \
            python3-devel \
            python3-pip \
            gcc \
            gcc-c++ \
            make \
            openssl-devel \
            libffi-devel \
            cmake \
            git \
            curl \
            wget
            
        if [ $? -eq 0 ]; then
            echo "✅ CentOS/RHEL/Fedora dependencies installed"
        else
            echo "❌ Failed to install dependencies"
            exit 1
        fi
        ;;
        
    alpine)
        echo "📦 Installing Alpine Linux dependencies..."
        $SUDO apk update
        $SUDO apk add \
            python3-dev \
            py3-pip \
            build-base \
            libffi-dev \
            openssl-dev \
            cmake \
            git \
            curl \
            wget
            
        if [ $? -eq 0 ]; then
            echo "✅ Alpine Linux dependencies installed"
        else
            echo "❌ Failed to install dependencies"
            exit 1
        fi
        ;;
        
    *)
        echo "⚠️  Unsupported OS: $OS"
        echo "💡 Manual installation required:"
        echo "   • Python 3 development headers"
        echo "   • Build tools (gcc, make, cmake)"
        echo "   • SSL/TLS development libraries"
        echo "   • FFI development libraries"
        exit 1
        ;;
esac

# Verify Python installation
echo "🔍 Verifying Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "✅ $PYTHON_VERSION found"
else
    echo "❌ Python 3 not found"
    exit 1
fi

# Verify pip installation
if command -v pip3 &> /dev/null || python3 -m pip --version &> /dev/null; then
    echo "✅ pip found"
else
    echo "❌ pip not found"
    exit 1
fi

# Test virtual environment creation
echo "🧪 Testing virtual environment creation..."
python3 -m venv test-venv-check &> /dev/null
if [ $? -eq 0 ]; then
    rm -rf test-venv-check
    echo "✅ Virtual environment creation works"
else
    echo "⚠️  Virtual environment creation failed"
    echo "💡 You may need to install python3-venv package"
fi

echo ""
echo "🎉 System dependencies installation complete!"
echo ""
echo "🚀 Next steps:"
echo "   1. Run './start-simple.sh' to start MediVote"
echo "   2. Or run './start.sh' for virtual environment setup"
echo ""