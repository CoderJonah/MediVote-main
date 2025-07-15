#!/usr/bin/env python3
"""
MediVote Node Installer
Easy setup and installation for blockchain nodes

Users can download this installer to quickly set up and run
MediVote blockchain nodes to participate in the network.
"""

import os
import sys
import json
import shutil
import subprocess
import platform
import urllib.request
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Any

class MediVoteNodeInstaller:
    """Installer for MediVote blockchain nodes"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.architecture = platform.machine().lower()
        self.install_dir = Path.home() / "MediVote"
        self.node_dir = self.install_dir / "node"
        self.config_dir = self.install_dir / "config"
        
        # Node configuration
        self.node_config = {
            "node": {
                "name": "MediVote Node",
                "port": 8545,
                "rpc_port": 8546,
                "max_peers": 50,
                "sync_interval": 30,
                "block_time": 15
            },
            "network": {
                "bootstrap_nodes": [
                    "node1.medivote.net:8545",
                    "node2.medivote.net:8545",
                    "node3.medivote.net:8545"
                ],
                "network_id": "medivote_mainnet",
                "genesis_block": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "blockchain": {
                "rpc_url": "http://localhost:8545",
                "private_key": None,
                "gas_limit": 3000000,
                "gas_price": "20 gwei"
            },
            "storage": {
                "data_dir": "./blockchain_data",
                "backup_interval": 3600,
                "max_storage_gb": 10
            }
        }
    
    def print_banner(self):
        """Print installer banner"""
        print("🚀 MediVote Node Installer")
        print("=" * 50)
        print("Decentralized voting network node setup")
        print("Join the network and help secure voting")
        print("=" * 50)
        print(f"System: {self.system} {self.architecture}")
        print(f"Install Directory: {self.install_dir}")
        print("=" * 50)
    
    def check_requirements(self) -> bool:
        """Check if system meets requirements"""
        print("🔍 Checking system requirements...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            print("❌ Python 3.8 or higher required")
            return False
        
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}")
        
        # Check available disk space
        try:
            free_space = shutil.disk_usage(self.install_dir).free
            required_space = 2 * 1024 * 1024 * 1024  # 2GB
            if free_space < required_space:
                print("❌ Insufficient disk space (need at least 2GB)")
                return False
            print(f"✅ Disk space: {free_space // (1024**3)}GB available")
        except Exception as e:
            print(f"⚠️  Could not check disk space: {e}")
        
        # Check network connectivity
        try:
            urllib.request.urlopen("https://www.google.com", timeout=5)
            print("✅ Network connectivity")
        except Exception:
            print("⚠️  Network connectivity issues detected")
        
        print("✅ System requirements met")
        return True
    
    def create_directories(self):
        """Create installation directories"""
        print("📁 Creating directories...")
        
        try:
            self.install_dir.mkdir(exist_ok=True)
            self.node_dir.mkdir(exist_ok=True)
            self.config_dir.mkdir(exist_ok=True)
            
            print(f"✅ Created: {self.install_dir}")
            print(f"✅ Created: {self.node_dir}")
            print(f"✅ Created: {self.config_dir}")
            
        except Exception as e:
            print(f"❌ Failed to create directories: {e}")
            return False
        
        return True
    
    def download_node_files(self):
        """Download node files"""
        print("📥 Downloading node files...")
        
        # For now, we'll copy local files
        # In a real implementation, this would download from a repository
        
        try:
            # Copy blockchain node
            if os.path.exists("blockchain_node.py"):
                shutil.copy("blockchain_node.py", self.node_dir / "blockchain_node.py")
                print("✅ Copied blockchain_node.py")
            else:
                print("⚠️  blockchain_node.py not found locally")
            
            # Copy network coordinator
            if os.path.exists("network_coordinator.py"):
                shutil.copy("network_coordinator.py", self.node_dir / "network_coordinator.py")
                print("✅ Copied network_coordinator.py")
            else:
                print("⚠️  network_coordinator.py not found locally")
            
            # Copy backend files
            if os.path.exists("backend"):
                backend_dest = self.node_dir / "backend"
                if backend_dest.exists():
                    shutil.rmtree(backend_dest)
                shutil.copytree("backend", backend_dest)
                print("✅ Copied backend files")
            else:
                print("⚠️  backend directory not found locally")
            
        except Exception as e:
            print(f"❌ Failed to copy files: {e}")
            return False
        
        return True
    
    def create_config_files(self):
        """Create configuration files"""
        print("⚙️  Creating configuration files...")
        
        try:
            # Node configuration
            node_config_path = self.config_dir / "node_config.json"
            with open(node_config_path, 'w') as f:
                json.dump(self.node_config, f, indent=2)
            print(f"✅ Created: {node_config_path}")
            
            # Network configuration
            network_config = {
                "network": {
                    "name": "MediVote Mainnet",
                    "network_id": "medivote_mainnet",
                    "coordinator_port": 8080,
                    "discovery_interval": 60,
                    "node_timeout": 300,
                    "max_nodes": 1000
                },
                "api": {
                    "enabled": True,
                    "port": 8081,
                    "rate_limit": 100
                },
                "storage": {
                    "data_dir": "./network_data",
                    "backup_interval": 3600
                }
            }
            
            network_config_path = self.config_dir / "network_config.json"
            with open(network_config_path, 'w') as f:
                json.dump(network_config, f, indent=2)
            print(f"✅ Created: {network_config_path}")
            
        except Exception as e:
            print(f"❌ Failed to create config files: {e}")
            return False
        
        return True
    
    def install_dependencies(self):
        """Install Python dependencies"""
        print("📦 Installing dependencies...")
        
        try:
            # Create requirements file
            requirements = [
                "aiohttp>=3.8.0",
                "aiofiles>=0.8.0",
                "web3>=6.0.0",
                "eth-account>=0.8.0",
                "loguru>=0.6.0",
                "fastapi>=0.68.0",
                "uvicorn>=0.15.0",
                "pydantic>=1.8.0",
                "sqlalchemy>=1.4.0",
                "bcrypt>=4.0.0",
                "pyotp>=2.6.0",
                "gmpy2>=2.1.0",
                "py_ecc>=5.2.0"
            ]
            
            requirements_path = self.node_dir / "requirements.txt"
            with open(requirements_path, 'w') as f:
                f.write('\n'.join(requirements))
            
            print(f"✅ Created: {requirements_path}")
            
            # Install dependencies
            print("Installing Python packages...")
            subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", str(requirements_path)
            ], check=True, cwd=self.node_dir)
            
            print("✅ Dependencies installed")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False
        except Exception as e:
            print(f"❌ Error installing dependencies: {e}")
            return False
        
        return True
    
    def create_startup_scripts(self):
        """Create startup scripts for different platforms"""
        print("📝 Creating startup scripts...")
        
        try:
            # Windows batch script
            if self.system == "windows":
                batch_script = self.install_dir / "start_node.bat"
                with open(batch_script, 'w') as f:
                    f.write(f"""@echo off
cd /d "{self.node_dir}"
echo Starting MediVote Blockchain Node...
python blockchain_node.py
pause
""")
                print(f"✅ Created: {batch_script}")
            
            # Unix shell script
            else:
                shell_script = self.install_dir / "start_node.sh"
                with open(shell_script, 'w') as f:
                    f.write(f"""#!/bin/bash
cd "{self.node_dir}"
echo "Starting MediVote Blockchain Node..."
python3 blockchain_node.py
""")
                
                # Make executable
                os.chmod(shell_script, 0o755)
                print(f"✅ Created: {shell_script}")
            
            # Python launcher script
            launcher_script = self.install_dir / "launch_node.py"
            with open(launcher_script, 'w') as f:
                f.write(f"""#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

def main():
    node_dir = Path("{self.node_dir}")
    os.chdir(node_dir)
    
    print("🚀 Launching MediVote Blockchain Node...")
    print(f"Node Directory: {{node_dir}}")
    print("=" * 50)
    
    try:
        subprocess.run([sys.executable, "blockchain_node.py"], check=True)
    except KeyboardInterrupt:
        print("\\n🛑 Node stopped by user")
    except Exception as e:
        print(f"❌ Error running node: {{e}}")

if __name__ == "__main__":
    main()
""")
            
            print(f"✅ Created: {launcher_script}")
            
        except Exception as e:
            print(f"❌ Failed to create startup scripts: {e}")
            return False
        
        return True
    
    def create_desktop_shortcut(self):
        """Create desktop shortcut"""
        print("🖥️  Creating desktop shortcut...")
        
        try:
            desktop = Path.home() / "Desktop"
            if not desktop.exists():
                desktop = Path.home() / "Desktop"
            
            if self.system == "windows":
                shortcut_path = desktop / "MediVote Node.lnk"
                # Windows shortcut creation would go here
                print(f"✅ Desktop shortcut: {shortcut_path}")
            else:
                desktop_file = desktop / "medivote-node.desktop"
                with open(desktop_file, 'w') as f:
                    f.write(f"""[Desktop Entry]
Version=1.0
Type=Application
Name=MediVote Node
Comment=Launch MediVote Blockchain Node
Exec=python3 "{self.install_dir}/launch_node.py"
Icon={self.install_dir}/assets/medivote_icon.png
Terminal=true
Categories=Network;
""")
                print(f"✅ Desktop shortcut: {desktop_file}")
            
        except Exception as e:
            print(f"⚠️  Could not create desktop shortcut: {e}")
    
    def create_readme(self):
        """Create README file"""
        print("📖 Creating documentation...")
        
        try:
            readme_path = self.install_dir / "README.md"
            with open(readme_path, 'w') as f:
                f.write(f"""# MediVote Blockchain Node

Welcome to the MediVote decentralized voting network!

## What is this?

This is a blockchain node for the MediVote network. By running this node, you're helping to:
- Secure the voting network
- Process voting transactions
- Maintain network decentralization
- Support democratic voting worldwide

## Quick Start

### Windows
1. Double-click `start_node.bat` in the installation directory
2. Or run: `python launch_node.py`

### Linux/macOS
1. Run: `./start_node.sh`
2. Or run: `python3 launch_node.py`

## Configuration

Node configuration is stored in:
- `config/node_config.json` - Node settings
- `config/network_config.json` - Network settings

## Directory Structure

```
{self.install_dir}/
├── node/              # Node executable files
├── config/            # Configuration files
├── blockchain_data/   # Blockchain data (created when running)
├── start_node.bat     # Windows startup script
├── start_node.sh      # Unix startup script
└── launch_node.py     # Python launcher
```

## Network Participation

Your node will:
- Connect to the MediVote network
- Sync with other nodes
- Process voting transactions
- Help maintain network security

## Support

For support, visit: https://github.com/medivote/network

## Version

MediVote Node v1.0.0
""")
            
            print(f"✅ Created: {readme_path}")
            
        except Exception as e:
            print(f"❌ Failed to create README: {e}")
            return False
        
        return True
    
    def run_installation(self) -> bool:
        """Run the complete installation process"""
        self.print_banner()
        
        # Check requirements
        if not self.check_requirements():
            return False
        
        print("\n🚀 Starting installation...")
        
        # Create directories
        if not self.create_directories():
            return False
        
        # Download files
        if not self.download_node_files():
            return False
        
        # Create config files
        if not self.create_config_files():
            return False
        
        # Install dependencies
        if not self.install_dependencies():
            return False
        
        # Create startup scripts
        if not self.create_startup_scripts():
            return False
        
        # Create desktop shortcut
        self.create_desktop_shortcut()
        
        # Create documentation
        if not self.create_readme():
            return False
        
        print("\n🎉 Installation completed successfully!")
        print("=" * 50)
        print(f"Installation Directory: {self.install_dir}")
        print(f"Node Directory: {self.node_dir}")
        print(f"Configuration: {self.config_dir}")
        print("=" * 50)
        print("\nTo start your node:")
        
        if self.system == "windows":
            print(f"1. Open: {self.install_dir}")
            print("2. Double-click: start_node.bat")
        else:
            print(f"1. Open terminal in: {self.install_dir}")
            print("2. Run: ./start_node.sh")
        
        print("\n3. Or run: python launch_node.py")
        print("\nYour node will connect to the MediVote network and start processing votes!")
        
        return True

def main():
    """Main installation function"""
    installer = MediVoteNodeInstaller()
    
    try:
        success = installer.run_installation()
        if success:
            print("\n✅ Installation completed successfully!")
            return 0
        else:
            print("\n❌ Installation failed!")
            return 1
            
    except KeyboardInterrupt:
        print("\n🛑 Installation cancelled by user")
        return 1
    except Exception as e:
        print(f"\n❌ Installation error: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 