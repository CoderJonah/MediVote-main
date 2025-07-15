#!/usr/bin/env python3
"""
MediVote Decentralized Network Demo
Demonstrates the decentralized voting network with multiple nodes

This script shows how users can download and run nodes to participate
in the MediVote network, making it more powerful and decentralized.
"""

import asyncio
import json
import logging
import os
import sys
import time
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DecentralizedNetworkDemo:
    """Demo of the decentralized MediVote network"""
    
    def __init__(self):
        self.nodes: Dict[str, subprocess.Popen] = {}
        self.coordinator: Optional[subprocess.Popen] = None
        self.dashboard: Optional[subprocess.Popen] = None
        self.is_running = False
        
    def print_banner(self):
        """Print demo banner"""
        print("🌐 MediVote Decentralized Network Demo")
        print("=" * 60)
        print("Demonstrating decentralized voting network")
        print("Multiple nodes working together for secure voting")
        print("=" * 60)
    
    async def start_network_coordinator(self):
        """Start the network coordinator"""
        print("🌐 Starting Network Coordinator...")
        
        try:
            self.coordinator = subprocess.Popen([
                sys.executable, "network_coordinator.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a moment for startup
            await asyncio.sleep(3)
            
            if self.coordinator.poll() is None:
                print("✅ Network Coordinator started")
                return True
            else:
                print("❌ Failed to start Network Coordinator")
                return False
                
        except Exception as e:
            print(f"❌ Error starting Network Coordinator: {e}")
            return False
    
    async def start_network_dashboard(self):
        """Start the network dashboard"""
        print("📊 Starting Network Dashboard...")
        
        try:
            self.dashboard = subprocess.Popen([
                sys.executable, "network_dashboard.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a moment for startup
            await asyncio.sleep(3)
            
            if self.dashboard.poll() is None:
                print("✅ Network Dashboard started")
                print("🌐 Dashboard URL: http://localhost:8080")
                return True
            else:
                print("❌ Failed to start Network Dashboard")
                return False
                
        except Exception as e:
            print(f"❌ Error starting Network Dashboard: {e}")
            return False
    
    async def start_blockchain_nodes(self, num_nodes: int = 3):
        """Start multiple blockchain nodes"""
        print(f"🚀 Starting {num_nodes} Blockchain Nodes...")
        
        for i in range(num_nodes):
            node_id = f"demo_node_{i+1}"
            port = 8545 + i
            rpc_port = 8546 + i
            
            print(f"Starting {node_id} on port {port}...")
            
            try:
                # Create node configuration
                node_config = {
                    "node": {
                        "name": f"Demo Node {i+1}",
                        "port": port,
                        "rpc_port": rpc_port,
                        "max_peers": 10,
                        "sync_interval": 15,
                        "block_time": 10
                    },
                    "network": {
                        "bootstrap_nodes": [
                            "localhost:8545",
                            "localhost:8546",
                            "localhost:8547"
                        ],
                        "network_id": "medivote_demo",
                        "genesis_block": "0x0000000000000000000000000000000000000000000000000000000000000000"
                    },
                    "blockchain": {
                        "rpc_url": f"http://localhost:{port}",
                        "private_key": None,
                        "gas_limit": 3000000,
                        "gas_price": "20 gwei"
                    },
                    "storage": {
                        "data_dir": f"./blockchain_data_{i+1}",
                        "backup_interval": 3600,
                        "max_storage_gb": 1
                    }
                }
                
                # Save node configuration
                config_file = f"node_config_{i+1}.json"
                with open(config_file, 'w') as f:
                    json.dump(node_config, f, indent=2)
                
                # Start node process
                node_process = subprocess.Popen([
                    sys.executable, "blockchain_node.py"
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.nodes[node_id] = node_process
                
                # Wait a moment for startup
                await asyncio.sleep(2)
                
                if node_process.poll() is None:
                    print(f"✅ {node_id} started successfully")
                else:
                    print(f"❌ Failed to start {node_id}")
                
            except Exception as e:
                print(f"❌ Error starting {node_id}: {e}")
        
        print(f"✅ Started {len(self.nodes)} blockchain nodes")
    
    async def simulate_voting_activity(self):
        """Simulate voting activity across the network"""
        print("🗳️  Simulating Voting Activity...")
        
        # Simulate election creation
        print("📝 Creating demo election...")
        await asyncio.sleep(2)
        
        # Simulate vote submissions
        for i in range(5):
            print(f"🗳️  Processing vote {i+1}/5...")
            await asyncio.sleep(1)
        
        print("✅ Voting simulation completed")
    
    async def show_network_statistics(self):
        """Show network statistics"""
        print("\n📊 Network Statistics:")
        print("=" * 40)
        print(f"Active Nodes: {len(self.nodes)}")
        print(f"Network Coordinator: {'✅ Running' if self.coordinator and self.coordinator.poll() is None else '❌ Stopped'}")
        print(f"Network Dashboard: {'✅ Running' if self.dashboard and self.dashboard.poll() is None else '❌ Stopped'}")
        print(f"Demo Duration: {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 40)
    
    async def demonstrate_node_installer(self):
        """Demonstrate the node installer"""
        print("\n📦 Node Installer Demo:")
        print("=" * 40)
        print("Users can download and run the node installer to join the network:")
        print()
        print("1. Download installer:")
        print("   wget https://github.com/medivote/network/releases/latest/download/node_installer.py")
        print()
        print("2. Run installer:")
        print("   python node_installer.py")
        print()
        print("3. Start node:")
        print("   cd ~/MediVote")
        print("   python launch_node.py")
        print()
        print("This makes the network more decentralized and powerful!")
        print("=" * 40)
    
    async def run_demo(self):
        """Run the complete demo"""
        self.print_banner()
        
        try:
            # Start network coordinator
            if not await self.start_network_coordinator():
                return False
            
            # Start network dashboard
            if not await self.start_network_dashboard():
                return False
            
            # Start blockchain nodes
            await self.start_blockchain_nodes(3)
            
            # Show initial statistics
            await self.show_network_statistics()
            
            # Demonstrate voting activity
            await self.simulate_voting_activity()
            
            # Show updated statistics
            await self.show_network_statistics()
            
            # Demonstrate node installer
            await self.demonstrate_node_installer()
            
            print("\n🎉 Demo completed successfully!")
            print("=" * 60)
            print("What you've seen:")
            print("✅ Decentralized network with multiple nodes")
            print("✅ Network coordination and discovery")
            print("✅ Real-time dashboard monitoring")
            print("✅ Simulated voting activity")
            print("✅ Easy node installation process")
            print("=" * 60)
            print("\nThe network is now more powerful and decentralized!")
            print("Users can download and run nodes to participate.")
            
            return True
            
        except Exception as e:
            print(f"❌ Demo error: {e}")
            return False
    
    async def cleanup(self):
        """Clean up demo processes"""
        print("\n🧹 Cleaning up demo processes...")
        
        # Stop nodes
        for node_id, process in self.nodes.items():
            if process.poll() is None:
                process.terminate()
                print(f"🛑 Stopped {node_id}")
        
        # Stop coordinator
        if self.coordinator and self.coordinator.poll() is None:
            self.coordinator.terminate()
            print("🛑 Stopped Network Coordinator")
        
        # Stop dashboard
        if self.dashboard and self.dashboard.poll() is None:
            self.dashboard.terminate()
            print("🛑 Stopped Network Dashboard")
        
        # Clean up config files
        for i in range(3):
            config_file = f"node_config_{i+1}.json"
            if os.path.exists(config_file):
                os.remove(config_file)
                print(f"🗑️  Removed {config_file}")
        
        print("✅ Cleanup completed")

async def main():
    """Main demo function"""
    demo = DecentralizedNetworkDemo()
    
    try:
        # Run the demo
        success = await demo.run_demo()
        
        if success:
            print("\n✅ Demo completed successfully!")
            print("Press Enter to clean up and exit...")
            input()
        else:
            print("\n❌ Demo failed!")
        
    except KeyboardInterrupt:
        print("\n🛑 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
    finally:
        # Clean up
        await demo.cleanup()
        print("\n👋 Demo finished!")

if __name__ == "__main__":
    asyncio.run(main()) 