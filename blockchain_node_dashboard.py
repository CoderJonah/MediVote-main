#!/usr/bin/env python3
"""
Blockchain Node Dashboard
Dedicated dashboard for managing and monitoring blockchain nodes
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp
from aiohttp import web
import webbrowser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('blockchain_dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class NodeStats:
    """Blockchain node statistics"""
    node_id: str = ""
    version: str = "1.0.0"
    network_id: str = "medivote_mainnet"
    node_type: str = "full_node"
    is_active: bool = False
    peers_connected: int = 0
    blocks_processed: int = 0
    votes_processed: int = 0
    last_sync: Optional[datetime] = None
    uptime: timedelta = timedelta(0)
    credibility_points: int = 0
    reputation_score: float = 0.0

class BlockchainNodeDashboard:
    """Dashboard for blockchain node management"""
    
    def __init__(self, config_path: str = "node_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.stats = NodeStats()
        self.peers: List[Dict[str, Any]] = []
        self.blocks: List[Dict[str, Any]] = []
        self.is_running = False
        self.dashboard_port = 8093
        self.node_port = 8546
        
    def _load_config(self) -> Dict[str, Any]:
        """Load dashboard configuration"""
        default_config = {
            "dashboard": {
                "name": "Blockchain Node Dashboard",
                "port": 8093,
                "host": "0.0.0.0",
                "refresh_interval": 10,
                "node_url": "http://localhost:8546"
            },
            "security": {
                "enable_shutdown": True,
                "require_confirmation": True,
                "credibility_warning": True
            }
        }
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                return default_config
        else:
            return default_config
    
    async def start(self):
        """Start the blockchain node dashboard"""
        try:
            logger.info("Starting Blockchain Node Dashboard...")
            
            # Setup routes
            app = web.Application()
            
            app.router.add_get('/', self._index_handler)
            app.router.add_get('/api/status', self._status_handler)
            app.router.add_get('/api/peers', self._peers_handler)
            app.router.add_get('/api/blocks', self._blocks_handler)
            app.router.add_post('/api/shutdown', self._shutdown_handler)
            app.router.add_post('/api/restart', self._restart_handler)
            
            # Setup static files
            self._setup_static_files(app)
            
            # Start server
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, '0.0.0.0', self.dashboard_port)
            await site.start()
            
            self.is_running = True
            logger.info(f"Blockchain Node Dashboard started on port {self.dashboard_port}")
            
            # Start background tasks
            asyncio.create_task(self._update_loop())
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start dashboard: {e}")
            return False
    
    def _setup_static_files(self, app):
        """Setup static file serving"""
        async def static_handler(request):
            path = request.match_info['path']
            file_path = Path(f"static/{path}")
            
            if file_path.exists() and file_path.is_file():
                return web.FileResponse(file_path)
            else:
                return web.Response(text="File not found", status=404)
        
        app.router.add_get('/static/{path:.*}', static_handler)
    
    async def _update_loop(self):
        """Background update loop"""
        while self.is_running:
            try:
                await self._update_node_status()
                await self._update_peers()
                await self._update_blocks()
                await asyncio.sleep(self.config['dashboard']['refresh_interval'])
            except Exception as e:
                logger.error(f"Update loop error: {e}")
                await asyncio.sleep(10)
    
    async def _update_node_status(self):
        """Update node status from blockchain node"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.config['dashboard']['node_url']}/status") as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        self.stats.node_id = data.get("node_id", "")
                        self.stats.version = data.get("version", "1.0.0")
                        self.stats.network_id = data.get("network_id", "medivote_mainnet")
                        self.stats.node_type = data.get("node_type", "full_node")
                        self.stats.is_active = data.get("is_active", False)
                        self.stats.peers_connected = data.get("peers_connected", 0)
                        self.stats.blocks_processed = data.get("blocks_processed", 0)
                        self.stats.votes_processed = data.get("votes_processed", 0)
                        
                        # Calculate uptime
                        if data.get("start_time"):
                            start_time = datetime.fromisoformat(data["start_time"])
                            self.stats.uptime = datetime.utcnow() - start_time
                        
                        # Mock credibility points (in real system, this would come from incentive system)
                        self.stats.credibility_points = self.stats.blocks_processed * 10
                        self.stats.reputation_score = min(100.0, self.stats.credibility_points / 100.0)
                        
        except Exception as e:
            logger.error(f"Failed to update node status: {e}")
    
    async def _update_peers(self):
        """Update peers list from blockchain node"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.config['dashboard']['node_url']}/peers") as response:
                    if response.status == 200:
                        self.peers = await response.json()
        except Exception as e:
            logger.error(f"Failed to update peers: {e}")
    
    async def _update_blocks(self):
        """Update blocks information"""
        # Mock blocks data for now
        self.blocks = [
            {
                "block_number": i,
                "hash": f"0x{hash(f'block_{i}') % 1000000:06x}",
                "timestamp": (datetime.utcnow() - timedelta(minutes=i)).isoformat(),
                "transactions": i * 5,
                "votes": i * 3
            }
            for i in range(1, 11)
        ]
    
    async def _index_handler(self, request):
        """Handle main dashboard page"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.config['dashboard']['name']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .stat-card h3 {{ color: #333; margin-bottom: 15px; font-size: 1.2em; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #667eea; margin-bottom: 5px; }}
        .stat-label {{ color: #666; font-size: 0.9em; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .danger {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .btn {{ padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 1em; margin: 5px; }}
        .btn-primary {{ background: #667eea; color: white; }}
        .btn-danger {{ background: #dc3545; color: white; }}
        .btn:hover {{ opacity: 0.8; }}
        .section {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .section h2 {{ color: #333; margin-bottom: 20px; }}
        .peer-item {{ padding: 10px; border-bottom: 1px solid #eee; }}
        .peer-item:last-child {{ border-bottom: none; }}
        .status-active {{ color: #28a745; }}
        .status-inactive {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Blockchain Node Dashboard</h1>
            <p>Monitor and manage your MediVote blockchain node</p>
            <p style="font-size: 0.9em; opacity: 0.8;">For a truly decentralized network, run nodes on separate machines</p>
        </div>
        
        <div class="warning">
            <strong>Credibility Warning:</strong> Shutting down this node will result in loss of credibility points and network participation rewards. 
            Keep your node running to maintain network participation and earn rewards.
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Node Status</h3>
                <div class="stat-value" id="node-status">-</div>
                <div class="stat-label">Current status</div>
            </div>
            
            <div class="stat-card">
                <h3>Credibility Points</h3>
                <div class="stat-value" id="credibility-points">-</div>
                <div class="stat-label">Accumulated points</div>
            </div>
            
            <div class="stat-card">
                <h3>Reputation Score</h3>
                <div class="stat-value" id="reputation-score">-</div>
                <div class="stat-label">Network trust level</div>
            </div>
            
            <div class="stat-card">
                <h3>Connected Peers</h3>
                <div class="stat-value" id="connected-peers">-</div>
                <div class="stat-label">Active connections</div>
            </div>
            
            <div class="stat-card">
                <h3>Blocks Processed</h3>
                <div class="stat-value" id="blocks-processed">-</div>
                <div class="stat-label">Total blocks</div>
            </div>
            
            <div class="stat-card">
                <h3>Votes Processed</h3>
                <div class="stat-value" id="votes-processed">-</div>
                <div class="stat-label">Total votes</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Node Management</h2>
            <button class="btn btn-primary" onclick="refreshData()">Refresh Data</button>
            <button class="btn btn-danger" onclick="confirmShutdown()">Shutdown Node</button>
            <button class="btn btn-primary" onclick="restartNode()">Restart Node</button>
        </div>
        
        <div class="section">
            <h2>🌐 Connected Peers</h2>
            <div id="peers-container">
                <div class="loading">Loading peers...</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📦 Recent Blocks</h2>
            <div id="blocks-container">
                <div class="loading">Loading blocks...</div>
            </div>
        </div>
    </div>
    
    <script>
        async function refreshData() {{
            try {{
                const response = await fetch('/api/status');
                const data = await response.json();
                updateStats(data);
            }} catch (error) {{
                console.error('Error refreshing data:', error);
            }}
        }}
        
        async function confirmShutdown() {{
            const warning = `CREDIBILITY LOSS WARNING\\n\\n` +
                          `Shutting down this node will result in:\\n` +
                          `• Loss of accumulated credibility points\\n` +
                          `• Disconnection from the MediVote network\\n` +
                          `• Need to re-establish trust when restarting\\n` +
                          `• Loss of potential rewards and incentives\\n\\n` +
                          `Are you sure you want to continue?`;
            
            if (confirm(warning)) {{
                await shutdownNode();
            }}
        }}
        
        async function shutdownNode() {{
            try {{
                const response = await fetch('/api/shutdown', {{ method: 'POST' }});
                const result = await response.json();
                alert(result.message || 'Shutdown initiated');
            }} catch (error) {{
                console.error('Error shutting down node:', error);
                alert('Failed to shutdown node');
            }}
        }}
        
        async function restartNode() {{
            try {{
                const response = await fetch('/api/restart', {{ method: 'POST' }});
                const result = await response.json();
                alert(result.message || 'Restart initiated');
            }} catch (error) {{
                console.error('Error restarting node:', error);
                alert('Failed to restart node');
            }}
        }}
        
        function updateStats(data) {{
            document.getElementById('node-status').textContent = data.is_active ? 'Active' : 'Inactive';
            document.getElementById('credibility-points').textContent = data.credibility_points || 0;
            document.getElementById('reputation-score').textContent = (data.reputation_score || 0).toFixed(1) + '%';
            document.getElementById('connected-peers').textContent = data.peers_connected || 0;
            document.getElementById('blocks-processed').textContent = data.blocks_processed || 0;
            document.getElementById('votes-processed').textContent = data.votes_processed || 0;
        }}
        
        // Auto-refresh every 10 seconds
        setInterval(refreshData, 10000);
        
        // Initial load
        refreshData();
    </script>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')
    
    async def _status_handler(self, request):
        """Handle status API endpoint"""
        try:
            return web.json_response(asdict(self.stats))
        except Exception as e:
            logger.error(f"Status handler error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _peers_handler(self, request):
        """Handle peers API endpoint"""
        try:
            return web.json_response(self.peers)
        except Exception as e:
            logger.error(f"Peers handler error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _blocks_handler(self, request):
        """Handle blocks API endpoint"""
        try:
            return web.json_response(self.blocks)
        except Exception as e:
            logger.error(f"Blocks handler error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _shutdown_handler(self, request):
        """Handle shutdown API endpoint"""
        try:
            # Forward shutdown request to blockchain node
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.config['dashboard']['node_url']}/shutdown") as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.warning("Node shutdown requested via dashboard")
                        return web.json_response(result)
                    else:
                        return web.json_response({"error": "Failed to shutdown node"}, status=500)
        except Exception as e:
            logger.error(f"Shutdown handler error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _restart_handler(self, request):
        """Handle restart API endpoint"""
        try:
            # For now, just return success (restart would be handled by service manager)
            return web.json_response({"message": "Restart request sent to service manager"})
        except Exception as e:
            logger.error(f"Restart handler error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def stop(self):
        """Stop the dashboard"""
        logger.info("Stopping Blockchain Node Dashboard...")
        self.is_running = False

async def main():
    """Main function"""
    print("Blockchain Node Dashboard")
    print("=" * 50)
    print("Dedicated dashboard for blockchain node management")
    print("=" * 50)
    
    dashboard = BlockchainNodeDashboard()
    
    try:
        if await dashboard.start():
            print("Dashboard started successfully!")
            print(f"Dashboard URL: http://localhost:{dashboard.dashboard_port}")
            print("\nPress Ctrl+C to stop the dashboard")
            
            # Keep running
            await asyncio.Event().wait()
            
        else:
            print("Failed to start dashboard")
            return 1
            
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
        await dashboard.stop()
        print("Dashboard stopped")
        return 0
        
    except Exception as e:
        print(f"Error running dashboard: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 