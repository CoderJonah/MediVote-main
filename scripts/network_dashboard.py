#!/usr/bin/env python3
"""
MediVote Network Dashboard
Real-time monitoring of the decentralized voting network

Provides a web interface to monitor network health, node status,
and voting statistics across the decentralized MediVote network.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import aiohttp
from aiohttp import web
import aiofiles
from pathlib import Path
import time
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class DashboardStats:
    """Dashboard statistics"""
    total_nodes: int = 0
    active_nodes: int = 0
    total_votes: int = 0
    total_elections: int = 0
    network_uptime: timedelta = timedelta(0)
    last_updated: datetime = None

class MediVoteNetworkDashboard:
    """Web dashboard for monitoring the MediVote network"""
    
    def __init__(self, config_path: str = "dashboard_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.stats = DashboardStats()
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.elections: Dict[str, Dict[str, Any]] = {}
        self.app = web.Application()
        self.is_running = False
        self.start_time = datetime.utcnow()
        
        # Security enhancements
        self.request_counts = defaultdict(int)
        self.last_request_reset = time.time()
        self.rate_limit_window = 60  # 1 minute
        self.max_requests_per_window = 200  # Higher limit for dashboard
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_dashboard.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config = self._load_config()
        
        # Setup static files first
        self._setup_static_files()
        
        # Setup routes
        self._setup_routes()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load dashboard configuration"""
        default_config = {
            "dashboard": {
                "name": "MediVote Network Dashboard",
                "port": 8080,
                "host": "0.0.0.0",
                "refresh_interval": 30,
                "max_nodes_display": 100
            },
            "network": {
                "coordinator_url": "http://localhost:8083",
                "bootstrap_nodes": [
                    "node1.medivote.net:8546",
                    "node2.medivote.net:8546",
                    "node3.medivote.net:8546"
                ]
            },
            "storage": {
                "data_dir": "./dashboard_data",
                "backup_interval": 3600
            },
            "security": {
                "trusted_ips": ["127.0.0.1", "localhost"]
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
            # Create default config
            with open(self.config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            return default_config
    
    def _setup_routes(self):
        """Setup web routes"""
        self.app.router.add_get('/', self._index_handler)
        self.app.router.add_get('/api/stats', self._stats_handler)
        self.app.router.add_get('/api/nodes', self._nodes_handler)
        self.app.router.add_get('/api/elections', self._elections_handler)
        self.app.router.add_get('/api/network', self._network_handler)
        self.app.router.add_post('/shutdown', self._shutdown_handler)
        
        # Setup static files if directory exists
        static_dir = Path("static")
        if static_dir.exists() and static_dir.is_dir():
            self.app.router.add_static('/static', path='static', name='static')
    
    def _setup_static_files(self):
        """Setup static files for the dashboard"""
        static_dir = Path("static")
        static_dir.mkdir(exist_ok=True)
        
        # Create CSS file
        css_file = static_dir / "style.css"
        if not css_file.exists():
            with open(css_file, 'w') as f:
                f.write("""
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    margin: 0;
    padding: 20px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: #333;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    border-radius: 10px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    overflow: hidden;
}

.header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 20px;
    text-align: center;
}

.header h1 {
    margin: 0;
    font-size: 2.5em;
    font-weight: 300;
}

.header p {
    margin: 10px 0 0 0;
    opacity: 0.9;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    padding: 20px;
}

.stat-card {
    background: white;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    text-align: center;
    border-left: 4px solid #667eea;
}

.stat-card h3 {
    margin: 0 0 10px 0;
    color: #667eea;
    font-size: 1.2em;
}

.stat-card .value {
    font-size: 2.5em;
    font-weight: bold;
    color: #333;
    margin: 10px 0;
}

.stat-card .label {
    color: #666;
    font-size: 0.9em;
}

.nodes-section {
    padding: 20px;
}

.nodes-section h2 {
    color: #333;
    margin-bottom: 20px;
}

.nodes-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 15px;
}

.node-card {
    background: white;
    border-radius: 8px;
    padding: 15px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    border-left: 4px solid #28a745;
}

.node-card.inactive {
    border-left-color: #dc3545;
}

.node-card h4 {
    margin: 0 0 10px 0;
    color: #333;
}

.node-card .status {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.8em;
    font-weight: bold;
}

.node-card .status.active {
    background: #d4edda;
    color: #155724;
}

.node-card .status.inactive {
    background: #f8d7da;
    color: #721c24;
}

.node-card .details {
    margin-top: 10px;
    font-size: 0.9em;
    color: #666;
}

.refresh-button {
    background: #667eea;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 1em;
    margin: 20px;
}

.refresh-button:hover {
    background: #5a6fd8;
}

.loading {
    text-align: center;
    padding: 40px;
    color: #666;
}

.error {
    background: #f8d7da;
    color: #721c24;
    padding: 15px;
    border-radius: 5px;
    margin: 20px;
}
""")
        
        # Create JavaScript file
        js_file = static_dir / "dashboard.js"
        if not js_file.exists():
            with open(js_file, 'w') as f:
                f.write("""
// Dashboard JavaScript
class MediVoteDashboard {
    constructor() {
        this.refreshInterval = 30000; // 30 seconds
        this.init();
    }
    
    init() {
        this.loadStats();
        this.loadNodes();
        this.loadElections();
        
        // Auto-refresh
        setInterval(() => {
            this.loadStats();
            this.loadNodes();
            this.loadElections();
        }, this.refreshInterval);
        
        // Manual refresh button
        document.getElementById('refresh-btn').addEventListener('click', () => {
            this.loadStats();
            this.loadNodes();
            this.loadElections();
        });
    }
    
    async loadStats() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            this.updateStats(stats);
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }
    
    async loadNodes() {
        try {
            const response = await fetch('/api/nodes');
            const nodes = await response.json();
            this.updateNodes(nodes);
        } catch (error) {
            console.error('Failed to load nodes:', error);
        }
    }
    
    async loadElections() {
        try {
            const response = await fetch('/api/elections');
            const elections = await response.json();
            this.updateElections(elections);
        } catch (error) {
            console.error('Failed to load elections:', error);
        }
    }
    
    updateStats(stats) {
        document.getElementById('total-nodes').textContent = stats.total_nodes;
        document.getElementById('active-nodes').textContent = stats.active_nodes;
        document.getElementById('total-votes').textContent = stats.total_votes;
        document.getElementById('total-elections').textContent = stats.total_elections;
        document.getElementById('network-uptime').textContent = stats.network_uptime;
        document.getElementById('last-updated').textContent = new Date(stats.last_updated).toLocaleString();
    }
    
    updateNodes(nodes) {
        const container = document.getElementById('nodes-container');
        container.innerHTML = '';
        
        nodes.forEach(node => {
            const nodeCard = document.createElement('div');
            nodeCard.className = `node-card ${node.is_active ? 'active' : 'inactive'}`;
            
            nodeCard.innerHTML = `
                <h4>${node.node_id}</h4>
                <span class="status ${node.is_active ? 'active' : 'inactive'}">
                    ${node.is_active ? 'Active' : 'Inactive'}
                </span>
                <div class="details">
                    <div>Address: ${node.address}:${node.port}</div>
                    <div>Type: ${node.node_type}</div>
                    <div>Votes: ${node.votes_processed}</div>
                    <div>Blocks: ${node.blocks_processed}</div>
                    <div>Last Seen: ${new Date(node.last_seen).toLocaleString()}</div>
                </div>
            `;
            
            container.appendChild(nodeCard);
        });
    }
    
    updateElections(elections) {
        const container = document.getElementById('elections-container');
        container.innerHTML = '';
        
        elections.forEach(election => {
            const electionCard = document.createElement('div');
            electionCard.className = 'node-card';
            
            electionCard.innerHTML = `
                <h4>${election.election_id}</h4>
                <div class="details">
                    <div>Status: ${election.status}</div>
                    <div>Total Votes: ${election.total_votes}</div>
                    <div>Start Date: ${new Date(election.start_date).toLocaleDateString()}</div>
                    <div>End Date: ${new Date(election.end_date).toLocaleDateString()}</div>
                </div>
            `;
            
            container.appendChild(electionCard);
        });
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    new MediVoteDashboard();
});
""")
    
    async def _index_handler(self, request):
        """Handle main dashboard page"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.config['dashboard']['name']}</title>
                    <link rel="stylesheet" href="/src/shared/static/style.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 MediVote Network Dashboard</h1>
            <p>Real-time monitoring of the decentralized voting network</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Nodes</h3>
                <div class="value" id="total-nodes">-</div>
                <div class="label">Network participants</div>
            </div>
            
            <div class="stat-card">
                <h3>Active Nodes</h3>
                <div class="value" id="active-nodes">-</div>
                <div class="label">Currently online</div>
            </div>
            
            <div class="stat-card">
                <h3>Total Votes</h3>
                <div class="value" id="total-votes">-</div>
                <div class="label">Processed votes</div>
            </div>
            
            <div class="stat-card">
                <h3>Total Elections</h3>
                <div class="value" id="total-elections">-</div>
                <div class="label">Active elections</div>
            </div>
            
            <div class="stat-card">
                <h3>Network Uptime</h3>
                <div class="value" id="network-uptime">-</div>
                <div class="label">Time online</div>
            </div>
            
            <div class="stat-card">
                <h3>Last Updated</h3>
                <div class="value" id="last-updated">-</div>
                <div class="label">Data freshness</div>
            </div>
        </div>
        
        <button class="refresh-button" id="refresh-btn">🔄 Refresh Data</button>
        
        <div class="nodes-section">
            <h2>🌐 Network Nodes</h2>
            <div class="nodes-grid" id="nodes-container">
                <div class="loading">Loading nodes...</div>
            </div>
        </div>
        
        <div class="nodes-section">
            <h2>🗳️ Active Elections</h2>
            <div class="nodes-grid" id="elections-container">
                <div class="loading">Loading elections...</div>
            </div>
        </div>
    </div>
    
                    <script src="/src/shared/static/dashboard.js"></script>
</body>
</html>
"""
        return web.Response(text=html, content_type='text/html')
    
    def _format_uptime(self, uptime: timedelta) -> str:
        """Format uptime without microseconds"""
        total_seconds = int(uptime.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client has exceeded rate limit"""
        current_time = time.time()
        
        # Reset counters if window has passed
        if current_time - self.last_request_reset > self.rate_limit_window:
            self.request_counts.clear()
            self.last_request_reset = current_time
        
        # Check rate limit
        if self.request_counts[client_ip] >= self.max_requests_per_window:
            self.logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return False
        
        self.request_counts[client_ip] += 1
        return True

    def _log_security_event(self, event_type: str, client_ip: str, details: str = ""):
        """Log security events for monitoring"""
        self.logger.info(f"SECURITY_EVENT: {event_type} from {client_ip} - {details}")

    def _is_trusted_client(self, client_ip: str) -> bool:
        """Check if client is trusted (internal network)"""
        trusted_ips = self.config.get("security", {}).get("trusted_ips", ["127.0.0.1", "localhost"])
        return client_ip in trusted_ips or client_ip.startswith("192.168.") or client_ip.startswith("10.")

    def _sanitize_node_data(self, node_data: Dict[str, Any], is_trusted: bool) -> Dict[str, Any]:
        """Sanitize node data based on client trust level"""
        if is_trusted:
            return node_data
        else:
            # For untrusted clients, only show basic info
            return {
                "node_id": node_data.get("node_id", ""),
                "node_type": node_data.get("node_type", "full_node"),
                "is_active": node_data.get("is_active", False),
                "votes_processed": node_data.get("votes_processed", 0),
                "blocks_processed": node_data.get("blocks_processed", 0),
                "version": node_data.get("version", "1.0.0")
                # Note: address and port are excluded for untrusted clients
            }

    async def _stats_handler(self, request):
        """Handle stats API endpoint with security"""
        client_ip = request.remote
        
        # Security: Rate limiting
        if not self._check_rate_limit(client_ip):
            self._log_security_event("RATE_LIMIT_EXCEEDED", client_ip)
            return web.json_response({"error": "Rate limit exceeded"}, status=429)
        
        # Security: Log access
        self._log_security_event("API_ACCESS", client_ip, "stats endpoint")
        
        try:
            # Update stats from network
            await self._update_stats()
            
            stats_data = {
                "total_nodes": self.stats.total_nodes,
                "active_nodes": self.stats.active_nodes,
                "total_votes": self.stats.total_votes,
                "total_elections": self.stats.total_elections,
                "network_uptime": self._format_uptime(self.stats.network_uptime),
                "last_updated": self.stats.last_updated.isoformat() if self.stats.last_updated else None
            }
            
            return web.json_response(stats_data)
            
        except Exception as e:
            self.logger.error(f"Stats handler error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _nodes_handler(self, request):
        """Handle nodes API endpoint with security"""
        client_ip = request.remote
        is_trusted = self._is_trusted_client(client_ip)
        
        # Security: Rate limiting
        if not self._check_rate_limit(client_ip):
            self._log_security_event("RATE_LIMIT_EXCEEDED", client_ip)
            return web.json_response({"error": "Rate limit exceeded"}, status=429)
        
        # Security: Log access
        self._log_security_event("API_ACCESS", client_ip, f"nodes endpoint (trusted: {is_trusted})")
        
        try:
            # Update nodes from network
            await self._update_nodes()
            
            nodes_data = []
            for node_id, node in self.nodes.items():
                sanitized_node = self._sanitize_node_data(node, is_trusted)
                nodes_data.append(sanitized_node)
            
            return web.json_response(nodes_data)
            
        except Exception as e:
            self.logger.error(f"Nodes handler error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _elections_handler(self, request):
        """Handle elections API endpoint"""
        try:
            # Update elections from network
            await self._update_elections()
            
            elections_data = []
            for election_id, election in self.elections.items():
                elections_data.append({
                    "election_id": election_id,
                    "name": election.get("name", ""),
                    "status": election.get("status", "unknown"),
                    "total_votes": election.get("total_votes", 0),
                    "start_date": election.get("start_date", ""),
                    "end_date": election.get("end_date", "")
                })
            
            return web.json_response(elections_data)
            
        except Exception as e:
            logger.error(f"Elections handler error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _network_handler(self, request):
        """Handle network API endpoint"""
        try:
            network_data = {
                "network_name": self.config["dashboard"]["name"],
                "is_running": self.is_running,
                "start_time": self.start_time.isoformat(),
                "config": self.config
            }
            
            return web.json_response(network_data)
            
        except Exception as e:
            logger.error(f"Network handler error: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def _shutdown_handler(self, request):
        """Handle graceful shutdown requests"""
        try:
            # Security: Only allow shutdown from localhost (service manager)
            client_ip = request.remote
            if client_ip not in ["127.0.0.1", "localhost", "::1"]:
                logger.warning(f"Unauthorized shutdown attempt from {client_ip}")
                return web.json_response({"error": "Unauthorized"}, status=403)
            
            logger.info("Shutdown request received via HTTP endpoint")
            
            # Immediate response to confirm shutdown initiation
            response_data = {
                "message": "Network dashboard graceful shutdown initiated",
                "status": "shutting_down",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Send response immediately
            response = web.json_response(response_data, status=200)
            
            # Schedule shutdown after response is sent
            async def delayed_shutdown():
                await asyncio.sleep(0.3)  # Brief delay to ensure response is sent
                logger.info("Executing graceful shutdown...")
                self.is_running = False
                # Signal shutdown
                import os
                import signal
                os.kill(os.getpid(), signal.SIGTERM)
            
            # Schedule shutdown
            asyncio.create_task(delayed_shutdown())
            
            return response
            
        except Exception as e:
            logger.error(f"Shutdown handler error: {e}")
            return web.json_response({"error": "Shutdown failed", "details": str(e)}, status=500)
    
    async def _update_stats(self):
        """Update dashboard statistics"""
        try:
            # Get data from network coordinator
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.config['network']['coordinator_url']}/") as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        self.stats.total_nodes = data.get("stats", {}).get("total_nodes", 0)
                        self.stats.active_nodes = data.get("stats", {}).get("active_nodes", 0)
                        self.stats.total_votes = data.get("stats", {}).get("total_votes_processed", 0)
                        self.stats.total_elections = len(self.elections)
                        self.stats.network_uptime = datetime.utcnow() - self.start_time
                        self.stats.last_updated = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Failed to update stats: {e}")
    
    async def _update_nodes(self):
        """Update nodes data"""
        try:
            # Get nodes from network coordinator
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.config['network']['coordinator_url']}/") as response:
                    if response.status == 200:
                        data = await response.json()
                        self.nodes = {node["node_id"]: node for node in data.get("nodes", [])}
            
        except Exception as e:
            logger.error(f"Failed to update nodes: {e}")
    
    async def _update_elections(self):
        """Update elections data"""
        try:
            # Get elections from network
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.config['network']['coordinator_url']}/elections") as response:
                    if response.status == 200:
                        data = await response.json()
                        self.elections = {election["election_id"]: election for election in data.get("elections", [])}
            
        except Exception as e:
            logger.error(f"Failed to update elections: {e}")
    
    async def start(self):
        """Start the dashboard"""
        try:
            logger.info("Starting MediVote Network Dashboard...")
            
            # Create data directory
            data_dir = Path(self.config["storage"]["data_dir"])
            data_dir.mkdir(exist_ok=True)
            
            # Start web server
            runner = web.AppRunner(self.app)
            await runner.setup()
            
            site = web.TCPSite(
                runner,
                self.config["dashboard"]["host"],
                self.config["dashboard"]["port"]
            )
            
            await site.start()
            
            self.is_running = True
            logger.info(f"Dashboard started on http://{self.config['dashboard']['host']}:{self.config['dashboard']['port']}")
            
            # Keep running
            while True:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Failed to start dashboard: {e}")
            return False
    
    async def stop(self):
        """Stop the dashboard"""
        logger.info("Stopping MediVote Network Dashboard...")
        self.is_running = False

async def main():
    """Main function to run the dashboard"""
    print("MediVote Network Dashboard")
    print("=" * 50)
    print("Real-time network monitoring")
    print("Monitor the decentralized voting network")
    print("=" * 50)
    
    # Create and start the dashboard
    dashboard = MediVoteNetworkDashboard()
    
    try:
        # Start the dashboard
        if await dashboard.start():
            print("Dashboard started successfully!")
            print(f"URL: http://localhost:{dashboard.config['dashboard']['port']}")
            print("\nPress Ctrl+C to stop the dashboard")
            
            # Keep the dashboard running
            while True:
                await asyncio.sleep(1)
                
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