#!/usr/bin/env python3
"""
MediVote Background Startup Script
Runs all MediVote services in the background with individual dashboards
"""

import asyncio
import json
import logging
import os
import sys
import time
import subprocess
import threading
import webbrowser
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import signal
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('medivote_background.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MediVoteBackgroundManager:
    """Manages all MediVote services running in background"""
    
    def __init__(self):
        self.services: Dict[str, Dict[str, Any]] = {}
        self.processes: Dict[str, subprocess.Popen] = {}
        self.is_running = False
        
        # Service configurations with unique ports
        self.service_configs = {
            "backend": {
                "name": "MediVote Backend",
                "script": "backend/main.py",
                "port": 8001,
                "dashboard_port": 8091,
                "log_file": "logs/backend.log",
                "auto_restart": True,
                "startup_delay": 3
            },
            "blockchain_node_1": {
                "name": "Blockchain Node 1",
                "script": "blockchain_node.py",
                "port": 8546,
                "dashboard_port": 8093,
                "log_file": "blockchain_node_1.log",
                "auto_restart": True,
                "startup_delay": 2,
                "config_file": "node_config_1.json"
            },
            "blockchain_node_2": {
                "name": "Blockchain Node 2", 
                "script": "blockchain_node.py",
                "port": 8547,
                "dashboard_port": 8094,
                "log_file": "blockchain_node_2.log",
                "auto_restart": True,
                "startup_delay": 2,
                "config_file": "node_config_2.json"
            },
            "incentive_system": {
                "name": "Node Incentive System",
                "script": "node_incentive_system.py",
                "port": 8082,
                "dashboard_port": 8095,
                "log_file": "node_incentive.log",
                "auto_restart": True,
                "startup_delay": 2
            },
            "network_coordinator": {
                "name": "Network Coordinator",
                "script": "network_coordinator.py",
                "port": 8083,
                "dashboard_port": 8096,
                "log_file": "network_coordinator.log",
                "auto_restart": True,
                "startup_delay": 2
            },
            "network_dashboard": {
                "name": "Network Dashboard",
                "script": "network_dashboard.py",
                "port": 8084,
                "log_file": "network_dashboard.log",
                "auto_restart": True,
                "startup_delay": 2
            },
            "frontend": {
                "name": "MediVote Frontend",
                "script": "frontend/serve.py",
                "port": 8080,
                "dashboard_port": 8098,
                "log_file": "logs/frontend.log",
                "auto_restart": True,
                "startup_delay": 3
            }
        }
        
        # Credibility warnings
        self.credibility_warnings = {
            "blockchain_node_1": "WARNING: Shutting down this node will result in loss of credibility points and network participation rewards.",
            "blockchain_node_2": "WARNING: Shutting down this node will result in loss of credibility points and network participation rewards.",
            "incentive_system": "WARNING: Shutting down the incentive system will stop reward distribution and node reputation tracking.",
            "network_coordinator": "WARNING: Shutting down the coordinator will affect network discovery and node communication.",
            "backend": "WARNING: Shutting down the backend will disable voting functionality and API access.",
            "frontend": "WARNING: Shutting down the frontend will disable web interface access."
        }
    
    def _create_node_configs(self):
        """Create unique node configurations to avoid port conflicts"""
        for i in range(1, 3):
            config = {
                "node": {
                    "name": f"MediVote Node {i}",
                    "port": 8545 + i,
                    "rpc_port": 8546 + i,
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
                    "rpc_url": f"http://localhost:{8546 + i}",
                    "private_key": None,
                    "gas_limit": 3000000,
                    "gas_price": "20 gwei"
                },
                "storage": {
                    "data_dir": f"./blockchain_data_{i}",
                    "backup_interval": 3600,
                    "max_storage_gb": 10
                }
            }
            
            config_file = f"node_config_{i}.json"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Created node configuration: {config_file}")
    
    async def start_all_services(self):
        """Start all services in background"""
        logger.info("Starting all MediVote services in background...")
        
        # Create unique node configurations
        self._create_node_configs()
        
        # Start services in order
        startup_order = [
            "backend",
            "blockchain_node_1", 
            "blockchain_node_2",
            "incentive_system",
            "network_coordinator",
            "network_dashboard",
            "frontend"
        ]
        
        for service_id in startup_order:
            if service_id in self.service_configs:
                await self.start_service(service_id)
                await asyncio.sleep(self.service_configs[service_id]["startup_delay"])
        
        # Start dashboard servers for each service
        await self.start_dashboard_servers()
        
        # Open management dashboard
        await self.open_management_dashboard()
        
        logger.info("All services started successfully!")
        return True
    
    async def start_service(self, service_id: str) -> bool:
        """Start a specific service in background"""
        if service_id not in self.service_configs:
            logger.error(f"Unknown service: {service_id}")
            return False
        
        config = self.service_configs[service_id]
        
        if service_id in self.processes and self.processes[service_id].poll() is None:
            logger.info(f"Service {service_id} is already running")
            return True
        
        try:
            logger.info(f"Starting {config['name']}...")
            
            # Prepare command
            cmd = [sys.executable, config["script"]]
            
            # Add config file if specified
            if "config_file" in config:
                cmd.extend(["--config", config["config_file"]])

            # Set working directory for backend and frontend
            cwd = None
            script_path = config["script"]
            if service_id == "backend":
                cwd = "backend"
                script_path = "main.py"
            elif service_id == "frontend":
                cwd = "frontend"
                script_path = "serve.py"

            # Open log file for both stdout and stderr
            log_file = open(config["log_file"], "a")

            # Start process in background, redirecting stdout and stderr
            process = subprocess.Popen(
                [sys.executable, script_path] + (cmd[2:] if len(cmd) > 2 else []),
                cwd=cwd,
                stdout=log_file,
                stderr=log_file
            )
            self.processes[service_id] = process
            self.services[service_id] = {
                "name": config["name"],
                "port": config["port"],
                "dashboard_port": config.get("dashboard_port", "N/A"),
                "status": "running",
                "pid": process.pid,
                "start_time": datetime.utcnow()
            }
            
            # Start monitoring thread
            threading.Thread(target=self._monitor_service, args=(service_id,), daemon=True).start()
            
            logger.info(f"Started {config['name']} (PID: {process.pid}) on port {config['port']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start {config['name']}: {e}")
            return False
    
    async def start_dashboard_servers(self):
        """Start dashboard servers for each service"""
        logger.info("Starting dashboard servers...")
        
        for service_id, config in self.service_configs.items():
            # Skip network dashboard as it doesn't need its own dashboard
            if service_id == "network_dashboard":
                continue
            # Only access dashboard_port if it exists
            dashboard_port = config.get("dashboard_port")
            if dashboard_port is not None:
                await self.start_service_dashboard(service_id)
                await asyncio.sleep(1)  # Small delay between dashboard starts
    
    async def start_service_dashboard(self, service_id: str):
        """Start a dashboard server for a specific service"""
        config = self.service_configs[service_id]
        
        # Skip if no dashboard port configured
        if "dashboard_port" not in config:
            return
            
        dashboard_port = config["dashboard_port"]
        
        try:
            # Create dashboard HTML
            dashboard_html = self._create_service_dashboard(service_id, config)
            
            # Start dashboard server
            import http.server
            import socketserver
            
            class ServiceDashboardHandler(http.server.SimpleHTTPRequestHandler):
                def do_GET(self):
                    if self.path == '/':
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(dashboard_html.encode('utf-8'))
                    else:
                        super().do_GET()
            
            # Start dashboard server in background
            dashboard_server = socketserver.TCPServer(("", dashboard_port), ServiceDashboardHandler)
            logger.info(f"Started {config['name']} dashboard on port {dashboard_port}")
            
            # Run server in background
            threading.Thread(target=dashboard_server.serve_forever, daemon=True).start()
            
        except Exception as e:
            logger.error(f"Failed to start {config['name']} dashboard: {e}")
    
    def _create_service_dashboard(self, service_id: str, config: dict) -> str:
        """Create HTML dashboard for a specific service"""
        service_name = config["name"]
        service_port = config["port"]
        dashboard_port = config.get("dashboard_port", "N/A")
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{service_name} Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .content {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .status {{ padding: 10px; border-radius: 5px; margin: 10px 0; }}
        .status.running {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
        .status.stopped {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
        .actions {{ margin-top: 15px; }}
        button {{ padding: 8px 16px; margin: 2px; border: none; border-radius: 4px; cursor: pointer; }}
        button.primary {{ background: #007bff; color: white; }}
        button.danger {{ background: #dc3545; color: white; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .info-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{service_name} Dashboard</h1>
        <p>Monitor and manage {service_name}</p>
    </div>
    
    <div class="content">
        <div class="status running">
            <strong>Status: Running</strong>
        </div>
        
        <div class="info-grid">
            <div class="info-card">
                <h3>Service Information</h3>
                <p><strong>Service Name:</strong> {service_name}</p>
                <p><strong>Service Port:</strong> {service_port}</p>
                <p><strong>Dashboard Port:</strong> {dashboard_port}</p>
                <p><strong>Service ID:</strong> {service_id}</p>
            </div>
            
            <div class="info-card">
                <h3>Quick Actions</h3>
                <div class="actions">
                    <button class="primary" onclick="openServiceInterface()">Open Service Interface</button>
                    <button class="primary" onclick="refreshDashboard()">Refresh Dashboard</button>
                    <button class="danger" onclick="stopService()">Stop Service</button>
                </div>
            </div>
        </div>
        
        <div class="info-card">
            <h3>Service Details</h3>
            <p>This dashboard provides monitoring and management capabilities for {service_name}.</p>
            <p>The service is running on port {service_port} and can be accessed directly for its main interface.</p>
            <p>Use the buttons above to interact with the service or return to the main management dashboard.</p>
        </div>
    </div>
    
    <script>
        function openServiceInterface() {{
            window.open(`http://localhost:{service_port}`, '_blank');
        }}
        
        function refreshDashboard() {{
            location.reload();
        }}
        
        function stopService() {{
            if (confirm('Are you sure you want to stop this service?')) {{
                alert('Stop request sent to service manager');
            }}
        }}
        
        // Auto-refresh every 30 seconds
        setInterval(() => location.reload(), 30000);
    </script>
</body>
</html>
        """
    
    def _monitor_service(self, service_id: str):
        """Monitor a service for health and restart if needed"""
        config = self.service_configs[service_id]
        
        while service_id in self.processes and self.processes[service_id].poll() is None:
            try:
                # Check if process is still alive
                if self.processes[service_id].poll() is not None:
                    logger.warning(f"Service {service_id} has stopped unexpectedly")
                    
                    # Auto-restart if enabled
                    if config["auto_restart"]:
                        logger.info(f"Restarting {config['name']}...")
                        asyncio.run(self.start_service(service_id))
                    break
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring {service_id}: {e}")
                time.sleep(10)
    
    async def stop_service(self, service_id: str, force: bool = False) -> bool:
        """Stop a specific service gracefully"""
        if service_id not in self.service_configs:
            logger.error(f"Unknown service: {service_id}")
            return False
        
        config = self.service_configs[service_id]
        
        if service_id not in self.processes:
            logger.info(f"Service {service_id} is not running")
            return True
        
        try:
            logger.info(f"Stopping {config['name']}...")
            
            # Show credibility warning
            if service_id in self.credibility_warnings:
                logger.warning(self.credibility_warnings[service_id])
            
            # Send graceful shutdown signal
            if not force and config["port"] > 0:
                try:
                    import requests
                    response = requests.post(f"http://localhost:{config['port']}/shutdown", timeout=5)
                    if response.status_code == 200:
                        logger.info(f"Graceful shutdown signal sent to {config['name']}")
                        # Wait for graceful shutdown
                        await asyncio.sleep(5)
                except:
                    logger.warning(f"Could not send graceful shutdown to {config['name']}")
            
            # Force kill if still running
            process = self.processes[service_id]
            if process.poll() is None:
                if os.name == 'nt':
                    process.terminate()
                else:
                    process.send_signal(signal.SIGTERM)
                
                # Wait for termination
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Force killing {config['name']}")
                    process.kill()
            
            del self.processes[service_id]
            if service_id in self.services:
                self.services[service_id]["status"] = "stopped"
            
            logger.info(f"Stopped {config['name']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop {config['name']}: {e}")
            return False
    
    async def stop_all_services(self):
        """Stop all services gracefully"""
        logger.info("Stopping all services...")
        
        # Stop management dashboard server
        if hasattr(self, 'management_server'):
            try:
                self.management_server.shutdown()
                self.management_server.server_close()
                logger.info("Management dashboard server stopped")
            except Exception as e:
                logger.error(f"Failed to stop management dashboard server: {e}")
        
        # Stop in reverse order
        stop_order = [
            "frontend",
            "network_dashboard", 
            "network_coordinator",
            "incentive_system",
            "blockchain_node_2",
            "blockchain_node_1",
            "backend"
        ]
        
        for service_id in stop_order:
            if service_id in self.service_configs:
                await self.stop_service(service_id)
                await asyncio.sleep(1)
        
        logger.info("All services stopped")
    
    async def restart_service(self, service_id: str) -> bool:
        """Restart a specific service"""
        await self.stop_service(service_id)
        await asyncio.sleep(2)
        return await self.start_service(service_id)
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all services"""
        status = {}
        for service_id, config in self.service_configs.items():
            service_info = {
                "name": config["name"],
                "port": config["port"],
                "status": "stopped"
            }
            
            # Add dashboard port if configured
            if "dashboard_port" in config:
                service_info["dashboard_port"] = config["dashboard_port"]
            else:
                service_info["dashboard_port"] = "N/A"
            
            if service_id in self.processes:
                process = self.processes[service_id]
                if process.poll() is None:
                    service_info["status"] = "running"
                    service_info["pid"] = process.pid
                    
                    # Get process info
                    try:
                        proc = psutil.Process(process.pid)
                        service_info["cpu_percent"] = proc.cpu_percent()
                        service_info["memory_mb"] = proc.memory_info().rss / 1024 / 1024
                    except:
                        pass
            
            status[service_id] = service_info
        
        return status
    
    async def open_management_dashboard(self):
        """Open the main management dashboard"""
        try:
            # Create a simple management dashboard
            dashboard_html = self._create_management_dashboard()
            
            # Start a simple HTTP server to serve the dashboard
            import http.server
            import socketserver
            
            class DashboardHandler(http.server.SimpleHTTPRequestHandler):
                def do_GET(self):
                    if self.path == '/':
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(dashboard_html.encode())
                    else:
                        super().do_GET()
                
                def do_POST(self):
                    import json
                    
                    if self.path.startswith('/restart/'):
                        service_id = self.path.split('/')[-1]
                        try:
                            # Use the manager instance directly
                            if hasattr(self, 'manager') and self.manager:
                                # Run restart in background
                                import asyncio
                                loop = asyncio.new_event_loop()
                                asyncio.set_event_loop(loop)
                                success = loop.run_until_complete(self.manager.restart_service(service_id))
                                loop.close()
                                
                                response = {'success': success, 'error': None if success else 'Failed to restart service'}
                            else:
                                response = {'success': False, 'error': 'Manager not available'}
                                
                        except Exception as e:
                            response = {'success': False, 'error': str(e)}
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps(response).encode())
                        
                    elif self.path.startswith('/stop/'):
                        service_id = self.path.split('/')[-1]
                        try:
                            # Use the manager instance directly
                            if hasattr(self, 'manager') and self.manager:
                                # Run stop in background
                                import asyncio
                                loop = asyncio.new_event_loop()
                                asyncio.set_event_loop(loop)
                                success = loop.run_until_complete(self.manager.stop_service(service_id))
                                loop.close()
                                
                                response = {'success': success, 'error': None if success else 'Failed to stop service'}
                            else:
                                response = {'success': False, 'error': 'Manager not available'}
                                
                        except Exception as e:
                            response = {'success': False, 'error': str(e)}
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps(response).encode())
                        
                    else:
                        self.send_response(404)
                        self.end_headers()
            
            # Start dashboard server in background
            port = 8090
            
            # Create a custom handler that has access to the manager
            manager_instance = self  # Capture the manager instance
            
            class ManagerDashboardHandler(DashboardHandler):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.manager = manager_instance  # Access to the manager instance
            
            # Create server
            self.management_server = socketserver.TCPServer(("", port), ManagerDashboardHandler)
            logger.info(f"Management dashboard started on port {port}")
            webbrowser.open(f"http://localhost:{port}")
            
            # Run server in background
            threading.Thread(target=self.management_server.serve_forever, daemon=True).start()
                
        except Exception as e:
            logger.error(f"Failed to open management dashboard: {e}")
    
    def _create_management_dashboard(self) -> str:
        """Create HTML for management dashboard"""
        status = self.get_service_status()
        
        services_html = ""
        for service_id, info in status.items():
            status_icon = "●" if info["status"] == "running" else "○"
            # Build dashboard button outside the f-string to avoid backslash issues
            if service_id != 'network_dashboard':
                dashboard_button = f'<button onclick="openDashboard(\'{service_id}\')">Open Dashboard</button>'
            else:
                dashboard_button = ''
            
            # Add "Open Website" button for frontend
            website_button = ''
            if service_id == 'frontend':
                website_button = '<button onclick="openWebsite()" class="primary">Open Website</button>'
            
            services_html += f"""
                <div class="service-card {info['status']}">
                    <h3>{status_icon} {info['name']}</h3>
                    <p>Status: {info['status'].title()}</p>
                    <p>Port: {info['port']}</p>
                    <p>Dashboard: {info['dashboard_port']}</p>
                    {f'<p>PID: {info["pid"]}</p>' if 'pid' in info else ''}
                    {f'<p>CPU: {info["cpu_percent"]:.1f}%</p>' if 'cpu_percent' in info else ''}
                    {f'<p>Memory: {info["memory_mb"]:.1f} MB</p>' if 'memory_mb' in info else ''}
                    <div class="actions">
                        <button onclick=\"openServerInterface('{service_id}')\">Server Interface</button>
                        {dashboard_button}
                        {website_button}
                        <button onclick=\"restartService('{service_id}')\">Restart</button>
                        <button onclick=\"stopService('{service_id}')\" class=\"danger\">Stop</button>
                    </div>
                </div>
            """
        
        html_template = r"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MediVote Service Manager</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .services-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .service-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .service-card.running {{ border-left: 4px solid #28a745; }}
        .service-card.stopped {{ border-left: 4px solid #dc3545; }}
        .actions {{ margin-top: 15px; }}
        button {{ padding: 8px 16px; margin: 2px; border: none; border-radius: 4px; cursor: pointer; }}
        button.danger {{ background: #dc3545; color: white; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>MediVote Service Manager</h1>
        <p>Manage all MediVote background services</p>
    </div>
    
    <div class="warning">
        <strong>Important:</strong> Stopping services may result in loss of credibility points and network participation rewards. 
        Keep services running to maintain network participation.
    </div>
    
    <div class="services-grid">
        {services_html}
    </div>
    
    <script>
        function openServerInterface(serviceId) {{
            const serverPorts = {{
                'backend': 8001,
                'blockchain_node_1': 8546,
                'blockchain_node_2': 8547,
                'incentive_system': 8082,
                'network_coordinator': 8083,
                'network_dashboard': 8084,
                'frontend': 8080
            }};
            
            const port = serverPorts[serviceId];
            if (port) {{
                window.open(`http://localhost:${{port}}`, '_blank');
            }}
        }}
        
        function openDashboard(serviceId) {{
            const dashboardPorts = {{
                'backend': 8091,
                'blockchain_node_1': 8093,
                'blockchain_node_2': 8094,
                'incentive_system': 8095,
                'network_coordinator': 8096,
                'frontend': 8098
            }};
            
            const port = dashboardPorts[serviceId];
            if (port) {{
                window.open(`http://localhost:${{port}}`, '_blank');
            }}
        }}
        
        function openWebsite() {{
            window.open('http://localhost:8080', '_blank');
        }}
        
        function restartService(serviceId) {{
            if (confirm('Are you sure you want to restart this service?')) {{
                fetch('/restart/' + serviceId, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }}
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Service restart initiated. The page will refresh in 3 seconds.');
                        setTimeout(() => location.reload(), 3000);
                    }} else {{
                        alert('Failed to restart service: ' + data.error);
                    }}
                }})
                .catch(error => {{
                    alert('Error restarting service: ' + error);
                }});
            }}
        }}
        
        function stopService(serviceId) {{
            const warnings = {{
                'blockchain_node_1': 'WARNING: Shutting down this node will result in loss of credibility points and network participation rewards.',
                'blockchain_node_2': 'WARNING: Shutting down this node will result in loss of credibility points and network participation rewards.',
                'incentive_system': 'WARNING: Shutting down the incentive system will stop reward distribution and node reputation tracking.',
                'network_coordinator': 'WARNING: Shutting down the coordinator will affect network discovery and node communication.',
                'backend': 'WARNING: Shutting down the backend will disable voting functionality and API access.',
                'frontend': 'WARNING: Shutting down the frontend will disable web interface access.'
            }};
            
            const warning = warnings[serviceId] || 'Are you sure you want to stop this service?';
            const confirmMessage = warning + '\\n\\nAre you sure you want to continue?';
            
            if (confirm(confirmMessage)) {{
                fetch('/stop/' + serviceId, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }}
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Service stopped. The page will refresh in 3 seconds.');
                        setTimeout(() => location.reload(), 3000);
                    }} else {{
                        alert('Failed to stop service: ' + data.error);
                    }}
                }})
                .catch(error => {{
                    alert('Error stopping service: ' + error);
                }});
            }}
        }}
        
        // Auto-refresh every 30 seconds
        setInterval(() => location.reload(), 30000);
    </script>
</body>
</html>
        """
        
        return html_template.format(services_html=services_html)
    
    async def open_service_dashboard(self, service_id: str):
        """Open dashboard for a specific service"""
        if service_id not in self.service_configs:
            logger.error(f"Unknown service: {service_id}")
            return
        
        config = self.service_configs[service_id]
        if "dashboard_port" in config and config["dashboard_port"] > 0:
            try:
                webbrowser.open(f"http://localhost:{config['dashboard_port']}")
                logger.info(f"Opened {config['name']} dashboard at http://localhost:{config['dashboard_port']}")
            except Exception as e:
                logger.error(f"Failed to open {config['name']} dashboard: {e}")

async def main():
    """Main function"""
    print("MediVote Background Service Manager")
    print("=" * 50)
    print("Starting all MediVote services in background")
    print("Each service will have its own dashboard")
    print("=" * 50)
    
    manager = MediVoteBackgroundManager()
    
    try:
        # Start all services
        await manager.start_all_services()
        
        print("\nAll services started successfully!")
        print("Management Dashboard: http://localhost:8090")
        print("\nService URLs:")
        for service_id, config in manager.service_configs.items():
            print(f"  • {config['name']}: http://localhost:{config['port']}")
        print("\nDashboard URLs:")
        for service_id, config in manager.service_configs.items():
            if "dashboard_port" in config:
                print(f"  • {config['name']} Dashboard: http://localhost:{config['dashboard_port']}")
        
        print("\nCredibility Warning: Stopping services may result in loss of credibility points!")
        print("Press Ctrl+C to stop all services gracefully")
        
        # Keep running
        await asyncio.Event().wait()
        
    except KeyboardInterrupt:
        print("\nStopping all services...")
        await manager.stop_all_services()
        print("All services stopped gracefully")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 