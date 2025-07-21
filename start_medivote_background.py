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
from functools import partial  # <-- Add this import

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
        self.is_running = True  # Set to True to enable health monitoring
        self.cpu_cache: Dict[int, float] = {}  # Cache CPU values by PID
        self.memory_cache: Dict[int, float] = {}  # Cache memory values by PID
        self.last_update: Dict[int, float] = {}  # Track last update time for each PID
        self.stopped_services: set[str] = set() # Track services that have been stopped
        self.service_pids: Dict[str, int] = {}  # Track current PIDs for each service
        self._lock = threading.Lock()  # Thread safety for concurrent operations
        
        # Concurrent operation handling
        self.service_locks: Dict[str, threading.Lock] = {}  # Service-specific locks
        self.operation_queues: Dict[str, list] = {}  # Operation queues per service
        self.active_operations: Dict[str, str] = {}  # Track active operations per service
        
        # Enhanced Error Recovery and Resilience (High Priority 3)
        self.service_health: Dict[str, dict] = {}  # Track service health metrics
        self.failure_counts: Dict[str, int] = {}  # Track consecutive failures per service
        self.last_health_check: Dict[str, float] = {}  # Track last health check time
        self.auto_recovery_enabled: Dict[str, bool] = {}  # Auto-recovery settings per service
        self.recovery_attempts: Dict[str, int] = {}  # Track recovery attempts per service
        self.max_recovery_attempts: Dict[str, int] = {}  # Max recovery attempts per service
        self.health_check_interval = 10  # Health check interval in seconds (reduced for testing)
        self.max_failures_before_disable = 5  # Max failures before disabling auto-recovery
        
        # Initialize locks and queues for each service
        for service_id in ["backend", "blockchain_node_1", "blockchain_node_2", 
                          "incentive_system", "network_coordinator", "network_dashboard", "frontend"]:
            self.service_locks[service_id] = threading.Lock()
            self.operation_queues[service_id] = []
            self.service_health[service_id] = {
                'status': 'unknown',
                'last_check': 0,
                'uptime': 0,
                'restart_count': 0,
                'failure_count': 0,
                'last_failure': None,
                'recovery_attempts': 0
            }
            self.failure_counts[service_id] = 0
            self.last_health_check[service_id] = 0
            self.auto_recovery_enabled[service_id] = True
            self.recovery_attempts[service_id] = 0
            self.max_recovery_attempts[service_id] = 3
        
        # Service configurations with unique ports
        self.service_configs = {
            "backend": {
                "name": "MediVote Backend",
                "script": "backend/main.py",
                "port": 8001,
                "dashboard_port": 8091,
                "log_file": "logs/backend.log",
                "auto_restart": False,  # Changed from True to False
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
    
    def _handle_concurrent_operation(self, service_id: str, operation: str, operation_func, *args, **kwargs):
        """Handle concurrent operations safely with queuing and service-specific locks"""
        if service_id not in self.service_locks:
            logger.error(f"Unknown service: {service_id}")
            return False
        
        service_lock = self.service_locks[service_id]
        
        with service_lock:
            # Check if there's already an active operation
            if service_id in self.active_operations:
                current_op = self.active_operations[service_id]
                logger.warning(f"Service {service_id} has active operation '{current_op}', queuing '{operation}'")
                
                # Add operation to queue
                self.operation_queues[service_id].append((operation, operation_func, args, kwargs))
                return False
            
            # Mark this operation as active
            self.active_operations[service_id] = operation
            logger.info(f"Starting operation '{operation}' on service {service_id}")
            
            try:
                # Execute the operation (handle both sync and async functions)
                if asyncio.iscoroutinefunction(operation_func):
                    # For async functions, we need to run them in an event loop
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            # If we're already in an event loop, create a task
                            import concurrent.futures
                            with concurrent.futures.ThreadPoolExecutor() as executor:
                                future = executor.submit(asyncio.run, operation_func(*args, **kwargs))
                                result = future.result(timeout=30)  # 30 second timeout
                        else:
                            result = loop.run_until_complete(operation_func(*args, **kwargs))
                    except Exception as e:
                        logger.error(f"Failed to execute async operation '{operation}' on service {service_id}: {e}")
                        result = False
                else:
                    # For sync functions, call directly
                    result = operation_func(*args, **kwargs)
                
                # Process queued operations
                while self.operation_queues[service_id]:
                    queued_op, queued_func, queued_args, queued_kwargs = self.operation_queues[service_id].pop(0)
                    logger.info(f"Processing queued operation '{queued_op}' on service {service_id}")
                    
                    # Update active operation
                    self.active_operations[service_id] = queued_op
                    
                    # Execute queued operation
                    try:
                        if asyncio.iscoroutinefunction(queued_func):
                            # Handle async queued operations
                            try:
                                loop = asyncio.get_event_loop()
                                if loop.is_running():
                                    import concurrent.futures
                                    with concurrent.futures.ThreadPoolExecutor() as executor:
                                        future = executor.submit(asyncio.run, queued_func(*queued_args, **queued_kwargs))
                                        queued_result = future.result(timeout=30)
                                else:
                                    queued_result = loop.run_until_complete(queued_func(*queued_args, **queued_kwargs))
                            except Exception as e:
                                logger.error(f"Queued async operation '{queued_op}' failed on service {service_id}: {e}")
                                queued_result = False
                        else:
                            # Handle sync queued operations
                            queued_result = queued_func(*queued_args, **queued_kwargs)
                        
                        logger.info(f"Queued operation '{queued_op}' completed on service {service_id}")
                    except Exception as e:
                        logger.error(f"Queued operation '{queued_op}' failed on service {service_id}: {e}")
                
                return result
                
            except Exception as e:
                logger.error(f"Operation '{operation}' failed on service {service_id}: {e}")
                return False
            finally:
                # Clear active operation
                if service_id in self.active_operations:
                    del self.active_operations[service_id]
    
    def _create_node_configs(self):
        """Create unique node configurations to avoid port conflicts"""
        for i in range(1, 3):
            # Use the actual ports defined in service_configs
            node_port = 8545 + i
            rpc_port = 8546 + i - 1  # This will be 8546 for node 1, 8547 for node 2
            
            config = {
                "node": {
                    "name": f"MediVote Node {i}",
                    "port": node_port,
                    "rpc_port": rpc_port,
                    "http_port": rpc_port,  # Add http_port for the web interface
                    "max_peers": 50,
                    "sync_interval": 30,
                    "block_time": 15,
                    "enable_http": True,  # Enable HTTP interface
                    "enable_rpc": True    # Enable RPC interface
                },
                "network": {
                    "bootstrap_nodes": [
                        f"localhost:{8546}",
                        f"localhost:{8547}"
                    ],
                    "network_id": "medivote_mainnet",
                    "genesis_block": "0x0000000000000000000000000000000000000000000000000000000000000000"
                },
                "blockchain": {
                    "rpc_url": f"http://localhost:{rpc_port}",
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
            
            # Ensure blockchain data directory exists
            data_dir = f"./blockchain_data_{i}"
            os.makedirs(data_dir, exist_ok=True)
            
            logger.info(f"Created node configuration: {config_file}")
    
    def _record_service_failure(self, service_id: str, error_message: str):
        """Record a service failure for enhanced error recovery"""
        if service_id not in self.failure_counts:
            self.failure_counts[service_id] = 0
        
        self.failure_counts[service_id] += 1
        current_time = time.time()
        
        # Update service health
        if service_id in self.service_health:
            self.service_health[service_id].update({
                'status': 'failed',
                'last_failure': current_time,
                'failure_count': self.failure_counts[service_id],
                'last_check': current_time
            })
        
        logger.warning(f"Service {service_id} failure #{self.failure_counts[service_id]}: {error_message}")
        
        # Check if we should disable auto-recovery
        if self.failure_counts[service_id] >= self.max_failures_before_disable:
            self.auto_recovery_enabled[service_id] = False
            logger.error(f"Auto-recovery disabled for {service_id} due to {self.failure_counts[service_id]} consecutive failures")
    
    def _record_service_success(self, service_id: str):
        """Record a successful service operation"""
        if service_id in self.failure_counts:
            self.failure_counts[service_id] = 0
        
        current_time = time.time()
        if service_id in self.service_health:
            self.service_health[service_id].update({
                'status': 'healthy',
                'last_check': current_time,
                'failure_count': 0
            })
    
    async def _check_service_health(self, service_id: str) -> bool:
        """Enhanced health check with multiple validation methods"""
        if service_id not in self.service_configs:
            return False
        
        config = self.service_configs[service_id]
        current_time = time.time()
        
        # Check if we should perform health check (rate limiting)
        # Only rate limit if we're not in the monitoring loop
        if current_time - self.last_health_check.get(service_id, 0) < self.health_check_interval:
            # Don't update last_check if we're rate limited
            return True
        
        # Update the last check time
        self.last_health_check[service_id] = current_time
        
        try:
            # Method 1: Process check
            process_healthy = False
            if service_id in self.processes:
                process = self.processes[service_id]
                if process.poll() is None:  # Process is running
                    process_healthy = True
            
            # Method 2: Port check
            port_healthy = False
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('localhost', config['port']))
                sock.close()
                port_healthy = (result == 0)
            except Exception as e:
                logger.debug(f"Port health check failed for {service_id}: {e}")
            
            # Method 3: HTTP health check (for services with HTTP endpoints)
            http_healthy = False
            if service_id in ['backend', 'frontend', 'network_dashboard']:
                try:
                    import requests
                    response = requests.get(f"http://localhost:{config['port']}/", timeout=3)
                    http_healthy = (response.status_code == 200)
                except Exception as e:
                    logger.debug(f"HTTP health check failed for {service_id}: {e}")
            
            # Determine overall health
            is_healthy = process_healthy or port_healthy or http_healthy
            
            # Update health metrics
            if service_id in self.service_health:
                uptime = 0
                if service_id in self.processes and self.processes[service_id].poll() is None:
                    uptime = current_time - self.service_health[service_id].get('start_time', current_time)
                
                self.service_health[service_id].update({
                    'status': 'healthy' if is_healthy else 'unhealthy',
                    'last_check': current_time,
                    'uptime': uptime,
                    'process_healthy': process_healthy,
                    'port_healthy': port_healthy,
                    'http_healthy': http_healthy
                })
            
            if is_healthy:
                self._record_service_success(service_id)
                logger.debug(f"Service {service_id} health check passed")
            else:
                logger.warning(f"Service {service_id} health check failed")
            
            return is_healthy
            
        except Exception as e:
            logger.error(f"Health check error for {service_id}: {e}")
            return False
    
    async def _auto_recover_service(self, service_id: str) -> bool:
        """Attempt automatic recovery of a failed service"""
        if not self.auto_recovery_enabled.get(service_id, True):
            logger.warning(f"Auto-recovery disabled for {service_id}")
            return False
        
        if service_id not in self.recovery_attempts:
            self.recovery_attempts[service_id] = 0
        
        if self.recovery_attempts[service_id] >= self.max_recovery_attempts.get(service_id, 3):
            logger.error(f"Max recovery attempts reached for {service_id}")
            return False
        
        self.recovery_attempts[service_id] += 1
        logger.info(f"Attempting auto-recovery for {service_id} (attempt {self.recovery_attempts[service_id]})")
        
        try:
            # Stop the service first
            await self.stop_service(service_id, force=True)
            await asyncio.sleep(2)
            
            # Start the service
            success = await self.start_service(service_id)
            
            if success:
                logger.info(f"Auto-recovery successful for {service_id}")
                self.recovery_attempts[service_id] = 0
                return True
            else:
                logger.error(f"Auto-recovery failed for {service_id}")
                return False
                
        except Exception as e:
            logger.error(f"Auto-recovery error for {service_id}: {e}")
            return False
    
    async def _monitor_all_services_health(self):
        """Monitor health of all services and attempt recovery"""
        logger.info("Starting health monitoring for all services...")
        while self.is_running:
            try:
                logger.debug("Performing health check cycle...")
                for service_id in self.service_configs.keys():
                    try:
                        is_healthy = await self._check_service_health(service_id)
                        
                        if not is_healthy and self.auto_recovery_enabled.get(service_id, True):
                            logger.warning(f"Service {service_id} is unhealthy, attempting recovery")
                            await self._auto_recover_service(service_id)
                    
                    except Exception as e:
                        logger.error(f"Health monitoring error for {service_id}: {e}")
                
                # Wait before next health check
                logger.debug(f"Health check cycle complete, waiting {self.health_check_interval}s...")
                await asyncio.sleep(self.health_check_interval)
                
            except Exception as e:
                logger.error(f"Health monitoring loop error: {e}")
                await asyncio.sleep(10)  # Wait before retrying
    
    def get_service_health_info(self, service_id: str) -> dict:
        """Get detailed health information for a service"""
        if service_id not in self.service_health:
            return {}
        
        health_info = self.service_health[service_id].copy()
        health_info['auto_recovery_enabled'] = self.auto_recovery_enabled.get(service_id, True)
        health_info['failure_count'] = self.failure_counts.get(service_id, 0)
        health_info['recovery_attempts'] = self.recovery_attempts.get(service_id, 0)
        health_info['max_recovery_attempts'] = self.max_recovery_attempts.get(service_id, 3)
        
        return health_info
    
    def get_all_health_info(self) -> dict:
        """Get health information for all services"""
        return {
            service_id: self.get_service_health_info(service_id)
            for service_id in self.service_configs.keys()
        }
    
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
        
        # Start health monitoring in background
        asyncio.create_task(self._monitor_all_services_health())
        
        logger.info("All services started successfully!")
        return True
    
    async def start_service(self, service_id: str) -> bool:
        """Start a specific service in background"""
        if service_id not in self.service_configs:
            logger.error(f"Unknown service: {service_id}")
            return False
        
        # Use concurrent operation handler to prevent race conditions
        return self._handle_concurrent_operation(service_id, "start", self._start_service_impl, service_id)
    
    async def _start_service_impl(self, service_id: str) -> bool:
        """Internal implementation of start_service"""
        config = self.service_configs[service_id]
        
        if service_id in self.processes and self.processes[service_id].poll() is None:
            logger.info(f"Service {service_id} is already running")
            return True
        
        try:
            logger.info(f"Starting {config['name']}...")
            
            # Remove from stopped services tracking if it was stopped
            if hasattr(self, 'stopped_services') and service_id in self.stopped_services:
                self.stopped_services.remove(service_id)
            
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
            self.service_pids[service_id] = process.pid  # Track the PID
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
            
            # Record successful start
            self._record_service_success(service_id)
            
            logger.info(f"Started {config['name']} (PID: {process.pid}) on port {config['port']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start {config['name']}: {e}")
            self._record_service_failure(service_id, str(e))
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
        
        # Use concurrent operation handler to prevent race conditions
        return self._handle_concurrent_operation(service_id, "stop", self._stop_service_impl, service_id, force)
    
    async def _stop_service_impl(self, service_id: str, force: bool = False) -> bool:
        """Internal implementation of stop_service with enhanced graceful shutdown"""
        config = self.service_configs[service_id]
        
        if service_id not in self.processes:
            logger.info(f"Service {service_id} is not running")
            return True
        
        try:
            logger.info(f"Stopping {config['name']}...")
            
            # Show credibility warning
            if service_id in self.credibility_warnings:
                logger.warning(self.credibility_warnings[service_id])
            
            process = self.processes[service_id]
            
            # Step 1: Try graceful shutdown via HTTP endpoint
            if not force and config["port"] > 0:
                graceful_shutdown_success = await self._try_graceful_shutdown(service_id, config, process)
                if graceful_shutdown_success:
                    logger.info(f"{config['name']} stopped gracefully via HTTP shutdown")
                    await self._cleanup_service_resources(service_id, process.pid)
                    return True
            
            # Step 2: Send SIGTERM (graceful termination signal)
            if process.poll() is None:
                logger.info(f"Sending SIGTERM to {config['name']} (PID: {process.pid})")
                
                if os.name == 'nt':
                    process.terminate()
                else:
                    process.send_signal(signal.SIGTERM)
                
                # Wait for graceful termination
                graceful_termination = await self._wait_for_termination(process, config['name'], timeout=15)
                if graceful_termination:
                    logger.info(f"{config['name']} stopped gracefully via SIGTERM")
                    await self._cleanup_service_resources(service_id, process.pid)
                    return True
            
            # Step 3: Force kill if still running
            if process.poll() is None:
                logger.warning(f"Force killing {config['name']} (PID: {process.pid})")
                process.kill()
                
                # Wait for force termination
                force_termination = await self._wait_for_termination(process, config['name'], timeout=5)
                if force_termination:
                    logger.info(f"{config['name']} stopped via force kill")
                    await self._cleanup_service_resources(service_id, process.pid)
                    return True
                else:
                    logger.error(f"Failed to force kill {config['name']}")
                    return False
            
            # Cleanup if process was already terminated
            await self._cleanup_service_resources(service_id, process.pid)
            logger.info(f"Stopped {config['name']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop {config['name']}: {e}")
            return False
    
    async def _try_graceful_shutdown(self, service_id: str, config: dict, process) -> bool:
        """Try graceful shutdown via HTTP endpoint"""
        try:
            import requests
            response = requests.post(f"http://localhost:{config['port']}/shutdown", timeout=5)
            if response.status_code == 200:
                logger.info(f"Graceful shutdown signal sent to {config['name']}")
                # Wait for graceful shutdown with timeout
                return await self._wait_for_termination(process, config['name'], timeout=10)
            else:
                logger.warning(f"Shutdown request failed for {config['name']}: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not send graceful shutdown to {config['name']}: {e}")
            return False
        except Exception as e:
            logger.warning(f"Unexpected error during graceful shutdown for {config['name']}: {e}")
            return False
    
    async def _wait_for_termination(self, process, service_name: str, timeout: int = 10) -> bool:
        """Wait for process termination with timeout"""
        try:
            # Wait for termination with timeout
            process.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout waiting for {service_name} to terminate")
            return False
        except Exception as e:
            logger.error(f"Error waiting for {service_name} termination: {e}")
            return False
    
    async def _cleanup_service_resources(self, service_id: str, pid: int):
        """Comprehensive cleanup of service resources"""
        try:
            # Clean up process resources
            self._cleanup_process_resources(pid)
            
            # Clean up service-specific resources
            await self._cleanup_service_specific_resources(service_id)
            
            # Remove from processes and mark as stopped
            if service_id in self.processes:
                del self.processes[service_id]
            
            # Clean up tracked PID
            if service_id in self.service_pids:
                del self.service_pids[service_id]
            
            # Add to stopped services tracking
            if not hasattr(self, 'stopped_services'):
                self.stopped_services = set()
            self.stopped_services.add(service_id)
            
            # Clean up any active operations for this service
            if service_id in self.active_operations:
                del self.active_operations[service_id]
            
            # Clear operation queue for this service
            if service_id in self.operation_queues:
                self.operation_queues[service_id].clear()
            
            logger.debug(f"Cleaned up resources for {service_id} (PID: {pid})")
            
        except Exception as e:
            logger.error(f"Error during cleanup for {service_id}: {e}")
    
    async def _cleanup_service_specific_resources(self, service_id: str):
        """Clean up service-specific resources (files, ports, etc.)"""
        try:
            config = self.service_configs[service_id]
            
            # Clean up log files if they're too large
            if "log_file" in config:
                await self._cleanup_log_file(config["log_file"])
            
            # Clean up blockchain data if it's a blockchain node
            if service_id.startswith("blockchain_node"):
                await self._cleanup_blockchain_data(service_id)
            
            # Clean up temporary files
            await self._cleanup_temp_files(service_id)
            
        except Exception as e:
            logger.error(f"Error cleaning up service-specific resources for {service_id}: {e}")
    
    async def _cleanup_log_file(self, log_file: str):
        """Clean up log file if it's too large"""
        try:
            if os.path.exists(log_file):
                file_size = os.path.getsize(log_file)
                max_size = 50 * 1024 * 1024  # 50MB
                
                if file_size > max_size:
                    # Create backup and truncate
                    backup_file = f"{log_file}.backup"
                    if os.path.exists(backup_file):
                        os.remove(backup_file)
                    os.rename(log_file, backup_file)
                    logger.info(f"Log file {log_file} was too large, created backup")
        except Exception as e:
            logger.error(f"Error cleaning up log file {log_file}: {e}")
    
    async def _cleanup_blockchain_data(self, service_id: str):
        """Clean up blockchain data for blockchain nodes"""
        try:
            # Only clean up if it's a test environment or explicitly requested
            # In production, we would want to preserve blockchain data
            data_dir = f"./blockchain_data_{service_id.split('_')[-1]}"
            if os.path.exists(data_dir):
                # Check if it's safe to clean up (not in production)
                if os.path.exists(".test_mode"):
                    import shutil
                    shutil.rmtree(data_dir)
                    logger.info(f"Cleaned up blockchain data for {service_id}")
        except Exception as e:
            logger.error(f"Error cleaning up blockchain data for {service_id}: {e}")
    
    async def _cleanup_temp_files(self, service_id: str):
        """Clean up temporary files for the service"""
        try:
            # Clean up any temporary files in the service directory
            temp_patterns = ["*.tmp", "*.temp", "*.cache"]
            config = self.service_configs[service_id]
            
            if "script" in config:
                script_dir = os.path.dirname(config["script"])
                if os.path.exists(script_dir):
                    for pattern in temp_patterns:
                        import glob
                        temp_files = glob.glob(os.path.join(script_dir, pattern))
                        for temp_file in temp_files:
                            try:
                                os.remove(temp_file)
                                logger.debug(f"Cleaned up temp file: {temp_file}")
                            except Exception:
                                pass
        except Exception as e:
            logger.error(f"Error cleaning up temp files for {service_id}: {e}")
    
    async def stop_all_services(self):
        """Stop all services gracefully with comprehensive cleanup"""
        logger.info("🛑 Starting graceful shutdown of all services...")
        
        # Step 1: Stop management dashboard server gracefully
        await self._stop_management_dashboard()
        
        # Step 2: Stop services in reverse dependency order with enhanced cleanup
        stop_order = [
            "frontend",
            "network_dashboard", 
            "network_coordinator",
            "incentive_system",
            "blockchain_node_2",
            "blockchain_node_1",
            "backend"
        ]
        
        successful_stops = 0
        total_services = len(stop_order)
        
        for service_id in stop_order:
            if service_id in self.service_configs:
                logger.info(f"🔄 Stopping {service_id}...")
                try:
                    success = await self.stop_service(service_id)
                    if success:
                        successful_stops += 1
                        logger.info(f"✅ {service_id} stopped successfully")
                    else:
                        logger.warning(f"⚠️ {service_id} failed to stop gracefully")
                except Exception as e:
                    logger.error(f"❌ Error stopping {service_id}: {e}")
                
                # Small delay between stops to prevent overwhelming the system
                await asyncio.sleep(0.5)
        
        # Step 3: Final cleanup
        await self._final_cleanup()
        
        logger.info(f"🎯 Shutdown complete: {successful_stops}/{total_services} services stopped successfully")
        
        if successful_stops == total_services:
            logger.info("✅ All services stopped gracefully")
        else:
            logger.warning(f"⚠️ {total_services - successful_stops} services may not have stopped cleanly")
    
    async def _stop_management_dashboard(self):
        """Stop management dashboard server gracefully"""
        if hasattr(self, 'management_server'):
            try:
                logger.info("🖥️ Stopping management dashboard server...")
                
                # Shutdown the server gracefully
                self.management_server.shutdown()
                self.management_server.server_close()
                
                # Wait a moment for connections to close
                await asyncio.sleep(1)
                
                logger.info("✅ Management dashboard server stopped")
            except Exception as e:
                logger.error(f"❌ Failed to stop management dashboard server: {e}")
        else:
            logger.info("ℹ️ No management dashboard server to stop")
    
    async def _final_cleanup(self):
        """Perform final cleanup after all services are stopped"""
        try:
            logger.info("🧹 Performing final cleanup...")
            
            # Clean up any remaining process resources
            await self._cleanup_remaining_processes()
            
            # Clean up global resources
            await self._cleanup_global_resources()
            
            # Clean up temporary files and directories
            await self._cleanup_temp_directories()
            
            logger.info("✅ Final cleanup completed")
            
        except Exception as e:
            logger.error(f"❌ Error during final cleanup: {e}")
    
    async def _cleanup_remaining_processes(self):
        """Clean up any remaining processes that might not have been properly stopped"""
        try:
            import psutil
            
            # Find any remaining MediVote processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info['cmdline']
                    if cmdline and any('medivote' in arg.lower() or 'python' in arg.lower() for arg in cmdline):
                        # Check if it's one of our managed processes
                        if proc.pid not in [p.pid for p in self.processes.values() if p.poll() is None]:
                            logger.warning(f"🧹 Cleaning up orphaned process: {proc.pid}")
                            proc.terminate()
                            try:
                                proc.wait(timeout=5)
                            except psutil.TimeoutExpired:
                                proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
        except Exception as e:
            logger.error(f"Error cleaning up remaining processes: {e}")
    
    async def _cleanup_global_resources(self):
        """Clean up global resources like locks, queues, and caches"""
        try:
            # Clear all caches
            self.cpu_cache.clear()
            self.memory_cache.clear()
            self.last_update.clear()
            
            # Clear operation queues
            for queue in self.operation_queues.values():
                queue.clear()
            
            # Clear active operations
            self.active_operations.clear()
            
            # Clear stopped services tracking
            if hasattr(self, 'stopped_services'):
                self.stopped_services.clear()
            
            # Clear service PIDs
            self.service_pids.clear()
            
            logger.debug("🧹 Cleared global resource caches")
            
        except Exception as e:
            logger.error(f"Error cleaning up global resources: {e}")
    
    async def _cleanup_temp_directories(self):
        """Clean up temporary directories and files"""
        try:
            import glob
            import shutil
            
            # Clean up common temporary directories
            temp_dirs = ['temp', 'tmp', 'logs', 'uploads']
            
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    try:
                        # Remove temporary files but keep the directory
                        temp_files = glob.glob(os.path.join(temp_dir, '*'))
                        for temp_file in temp_files:
                            if os.path.isfile(temp_file):
                                os.remove(temp_file)
                                logger.debug(f"🧹 Cleaned up temp file: {temp_file}")
                    except Exception as e:
                        logger.debug(f"Could not clean up {temp_dir}: {e}")
            
            # Clean up large log files
            log_files = glob.glob('*.log')
            for log_file in log_files:
                try:
                    if os.path.getsize(log_file) > 10 * 1024 * 1024:  # 10MB
                        backup_file = f"{log_file}.backup"
                        if os.path.exists(backup_file):
                            os.remove(backup_file)
                        os.rename(log_file, backup_file)
                        logger.info(f"📦 Archived large log file: {log_file}")
                except Exception as e:
                    logger.debug(f"Could not archive log file {log_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Error cleaning up temp directories: {e}")
    
    async def restart_service(self, service_id: str) -> bool:
        """Restart a specific service"""
        # Use concurrent operation handler to prevent race conditions
        return self._handle_concurrent_operation(service_id, "restart", self._restart_service_impl, service_id)
    
    async def _restart_service_impl(self, service_id: str) -> bool:
        """Internal implementation of restart_service"""
        await self.stop_service(service_id)
        await asyncio.sleep(2)
        return await self.start_service(service_id)
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all services"""
        with self._lock:  # Thread safety for status updates
            status = {}
            for service_id, config in self.service_configs.items():
                service_info = {
                    "name": config["name"],
                    "port": config["port"],
                    "status": "stopped"  # Default to stopped
                }
                
                # Add dashboard port if configured
                if "dashboard_port" in config:
                    service_info["dashboard_port"] = config["dashboard_port"]
                else:
                    service_info["dashboard_port"] = "N/A"
                
                # Check if service was explicitly stopped
                if hasattr(self, 'stopped_services') and service_id in self.stopped_services:
                    service_info["status"] = "stopped"
                    status[service_id] = service_info
                    continue
                
                # Check if process is running
                process_running = False
                current_pid = None
                
                if service_id in self.processes:
                    process = self.processes[service_id]
                    if process.poll() is None:
                        process_running = True
                        service_info["status"] = "running"
                        current_pid = process.pid
                        service_info["pid"] = current_pid
                        # Update tracked PID
                        self.service_pids[service_id] = current_pid
                
                # If process not running, check if port is accessible (for all services)
                if not process_running:
                    import socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    try:
                        s.connect(("localhost", config["port"]))
                        service_info["status"] = "running"
                        # Try to get PID and resource usage from port if we can
                        try:
                            import psutil
                            for conn in psutil.net_connections():
                                if conn.laddr.port == config["port"] and conn.status == 'LISTEN':
                                    current_pid = conn.pid
                                    service_info["pid"] = current_pid
                                    # Update tracked PID
                                    self.service_pids[service_id] = current_pid
                                    break
                        except:
                            pass
                    except:
                        service_info["status"] = "stopped"
                    finally:
                        s.close()
                
                # If we still don't have a PID but have a tracked one, try to use it
                if not current_pid and service_id in self.service_pids:
                    tracked_pid = self.service_pids[service_id]
                    try:
                        # Check if the tracked PID is still valid
                        proc = psutil.Process(tracked_pid)
                        if proc.is_running():
                            current_pid = tracked_pid
                            service_info["pid"] = current_pid
                            service_info["status"] = "running"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        # Clean up invalid tracked PID
                        if service_id in self.service_pids:
                            del self.service_pids[service_id]
                
                # Get CPU and Memory for the current PID if we have one
                if current_pid and service_info["status"] == "running":
                    try:
                        cpu_percent, memory_mb = self._get_process_resources(current_pid)
                        service_info["cpu_percent"] = cpu_percent
                        service_info["memory_mb"] = memory_mb
                    except Exception as e:
                        logger.debug(f"Error getting resources for PID {current_pid}: {e}")
                        service_info["cpu_percent"] = 0.0
                        service_info["memory_mb"] = 0.0
                else:
                    service_info["cpu_percent"] = 0.0
                    service_info["memory_mb"] = 0.0
                
                # Add health information
                health_info = self.get_service_health_info(service_id)
                if health_info:
                    service_info["health"] = health_info
                
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
            
            # Store manager reference at module level for access by handler
            handler_manager = self
            
            class DashboardHandler(http.server.SimpleHTTPRequestHandler):
                @property
                def manager(self):
                    """Get manager from server"""
                    if hasattr(self.server, 'manager'):
                        return self.server.manager
                    return None
                
                def finish(self):
                    """Override finish to prevent errors on SSE connections"""
                    try:
                        super().finish()
                    except (ValueError, OSError):
                        # Ignore errors when connection is already closed (common with SSE)
                        pass
                
                def handle_one_request(self):
                    """Override handle_one_request to prevent flush errors on SSE"""
                    try:
                        super().handle_one_request()
                    except (ValueError, OSError) as e:
                        # Ignore errors when connection is already closed (common with SSE)
                        logger.debug(f"Connection error in handle_one_request: {e}")
                        pass
                
                def do_GET(self):
                    if self.path == '/':
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.send_header('X-Content-Type-Options', 'nosniff')
                        self.send_header('X-Frame-Options', 'DENY')
                        self.send_header('X-XSS-Protection', '1; mode=block')
                        # Remove CSP header that blocks eval - we're not using eval anyway
                        self.end_headers()
                        self.wfile.write(dashboard_html.encode())
                    elif self.path == '/status':
                        # Return current service status as JSON
                        import json
                        if self.manager:
                            status = self.manager.get_service_status()
                        else:
                            status = {}
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        self.wfile.write(json.dumps(status).encode())
                    elif self.path == '/health':
                        # Return detailed health information as JSON
                        import json
                        if self.manager:
                            health_info = self.manager.get_all_health_info()
                        else:
                            health_info = {}
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        self.wfile.write(json.dumps(health_info).encode())
                    elif self.path == '/events':
                        import json  # Ensure json is imported in this scope
                        # Server-Sent Events for real-time updates
                        self.send_response(200)
                        self.send_header('Content-type', 'text/event-stream')
                        self.send_header('Cache-Control', 'no-cache')
                        self.send_header('Connection', 'keep-alive')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        
                        # Send initial data immediately
                        try:
                            if self.manager:
                                status = self.manager.get_service_status()
                                # Compress the JSON to reduce size
                                compressed_status = {}
                                for service_id, info in status.items():
                                    compressed_status[service_id] = {
                                        'name': info.get('name', ''),
                                        'status': info.get('status', ''),
                                        'pid': info.get('pid', None),
                                        'cpu': info.get('cpu_percent', 0),
                                        'mem': info.get('memory_mb', 0)
                                    }
                                data = f"data: {json.dumps(compressed_status)}\n\n"
                                self.wfile.write(data.encode())
                                self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, ValueError, OSError):
                            logger.debug("SSE initial data error - client disconnected")
                            return
                        except Exception as e:
                            logger.debug(f"SSE initial data error: {e}")
                            return
                        
                        # Then start the continuous stream
                        try:
                            while True:
                                # Check if connection is still valid before writing
                                if not hasattr(self, 'wfile') or not self.wfile:
                                    logger.debug("SSE connection lost")
                                    break
                                
                                # Additional check for connection validity
                                try:
                                    # Test if the connection is still alive
                                    if hasattr(self, 'connection') and self.connection:
                                        # Try to get socket info to check if it's still valid
                                        self.connection.getpeername()
                                except (OSError, ValueError):
                                    logger.debug("SSE connection no longer valid")
                                    break
                                
                                if self.manager:
                                    status = self.manager.get_service_status()
                                    # Compress the JSON to reduce size
                                    compressed_status = {}
                                    for service_id, info in status.items():
                                        compressed_status[service_id] = {
                                            'name': info.get('name', ''),
                                            'status': info.get('status', ''),
                                            'pid': info.get('pid', None),
                                            'cpu': info.get('cpu_percent', 0),
                                            'mem': info.get('memory_mb', 0)
                                        }
                                    data = f"data: {json.dumps(compressed_status)}\n\n"
                                    try:
                                        self.wfile.write(data.encode())
                                        self.wfile.flush()
                                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, ValueError, OSError):
                                        logger.debug("SSE client disconnected")
                                        break
                                    except Exception as e:
                                        logger.debug(f"SSE write error: {e}")
                                        break
                                time.sleep(1)  # Send updates every 1 second for better CPU/memory monitoring
                        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, ValueError, OSError):
                            logger.debug("SSE connection closed by client")
                        except Exception as e:
                            logger.debug(f"SSE error: {e}")
                        finally:
                            # Ensure connection is properly closed
                            try:
                                if hasattr(self, 'wfile') and self.wfile:
                                    self.wfile.close()
                            except Exception:
                                pass
                            # Prevent the base HTTP server from trying to flush after we've handled SSE
                            return
                    else:
                        super().do_GET()
                
                def do_POST(self):
                    import json
                    logger.debug(f"do_POST called with path: {self.path}")
                    if self.path.startswith('/restart/'):
                        service_id = self.path.split('/')[-1]
                        logger.info(f"Received POST /restart/ for {service_id}")
                        try:
                            if self.manager:
                                # Use threading to avoid blocking the HTTP handler
                                import threading
                                import queue
                                
                                result_queue = queue.Queue()
                                manager_ref = self.manager  # Capture manager reference for thread
                                
                                def restart_service_thread():
                                    try:
                                        import asyncio
                                        loop = asyncio.new_event_loop()
                                        asyncio.set_event_loop(loop)
                                        success = loop.run_until_complete(manager_ref.restart_service(service_id))
                                        loop.close()
                                        result_queue.put(('success', success))
                                    except Exception as e:
                                        result_queue.put(('error', str(e)))
                                
                                # Start the restart operation in a separate thread
                                thread = threading.Thread(target=restart_service_thread, daemon=True)
                                thread.start()
                                
                                # Wait for result with timeout (10 seconds for restart)
                                try:
                                    result_type, result_data = result_queue.get(timeout=10)
                                    if result_type == 'success':
                                        response = {'success': result_data, 'error': None if result_data else 'Failed to restart service'}
                                    else:
                                        response = {'success': False, 'error': result_data}
                                except queue.Empty:
                                    response = {'success': False, 'error': 'Operation timed out'}
                            else:
                                response = {'success': False, 'error': 'Manager not available'}
                        except Exception as e:
                            response = {'success': False, 'error': str(e)}
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        try:
                            self.wfile.write(json.dumps(response).encode())
                        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                            logger.debug(f"Client disconnected during /restart/{service_id} response")
                        
                    elif self.path.startswith('/stop/'):
                        service_id = self.path.split('/')[-1]
                        logger.info(f"Received POST /stop/ for {service_id}")
                        try:
                            if self.manager:
                                # Use threading to avoid blocking the HTTP handler
                                import threading
                                import queue
                                
                                result_queue = queue.Queue()
                                manager_ref = self.manager  # Capture manager reference for thread
                                
                                def stop_service_thread():
                                    logger.debug(f"stop_service_thread started for {service_id}")
                                    try:
                                        import asyncio
                                        loop = asyncio.new_event_loop()
                                        asyncio.set_event_loop(loop)
                                        success = loop.run_until_complete(manager_ref.stop_service(service_id))
                                        logger.debug(f"stop_service returned: {success}")
                                        loop.close()
                                        result_queue.put(('success', success))
                                    except Exception as e:
                                        logger.error(f"Error in stop_service_thread: {e}")
                                        result_queue.put(('error', str(e)))
                                
                                # Start the stop operation in a separate thread
                                thread = threading.Thread(target=stop_service_thread, daemon=True)
                                thread.start()
                                logger.info(f"Started thread for stopping {service_id}")
                                
                                # Wait for result with timeout (10 seconds for stop operations)
                                try:
                                    logger.info("Waiting for result from queue...")
                                    # Use longer timeout for blockchain nodes
                                    timeout = 15 if 'blockchain' in service_id else 10
                                    result_type, result_data = result_queue.get(timeout=timeout)
                                    logger.info(f"Got result from queue: {result_type}, {result_data}")
                                    if result_type == 'success':
                                        response = {'success': result_data, 'error': None if result_data else 'Failed to stop service'}
                                    else:
                                        response = {'success': False, 'error': result_data}
                                except queue.Empty:
                                    logger.error(f"Queue timeout after {timeout}s - no response from stop_service_thread")
                                    response = {'success': False, 'error': f'Operation timed out after {timeout} seconds'}
                            else:
                                logger.error("Manager not available in /stop/ handler")
                                response = {'success': False, 'error': 'Manager not available'}
                        except Exception as e:
                            logger.error(f"Exception in /stop/ handler: {e}", exc_info=True)
                            response = {'success': False, 'error': str(e)}
                        
                        logger.info(f"Sending response for /stop/{service_id}: {response}")
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        try:
                            self.wfile.write(json.dumps(response).encode())
                        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                            logger.debug(f"Client disconnected during /stop/{service_id} response")
                        
                    elif self.path.startswith('/start/'):
                        service_id = self.path.split('/')[-1]
                        logger.info(f"Received POST /start/ for {service_id}")
                        try:
                            if self.manager:
                                # Use threading to avoid blocking the HTTP handler
                                import threading
                                import queue
                                
                                result_queue = queue.Queue()
                                manager_ref = self.manager  # Capture manager reference for thread
                                
                                def start_service_thread():
                                    try:
                                        import asyncio
                                        loop = asyncio.new_event_loop()
                                        asyncio.set_event_loop(loop)
                                        success = loop.run_until_complete(manager_ref.start_service(service_id))
                                        loop.close()
                                        result_queue.put(('success', success))
                                    except Exception as e:
                                        result_queue.put(('error', str(e)))
                                
                                # Start the start operation in a separate thread
                                thread = threading.Thread(target=start_service_thread, daemon=True)
                                thread.start()
                                
                                # Wait for result with timeout (5 seconds)
                                try:
                                    result_type, result_data = result_queue.get(timeout=5)
                                    if result_type == 'success':
                                        response = {'success': result_data, 'error': None if result_data else 'Failed to start service'}
                                    else:
                                        response = {'success': False, 'error': result_data}
                                except queue.Empty:
                                    response = {'success': False, 'error': 'Operation timed out'}
                            else:
                                response = {'success': False, 'error': 'Manager not available'}
                        except Exception as e:
                            response = {'success': False, 'error': str(e)}
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.end_headers()
                        try:
                            self.wfile.write(json.dumps(response).encode())
                        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                            logger.debug(f"Client disconnected during /start/{service_id} response")
                        
                    else:
                        self.send_response(404)
                        self.end_headers()
            
            # Start dashboard server with custom handler
            port = 8090
            
            # Create a custom THREADED server class that stores the manager
            class CustomThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
                def __init__(self, server_address, RequestHandlerClass, manager):
                    self.manager = manager
                    super().__init__(server_address, RequestHandlerClass)
            
            self.management_server = CustomThreadedTCPServer(("", port), DashboardHandler, self)
            logger.info(f"Management dashboard started on port {port}")
            webbrowser.open(f"http://localhost:{port}")
            
            # Run server in background to allow health monitoring to run
            logger.info("Starting HTTP server in background...")
            def run_server():
                try:
                    self.management_server.serve_forever()
                except KeyboardInterrupt:
                    logger.info("HTTP server stopped by user")
                except Exception as e:
                    logger.error(f"HTTP server error: {e}")
                finally:
                    try:
                        self.management_server.shutdown()
                        self.management_server.server_close()
                    except Exception as e:
                        logger.error(f"Error shutting down HTTP server: {e}")
            
            # Start server in background thread
            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()
            
            # Give server a moment to start
            await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Failed to open management dashboard: {e}")
    
    def _create_management_dashboard(self) -> str:
        """Create HTML for management dashboard"""
        # Start with all services as stopped by default
        default_status = {}
        for service_id, config in self.service_configs.items():
            default_status[service_id] = {
                "name": config["name"],
                "port": config["port"],
                "status": "stopped",  # Default to stopped
                "dashboard_port": config.get("dashboard_port", "N/A")
            }
        
        services_html = ""
        for service_id, info in default_status.items():
            status_icon = "○"  # Default to stopped icon
            
            # Determine which buttons to show
            buttons_html = ""
            
            # Server Interface button - special handling for network_dashboard and frontend
            if service_id == 'network_dashboard':
                # For Network Dashboard, use Open Dashboard as the main interface
                buttons_html += f'<button onclick="openServerInterface(\'{service_id}\')" class="primary">Open Dashboard</button>'
            elif service_id == 'frontend':
                # For Frontend, only show website button
                buttons_html += '<button onclick="openWebsite()" class="primary">Open Website</button>'
            else:
                # For all other services, show Server Interface
                buttons_html += f'<button onclick="openServerInterface(\'{service_id}\')">Server Interface</button>'
            
            # Dashboard button - only for services with dashboards (not network_dashboard)
            if service_id != 'network_dashboard' and "dashboard_port" in self.service_configs[service_id]:
                buttons_html += f'<button onclick="openDashboard(\'{service_id}\')">Open Dashboard</button>'
            
            # Restart and Toggle buttons for all services
            buttons_html += f'<button onclick="restartService(\'{service_id}\')">Restart</button>'
            
            action_button_text = "Start"  # Default to Start button
            action_button_class = "primary"  # Default to primary class
            buttons_html += f'<button onclick="toggleService(\'{service_id}\')" class="{action_button_class}" id="toggle-{service_id}">{action_button_text}</button>'
            
            # Don't show Dashboard port for Network Dashboard
            dashboard_info = ""
            if service_id != 'network_dashboard':
                dashboard_info = f'<p>Dashboard: {info["dashboard_port"]}</p>'
            
            services_html += f"""
                <div class="service-card stopped" id="service-{service_id}">
                    <h3>{status_icon} {info['name']}</h3>
                    <p>Status: <span class="status-text">Stopped</span></p>
                    <p>Port: {info['port']}</p>
                    {dashboard_info}
                    <p>PID: <span class="pid-text">-</span></p>
                    <p>CPU: <span class="cpu-text">-</span></p>
                    <p>Memory: <span class="memory-text">-</span></p>
                    <div class="actions">
                        {buttons_html}
                    </div>
                </div>
            """
        
        return f"""
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
        button.primary {{ background: #007bff; color: white; }}
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
        function openServerInterface(service_id) {{
            const serverPorts = {{
                'backend': 8001,
                'blockchain_node_1': 8546,
                'blockchain_node_2': 8547,
                'incentive_system': 8082,
                'network_coordinator': 8083,
                'network_dashboard': 8084,
                'frontend': 8001  // Frontend server interface should point to backend API
            }};
            
            const port = serverPorts[service_id];
            if (port) {{
                window.open(`http://localhost:${{port}}`, '_blank');
            }}
        }}
        
        function openDashboard(service_id) {{
            const dashboardPorts = {{
                'backend': 8091,
                'blockchain_node_1': 8093,
                'blockchain_node_2': 8094,
                'incentive_system': 8095,
                'network_coordinator': 8096,
                'frontend': 8098
            }};
            
            const port = dashboardPorts[service_id];
            if (port) {{
                window.open(`http://localhost:${{port}}`, '_blank');
            }}
        }}
        
        function openWebsite() {{
            window.open('http://localhost:8080', '_blank');
        }}
        
        function updateServiceStatus(service_id, status) {{
            const serviceCard = document.getElementById(`service-${{service_id}}`);
            if (!serviceCard) return;
            const statusText = serviceCard.querySelector('.status-text');
            const toggleButton = document.getElementById(`toggle-${{service_id}}`);
            const restartButton = document.querySelector(`button[onclick="restartService('${{service_id}}')"]`);
            const pidText = serviceCard.querySelector('.pid-text');
            const cpuText = serviceCard.querySelector('.cpu-text');
            const memoryText = serviceCard.querySelector('.memory-text');
            const statusIcon = serviceCard.querySelector('h3');
            
            if (statusText) {{
                statusText.textContent = status.status.charAt(0).toUpperCase() + status.status.slice(1);
            }}
            
            if (toggleButton) {{
                // Always re-enable the button when updating status
                toggleButton.disabled = false;
                if (status.status === 'stopped') {{
                    toggleButton.textContent = 'Start';
                    toggleButton.className = 'primary';
                }} else {{
                    toggleButton.textContent = 'Stop';
                    toggleButton.className = 'danger';
                }}
            }}
            
            // Reset restart button state when status updates
            if (restartButton) {{
                restartButton.disabled = false;
                restartButton.textContent = 'Restart';
            }}
            
            serviceCard.className = `service-card ${{status.status}}`;
            
            // Update status icon
            if (statusIcon) {{
                const serviceName = statusIcon.textContent.split(' ').slice(1).join(' ');
                statusIcon.innerHTML = `${{status.status === 'running' ? '●' : '○'}} ${{serviceName}}`;
            }}
            
            if (pidText) {{
                // Handle PID field - it might be null, undefined, or a number
                const pidValue = status.pid;
                pidText.textContent = (pidValue !== null && pidValue !== undefined && pidValue !== '') ? pidValue : '-';
            }}
            if (cpuText) {{
                // Handle both compressed (cpu) and full (cpu_percent) field names
                const cpuValue = status.cpu !== undefined ? status.cpu : status.cpu_percent;
                cpuText.textContent = (cpuValue !== null && cpuValue !== undefined) ? cpuValue.toFixed(1) + '%' : '-';
            }}
            if (memoryText) {{
                // Handle both compressed (mem) and full (memory_mb) field names
                const memValue = status.mem !== undefined ? status.mem : status.memory_mb;
                memoryText.textContent = (memValue !== null && memValue !== undefined) ? memValue.toFixed(1) + ' MB' : '-';
            }}
        }}
        
        // Initialize Server-Sent Events for real-time updates
        function initEventSource() {{
            try {{
                const eventSource = new EventSource('/events');
                
                eventSource.onmessage = function(event) {{
                    try {{
                        const data = JSON.parse(event.data);
                        Object.keys(data).forEach(service_id => {{
                            updateServiceStatus(service_id, data[service_id]);
                        }});
                    }} catch (error) {{
                        console.error('Error parsing SSE data:', error);
                    }}
                }};
                
                eventSource.onerror = function(error) {{
                    console.error('SSE connection error:', error);
                    // Reconnect after 5 seconds
                    setTimeout(() => {{
                        eventSource.close();
                        initEventSource();
                    }}, 5000);
                }};
                
                return eventSource;
            }} catch (error) {{
                console.error('Failed to initialize EventSource:', error);
                // Fallback to polling - more frequent updates for CPU/memory
                setInterval(refreshServiceStatus, 2000);
                return null;
            }}
        }}
        
        // Fallback polling function (kept for compatibility)
        function refreshServiceStatus() {{
            fetch('/status')
                .then(response => response.json())
                .then(data => {{
                    Object.keys(data).forEach(service_id => {{
                        updateServiceStatus(service_id, data[service_id]);
                    }});
                }})
                .catch(error => console.error('Error fetching status:', error));
        }}
        
        function toggleService(service_id) {{
            const toggleButton = document.getElementById(`toggle-${{service_id}}`);
            if (!toggleButton) {{
                console.error('Toggle button not found for service:', service_id);
                return;
            }}
            const isRunning = toggleButton.textContent === 'Stop';
            console.log('toggleService called for', service_id, 'isRunning:', isRunning);
            // Disable button during operation
            toggleButton.disabled = true;
            toggleButton.textContent = isRunning ? 'Stopping...' : 'Starting...';
            
            if (isRunning) {{
                const warnings = {{
                    'blockchain_node_1': 'WARNING: Shutting down this node will result in loss of credibility points and network participation rewards.',
                    'blockchain_node_2': 'WARNING: Shutting down this node will result in loss of credibility points and network participation rewards.',
                    'incentive_system': 'WARNING: Shutting down the incentive system will stop reward distribution and node reputation tracking.',
                    'network_coordinator': 'WARNING: Shutting down the coordinator will affect network discovery and node communication.',
                    'backend': 'WARNING: Shutting down the backend will disable voting functionality and API access.',
                    'frontend': 'WARNING: Shutting down the frontend will disable web interface access.'
                }};
                const warning = warnings[service_id] || 'Are you sure you want to stop this service?';
                const confirmMessage = warning + '\\n\\nAre you sure you want to continue?';
                if (confirm(confirmMessage)) {{
                    console.log('Sending POST /stop/' + service_id);
                    fetch('/stop/' + service_id, {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }}
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        console.log('POST /stop/ response:', data);
                        if (data.success) {{
                            // Button will be updated by SSE within 2 seconds
                            setTimeout(() => {{
                                toggleButton.disabled = false;
                                refreshServiceStatus();
                            }}, 2000);
                        }} else {{
                            alert('Failed to stop service: ' + data.error);
                            toggleButton.disabled = false;
                            toggleButton.textContent = 'Stop';
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error stopping service:', error);
                        alert('Error stopping service: ' + error);
                        toggleButton.disabled = false;
                        toggleButton.textContent = 'Stop';
                    }});
                }} else {{
                    console.log('Stop cancelled by user');
                    toggleButton.disabled = false;
                    toggleButton.textContent = 'Stop';
                }}
            }} else {{
                console.log('Sending POST /start/' + service_id);
                fetch('/start/' + service_id, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }}
                }})
                .then(response => response.json())
                .then(data => {{
                    console.log('POST /start/ response:', data);
                    if (data.success) {{
                        // Button will be updated by SSE within 2 seconds
                        setTimeout(() => {{
                            toggleButton.disabled = false;
                            refreshServiceStatus();
                        }}, 2000);
                    }} else {{
                        alert('Failed to start service: ' + data.error);
                        toggleButton.disabled = false;
                        toggleButton.textContent = 'Start';
                    }}
                }})
                .catch(error => {{
                    console.error('Error starting service:', error);
                    alert('Error starting service: ' + error);
                    toggleButton.disabled = false;
                    toggleButton.textContent = 'Start';
                }});
            }}
        }}
        
        function restartService(service_id) {{
            if (confirm('Are you sure you want to restart this service?')) {{
                const restartButton = document.querySelector(`button[onclick="restartService('${{service_id}}')"]`);
                if (restartButton) {{
                    restartButton.disabled = true;
                    restartButton.textContent = 'Restarting...';
                }}
                
                fetch('/restart/' + service_id, {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }}
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        // Status will be updated by SSE within 2 seconds
                        // The button will be automatically reset by the SSE update
                        console.log('Restart successful, waiting for SSE update...');
                    }} else {{
                        alert('Failed to restart service: ' + data.error);
                        if (restartButton) {{
                            restartButton.disabled = false;
                            restartButton.textContent = 'Restart';
                        }}
                    }}
                }})
                .catch(error => {{
                    alert('Error restarting service: ' + error);
                    if (restartButton) {{
                        restartButton.disabled = false;
                        restartButton.textContent = 'Restart';
                    }}
                }});
            }}
        }}
        
        // Initialize real-time updates with Server-Sent Events
        let eventSource = initEventSource();
        
        // Initial status check after 1 second
        setTimeout(refreshServiceStatus, 1000);
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

    def _get_process_resources(self, pid: int) -> tuple[float, float]:
        """Get CPU and memory usage for a process with proper caching"""
        import time
        current_time = time.time()
        
        # Check if we need to update (every 2 seconds)
        if pid in self.last_update and current_time - self.last_update[pid] < 2.0:
            # Return cached values
            return self.cpu_cache.get(pid, 0.0), self.memory_cache.get(pid, 0.0)
        
        try:
            proc = psutil.Process(pid)
            
            # Get CPU percentage with better accuracy
            if pid not in self.cpu_cache:
                # First call primes the counter and returns 0.0
                proc.cpu_percent(interval=None)
                cpu_percent = 0.0
            else:
                # Get actual CPU usage - this gives more accurate readings
                cpu_percent = proc.cpu_percent(interval=None)
                # If still 0.0, try to get a more sensitive reading
                if cpu_percent == 0.0:
                    # Use a small interval to get more sensitive readings
                    cpu_percent = proc.cpu_percent(interval=0.1)
            
            # Get memory usage
            memory_mb = proc.memory_info().rss / 1024 / 1024
            
            # Update caches
            self.cpu_cache[pid] = cpu_percent
            self.memory_cache[pid] = memory_mb
            self.last_update[pid] = current_time
            
            return cpu_percent, memory_mb
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process no longer exists or we can't access it - clean up cache
            self._cleanup_process_cache(pid)
            return 0.0, 0.0
        except Exception as e:
            logger.debug(f"Error getting process resources for PID {pid}: {e}")
            # Don't clean up cache on general exceptions - might be temporary
            # Only return 0.0 values
            return 0.0, 0.0
    
    def _cleanup_process_cache(self, pid: int):
        """Clean up cache entries for a terminated process"""
        try:
            if pid in self.cpu_cache:
                del self.cpu_cache[pid]
            if pid in self.memory_cache:
                del self.memory_cache[pid]
            if pid in self.last_update:
                del self.last_update[pid]
        except KeyError:
            # Entry already removed
            pass
    
    def _cleanup_process_resources(self, pid: int):
        """Clean up all resources for a terminated process"""
        # Clean up cache
        self._cleanup_process_cache(pid)
        
        # Clean up any child processes
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

async def main():
    """Main function with enhanced graceful shutdown"""
    print("🚀 MediVote Background Service Manager")
    print("=" * 50)
    print("Starting all MediVote services in background")
    print("Each service will have its own dashboard")
    print("=" * 50)
    
    manager = MediVoteBackgroundManager()
    
    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\n🛑 Received signal {signum}, initiating graceful shutdown...")
        # This will be handled in the main loop
    
    # Register signal handlers
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start all services
        await manager.start_all_services()
        
        print("\n✅ All services started successfully!")
        print("🌐 Management Dashboard: http://localhost:8090")
        print("\n🔗 Service URLs:")
        for service_id, config in manager.service_configs.items():
            print(f"  • {config['name']}: http://localhost:{config['port']}")
        print("\n📊 Dashboard URLs:")
        for service_id, config in manager.service_configs.items():
            if "dashboard_port" in config:
                print(f"  • {config['name']} Dashboard: http://localhost:{config['dashboard_port']}")
        
        print("\n⚠️ Credibility Warning: Stopping services may result in loss of credibility points!")
        print("🛑 Press Ctrl+C to stop all services gracefully")
        
        # Keep running with periodic health checks
        shutdown_requested = False
        while not shutdown_requested:
            try:
                # Check for shutdown signals
                if hasattr(manager, '_shutdown_requested') and manager._shutdown_requested:
                    shutdown_requested = True
                    break
                
                # Periodic health check every 30 seconds
                await asyncio.sleep(30)
                
                # Optional: Log system health
                if hasattr(manager, 'get_service_status'):
                    status = manager.get_service_status()
                    running_services = sum(1 for s in status.values() if s.get('status') == 'running')
                    total_services = len(status)
                    if running_services < total_services:
                        logger.info(f"Health check: {running_services}/{total_services} services running")
                
            except KeyboardInterrupt:
                print("\n🛑 Keyboard interrupt received, initiating graceful shutdown...")
                shutdown_requested = True
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying
        
        # Graceful shutdown
        if shutdown_requested:
            print("\n🔄 Initiating graceful shutdown...")
            await manager.stop_all_services()
            print("✅ All services stopped gracefully")
        
    except KeyboardInterrupt:
        print("\n🛑 Keyboard interrupt received, stopping all services...")
        await manager.stop_all_services()
        print("✅ All services stopped gracefully")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Critical error in main function: {e}")
        
        # Emergency cleanup
        try:
            print("🧹 Performing emergency cleanup...")
            await manager.stop_all_services()
        except Exception as cleanup_error:
            logger.error(f"Error during emergency cleanup: {cleanup_error}")
        
        return 1
    
    finally:
        # Final cleanup
        try:
            print("🧹 Performing final system cleanup...")
            
            # Clean up any remaining resources
            if hasattr(manager, '_cleanup_global_resources'):
                await manager._cleanup_global_resources()
            
            # Clean up temporary files
            if hasattr(manager, '_cleanup_temp_directories'):
                await manager._cleanup_temp_directories()
            
            print("✅ System cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during final cleanup: {e}")
    
    print("🎯 MediVote Service Manager shutdown complete")
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 