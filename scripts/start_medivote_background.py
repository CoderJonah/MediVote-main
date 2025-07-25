#!/usr/bin/env python3
"""
MediVote Background Startup Script
"""

import asyncio
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import queue
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional
import http.server
import socketserver
import webbrowser
import random

# Configure logging with UTF-8 encoding support
import sys
import os

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Configure logging with proper encoding
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/medivote_background.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ],
    force=True  # Force reconfiguration
)
logger = logging.getLogger(__name__)

class MediVoteBackgroundManager:
    """Manages all MediVote services running in background"""
    
    def __init__(self):
        """Initialize the MediVote background service manager"""
        self.is_running = True
        self.processes = {}
        self.service_pids = {}
        self.memory_cache: Dict[int, float] = {}
        self.last_update: Dict[int, float] = {}
        self.stopped_services: set[str] = set()
        self._lock = threading.Lock()
        self._shutdown_requested = False  # Add shutdown flag
        
        # Concurrent operation handling
        self.service_locks = {}
        self.operation_queues = {}
        self.active_operations = {}
        
        # Health monitoring attributes
        self.service_failures = {}
        self.service_recovery_attempts = {}
        self.service_last_failure = {}
        self.service_uptime = {}
        self.service_last_check = {}
        self.last_health_check = {}
        self.service_health = {}
        self.failure_counts = {}
        self.cpu_cache = {}  # Add missing CPU cache
        
        # Auto-recovery settings
        self.auto_recovery_enabled = {}
        self.auto_recovery_cooldown = 30  # seconds
        self.max_failures_before_disable = 3
        
        # Health check settings
        self.health_check_interval = 5  # seconds
        self.health_check_timeout = 10  # seconds
        
        # Shutdown throttling to prevent HTTP timeout issues
        self.last_shutdown_time = {}  # Track last shutdown time per service
        self.shutdown_throttle_delay = 1.0  # Reduced from 2.0 to 1.0 seconds
        self.bulk_shutdown_mode = False  # Flag to indicate we're doing a bulk shutdown
        
        # Result queue for async operations
        self.result_queue = queue.Queue()
        
        # Service configurations
        self.service_configs = {
            "backend": {
                "name": "MediVote Backend",
                "command": ["python3", "src/backend/main.py"],
                "port": 8001,
                "dashboard_port": 8091,
                "auto_restart": True,
                "auto_recovery_enabled": True,  # Changed to True
                "startup_delay": 3,
                "log_file": "logs/backend.log"
            },
            "blockchain_node": {
                "name": "Blockchain Node",
                "command": ["python3", "scripts/blockchain_node.py", "--config", "config/node_config_1.json"],
                "port": 8546,
                "dashboard_port": 8093,
                "auto_restart": True,
                "auto_recovery_enabled": True,  # Changed to True
                "startup_delay": 2,
                "log_file": "logs/blockchain_node.log"
            },

            "network_coordinator": {
                "name": "Network Coordinator",
                "command": ["python3", "scripts/network_coordinator.py"],
                "port": 8083,
                "dashboard_port": 8096,
                "auto_restart": True,
                "auto_recovery_enabled": True,  # Changed to True
                "startup_delay": 2,
                "log_file": "logs/network_coordinator.log"
            },
            "network_dashboard": {
                "name": "Network Dashboard",
                "command": ["python3", "scripts/network_dashboard.py"],
                "port": 8084,
                "dashboard_port": 8097,
                "auto_restart": True,
                "auto_recovery_enabled": True,  # Changed to True
                "startup_delay": 2,
                "log_file": "logs/network_dashboard.log"
            },
            "frontend": {
                "name": "MediVote Frontend",
                "command": ["python3", "src/frontend/serve.py"],
                "port": 8080,
                "dashboard_port": 8098,
                "auto_restart": True,
                "auto_recovery_enabled": True,  # Changed to True
                "startup_delay": 3,
                "log_file": "logs/frontend.log"
            }
        }
        
        # Initialize auto-recovery status for all services
        for service_id in self.service_configs:
            self.auto_recovery_enabled[service_id] = self.service_configs[service_id]["auto_recovery_enabled"]
            self.failure_counts[service_id] = 0
            self.service_health[service_id] = {
                'status': 'unknown',
                'last_check': 0,
                'uptime': 0,
                'start_time': None,
                'process_healthy': False,
                'port_healthy': False,
                'http_healthy': False
            }
        
        # Initialize service locks and queues
        for service_id in self.service_configs:
            self.service_locks[service_id] = threading.Lock()
            self.operation_queues[service_id] = []
        
        # Credibility warnings for critical services
        self.credibility_warnings = {
            "backend": "WARNING: Shutting down the backend will disable API access.",
            "frontend": "WARNING: Shutting down the frontend will disable web interface access.",
            "blockchain_node": "WARNING: Shutting down blockchain node may affect voting integrity.",
            "network_coordinator": "WARNING: Shutting down the coordinator will affect network discovery and node communication.",
            "network_dashboard": "WARNING: Shutting down the dashboard will disable network monitoring."
        }
        
        # Create node configurations
        self._create_node_configs()
        
        # Start health monitoring - DON'T start it here as we're not in an async context yet
        # It will be started in start_all_services()
    
    def _handle_concurrent_operation(self, service_id: str, operation: str, operation_func, *args, **kwargs):
        """Handle concurrent operations safely with queuing and service-specific locks"""
        if service_id not in self.service_locks:
            logger.error(f"Unknown service: {service_id}")
            return False
        
        service_lock = self.service_locks[service_id]
        
        with service_lock:
            # Check for conflicting operations
            if service_id in self.active_operations:
                current_op = self.active_operations[service_id]
                
                # Allow compatible operations
                if operation == "restart" and current_op == "restart":
                    # Allow concurrent restart operations - they're idempotent
                    logger.info(f"Allowing concurrent restart operation on {service_id}")
                elif operation == "start" and current_op == "restart":
                    # Allow start during restart (service might not be running)
                    logger.info(f"Allowing start operation during restart for {service_id}")
                elif operation == "restart" and current_op in ["start", "stop"]:
                    # Allow restart to override start/stop
                    logger.info(f"Restart operation overriding {current_op} for {service_id}")
                else:
                    logger.warning(f"Service {service_id} has active operation '{current_op}', rejecting '{operation}'")
                    return False
            
            # Mark this operation as active
            self.active_operations[service_id] = operation
            logger.info(f"Starting operation '{operation}' on service {service_id}")
            
        # Execute outside the lock to avoid deadlocks
        try:
            # Return the function to be called - let the caller handle async/sync
            return operation_func, args, kwargs
        finally:
            # Clear active operation after operation completes (not in a background thread)
            # This will be done by the caller after the operation completes
            pass
    
    def _create_node_configs(self):
        """Create node configuration for the blockchain node with network discovery"""
        # Create config for single blockchain node with proper network registration
        config = {
            "node": {
                "name": "MediVote Blockchain Node",
                "port": 8545,
                "rpc_port": 8546,
                "http_port": 8546,  # HTTP interface port
                "max_peers": 50,
                "sync_interval": 30,
                "block_time": 15,
                "enable_http": True,  # Enable HTTP interface
                "enable_rpc": True,   # Enable RPC interface
                "register_with_coordinator": True,  # Auto-register with network coordinator
                "coordinator_url": "http://localhost:8083"  # Network coordinator endpoint
            },
            "network": {
                "bootstrap_nodes": ["127.0.0.1:8083"],  # Include network coordinator
                "network_id": "medivote_mainnet",
                "genesis_block": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "auto_discovery": True,  # Enable automatic node discovery
                "heartbeat_interval": 10  # Send heartbeat every 10 seconds
            },
            "blockchain": {
                "rpc_url": "http://localhost:8546",
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
        
        config_file = "node_config_1.json"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Create network data directory for node registration
        network_data_dir = "./network_data"
        os.makedirs(network_data_dir, exist_ok=True)
        
        # Create nodes.json file if it doesn't exist
        nodes_file = os.path.join(network_data_dir, "nodes.json")
        if not os.path.exists(nodes_file):
            initial_nodes = {
                "nodes": [],
                "last_updated": datetime.now().isoformat()
            }
            with open(nodes_file, 'w') as f:
                json.dump(initial_nodes, f, indent=2)
        
        # Ensure blockchain data directory exists
        data_dir = "./blockchain_data"
        os.makedirs(data_dir, exist_ok=True)
        
        logger.info(f"Created node configuration: {config_file}")
        logger.info("Node configured for automatic network registration")
    
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
        if current_time - self.last_health_check.get(service_id, 0) < self.health_check_interval:
            return True
        
        # Update the last check time
        self.last_health_check[service_id] = current_time
        
        try:
            # Method 1: Process check
            process_healthy = False
            if service_id in self.processes:
                process = self.processes[service_id]
                if process.poll() is None:  # Process is still running
                    process_healthy = True
            
            # Method 2: Port check
            port_healthy = False
            if "port" in config:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex(('localhost', config["port"]))
                    sock.close()
                    port_healthy = (result == 0)
                except Exception:
                    port_healthy = False
            
            # Method 3: HTTP health check
            http_healthy = False
            if "port" in config and config["port"] in [8001, 8080, 8083, 8084]:
                try:
                    import requests
                    response = requests.get(f"http://localhost:{config['port']}/health", timeout=3)
                    http_healthy = (response.status_code == 200)
                except Exception:
                    http_healthy = False
            
            # Determine overall health
            is_healthy = process_healthy or port_healthy or http_healthy
            
            # Update health metrics with proper None handling
            if service_id in self.service_health:
                uptime = 0
                start_time = self.service_health[service_id].get('start_time')
                if start_time is not None and service_id in self.processes and self.processes[service_id].poll() is None:
                    uptime = current_time - start_time
                
                self.service_health[service_id].update({
                    'status': 'healthy' if is_healthy else 'unhealthy',
                    'last_check': current_time,
                    'uptime': uptime,
                    'process_healthy': process_healthy,
                    'port_healthy': port_healthy,
                    'http_healthy': http_healthy
                })
            
            return is_healthy
            
        except Exception as e:
            logger.error(f"Health check error for {service_id}: {e}")
            return False
    
    async def _auto_recover_service(self, service_id: str) -> bool:
        """Automatically recover a failed service"""
        try:
            # Check if auto-recovery is enabled for this service
            if not self.auto_recovery_enabled.get(service_id, False):
                logger.info(f"Auto-recovery disabled for {service_id}, skipping recovery attempt")
                return False
            
            # Check cooldown period
            last_failure = self.service_last_failure.get(service_id, 0)
            current_time = time.time()
            if current_time - last_failure < self.auto_recovery_cooldown:
                logger.info(f"Auto-recovery cooldown active for {service_id}, skipping recovery attempt")
                return False
            
            logger.info(f"Attempting auto-recovery for {service_id}")
            
            # Attempt to restart the service
            success = await self.start_service(service_id)
            
            if success:
                logger.info(f"Auto-recovery successful for {service_id}")
                self._record_service_success(service_id)
                return True
            else:
                logger.warning(f"Auto-recovery failed for {service_id}")
                self._record_service_failure(service_id, "Auto-recovery attempt failed")
                return False
                
        except Exception as e:
            logger.error(f"Error during auto-recovery for {service_id}: {e}")
            self._record_service_failure(service_id, str(e))
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
                        
                        if not is_healthy and self.auto_recovery_enabled.get(service_id, False):
                            logger.warning(f"Service {service_id} is unhealthy, attempting recovery")
                            await self._auto_recover_service(service_id)
                    
                    except Exception as e:
                        logger.error(f"Health check error for {service_id}: {e}")
                        continue
                
                # Wait before next health check cycle
                await asyncio.sleep(self.health_check_interval)
                
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    def get_service_health_info(self, service_id: str) -> dict:
        """Get health information for a specific service"""
        if service_id not in self.service_configs:
            return {}
        
        # Use the service_health dictionary which is properly maintained
        if service_id in self.service_health:
            health_data = self.service_health[service_id].copy()
            # Add additional fields
            health_data['auto_recovery_enabled'] = self.auto_recovery_enabled.get(service_id, False)
            health_data['restart_count'] = self.service_recovery_attempts.get(service_id, 0)
            health_data['recovery_attempts'] = self.service_recovery_attempts.get(service_id, 0)
            return health_data
        
        # Fallback for services not yet checked
        current_time = time.time()
        return {
            'status': 'unknown',
            'last_check': 0,
            'uptime': 0,
            'restart_count': 0,
            'failure_count': 0,
            'last_failure': None,
            'recovery_attempts': 0,
            'auto_recovery_enabled': self.auto_recovery_enabled.get(service_id, False)
        }
    
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
            "blockchain_node", 
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
        result = self._handle_concurrent_operation(service_id, "start", self._start_service_impl, service_id)
        
        if result is False:
            return False
        
        # Result is a tuple of (function, args, kwargs)
        if isinstance(result, tuple) and len(result) == 3:
            func, args, kwargs = result
            try:
                # Execute the async function
                start_result = await func(*args, **kwargs)
                return start_result
            finally:
                # Clear active operation after completion
                if service_id in self.active_operations:
                    del self.active_operations[service_id]
        
        return False
    
    def is_valid_service(self, service_id: str) -> bool:
        """Check if a service ID is valid"""
        return service_id in self.service_configs
    
    async def _start_service_impl(self, service_id: str) -> bool:
        """Internal implementation of start_service"""
        config = self.service_configs[service_id]
        
        # Check if service is already running
        if service_id in self.processes and self.processes[service_id].poll() is None:
            logger.info(f"Service {service_id} is already running")
            return True
        
        # Check if port is already in use - this detects services started outside of the manager
        if "port" in config:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', config["port"]))
                sock.close()
                if result == 0:  # Port is in use
                    logger.info(f"Service {service_id} is already running on port {config['port']}")
                    # Try to find the actual process using the port
                    try:
                        import psutil
                        for conn in psutil.net_connections():
                            if conn.laddr.port == config["port"] and conn.status == 'LISTEN':
                                if conn.pid:
                                    # Create a process entry with the actual PID
                                    self.processes[service_id] = type('MockProcess', (), {
                                        'poll': lambda self=None: None,
                                        'pid': conn.pid,
                                        'terminate': lambda self=None: None,
                                        'kill': lambda self=None: None
                                    })()
                                    self.service_pids[service_id] = conn.pid
                                    logger.info(f"Found existing process for {service_id} with PID: {conn.pid}")
                                    return True
                    except Exception as e:
                        logger.debug(f"Could not find process for port {config['port']}: {e}")
                    
                    # Fallback to dummy process if we can't find the actual PID
                    self.processes[service_id] = type('MockProcess', (), {
                        'poll': lambda self=None: None,
                        'pid': -1,
                        'terminate': lambda self=None: None,
                        'kill': lambda self=None: None
                    })()
                    self.service_pids[service_id] = -1
                    return True
            except Exception:
                pass
        
        try:
            logger.info(f"Starting {config['name']}...")
            
            # Remove from stopped services tracking if it was stopped
            if hasattr(self, 'stopped_services') and service_id in self.stopped_services:
                self.stopped_services.remove(service_id)
            
            # Prepare command
            cmd = config["command"].copy()
            
            # Add config file if specified
            if "config_file" in config:
                cmd.extend(["--config", config["config_file"]])
            
            # Create log directory if it doesn't exist
            log_file = config.get("log_file", f"logs/{service_id}.log")
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                logger.debug(f"Created log directory: {log_dir}")
            
            # Create logs directory if it doesn't exist
            if not os.path.exists("logs"):
                os.makedirs("logs", exist_ok=True)
                logger.debug("Created logs directory")
            
            # Ensure log file exists (create empty file if it doesn't exist)
            if log_file and not os.path.exists(log_file):
                try:
                    with open(log_file, 'a') as f:
                        f.write(f"# Log file created for {service_id} at {datetime.now()}\n")
                    logger.debug(f"Created log file: {log_file}")
                except Exception as e:
                    logger.warning(f"Could not create log file {log_file}: {e}")
            
            # Start the process with proper log file redirection
            try:
                # Open log file for writing
                log_file = config.get("log_file", f"logs/{service_id}.log")
                log_handle = open(log_file, 'a', encoding='utf-8')
                
                process = subprocess.Popen(
                    cmd,
                    stdout=log_handle,
                    stderr=log_handle,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Store log handle for cleanup later
                if not hasattr(self, 'log_handles'):
                    self.log_handles = {}
                self.log_handles[service_id] = log_handle
                
                # Wait a moment to see if it starts successfully
                await asyncio.sleep(2)
                
                if process.poll() is None:  # Process is still running
                    self.processes[service_id] = process
                    self.service_pids[service_id] = process.pid
                    
                    # Update health tracking
                    if service_id in self.service_health:
                        self.service_health[service_id].update({
                            'start_time': time.time(),
                            'status': 'running',
                            'last_check': time.time()
                        })
                    
                    logger.info(f"Started {config['name']} (PID: {process.pid}) on port {config.get('port', 'N/A')}")
                    return True
                else:
                    # Process failed to start
                    stdout, stderr = process.communicate()
                    logger.error(f"Process for {service_id} failed to start")
                    if stdout:
                        logger.debug(f"STDOUT: {stdout}")
                    if stderr:
                        logger.debug(f"STDERR: {stderr}")
                    return False
                    
            except FileNotFoundError:
                logger.error(f"Command not found: {cmd[0]}")
                return False
            except Exception as e:
                logger.error(f"Failed to start {config['name']}: {e}")
                return False
        
        except Exception as e:
            logger.error(f"Error starting {service_id}: {e}")
            return False
    
    async def start_dashboard_servers(self):
        """Start individual dashboard servers for each service"""
        logger.info("Starting dashboard servers...")
        
        for service_id, config in self.service_configs.items():
            if "dashboard_port" in config:
                try:
                    await self.start_service_dashboard(service_id)
                except Exception as e:
                    logger.error(f"Failed to start {config['name']} dashboard: {e}")
        
        logger.info("Dashboard servers started")
    
    def _find_available_port(self, start_port: int, max_attempts: int = 10) -> int:
        """Find an available port starting from start_port"""
        for i in range(max_attempts):
            port = start_port + i
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                if result != 0:  # Port is available
                    return port
            except Exception:
                continue
        # If no port found, try a random port in a higher range
        for _ in range(5):
            port = random.randint(9000, 9999)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                if result != 0:  # Port is available
                    logger.warning(f"Using random port {port} instead of {start_port}")
                    return port
            except Exception:
                continue
        return start_port  # Fallback to original port
    
    async def start_service_dashboard(self, service_id: str):
        """Start a dashboard server for a specific service"""
        config = self.service_configs[service_id]
        
        # Skip if no dashboard port configured
        if "dashboard_port" not in config:
            return
            
        original_port = config["dashboard_port"]
        dashboard_port = self._find_available_port(original_port)
        
        if dashboard_port != original_port:
            logger.info(f"Port {original_port} in use, using {dashboard_port} for {config['name']} dashboard")
        
        try:
            # Create dashboard HTML
            dashboard_html = self._create_service_dashboard(service_id, config)
            
            # Start dashboard server
            class ServiceDashboardHandler(http.server.SimpleHTTPRequestHandler):
                def finish(self):
                    """Override finish to prevent errors on connection aborts"""
                    try:
                        super().finish()
                    except (ValueError, OSError, ConnectionAbortedError):
                        # Ignore errors when connection is already closed or aborted
                        pass
                
                def handle_one_request(self):
                    """Override handle_one_request to prevent connection errors"""
                    try:
                        super().handle_one_request()
                    except (ValueError, OSError, ConnectionAbortedError) as e:
                        # Ignore errors when connection is already closed or aborted
                        pass
                
                def do_HEAD(self):
                    """Handle HEAD requests - simplified and robust implementation"""
                    try:
                        if self.path == '/' or self.path == '':
                            # Fast HEAD response without calculating content length
                            self.send_response(200)
                            self.send_header('Content-Type', 'text/html; charset=utf-8')
                            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                            self.send_header('Connection', 'close')
                            self.end_headers()
                            # No body for HEAD requests
                        elif self.path == '/favicon.ico':
                            self.send_response(204)
                            self.send_header('Connection', 'close')
                            self.end_headers()
                        else:
                            self.send_response(404)
                            self.send_header('Connection', 'close')
                            self.end_headers()
                    except Exception as e:
                        # More comprehensive error handling
                        try:
                            self.send_response(500)
                            self.send_header('Connection', 'close')
                            self.end_headers()
                        except:
                            pass  # If we can't even send error response, just give up

                def do_GET(self):
                    try:
                        if self.path == '/' or self.path == '':
                            # Pre-encode the HTML for faster response
                            html_bytes = dashboard_html.encode('utf-8')
                            self.send_response(200)
                            self.send_header('Content-Type', 'text/html; charset=utf-8')
                            self.send_header('Content-Length', str(len(html_bytes)))
                            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                            self.send_header('Connection', 'close')  # Close connection after response
                            self.end_headers()
                            self.wfile.write(html_bytes)
                            self.wfile.flush()  # Ensure immediate send
                        elif self.path == '/favicon.ico':
                            # Return empty favicon to prevent 404
                            self.send_response(204)
                            self.send_header('Content-Length', '0')
                            self.send_header('Connection', 'close')
                            self.end_headers()
                        else:
                            # For any other path, return a simple 404
                            self.send_response(404)
                            self.send_header('Content-Type', 'text/html')
                            self.send_header('Content-Length', '9')
                            self.send_header('Connection', 'close')
                            self.end_headers()
                            self.wfile.write(b'Not Found')
                    except (ConnectionAbortedError, BrokenPipeError, OSError):
                        # Connection was aborted by client - this is normal
                        pass
            
            # Start dashboard server in background with optimizations
            dashboard_server = socketserver.TCPServer(("", dashboard_port), ServiceDashboardHandler)
            dashboard_server.timeout = 5  # Shorter timeout to prevent hanging
            dashboard_server.allow_reuse_address = True  # Allow quick restart
            dashboard_server.request_queue_size = 1  # Minimal queue to prevent backlog
            logger.info(f"Started {config['name']} dashboard on port {dashboard_port}")
            
            # Run server in background to allow health monitoring to run
            logger.info("Starting HTTP server in background...")
            def run_server():
                try:
                    dashboard_server.serve_forever()
                except KeyboardInterrupt:
                    logger.info("HTTP server stopped by user")
                except Exception as e:
                    logger.error(f"HTTP server error: {e}")
                finally:
                    try:
                        dashboard_server.shutdown()
                        dashboard_server.server_close()
                    except Exception as e:
                        logger.error(f"Error shutting down HTTP server: {e}")
            
            # Start server in background thread
            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()
            
            # Give server a moment to start
            await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Failed to start {config['name']} dashboard: {e}")
    
    def _create_service_dashboard(self, service_id: str, config: dict) -> str:
        """Create full-featured HTML dashboard for a specific service"""
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
        button.auto-recovery-btn {{ background: #6c757d; color: white; }}
        button.auto-recovery-btn.enabled {{ background: #28a745; }}
        button.auto-recovery-btn.disabled {{ background: #6c757d; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .info-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
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
        """Monitor a specific service for crashes and restart if needed"""
        while self.is_running:
            try:
                if service_id in self.processes:
                    process = self.processes[service_id]
                    if process.poll() is not None:  # Process has terminated
                        logger.warning(f"Service {service_id} has crashed, attempting restart...")
                        asyncio.run(self._auto_recover_service(service_id))
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Error monitoring {service_id}: {e}")
                time.sleep(5)
    
    async def stop_service(self, service_id: str, force: bool = False) -> bool:
        """Stop a specific service gracefully with shutdown throttling"""
        if service_id not in self.service_configs:
            logger.error(f"Unknown service: {service_id}")
            return False
        
        # Implement lightweight shutdown throttling 
        current_time = time.time()
        if service_id in self.last_shutdown_time:
            time_since_last_shutdown = current_time - self.last_shutdown_time[service_id]
            # Use minimal throttling delay for bulk shutdown
            throttle_delay = 0.3 if self.bulk_shutdown_mode else 0.5
            if time_since_last_shutdown < throttle_delay:
                throttle_wait = throttle_delay - time_since_last_shutdown
                logger.debug(f"Brief throttling for {service_id}, waiting {throttle_wait:.1f}s")
                await asyncio.sleep(throttle_wait)
        
        # Record this shutdown attempt
        self.last_shutdown_time[service_id] = time.time()
        
        # Use concurrent operation handler to prevent race conditions
        result = self._handle_concurrent_operation(service_id, "stop", self._stop_service_impl, service_id, force)
        
        if result is False:
            return False
        
        # Result is a tuple of (function, args, kwargs)
        if isinstance(result, tuple) and len(result) == 3:
            func, args, kwargs = result
            try:
                # Execute the async function
                stop_result = await func(*args, **kwargs)
                return stop_result
            finally:
                # Clear active operation after completion
                if service_id in self.active_operations:
                    del self.active_operations[service_id]
        
        return False
    
    async def _stop_service_impl(self, service_id: str, force: bool = False) -> bool:
        """Internal implementation of stop_service"""
        if service_id not in self.service_configs:
            logger.error(f"Unknown service: {service_id}")
            return False
        
        config = self.service_configs[service_id]
        logger.info(f"Stopping {config['name']}...")
        
        # Temporarily disable auto-recovery for this service to prevent restart
        original_auto_recovery = self.auto_recovery_enabled.get(service_id, False)
        self.auto_recovery_enabled[service_id] = False
        logger.info(f"Temporarily disabled auto-recovery for {service_id}")
        
        # Check if service is running
        if service_id not in self.processes:
            logger.warning(f"Service {service_id} is not running")
            # Restore auto-recovery setting
            self.auto_recovery_enabled[service_id] = original_auto_recovery
            return True  # Consider it already stopped
        
        process = self.processes[service_id]
        
        # Check if it's a mock process (PID -1 or no real process methods)
        is_mock_process = (hasattr(process, 'pid') and process.pid == -1) or not hasattr(process, 'poll')
        
        if is_mock_process:
            # For mock processes, just remove from tracking
            logger.info(f"Stopping mock process for {config['name']}")
            if service_id in self.processes:
                del self.processes[service_id]
            if service_id in self.service_pids:
                del self.service_pids[service_id]
            logger.info(f"Mock process for {config['name']} stopped")
            # Note: We don't restore auto-recovery here as service is stopped
            return True
        
        # Try graceful shutdown first
        if not force:
            graceful_success = await self._try_graceful_shutdown(service_id, config, process)
            if graceful_success:
                logger.info(f"{config['name']} stopped gracefully")
                # Cleanup
                await self._cleanup_service_resources(service_id, process.pid if hasattr(process, 'pid') else None)
                # Note: We don't restore auto-recovery here as service is stopped
                return True
        
        # Force stop if graceful failed or force=True
        try:
            if hasattr(process, 'terminate'):
                process.terminate()
                logger.info(f"Sending SIGTERM to {config['name']} (PID: {process.pid})")
                
                # Wait for termination
                termination_success = await self._wait_for_termination(process, config['name'], timeout=5)
                if termination_success:
                    logger.info(f"{config['name']} stopped gracefully via SIGTERM")
                else:
                    # Force kill if SIGTERM didn't work
                    if hasattr(process, 'kill'):
                        process.kill()
                        logger.info(f"Force killed {config['name']} (PID: {process.pid})")
                    else:
                        logger.warning(f"Could not force kill {config['name']} - no kill method")
            else:
                logger.warning(f"Could not terminate {config['name']} - no terminate method")
        except Exception as e:
            logger.error(f"Error stopping {config['name']}: {e}")
        
        # Cleanup
        try:
            await self._cleanup_service_resources(service_id, process.pid if hasattr(process, 'pid') else None)
        except Exception as e:
            logger.error(f"Error during cleanup of {service_id}: {e}")
        
        # Remove from tracking
        if service_id in self.processes:
            del self.processes[service_id]
        if service_id in self.service_pids:
            del self.service_pids[service_id]
        
        # Close log handle if it exists
        if hasattr(self, 'log_handles') and service_id in self.log_handles:
            try:
                self.log_handles[service_id].close()
                del self.log_handles[service_id]
                logger.debug(f"Closed log handle for {service_id}")
            except Exception as e:
                logger.warning(f"Error closing log handle for {service_id}: {e}")
        
        logger.info(f"Stopped {config['name']}")
        # Note: We don't restore auto-recovery here as service is successfully stopped
        return True
    
    async def _check_service_responsive(self, service_id: str, config: dict) -> bool:
        """Check if service is actually running and responsive before attempting HTTP shutdown"""
        if "port" not in config:
            return False
        
        # First check if the process is even running
        if service_id in self.processes:
            process = self.processes[service_id]
            if process.poll() is not None:  # Process has terminated
                logger.info(f"Service {config['name']} process is not running (PID terminated)")
                return False
        
        # Then check if port is actually listening
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Very quick check
            result = sock.connect_ex(('localhost', config["port"]))
            sock.close()
            
            if result != 0:  # Port not listening
                logger.info(f"Service {config['name']} port {config['port']} is not listening")
                return False
        except Exception as e:
            logger.info(f"Service {config['name']} port check failed: {e}")
            return False
        
        # Finally, try a quick HTTP health check (but only if port is listening)
        try:
            import requests
            response = requests.get(f"http://localhost:{config['port']}/status", timeout=1)
            is_responsive = response.status_code == 200
            if not is_responsive:
                logger.info(f"Service {config['name']} HTTP health check failed (status {response.status_code})")
            return is_responsive
        except Exception as e:
            logger.info(f"Service {config['name']} HTTP health check failed: {e}")
            return False
    
    async def _try_graceful_shutdown(self, service_id: str, config: dict, process) -> bool:
        """Try graceful shutdown via HTTP endpoint - TIERED APPROACH with service health check"""
        
        # 🏗️ TIER 1: Critical Services (HTTP + SIGTERM Fallback)
        # These services have proper /shutdown endpoints and handle state/data
        tier1_critical_services = ['backend', 'blockchain_node', 'network_coordinator']
        
        # 🔧 TIER 2: Simple Services (HTTP + SIGTERM Fallback)
        # These services have basic shutdown endpoints
        tier2_simple_services = ['network_dashboard', 'frontend']
        
        if service_id in tier1_critical_services or service_id in tier2_simple_services:
            # First check if service is actually responsive
            is_responsive = await self._check_service_responsive(service_id, config)
            if not is_responsive:
                logger.info(f"Service {config['name']} is not responsive, skipping HTTP shutdown")
                return False
            
            logger.info(f"TIER 1/2: Attempting HTTP graceful shutdown for {config['name']}")
            try:
                import requests
                # Use shorter timeouts for faster shutdown
                shutdown_wait_timeout = 5 if service_id == 'backend' else 3
                # Reduced HTTP request timeout for faster shutdown
                http_request_timeout = 6 if service_id in ['blockchain_node', 'backend'] else 4
                
                # Create session with reasonable retry logic
                session = requests.Session()
                
                # Configure session with minimal but reasonable retries
                from requests.adapters import HTTPAdapter
                from urllib3.util.retry import Retry
                
                retry_strategy = Retry(
                    total=1,  # One reasonable retry attempt
                    connect=1,  # One connection retry
                    backoff_factor=0.3,  # Short backoff
                    status_forcelist=[500, 502, 503, 504],  # Only retry on server errors
                )
                adapter = HTTPAdapter(max_retries=retry_strategy)
                session.mount("http://", adapter)
                
                # Use internal shutdown endpoint for backend
                shutdown_endpoint = "/internal-shutdown" if service_id == 'backend' else "/shutdown"
                logger.info(f"Sending HTTP shutdown request to {config['name']} on port {config['port']}{shutdown_endpoint}")
                response = session.post(f"http://localhost:{config['port']}{shutdown_endpoint}", timeout=http_request_timeout)
                
                if response.status_code == 200:
                    logger.info(f"SUCCESS: HTTP graceful shutdown signal sent to {config['name']}")
                    # Wait for graceful shutdown with service-specific timeout
                    return await self._wait_for_termination(process, config['name'], timeout=shutdown_wait_timeout)
                else:
                    logger.warning(f"HTTP shutdown returned {response.status_code} for {config['name']}, will fallback to SIGTERM")
                    return False
                    
            except requests.exceptions.Timeout as e:
                logger.warning(f"HTTP shutdown timeout for {config['name']} after {http_request_timeout}s: {e}, will fallback to SIGTERM")
                return False
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"HTTP shutdown connection error for {config['name']}: {e}, will fallback to SIGTERM")
                return False
            except requests.exceptions.RequestException as e:
                logger.warning(f"HTTP shutdown not available for {config['name']}: {e}, will fallback to SIGTERM")
                return False
            except Exception as e:
                logger.warning(f"HTTP shutdown error for {config['name']}: {e}, will fallback to SIGTERM")
                return False
                
        else:
            logger.info(f"Service {service_id} has no HTTP shutdown endpoint, skipping HTTP shutdown")
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
            
            if "command" in config:
                # Get the directory of the first command element (usually the script)
                script_path = config["command"][1] if len(config["command"]) > 1 else config["command"][0]
                script_dir = os.path.dirname(script_path)
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
        logger.info("STOP: Starting graceful shutdown of all services...")
        
        # Step 0: Enable bulk shutdown mode for better HTTP timeout handling
        self.bulk_shutdown_mode = True
        logger.info("Enabled bulk shutdown mode with enhanced throttling")
        
        # Step 1: Disable auto-recovery for all services to prevent restart
        logger.info("Disabling auto-recovery for all services...")
        for service_id in self.service_configs:
            self.auto_recovery_enabled[service_id] = False
        
        # Step 2: Stop management dashboard server gracefully
        await self._stop_management_dashboard()
        
        # Step 3: Stop services in reverse dependency order with enhanced cleanup
        stop_order = [
            "frontend",
            "network_dashboard", 
            "network_coordinator",
            "blockchain_node",
            "backend"
        ]
        
        successful_stops = 0
        total_services = len(stop_order)
        
        for service_id in stop_order:
            if service_id in self.service_configs:
                logger.info(f"Stopping {service_id}...")
                try:
                    # Use a timeout for each service stop to prevent hanging
                    success = await asyncio.wait_for(
                        self.stop_service(service_id), 
                        timeout=15.0  # 15 second timeout per service
                    )
                    if success:
                        successful_stops += 1
                        logger.info(f"{service_id} stopped successfully")
                    else:
                        logger.warning(f"{service_id} failed to stop gracefully")
                except asyncio.TimeoutError:
                    logger.error(f"Timeout stopping {service_id} after 15 seconds")
                    # Try to force kill the process if we have a PID
                    if service_id in self.service_pids:
                        try:
                            import psutil
                            pid = self.service_pids[service_id]
                            if pid > 0:
                                proc = psutil.Process(pid)
                                proc.kill()
                                logger.warning(f"Force killed {service_id} (PID: {pid}) due to timeout")
                        except Exception as kill_error:
                            logger.error(f"Could not force kill {service_id}: {kill_error}")
                except Exception as e:
                    logger.error(f"Error stopping {service_id}: {e}")
                
                # Shorter delay between stops for faster shutdown
                await asyncio.sleep(0.5)  # Reduced from 2.0s to 0.5s for faster shutdown
        
        # Step 4: Final cleanup
        await self._final_cleanup()
        
        # Step 5: Disable bulk shutdown mode
        self.bulk_shutdown_mode = False
        logger.info("Bulk shutdown completed, disabled bulk shutdown mode")
        
        logger.info(f"Shutdown complete: {successful_stops}/{total_services} services stopped successfully")
        
        if successful_stops == total_services:
            logger.info("All services stopped gracefully")
        else:
            logger.warning(f"{total_services - successful_stops} services may not have stopped cleanly")
    
    async def _stop_management_dashboard(self):
        """Stop management dashboard server gracefully"""
        if hasattr(self, 'management_server'):
            try:
                logger.info("Stopping management dashboard server...")
                
                # Shutdown the server gracefully
                self.management_server.shutdown()
                self.management_server.server_close()
                
                # Wait a moment for connections to close
                await asyncio.sleep(1)
        
                logger.info("Management dashboard server stopped")
            except Exception as e:
                logger.error(f"Failed to stop management dashboard server: {e}")
        else:
            logger.info("No management dashboard server to stop")
    
    async def _final_cleanup(self):
        """Perform final cleanup after all services are stopped"""
        try:
            logger.info("Performing final cleanup...")
            
            # Clean up any remaining process resources
            await self._cleanup_remaining_processes()
            
            # Clean up global resources
            await self._cleanup_global_resources()
            
            # Clean up temporary files and directories
            await self._cleanup_temp_directories()
            
            logger.info("Final cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during final cleanup: {e}")
    
    async def _cleanup_remaining_processes(self):
        """Clean up any remaining processes that might not have been properly stopped"""
        try:
            import psutil
            
            # Get list of our managed process PIDs
            managed_pids = set()
            for process in self.processes.values():
                try:
                    if hasattr(process, 'pid') and process.pid > 0:
                        managed_pids.add(process.pid)
                except Exception:
                    pass
            
            # Find any remaining MediVote-related processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info.get('cmdline', [])
                    if not cmdline:
                        continue
                        
                    # Look for MediVote-specific processes
                    is_medivote_process = any(
                        'medivote' in str(arg).lower() or 
                        'blockchain_node.py' in str(arg) or
                        'network_coordinator.py' in str(arg) or
                        'network_dashboard.py' in str(arg)
                        for arg in cmdline
                    )
                    
                    if is_medivote_process and proc.pid not in managed_pids:
                        logger.info(f"Cleaning up orphaned MediVote process: {proc.pid} ({proc.info.get('name', 'unknown')})")
                        try:
                            proc.terminate()
                            proc.wait(timeout=3)
                        except psutil.TimeoutExpired:
                            logger.debug(f"Force killing stubborn process: {proc.pid}")
                            proc.kill()
                        except psutil.AccessDenied:
                            logger.debug(f"Cannot clean up process {proc.pid} (access denied)")
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
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
            
            logger.debug("CLEANUP: Cleared global resource caches")
            
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
                                logger.debug(f"CLEANUP: Cleaned up temp file: {temp_file}")
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
                        logger.info(f"ARCHIVE: Archived large log file: {log_file}")
                except Exception as e:
                    logger.debug(f"Could not archive log file {log_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Error cleaning up temp directories: {e}")
    
    async def restart_service(self, service_id: str) -> bool:
        """Restart a specific service"""
        # Use concurrent operation handler to prevent race conditions
        result = self._handle_concurrent_operation(service_id, "restart", self._restart_service_impl, service_id)
        
        if result is False:
            return False
        
        # Result is a tuple of (function, args, kwargs)
        if isinstance(result, tuple) and len(result) == 3:
            func, args, kwargs = result
            try:
                # Execute the async function
                restart_result = await func(*args, **kwargs)
                return restart_result
            finally:
                # Clear active operation after completion
                if service_id in self.active_operations:
                    del self.active_operations[service_id]
        
        return False
    
    async def _restart_service_impl(self, service_id: str) -> bool:
        """Internal implementation of restart_service with improved timing"""
        try:
            logger.info(f"Restarting {service_id}...")
            
            # Check if service is actually running first
            is_running = False
            if service_id in self.processes:
                process = self.processes[service_id]
                if process and process.poll() is None:
                    is_running = True
            
            # Only stop if actually running
            if is_running:
                try:
                    stop_success = await self._stop_service_impl(service_id)
                    if not stop_success:
                        logger.warning(f"Stop returned false for {service_id} during restart, but continuing...")
                except Exception as e:
                    logger.warning(f"Error stopping {service_id} during restart: {e}, but continuing...")
                
                # Minimal wait for cleanup
                await asyncio.sleep(0.5)
            else:
                logger.info(f"Service {service_id} is not running, treating restart as start")
            
            # Start the service - call _start_service_impl directly to avoid concurrent operation conflict
            start_success = await self._start_service_impl(service_id)
            if start_success:
                logger.info(f"Successfully restarted {service_id}")
                return True
            else:
                logger.error(f"Failed to start {service_id} during restart")
                return False
                
        except Exception as e:
            logger.error(f"Error during restart of {service_id}: {e}")
            return False
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all services"""
        status = {}
        
        for service_id, config in self.service_configs.items():
            service_info = {
                "name": config["name"],
                "port": config.get("port", "N/A"),
                "status": "stopped",
                "pid": None,
                "cpu_percent": 0.0,
                "memory_mb": 0.0,
                "uptime": 0,
                "auto_recovery_enabled": self.get_auto_recovery_status(service_id)
            }
            
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
            if not process_running and "port" in config:
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
                                # Update tracked PID and create process entry
                                self.service_pids[service_id] = current_pid
                                # Create a mock process entry for tracking
                                self.processes[service_id] = type('MockProcess', (), {
                                    'poll': lambda self=None: None,
                                    'pid': current_pid,
                                    'terminate': lambda self=None: None,
                                    'kill': lambda self=None: None
                                })()
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
                    import psutil
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
            port = self._find_available_port(8090)
            
            if port != 8090:
                logger.info(f"Port 8090 in use, using {port} for management dashboard")
            
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
                        self.end_headers()
                        self.wfile.write(dashboard_html.encode())
                    elif self.path == '/status':
                        # Return current service status as JSON - optimized for speed
                        import json
                        if self.manager:
                            status = self.manager.get_service_status()
                        else:
                            status = {}
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.send_header('Cache-Control', 'no-cache')
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
                        self.send_header('Cache-Control', 'no-cache')
                        self.end_headers()
                        self.wfile.write(json.dumps(health_info).encode())
                    elif self.path == '/auto-recovery':
                        # Return auto-recovery status as JSON
                        import json
                        if self.manager:
                            auto_recovery_status = self.manager.get_all_auto_recovery_status()
                        else:
                            auto_recovery_status = {}
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.send_header('Access-Control-Allow-Origin', '*')
                        self.send_header('Cache-Control', 'no-cache')
                        self.end_headers()
                        self.wfile.write(json.dumps(auto_recovery_status).encode())
                    elif self.path == '/events':
                        import json  # Ensure json is imported in this scope
                        # Server-Sent Events for real-time updates - optimized
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
                        
                        # Then start the continuous stream with shorter intervals
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
                                time.sleep(0.5)  # Send updates every 0.5 seconds for faster response
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
                    """Handle POST requests for service control - optimized for speed"""
                    try:
                        # Parse the URL path
                        path = self.path.strip('/')
                        
                        if path.startswith('start/'):
                            service_id = path[6:]  # Remove 'start/' prefix
                            logger.info(f"Received POST /start/ for {service_id}")
                            
                            # Validate service ID first
                            if not self.manager.is_valid_service(service_id):
                                response_data = {
                                    'success': False,
                                    'error': f"Unknown service: {service_id}"
                                }
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.send_header('Cache-Control', 'no-cache')
                                self.end_headers()
                                self.wfile.write(json.dumps(response_data).encode())
                                return
                            
                            def start_service_thread():
                                try:
                                    # Create a new event loop for this thread
                                    loop = asyncio.new_event_loop()
                                    asyncio.set_event_loop(loop)
                                    result = loop.run_until_complete(self.manager.start_service(service_id))
                                    self.manager.result_queue.put(('start', service_id, result))
                                except Exception as e:
                                    logger.error(f"Error starting {service_id}: {e}")
                                    self.manager.result_queue.put(('start', service_id, False))
                                finally:
                                    loop.close()
                            
                            # Start operation in background thread
                            thread = threading.Thread(target=start_service_thread)
                            thread.daemon = True
                            thread.start()
                            
                            # Wait for result with shorter timeout
                            logger.info("Waiting for result from queue...")
                            try:
                                operation, service, result = self.manager.result_queue.get(timeout=15)
                                logger.info(f"Got result from queue: {operation}, {result}")
                            except queue.Empty:
                                logger.warning(f"Timeout waiting for start operation on {service_id}")
                                result = False
                            
                            response_data = {
                                'success': result,
                                'error': None if result else f"Failed to start {service_id}"
                            }
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.send_header('Cache-Control', 'no-cache')
                            self.end_headers()
                            self.wfile.write(json.dumps(response_data).encode())
                            
                        elif path.startswith('stop/'):
                            service_id = path[5:]  # Remove 'stop/' prefix
                            logger.info(f"Received POST /stop/ for {service_id}")
                            
                            # Validate service ID first
                            if not self.manager.is_valid_service(service_id):
                                response_data = {
                                    'success': False,
                                    'error': f"Unknown service: {service_id}"
                                }
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.send_header('Cache-Control', 'no-cache')
                                self.end_headers()
                                self.wfile.write(json.dumps(response_data).encode())
                                return
                            
                            def stop_service_thread():
                                try:
                                    # Create a new event loop for this thread
                                    loop = asyncio.new_event_loop()
                                    asyncio.set_event_loop(loop)
                                    result = loop.run_until_complete(self.manager.stop_service(service_id))
                                    self.manager.result_queue.put(('stop', service_id, result))
                                except Exception as e:
                                    logger.error(f"Error stopping {service_id}: {e}")
                                    self.manager.result_queue.put(('stop', service_id, False))
                                finally:
                                    loop.close()
                            
                            # Start operation in background thread
                            thread = threading.Thread(target=stop_service_thread)
                            thread.daemon = True
                            thread.start()
                            
                            # Wait for result with shorter timeout
                            logger.info("Waiting for result from queue...")
                            try:
                                operation, service, result = self.manager.result_queue.get(timeout=15)
                                logger.info(f"Got result from queue: {operation}, {result}")
                            except queue.Empty:
                                logger.warning(f"Timeout waiting for stop operation on {service_id}")
                                result = False
                            
                            response_data = {
                                'success': result,
                                'error': None if result else f"Failed to stop {service_id}"
                            }
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.send_header('Cache-Control', 'no-cache')
                            self.end_headers()
                            self.wfile.write(json.dumps(response_data).encode())
                            
                        elif path.startswith('restart/'):
                            service_id = path[8:]  # Remove 'restart/' prefix
                            logger.info(f"Received POST /restart/ for {service_id}")
                            
                            # Validate service ID first
                            if not self.manager.is_valid_service(service_id):
                                response_data = {
                                    'success': False,
                                    'error': f"Unknown service: {service_id}"
                                }
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.send_header('Cache-Control', 'no-cache')
                                self.end_headers()
                                self.wfile.write(json.dumps(response_data).encode())
                                return
                            
                            def restart_service_thread():
                                try:
                                    # Create a new event loop for this thread
                                    loop = asyncio.new_event_loop()
                                    asyncio.set_event_loop(loop)
                                    result = loop.run_until_complete(self.manager.restart_service(service_id))
                                    self.manager.result_queue.put(('restart', service_id, result))
                                except Exception as e:
                                    logger.error(f"Error restarting {service_id}: {e}")
                                    self.manager.result_queue.put(('restart', service_id, False))
                                finally:
                                    loop.close()
                            
                            # Start operation in background thread
                            thread = threading.Thread(target=restart_service_thread)
                            thread.daemon = True
                            thread.start()
                            
                            # Wait for result with longer timeout for restart operations
                            logger.info("Waiting for result from queue...")
                            try:
                                operation, service, result = self.manager.result_queue.get(timeout=15)
                                logger.info(f"Got result from queue: {operation}, {result}")
                            except queue.Empty:
                                logger.warning(f"Timeout waiting for restart operation on {service_id}")
                                result = False
                            
                            response_data = {
                                'success': result,
                                'error': None if result else f"Failed to restart {service_id}"
                            }
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.send_header('Cache-Control', 'no-cache')
                            self.end_headers()
                            self.wfile.write(json.dumps(response_data).encode())
                            
                        elif path.startswith('auto-recovery/enable/'):
                            service_id = path[21:]  # Remove 'auto-recovery/enable/' prefix
                            logger.info(f"Received POST /auto-recovery/enable/ for {service_id}")
                            
                            # Validate service ID first
                            if not self.manager.is_valid_service(service_id):
                                response_data = {
                                    'success': False,
                                    'error': f"Unknown service: {service_id}"
                                }
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.send_header('Cache-Control', 'no-cache')
                                self.end_headers()
                                self.wfile.write(json.dumps(response_data).encode())
                                return
                            
                            success = self.manager.enable_auto_recovery(service_id)
                            response_data = {
                                'success': success,
                                'error': None if success else f"Failed to enable auto-recovery for {service_id}"
                            }
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.send_header('Cache-Control', 'no-cache')
                            self.end_headers()
                            self.wfile.write(json.dumps(response_data).encode())
                            
                        elif path.startswith('auto-recovery/disable/'):
                            service_id = path[22:]  # Remove 'auto-recovery/disable/' prefix
                            logger.info(f"Received POST /auto-recovery/disable/ for {service_id}")
                            
                            # Validate service ID first
                            if not self.manager.is_valid_service(service_id):
                                response_data = {
                                    'success': False,
                                    'error': f"Unknown service: {service_id}"
                                }
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.send_header('Cache-Control', 'no-cache')
                                self.end_headers()
                                self.wfile.write(json.dumps(response_data).encode())
                                return
                            
                            success = self.manager.disable_auto_recovery(service_id)
                            response_data = {
                                'success': success,
                                'error': None if success else f"Failed to disable auto-recovery for {service_id}"
                            }
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.send_header('Cache-Control', 'no-cache')
                            self.end_headers()
                            self.wfile.write(json.dumps(response_data).encode())
                            
                        elif path.startswith('auto-recovery'):
                            """Get auto-recovery status for all services"""
                            auto_recovery_status = self.manager.get_all_auto_recovery_status()
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.send_header('Cache-Control', 'no-cache')
                            self.end_headers()
                            self.wfile.write(json.dumps(auto_recovery_status).encode())
                            
                        elif self.path == '/health':
                            """Get health information for all services"""
                            health_info = self.manager.get_all_health_info()
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.send_header('Cache-Control', 'no-cache')
                            self.end_headers()
                            self.wfile.write(json.dumps(health_info).encode())
                            
                        elif self.path == '/auto-recovery':
                            """Get auto-recovery status for all services"""
                            auto_recovery_status = self.manager.get_all_auto_recovery_status()
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/json')
                            self.send_header('Cache-Control', 'no-cache')
                            self.end_headers()
                            self.wfile.write(json.dumps(auto_recovery_status).encode())
                            
                        else:
                            self.send_response(404)
                            self.end_headers()
                            
                    except Exception as e:
                        logger.error(f"Error handling POST request: {e}")
                        self.send_response(500)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Cache-Control', 'no-cache')
                        self.end_headers()
                        self.wfile.write(json.dumps({'success': False, 'error': str(e)}).encode())
            
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
            
            # Auto-recovery toggle button
            buttons_html += f'<button onclick="toggleAutoRecovery(\'{service_id}\')" class="auto-recovery-btn enabled" id="auto-recovery-{service_id}">Auto-Recovery: ON</button>'
            
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
        button.auto-recovery-btn {{ background: #6c757d; color: white; }}
        button.auto-recovery-btn.enabled {{ background: #28a745; }}
        button.auto-recovery-btn.disabled {{ background: #6c757d; }}
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
                'blockchain_node': 8546,
                'network_coordinator': 8083,
                'network_dashboard': 8084,
                'frontend': 8001  // Frontend server interface should point to backend API
            }};
            
            const port = serverPorts[service_id];
            if (port) {{
                // First check if the service is running before trying to open it
                fetch('/status')
                    .then(response => response.json())
                    .then(data => {{
                        const serviceData = data[service_id];
                        if (serviceData && serviceData.status === 'running') {{
                            // Service is running, open interface immediately without HEAD request delay
                            const testUrl = `http://localhost:${{port}}`;
                            window.open(testUrl, '_blank');
                            console.log(`Opening ${{service_id}} server interface on port ${{port}}`);
                        }} else {{
                            alert(`Cannot open ${{service_id}} interface: Service is not running. Please start the service first.`);
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error checking service status:', error);
                        // Fallback: try to open the interface anyway
                        window.open(`http://localhost:${{port}}`, '_blank');
                    }});
            }}
        }}
        
        function openDashboard(service_id) {{
            const dashboardPorts = {{
                'backend': 8091,
                'blockchain_node': 8093,
                'network_coordinator': 8096,
                'frontend': 8098
            }};
            
            const port = dashboardPorts[service_id];
            if (port) {{
                // Open dashboard directly without HEAD request check for instant response
                const testUrl = `http://localhost:${{port}}`;
                window.open(testUrl, '_blank');
                
                // Optional: Show a quick toast notification
                console.log(`Opening dashboard for ${{service_id}} on port ${{port}}`);
            }}
        }}
        
        function openWebsite() {{
            window.open('http://localhost:8080', '_blank');
        }}
        
        function updateServiceStatus(service_id, serviceData) {{
            const serviceCard = document.getElementById(`service-${{service_id}}`);
            if (!serviceCard) {{
                console.error('Service card not found for', service_id);
                return;
            }}
            
            // If no serviceData provided, just return (used by some event handlers)
            if (!serviceData) {{
                return;
            }}
            
            // Update card styling based on status
            if (serviceData.status === 'running') {{
                serviceCard.classList.remove('stopped');
                serviceCard.classList.add('running');
            }} else {{
                serviceCard.classList.remove('running');
                serviceCard.classList.add('stopped');
            }}
            
            // Update status text
            const statusText = serviceCard.querySelector('.status-text');
            if (statusText) {{
                statusText.textContent = serviceData.status === 'running' ? 'Running' : 'Stopped';
            }}
            
            // Update PID
            const pidText = serviceCard.querySelector('.pid-text');
            if (pidText) {{
                pidText.textContent = serviceData.pid || '-';
            }}
            
            // Update CPU
            const cpuText = serviceCard.querySelector('.cpu-text');
            if (cpuText) {{
                const cpu = serviceData.cpu_percent || serviceData.cpu || 0;
                cpuText.textContent = `${{cpu.toFixed(1)}}%`;
            }}
            
            // Update Memory
            const memText = serviceCard.querySelector('.memory-text');
            if (memText) {{
                const mem = serviceData.memory_mb || serviceData.mem || 0;
                memText.textContent = `${{mem.toFixed(1)}} MB`;
            }}
            
            // Update the toggle button
            const toggleButton = document.getElementById(`toggle-${{service_id}}`);
            if (toggleButton && !toggleButton.disabled) {{
                if (serviceData.status === 'running') {{
                    toggleButton.textContent = 'Stop';
                    toggleButton.classList.remove('primary');
                    toggleButton.classList.add('danger');
                }} else {{
                    toggleButton.textContent = 'Start';
                    toggleButton.classList.remove('danger');
                    toggleButton.classList.add('primary');
                }}
            }}
            
            // Update the service icon
            const h3 = serviceCard.querySelector('h3');
            if (h3) {{
                // Get the service name from the h3 text content
                const currentText = h3.textContent;
                const serviceName = currentText.replace(/^[●○]\\s*/, ''); // Remove existing icon
                
                // Update with new icon and preserved name
                const newIcon = serviceData.status === 'running' ? '● ' : '○ ';
                h3.textContent = newIcon + serviceName;
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
                console.error('Toggle button not found for', service_id);
                return;
            }}
            const isRunning = toggleButton.textContent === 'Stop';
            console.log('toggleService called for', service_id, 'isRunning:', isRunning);
            // Disable button during operation
            toggleButton.disabled = true;
            toggleButton.textContent = isRunning ? 'Stopping...' : 'Starting...';
            
            if (isRunning) {{
                const warnings = {{
                    'blockchain_node': 'WARNING: Shutting down this node will result in loss of credibility points and network participation rewards.',
                    'network_coordinator': 'WARNING: Shutting down the coordinator will affect network discovery and node communication.',
                    'network_dashboard': 'WARNING: Shutting down the dashboard will disable network monitoring.',
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
                const restartButton = document.querySelector(`button[onclick="restartService('${service_id}')"]`);
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
        
        // Update auto-recovery status on load
        setTimeout(updateAutoRecoveryStatus, 1100);
        
        function toggleAutoRecovery(serviceId) {{
            const button = document.getElementById(`auto-recovery-${{serviceId}}`);
            const isEnabled = button.textContent.includes('ON');
            const action = isEnabled ? 'disable' : 'enable';
            
            fetch(`/auto-recovery/${{action}}/${{serviceId}}`, {{
                method: 'POST',
                headers: {{
                    'Content-Type': 'application/json'
                }}
            }})
            .then(response => response.json())
            .then(data => {{
                if (data.success) {{
                    button.textContent = `Auto-Recovery: ${{isEnabled ? 'OFF' : 'ON'}}`;
                    button.className = `auto-recovery-btn ${{isEnabled ? 'disabled' : 'enabled'}}`;
                }} else {{
                    console.error('Failed to toggle auto-recovery:', data.error);
                }}
            }})
            .catch(error => {{
                console.error('Error toggling auto-recovery:', error);
            }});
        }}
        
        function updateAutoRecoveryStatus() {{
            fetch('/auto-recovery')
            .then(response => response.json())
            .then(data => {{
                for (const [serviceId, isEnabled] of Object.entries(data)) {{
                    const button = document.getElementById(`auto-recovery-${{serviceId}}`);
                    if (button) {{
                        button.textContent = `Auto-Recovery: ${{isEnabled ? 'ON' : 'OFF'}}`;
                        button.className = `auto-recovery-btn ${{isEnabled ? 'enabled' : 'disabled'}}`;
                    }}
                }}
            }})
            .catch(error => {{
                console.error('Error updating auto-recovery status:', error);
            }});
        }}
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
        import psutil  # Ensure psutil is imported here
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

    def enable_auto_recovery(self, service_id: str) -> bool:
        """Enable auto-recovery for a specific service"""
        if service_id in self.service_configs:
            self.auto_recovery_enabled[service_id] = True
            logger.info(f"Auto-recovery enabled for {service_id}")
            return True
        else:
            logger.error(f"Unknown service: {service_id}")
            return False
    
    def disable_auto_recovery(self, service_id: str) -> bool:
        """Disable auto-recovery for a specific service"""
        if service_id in self.service_configs:
            self.auto_recovery_enabled[service_id] = False
            logger.info(f"Auto-recovery disabled for {service_id}")
            return True
        else:
            logger.error(f"Unknown service: {service_id}")
            return False
    
    def get_auto_recovery_status(self, service_id: str) -> bool:
        """Get auto-recovery status for a specific service"""
        return self.auto_recovery_enabled.get(service_id, False)
    
    def get_all_auto_recovery_status(self) -> dict:
        """Get auto-recovery status for all services"""
        return {service_id: self.get_auto_recovery_status(service_id) 
                for service_id in self.service_configs}
    
    async def _verify_service_interface(self, service_id: str) -> bool:
        """Verify that service provides proper HTTP interface"""
        if service_id not in self.service_configs:
            return False
        
        config = self.service_configs[service_id]
        port = config.get("port")
        
        if not port:
            return False
        
        try:
            import requests
            # Different endpoints for different services
            test_endpoints = {
                'backend': '/health',
                'blockchain_node': '/status',
                'incentive_system': '/status', 
                'network_coordinator': '/',
                'network_dashboard': '/',
                'frontend': '/'
            }
            
            endpoint = test_endpoints.get(service_id, '/')
            url = f"http://localhost:{port}{endpoint}"
            
            response = requests.get(url, timeout=5)
            return response.status_code in [200, 404]  # 404 is OK for some services
            
        except Exception as e:
            logger.debug(f"Interface verification failed for {service_id}: {e}")
            return False

async def main():
    """Main function with enhanced graceful shutdown"""
    print("MediVote Background Service Manager")
    print("=" * 50)
    print("Starting all MediVote services in background")
    print("Each service will have its own dashboard")
    print("=" * 50)
    
    manager = MediVoteBackgroundManager()
    
    # Set up signal handlers for graceful shutdown (prevent duplicate registration)
    shutdown_in_progress = False
    
    def signal_handler(signum, frame):
        nonlocal shutdown_in_progress
        if shutdown_in_progress:
            print("\nShutdown already in progress, please wait...")
            return
        
        shutdown_in_progress = True
        print(f"\nSTOP: Received signal {signum}, initiating graceful shutdown...")
        # Disable auto-recovery for all services to prevent restart during shutdown
        print("Disabling auto-recovery for all services...")
        for service_id in manager.service_configs:
            manager.auto_recovery_enabled[service_id] = False
        # Mark shutdown as requested
        manager._shutdown_requested = True
    
    # Register signal handlers (only once)
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
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
        
        # Keep running with periodic health checks
        shutdown_requested = False
        health_check_counter = 0
        while not shutdown_requested:
            try:
                # Check for shutdown signals frequently
                if hasattr(manager, '_shutdown_requested') and manager._shutdown_requested:
                    shutdown_requested = True
                    break
                
                # Sleep in short intervals to check for shutdown signal more frequently
                await asyncio.sleep(1)  # Check every second instead of every 30 seconds
                health_check_counter += 1
                
                # Periodic health check every 30 seconds (30 * 1-second sleeps)
                if health_check_counter >= 30:
                    health_check_counter = 0
                    # Optional: Log system health
                    if hasattr(manager, 'get_service_status'):
                        status = manager.get_service_status()
                        running_services = sum(1 for s in status.values() if s.get('status') == 'running')
                        total_services = len(status)
                        if running_services < total_services:
                            logger.info(f"Health check: {running_services}/{total_services} services running")
            except KeyboardInterrupt:
                print("\nKeyboard interrupt received, initiating graceful shutdown...")
                shutdown_requested = True
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                await asyncio.sleep(1)  # Wait before retrying
        
        # Graceful shutdown
        if shutdown_requested:
            print("\nInitiating graceful shutdown...")
            await manager.stop_all_services()
            print("All services stopped gracefully")
        
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received, stopping all services...")
        await manager.stop_all_services()
        print("All services stopped gracefully")
        
    except Exception as e:
        print(f"Error: {e}")
        logger.error(f"Critical error in main function: {e}")
        
        # Emergency cleanup
        try:
            print("Performing emergency cleanup...")
            await manager.stop_all_services()
        except Exception as cleanup_error:
            logger.error(f"Error during emergency cleanup: {cleanup_error}")
        
        return 1
    
    finally:
        # Final cleanup
        try:
            print("Performing final system cleanup...")
            
            # Clean up any remaining resources
            if hasattr(manager, '_cleanup_global_resources'):
                await manager._cleanup_global_resources()
            
            # Clean up temporary files
            if hasattr(manager, '_cleanup_temp_directories'):
                await manager._cleanup_temp_directories()
            
            print("System cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during final cleanup: {e}")
    
    print("MediVote Service Manager shutdown complete")
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 