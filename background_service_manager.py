#!/usr/bin/env python3
"""
MediVote Background Service Manager
Manages all MediVote applications running in the background with individual dashboards.
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
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp
from aiohttp import web
import psutil
import signal
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('service_manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ServiceInfo:
    """Information about a managed service"""
    name: str
    process: Optional[subprocess.Popen] = None
    pid: Optional[int] = None
    port: int = 0
    dashboard_port: int = 0
    status: str = "stopped"  # running, stopped, starting, error
    start_time: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None
    config_file: str = ""
    log_file: str = ""
    auto_restart: bool = True
    max_restarts: int = 3
    restart_count: int = 0

class BackgroundServiceManager:
    """Manages all MediVote background services"""
    
    def __init__(self):
        self.services: Dict[str, ServiceInfo] = {}
        self.is_running = False
        self.management_port = 8090
        self.credibility_warnings = {
            "blockchain_node": "Shutting down this node will result in loss of credibility points and network participation rewards.",
            "incentive_system": "Shutting down the incentive system will stop reward distribution and node reputation tracking.",
            "network_coordinator": "Shutting down the coordinator will affect network discovery and node communication.",
            "backend": "Shutting down the backend will disable voting functionality and API access.",
            "frontend": "Shutting down the frontend will disable web interface access."
        }
        
        # Initialize services
        self._initialize_services()
        
    def _initialize_services(self):
        """Initialize all managed services"""
        services_config = {
            "backend": {
                "name": "MediVote Backend",
                "script": "backend/main.py",
                "port": 8001,
                "dashboard_port": 8091,
                "config_file": "backend_config.json",
                "log_file": "logs/backend.log",
                "auto_restart": True
            },
            "frontend": {
                "name": "MediVote Frontend", 
                "script": "frontend/serve.py",
                "port": 8080,
                "dashboard_port": 8092,
                "config_file": "frontend_config.json",
                "log_file": "logs/frontend.log",
                "auto_restart": True
            },
            "blockchain_node": {
                "name": "Blockchain Node",
                "script": "blockchain_node.py",
                "port": 8546,
                "dashboard_port": 8093,
                "config_file": "node_config.json",
                "log_file": "blockchain_node.log",
                "auto_restart": True
            },
            "incentive_system": {
                "name": "Node Incentive System",
                "script": "node_incentive_system.py", 
                "port": 8082,
                "dashboard_port": 8094,
                "config_file": "incentive_config.json",
                "log_file": "node_incentive.log",
                "auto_restart": True
            },
            "network_coordinator": {
                "name": "Network Coordinator",
                "script": "network_coordinator.py",
                "port": 8083,
                "dashboard_port": 8095,
                "config_file": "network_config.json",
                "log_file": "network_coordinator.log",
                "auto_restart": True
            },
            "network_dashboard": {
                "name": "Network Dashboard",
                "script": "network_dashboard.py",
                "port": 8084,
                "dashboard_port": 8096,
                "config_file": "dashboard_config.json",
                "log_file": "network_dashboard.log",
                "auto_restart": True
            }
        }
        
        for service_id, config in services_config.items():
            self.services[service_id] = ServiceInfo(
                name=config["name"],
                port=config["port"],
                dashboard_port=config["dashboard_port"],
                config_file=config["config_file"],
                log_file=config["log_file"],
                auto_restart=config["auto_restart"]
            )
    
    async def start_all_services(self):
        """Start all services in background"""
        logger.info("Starting all MediVote services...")
        
        # Start services in order
        startup_order = ["backend", "blockchain_node", "incentive_system", "network_coordinator", "network_dashboard", "frontend"]
        
        for service_id in startup_order:
            if service_id in self.services:
                await self.start_service(service_id)
                await asyncio.sleep(2)  # Brief delay between starts
        
        # Open management dashboard
        await self.open_management_dashboard()
        
        logger.info("All services started successfully")
    
    async def start_service(self, service_id: str) -> bool:
        """Start a specific service"""
        if service_id not in self.services:
            logger.error(f"Unknown service: {service_id}")
            return False
        
        service = self.services[service_id]
        
        if service.status == "running":
            logger.info(f"Service {service_id} is already running")
            return True
        
        try:
            logger.info(f"Starting {service.name}...")
            service.status = "starting"
            
            # Start the service process
            cmd = [sys.executable, service_id + ".py"]
            if service_id == "backend":
                cmd = [sys.executable, "backend/main.py"]
            elif service_id == "frontend":
                cmd = [sys.executable, "frontend/serve.py"]
            
            # Start process in background
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            )
            
            service.process = process
            service.pid = process.pid
            service.start_time = datetime.utcnow()
            service.status = "running"
            
            # Start monitoring thread
            threading.Thread(target=self._monitor_service, args=(service_id,), daemon=True).start()
            
            logger.info(f"Started {service.name} (PID: {process.pid})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start {service.name}: {e}")
            service.status = "error"
            return False
    
    def _monitor_service(self, service_id: str):
        """Monitor a service for health and restart if needed"""
        service = self.services[service_id]
        
        while service.status == "running" and service.process:
            try:
                # Check if process is still alive
                if service.process.poll() is not None:
                    logger.warning(f"Service {service_id} has stopped unexpectedly")
                    service.status = "stopped"
                    
                    # Auto-restart if enabled
                    if service.auto_restart and service.restart_count < service.max_restarts:
                        logger.info(f"Restarting {service.name}...")
                        service.restart_count += 1
                        asyncio.run(self.start_service(service_id))
                    else:
                        logger.error(f"Service {service_id} failed too many times, not restarting")
                    break
                
                # Check service health via HTTP
                if service.port > 0:
                    try:
                        response = requests.get(f"http://localhost:{service.port}/status", timeout=5)
                        if response.status_code == 200:
                            service.last_heartbeat = datetime.utcnow()
                    except:
                        pass  # Service might not have HTTP endpoint
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring {service_id}: {e}")
                time.sleep(10)
    
    async def stop_service(self, service_id: str, force: bool = False) -> bool:
        """Stop a specific service gracefully"""
        if service_id not in self.services:
            logger.error(f"Unknown service: {service_id}")
            return False
        
        service = self.services[service_id]
        
        if service.status != "running":
            logger.info(f"Service {service_id} is not running")
            return True
        
        try:
            logger.info(f"Stopping {service.name}...")
            
            # Send graceful shutdown signal
            if not force and service.port > 0:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(f"http://localhost:{service.port}/shutdown", timeout=5) as response:
                            if response.status == 200:
                                logger.info(f"Graceful shutdown signal sent to {service.name}")
                                # Wait for graceful shutdown
                                await asyncio.sleep(5)
                except:
                    logger.warning(f"Could not send graceful shutdown to {service.name}")
            
            # Force kill if still running
            if service.process and service.process.poll() is None:
                if os.name == 'nt':
                    service.process.terminate()
                else:
                    service.process.send_signal(signal.SIGTERM)
                
                # Wait for termination
                try:
                    service.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Force killing {service.name}")
                    service.process.kill()
            
            service.status = "stopped"
            service.process = None
            service.pid = None
            
            logger.info(f"Stopped {service.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop {service.name}: {e}")
            return False
    
    async def stop_all_services(self):
        """Stop all services gracefully"""
        logger.info("Stopping all services...")
        
        # Stop in reverse order
        stop_order = ["frontend", "network_dashboard", "network_coordinator", "incentive_system", "blockchain_node", "backend"]
        
        for service_id in stop_order:
            if service_id in self.services:
                await self.stop_service(service_id)
                await asyncio.sleep(1)
        
        logger.info("All services stopped")
    
    async def restart_service(self, service_id: str) -> bool:
        """Restart a specific service"""
        await self.stop_service(service_id)
        await asyncio.sleep(2)
        return await self.start_service(service_id)
    
    def get_service_status(self, service_id: str) -> Dict[str, Any]:
        """Get detailed status of a service"""
        if service_id not in self.services:
            return {"error": "Service not found"}
        
        service = self.services[service_id]
        
        # Get process info
        process_info = {}
        if service.pid:
            try:
                process = psutil.Process(service.pid)
                process_info = {
                    "cpu_percent": process.cpu_percent(),
                    "memory_mb": process.memory_info().rss / 1024 / 1024,
                    "create_time": datetime.fromtimestamp(process.create_time()).isoformat()
                }
            except:
                pass
        
        return {
            "name": service.name,
            "status": service.status,
            "pid": service.pid,
            "port": service.port,
            "dashboard_port": service.dashboard_port,
            "start_time": service.start_time.isoformat() if service.start_time else None,
            "last_heartbeat": service.last_heartbeat.isoformat() if service.last_heartbeat else None,
            "restart_count": service.restart_count,
            "auto_restart": service.auto_restart,
            "process_info": process_info
        }
    
    def get_all_status(self) -> Dict[str, Any]:
        """Get status of all services"""
        return {
            service_id: self.get_service_status(service_id)
            for service_id in self.services.keys()
        }
    
    async def open_management_dashboard(self):
        """Open the main management dashboard"""
        try:
            webbrowser.open(f"http://localhost:{self.management_port}")
            logger.info(f"Opened management dashboard at http://localhost:{self.management_port}")
        except Exception as e:
            logger.error(f"Failed to open management dashboard: {e}")
    
    async def open_service_dashboard(self, service_id: str):
        """Open dashboard for a specific service"""
        if service_id not in self.services:
            logger.error(f"Unknown service: {service_id}")
            return
        
        service = self.services[service_id]
        if service.dashboard_port > 0:
            try:
                webbrowser.open(f"http://localhost:{service.dashboard_port}")
                logger.info(f"Opened {service.name} dashboard at http://localhost:{service.dashboard_port}")
            except Exception as e:
                logger.error(f"Failed to open {service.name} dashboard: {e}")
    
    async def start_management_server(self):
        """Start the management API server"""
        app = web.Application()
        
        async def status_handler(request):
            return web.json_response(self.get_all_status())
        
        async def start_service_handler(request):
            data = await request.json()
            service_id = data.get("service_id")
            success = await self.start_service(service_id)
            return web.json_response({"success": success})
        
        async def stop_service_handler(request):
            data = await request.json()
            service_id = data.get("service_id")
            force = data.get("force", False)
            success = await self.stop_service(service_id, force)
            return web.json_response({"success": success})
        
        async def restart_service_handler(request):
            data = await request.json()
            service_id = data.get("service_id")
            success = await self.restart_service(service_id)
            return web.json_response({"success": success})
        
        async def open_dashboard_handler(request):
            data = await request.json()
            service_id = data.get("service_id")
            await self.open_service_dashboard(service_id)
            return web.json_response({"success": True})
        
        app.router.add_get('/status', status_handler)
        app.router.add_post('/start', start_service_handler)
        app.router.add_post('/stop', stop_service_handler)
        app.router.add_post('/restart', restart_service_handler)
        app.router.add_post('/open_dashboard', open_dashboard_handler)
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.management_port)
        await site.start()
        
        logger.info(f"Management server started on port {self.management_port}")
        return runner

async def main():
    """Main function"""
    print("MediVote Background Service Manager")
    print("=" * 50)
    print("Managing all MediVote applications in background")
    print("=" * 50)
    
    manager = BackgroundServiceManager()
    
    try:
        # Start management server
        runner = await manager.start_management_server()
        
        # Start all services
        await manager.start_all_services()
        
        print("\nAll services started successfully!")
        print("Management Dashboard: http://localhost:8090")
        print("\nPress Ctrl+C to stop all services")
        
        # Keep running
        await asyncio.Event().wait()
        
    except KeyboardInterrupt:
        print("\nStopping all services...")
        await manager.stop_all_services()
        print("All services stopped")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 