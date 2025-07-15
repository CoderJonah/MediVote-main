#!/usr/bin/env python3
"""
MediVote Final Working Startup Script
Reliable startup with proper timing, port race condition fix, and live/logged output for all services.
"""

import os
import sys
import time
import subprocess
import requests
import psutil
import socket
import threading
import queue
from pathlib import Path

class MediVoteFinalRunner:
    def __init__(self):
        self.processes = {}
        self.threads = []
        self.service_ports = {
            "Backend": 8001,
            "Frontend": 8080,
            "Blockchain Node": 8081,
            "Incentive System": 8082,
            "Network Coordinator": 8083,
            "Network Dashboard": 8084,
        }
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        self.output_queue = queue.Queue()
        self.logging_active = True
    
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def kill_existing_processes(self):
        self.log("Stopping existing python.exe processes (except self)...")
        try:
            current_pid = os.getpid()
            killed_count = 0
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and 'python' in proc.info['name'].lower():
                        if proc.pid != current_pid:
                            proc.terminate()
                            killed_count += 1
                            self.log(f"Terminated python.exe with PID {proc.pid}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if killed_count > 0:
                time.sleep(0.5)  # Minimal delay
            else:
                self.log("No other Python processes found")
        except Exception as e:
            self.log(f"Error killing python processes: {e}")

    def is_port_in_use(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.05)  # Very fast timeout
            result = s.connect_ex(("127.0.0.1", port))
            return result == 0

    def wait_for_port_free(self, port, timeout=2):  # Very short timeout
        start = time.time()
        while self.is_port_in_use(port):
            if time.time() - start > timeout:
                self.log(f"Port {port} still in use after {timeout} seconds!")
                return False
            time.sleep(0.1)  # Very short wait
        return True

    def stream_output(self, process, service_name, log_file_path):
        """Read process output and write to log file only - no console output."""
        def reader(stream, is_stderr=False):
            try:
                with open(log_file_path, "a", encoding="utf-8", buffering=1) as log_file:
                    for line in iter(stream.readline, b""):
                        if not self.logging_active:
                            break
                        try:
                            decoded = line.decode(errors="replace").rstrip()
                        except Exception:
                            decoded = str(line)
                        
                        # Only log to file, no console output
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        log_line = f"{timestamp} - {decoded}\n"
                        try:
                            log_file.write(log_line)
                            log_file.flush()
                        except Exception as e:
                            # Only print actual errors to console
                            print(f"Log write error for {service_name}: {e}")
            except Exception as e:
                # Only print actual errors to console
                print(f"Stream reader error for {service_name}: {e}")
        
        # Start reader threads
        t1 = threading.Thread(target=reader, args=(process.stdout, False), daemon=True)
        t2 = threading.Thread(target=reader, args=(process.stderr, True), daemon=True)
        t1.start()
        t2.start()
        self.threads.extend([t1, t2])

    def start_service(self, name, command):
        port = self.service_ports.get(name)
        if port:
            if not self.wait_for_port_free(port, timeout=2):  # Very short timeout
                self.log(f"Failed to start {name} - port {port} unavailable")
                return False
        
        self.log(f"Starting {name}...")
        try:
            log_file_path = self.log_dir / f"{name.lower().replace(' ', '_')}.log"
            
            # Clear the log file with clean timestamp
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(log_file_path, "w") as f:
                f.write(f"=== {name} Log Started at {timestamp} ===\n")
            
            # Start the process
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0,
                cwd=os.getcwd()
            )
            self.processes[name] = process
            
            # Start output streaming
            self.stream_output(process, name, log_file_path)
            
            # Minimal startup wait
            time.sleep(0.5)  # Very short wait
            
            # Check if process is still running
            if process.poll() is None:
                self.log(f"{name} started successfully")
                return True
            else:
                self.log(f"{name} failed to start (exit code: {process.returncode})")
                return False
                
        except Exception as e:
            self.log(f"Error starting {name}: {e}")
            return False

    def start_all_services(self):
        services = [
            ("Backend", [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8001"]),
            ("Frontend", [sys.executable, "-m", "http.server", "8080", "--directory", "frontend"]),
            ("Blockchain Node", [sys.executable, "blockchain_node.py", "--port", "8081", "--data-dir", "blockchain_data"]),
            ("Incentive System", [sys.executable, "node_incentive_system.py", "--port", "8082"]),
            ("Network Coordinator", [sys.executable, "network_coordinator.py", "--port", "8083"]),
            ("Network Dashboard", [sys.executable, "network_dashboard.py", "--port", "8084"]),
        ]
        results = {}
        for name, command in services:
            results[name] = self.start_service(name, command)
            # No delay between services - start them all immediately
        return results

    def print_system_info(self):
        self.log("MediVote System is Running!")
        print("\n" + "=" * 70)
        print("System Components:")
        print("  • Frontend:        http://localhost:8080")
        print("  • Backend API:     http://localhost:8001")
        print("  • Blockchain:      Running in background")
        print("  • Incentive:       http://localhost:8082")
        print("  • Coordinator:     http://localhost:8083")
        print("  • Dashboard:       http://localhost:8084")
        print("=" * 70)
        print("Quick Start Guide:")
        print("1. Open http://localhost:8080 in your browser")
        print("2. Register as a voter")
        print("3. Run a blockchain node to create ballots")
        print("4. Cast your vote securely")
        print("5. Monitor the network at http://localhost:8084")
        print("=" * 70)
        print("System Features:")
        print("  • Decentralized blockchain voting")
        print("  • Node incentive system")
        print("  • Real-time network monitoring")
        print("  • Advanced cryptographic security")
        print("  • End-to-end verifiability")
        print("=" * 70)
        print("Press Ctrl+C to stop all services")
        print("=" * 70)

    def run(self):
        try:
            self.log("Starting MediVote Complete System...")
            self.kill_existing_processes()
            results = self.start_all_services()
            working = sum(1 for success in results.values() if success)
            self.log(f"Started {working}/{len(results)} services successfully")
            if working > 0:
                self.print_system_info()
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            self.log("Shutting down complete system...")
            self.cleanup()

    def cleanup(self):
        self.logging_active = False
        for name, process in self.processes.items():
            try:
                process.terminate()
                self.log(f"Stopped {name}")
            except:
                pass

if __name__ == "__main__":
    runner = MediVoteFinalRunner()
    runner.run() 