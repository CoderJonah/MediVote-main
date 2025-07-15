#!/usr/bin/env python3
"""
MediVote Main Executable (Final Fixed Version)
Professional desktop application for secure blockchain voting.
This version restores the full UI and includes the Uvicorn logging fix.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import webbrowser
import time
from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

import uvicorn
import multiprocessing
import secrets

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- Backend App Definition ---
backend_app = FastAPI()
frontend_path = resource_path('frontend')
backend_app.mount("/frontend", StaticFiles(directory=frontend_path, html=True), name="frontend")

@backend_app.get("/health")
def read_root():
    return {"status": "ok"}

# --- Uvicorn Server in a Thread ---
class ServerThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        # Pass log_config=None to prevent Uvicorn from setting up its own problematic loggers
        self.config = uvicorn.Config(app=backend_app, host="127.0.0.1", port=8000, log_config=None)
        self.server = uvicorn.Server(config=self.config)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True

# --- Class to Redirect stdout/stderr to the GUI ---
class RedirectText:
    def __init__(self, text_widget):
        self.output = text_widget

    def write(self, string):
        self.output.config(state=tk.NORMAL)
        self.output.insert(tk.END, string)
        self.output.see(tk.END)
        self.output.config(state=tk.DISABLED)

    def flush(self):
        pass

# --- Main Application Class ---
class MediVoteApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("MediVote - Secure Blockchain Voting")
        self.root.geometry("800x600")
        
        self.app_data_dir = self._get_app_data_dir()
        self.logger = self._setup_logging()
        
        self.setup_gui() # Setup GUI first
        
        # Redirect stdout and stderr after GUI is created
        sys.stdout = RedirectText(self.log_text)
        sys.stderr = RedirectText(self.log_text)
        
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Application initialized.")
        
        self.setup_icon()
        
        self.server_thread = None
        self.start_server()

    def _get_app_data_dir(self) -> Path:
        if sys.platform == "win32":
            return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "MediVote"
        else:
            return Path.home() / ".config" / "MediVote"

    def _setup_logging(self):
        log_dir = self.app_data_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "medivote_app.log"
        logger = logging.getLogger("MediVoteApp")
        logger.setLevel(logging.INFO)
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        if not logger.handlers:
            logger.addHandler(file_handler)
        return logger

    def start_server(self):
        if self.server_thread and self.server_thread.is_alive():
            print("Server is already running")
            return
        
        try:
            print("Starting MediVote backend server...")
            self.server_thread = ServerThread()
            self.server_thread.start()
            
            self.server_status.config(text="Running", foreground="green")
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            
            print("Backend server started successfully.")
            
        except Exception as e:
            print(f"ERROR: Failed to start server: {e}")
            messagebox.showerror("Error", f"Failed to start server: {e}")

    def setup_icon(self):
        try:
            icon_path = resource_path("assets/medivote_icon.ico")
            if Path(icon_path).exists():
                self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"ERROR: Failed to set icon: {e}")

    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        title_label = ttk.Label(main_frame, text="MediVote", font=("Arial", 24, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        subtitle_label = ttk.Label(main_frame, text="Secure Blockchain-Based Voting System", font=("Arial", 12))
        subtitle_label.grid(row=1, column=0, columnspan=2, pady=(0, 20))
        
        status_frame = ttk.LabelFrame(main_frame, text="System Status", padding="10")
        status_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        status_frame.columnconfigure(1, weight=1)
        ttk.Label(status_frame, text="Backend Server:").grid(row=0, column=0, sticky="w")
        self.server_status = ttk.Label(status_frame, text="Starting...", foreground="orange")
        self.server_status.grid(row=0, column=1, sticky="w", padx=(10, 0))
        ttk.Label(status_frame, text="Database:").grid(row=1, column=0, sticky="w")
        self.db_status = ttk.Label(status_frame, text="Ready", foreground="green")
        self.db_status.grid(row=1, column=1, sticky="w", padx=(10, 0))
        ttk.Label(status_frame, text="Security:").grid(row=2, column=0, sticky="w")
        self.security_status = ttk.Label(status_frame, text="Enabled", foreground="green")
        self.security_status.grid(row=2, column=1, sticky="w", padx=(10, 0))
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        self.start_button = ttk.Button(button_frame, text="Start Server", command=self.start_server, state=tk.DISABLED)
        self.start_button.grid(row=0, column=0, padx=5)
        self.stop_button = ttk.Button(button_frame, text="Stop Server", command=self.stop_server)
        self.stop_button.grid(row=0, column=1, padx=5)
        self.restart_button = ttk.Button(button_frame, text="Restart Server", command=self.restart_server)
        self.restart_button.grid(row=0, column=2, padx=5)
        
        access_frame = ttk.LabelFrame(main_frame, text="Access Application", padding="10")
        access_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        ttk.Button(access_frame, text="Open Web Interface", command=self.open_web_interface).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(access_frame, text="Open API Documentation", command=self.open_api_docs).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(access_frame, text="View System Health", command=self.view_health).grid(row=0, column=2, padx=5, pady=5)
        
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding="10")
        settings_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        ttk.Button(settings_frame, text="Configuration", command=self.open_config).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(settings_frame, text="View Logs", command=self.view_logs).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(settings_frame, text="About", command=self.show_about).grid(row=0, column=2, padx=5, pady=5)

        log_frame = ttk.LabelFrame(main_frame, text="System Log", padding="10")
        log_frame.grid(row=6, column=0, columnspan=2, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
        self.log_text = tk.Text(log_frame, height=10, wrap=tk.WORD, state=tk.DISABLED, bg="#f0f0f0")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scrollbar.set)

    def log_message(self, message: str):
        # This now only logs to the file, as stdout/stderr are redirected
        self.logger.info(message)
        print(message) # The redirected print will appear in the GUI

    def stop_server(self):
        if self.server_thread and self.server_thread.is_alive():
            print("Stopping MediVote backend server...")
            self.server_thread.stop()
            self.server_thread.join(timeout=2)
            self.server_status.config(text="Stopped", foreground="red")
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            print("Backend server stopped.")
        else:
            print("Server is not running.")
    
    def restart_server(self):
        self.stop_server()
        time.sleep(1)
        self.start_server()

    def open_web_interface(self):
        webbrowser.open("http://127.0.0.1:8000/frontend")

    def open_api_docs(self):
        webbrowser.open("http://127.0.0.1:8000/docs")

    def view_health(self):
        webbrowser.open("http://127.0.0.1:8000/health")

    def open_config(self):
        try:
            os.startfile(self.app_data_dir)
        except Exception as e:
            print(f"Error opening config directory: {e}")

    def view_logs(self):
        try:
            os.startfile(self.app_data_dir / "logs")
        except Exception as e:
            print(f"Error opening logs directory: {e}")

    def show_about(self):
        messagebox.showinfo("About MediVote", "MediVote v1.0.0\nSecure Blockchain Voting System")

    def on_closing(self):
        self.stop_server()
        self.root.destroy()

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = MediVoteApp()
    app.run()