#!/usr/bin/env python3
"""
Simple web server for serving the MediVote frontend
"""

import http.server
import socketserver
import os
import sys
import json
import logging
import webbrowser
from pathlib import Path

# Configure logging for frontend service
os.makedirs('../logs', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../logs/frontend.log', encoding='utf-8'),
        logging.StreamHandler()
    ],
    force=True
)
logger = logging.getLogger("medivote_frontend")

PORT = 8080

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()
    
    def do_GET(self):
        # Handle health check endpoint
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            health_data = {
                "status": "healthy",
                "service": "frontend",
                "timestamp": str(os.path.getmtime('index.html') if os.path.exists('index.html') else 0)
            }
            self.wfile.write(json.dumps(health_data).encode())
            logger.info("Health check endpoint called")
            return
        
        # Default behavior for other paths
        super().do_GET()

    def guess_type(self, path):
        mimetype = super().guess_type(path)
        # Fix JavaScript MIME type
        if path.endswith('.js'):
            return 'application/javascript'
        return mimetype

def main():
    logger.info("MediVote Frontend server starting")
    
    # Change to the frontend directory
    frontend_dir = Path(__file__).parent
    os.chdir(frontend_dir)
    
    # Ensure we're in the right directory
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"Frontend directory: {frontend_dir}")
    print(f"Working directory: {os.getcwd()}")
    print(f"Frontend directory: {frontend_dir}")
    
    # Check if index.html exists
    if not os.path.exists('index.html'):
        logger.error("index.html not found in the frontend directory")
        logger.error(f"Looking for index.html in: {os.getcwd()}")
        logger.error(f"Files in directory: {os.listdir('.')}")
        print("Error: index.html not found in the frontend directory")
        print(f"Looking for index.html in: {os.getcwd()}")
        print(f"Files in directory: {os.listdir('.')}")
        sys.exit(1)
    
    # Start the server
    with socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler) as httpd:
        logger.info(f"MediVote Frontend Server starting on port {PORT}")
        logger.info(f"Frontend URL: http://localhost:{PORT}")
        logger.info(f"Backend API: http://localhost:8000")
        print(f"MediVote Frontend Server starting on port {PORT}")
        print(f"Frontend URL: http://localhost:{PORT}")
        print(f"Backend API: http://localhost:8000")
        print(f"API Docs: http://localhost:8000/docs")
        print("\nPress Ctrl+C to stop the server")
        
        # Open browser
        try:
            webbrowser.open(f'http://localhost:{PORT}')
            logger.info("Opened browser to frontend URL")
        except Exception as e:
            logger.warning(f"Could not open browser: {e}")
            pass
        
        try:
            logger.info("Frontend server is now serving requests")
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Frontend server stopped by user")
            print("\nServer stopped")
            sys.exit(0)

if __name__ == "__main__":
    main() 