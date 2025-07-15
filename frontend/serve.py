#!/usr/bin/env python3
"""
Simple web server for serving the MediVote frontend
"""

import http.server
import socketserver
import os
import sys
import webbrowser
from pathlib import Path

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

    def guess_type(self, path):
        mimetype = super().guess_type(path)
        # Fix JavaScript MIME type
        if path.endswith('.js'):
            return 'application/javascript'
        return mimetype

def main():
    # Change to the frontend directory
    frontend_dir = Path(__file__).parent
    os.chdir(frontend_dir)
    
    # Ensure we're in the right directory
    print(f"Working directory: {os.getcwd()}")
    print(f"Frontend directory: {frontend_dir}")
    
    # Check if index.html exists
    if not os.path.exists('index.html'):
        print("Error: index.html not found in the frontend directory")
        print(f"Looking for index.html in: {os.getcwd()}")
        print(f"Files in directory: {os.listdir('.')}")
        sys.exit(1)
    
    # Start the server
    with socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler) as httpd:
        print(f"MediVote Frontend Server starting on port {PORT}")
        print(f"Frontend URL: http://localhost:{PORT}")
        print(f"Backend API: http://localhost:8000")
        print(f"API Docs: http://localhost:8000/docs")
        print("\nPress Ctrl+C to stop the server")
        
        # Open browser
        try:
            webbrowser.open(f'http://localhost:{PORT}')
        except:
            pass
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped")
            sys.exit(0)

if __name__ == "__main__":
    main() 