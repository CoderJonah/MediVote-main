#!/usr/bin/env python3
"""Ultra-simple test for Stop button"""

import requests

print("Testing Stop endpoint...")

try:
    # Set a short timeout
    response = requests.post("http://localhost:8090/stop/backend", timeout=5)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
except requests.exceptions.Timeout:
    print("Request timed out after 5 seconds")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}") 