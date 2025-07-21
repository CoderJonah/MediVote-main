#!/usr/bin/env python3
"""
Capture SSE data for debugging
"""

import requests
import json
import time

def capture_sse():
    print("🔍 Capturing SSE data...")
    
    try:
        response = requests.get("http://localhost:8090/events", timeout=3, stream=True)
        
        if response.status_code == 200:
            print(f"✅ SSE endpoint responding (Status: {response.status_code})")
            print(f"📋 Headers: {dict(response.headers)}")
            
            # Read initial data
            chunk = response.raw.read(1024)
            if chunk:
                data_str = chunk.decode('utf-8', errors='ignore')
                print(f"\n📝 Raw SSE Data:")
                print("=" * 50)
                print(repr(data_str))
                print("=" * 50)
                
                # Try to parse as JSON
                lines = data_str.split('\n')
                for line in lines:
                    if line.startswith('data: '):
                        json_str = line[6:].strip()
                        if json_str:
                            try:
                                data = json.loads(json_str)
                                print(f"\n✅ Parsed JSON:")
                                print(json.dumps(data, indent=2))
                            except json.JSONDecodeError as e:
                                print(f"\n❌ JSON Parse Error: {e}")
                                print(f"Raw JSON string: {repr(json_str)}")
                            break
            else:
                print("❌ No data received")
            
            response.close()
        else:
            print(f"❌ SSE endpoint failed (Status: {response.status_code})")
            
    except requests.exceptions.Timeout:
        print("⏰ SSE timeout (expected)")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    capture_sse() 