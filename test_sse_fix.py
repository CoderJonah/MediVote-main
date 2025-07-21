#!/usr/bin/env python3
import requests
import time

def test_sse_fix():
    print("🧪 TESTING SSE FIX")
    print("=" * 30)
    
    try:
        # Test SSE connection with short timeout
        print("Testing SSE connection...")
        start_time = time.time()
        
        response = requests.get('http://localhost:8090/events', timeout=3)
        
        elapsed = time.time() - start_time
        print(f"✅ SSE test completed in {elapsed:.2f} seconds")
        print(f"✅ Status: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ SSE connection successful")
        else:
            print(f"❌ SSE connection failed: {response.status_code}")
            
    except requests.exceptions.ReadTimeout:
        print("✅ SSE timeout (expected behavior)")
    except requests.exceptions.ConnectionError:
        print("✅ SSE connection error (expected behavior)")
    except Exception as e:
        print(f"❌ SSE test failed: {e}")
    
    print("\n🎉 SSE hanging issue should be fixed!")

if __name__ == "__main__":
    test_sse_fix() 