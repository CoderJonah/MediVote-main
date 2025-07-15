#!/usr/bin/env python3
"""
MediVote Deployment Verification Script
Tests connectivity and basic functionality of deployed components
"""

import sys
import time
import socket
import subprocess
import json
from datetime import datetime

def test_port_connectivity(host, port, service_name):
    """Test if a port is accessible"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"✅ {service_name} ({host}:{port}) is accessible")
            return True
        else:
            print(f"❌ {service_name} ({host}:{port}) is not accessible")
            return False
    except Exception as e:
        print(f"❌ {service_name} connectivity test failed: {e}")
        return False


def test_database_connectivity():
    """Test PostgreSQL database connectivity"""
    print("\n🗄️ Testing Database Connectivity...")
    
    # Test port connectivity first
    if not test_port_connectivity("localhost", 5432, "PostgreSQL"):
        return False
    
    try:
        # Try to install psycopg2 if not available
        try:
            import psycopg2
        except ImportError:
            print("📦 Installing psycopg2...")
            subprocess.run([sys.executable, "-m", "pip", "install", "psycopg2-binary"], 
                          check=True, capture_output=True)
            import psycopg2
        
        # Test database connection
        conn = psycopg2.connect(
            host="localhost",
            port=5432,
            database="medivote",
            user="medivote",
            password="medivote_secure_password"
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        print(f"✅ Database connection successful: {version[0][:50]}...")
        return True
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False


def test_redis_connectivity():
    """Test Redis connectivity"""
    print("\n🔴 Testing Redis Connectivity...")
    
    # Test port connectivity first
    if not test_port_connectivity("localhost", 6379, "Redis"):
        return False
    
    try:
        # Try to install redis if not available
        try:
            import redis
        except ImportError:
            print("📦 Installing redis...")
            subprocess.run([sys.executable, "-m", "pip", "install", "redis"], 
                          check=True, capture_output=True)
            import redis
        
        # Test Redis connection
        r = redis.Redis(host='localhost', port=6379, decode_responses=True)
        
        # Test basic operations
        r.set('medivote_test', 'deployment_verification')
        result = r.get('medivote_test')
        r.delete('medivote_test')
        
        if result == 'deployment_verification':
            print("✅ Redis connection and operations successful")
            return True
        else:
            print("❌ Redis operations failed")
            return False
            
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        return False


def test_docker_containers():
    """Test Docker container status"""
    print("\n🐳 Testing Docker Containers...")
    
    try:
        # Get container status
        result = subprocess.run(
            ["docker", "ps", "--format", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        
        containers = []
        for line in result.stdout.strip().split('\n'):
            if line:
                containers.append(json.loads(line))
        
        medivote_containers = [c for c in containers if 'medivote' in c['Names']]
        
        print(f"Found {len(medivote_containers)} MediVote containers:")
        
        all_healthy = True
        for container in medivote_containers:
            status = container['Status']
            name = container['Names']
            
            if 'Up' in status:
                print(f"✅ {name}: {status}")
            else:
                print(f"❌ {name}: {status}")
                all_healthy = False
        
        return all_healthy and len(medivote_containers) >= 2
        
    except subprocess.CalledProcessError:
        # Try with sudo
        try:
            result = subprocess.run(
                ["sudo", "docker", "ps", "--filter", "name=medivote", "--format", "table {{.Names}}\t{{.Status}}"],
                capture_output=True,
                text=True,
                check=True
            )
            
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            running_containers = [line for line in lines if 'Up' in line]
            
            print(f"Found {len(running_containers)} running MediVote containers")
            
            for line in running_containers:
                print(f"✅ {line}")
            
            return len(running_containers) >= 2
            
        except Exception as e:
            print(f"❌ Docker container check failed: {e}")
            return False
    
    except Exception as e:
        print(f"❌ Docker container check failed: {e}")
        return False


def test_system_requirements():
    """Test system requirements"""
    print("\n⚙️ Testing System Requirements...")
    
    requirements_met = True
    
    # Check Python version
    python_version = sys.version_info
    if python_version >= (3, 9):
        print(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}")
    else:
        print(f"❌ Python {python_version.major}.{python_version.minor}.{python_version.micro} (3.9+ required)")
        requirements_met = False
    
    # Check Docker
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True, check=True)
        print(f"✅ {result.stdout.strip()}")
    except:
        try:
            result = subprocess.run(["sudo", "docker", "--version"], capture_output=True, text=True, check=True)
            print(f"✅ {result.stdout.strip()} (requires sudo)")
        except:
            print("❌ Docker not found")
            requirements_met = False
    
    # Check available memory
    try:
        with open('/proc/meminfo', 'r') as f:
            mem_info = f.read()
        
        for line in mem_info.split('\n'):
            if 'MemTotal:' in line:
                mem_kb = int(line.split()[1])
                mem_gb = mem_kb / 1024 / 1024
                
                if mem_gb >= 4:
                    print(f"✅ Memory: {mem_gb:.1f} GB")
                else:
                    print(f"⚠️ Memory: {mem_gb:.1f} GB (4GB+ recommended)")
                break
    except:
        print("⚠️ Could not check memory")
    
    return requirements_met


def create_deployment_summary():
    """Create deployment summary"""
    return {
        "deployment_verified_at": datetime.utcnow().isoformat(),
        "components": {
            "postgresql": "running",
            "redis": "running",
            "docker": "operational"
        },
        "status": "infrastructure_ready",
        "next_steps": [
            "Build and deploy backend application",
            "Initialize database schema",
            "Deploy frontend application",
            "Configure SSL/TLS certificates",
            "Run security audit"
        ]
    }


def main():
    """Main verification function"""
    print("🚀 MediVote Deployment Verification")
    print("=" * 50)
    
    tests = [
        ("System Requirements", test_system_requirements),
        ("Docker Containers", test_docker_containers),
        ("Database Connectivity", test_database_connectivity),
        ("Redis Connectivity", test_redis_connectivity),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Verification Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 Deployment verification successful!")
        print("\n📄 Deployment Summary:")
        summary = create_deployment_summary()
        for key, value in summary.items():
            if isinstance(value, dict):
                print(f"  {key}:")
                for k, v in value.items():
                    print(f"    {k}: {v}")
            elif isinstance(value, list):
                print(f"  {key}:")
                for item in value:
                    print(f"    - {item}")
            else:
                print(f"  {key}: {value}")
        
        return True
    else:
        print("⚠️ Some verification tests failed.")
        print("Check the errors above and fix issues before proceeding.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 