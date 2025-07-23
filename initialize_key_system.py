#!/usr/bin/env python3
"""
🔐 MediVote Key System Initialization Script

Run this script to initialize the secure key management system for MediVote.
This will generate all required cryptographic keys and set up the secure storage.

Usage:
    python initialize_key_system.py
"""

import sys
import json
from pathlib import Path

def main():
    print("🔐 MediVote Key Management System Initialization")
    print("=" * 60)
    
    try:
        # Import the key integration system
        from backend.core.key_integration import setup_development_environment
        
        print("🚀 Initializing secure key management system...")
        print()
        
        # Setup development environment with automatic key generation
        status = setup_development_environment()
        
        print()
        print("✅ KEY SYSTEM INITIALIZATION COMPLETE!")
        print("=" * 60)
        print()
        
        # Show key directory contents
        keys_dir = Path("keys")
        if keys_dir.exists():
            print("📁 Generated Key Files:")
            for key_file in sorted(keys_dir.glob("*.key")):
                file_size = key_file.stat().st_size
                permissions = oct(key_file.stat().st_mode)[-3:]
                print(f"   📄 {key_file.name} ({file_size} bytes, permissions: {permissions})")
            print()
        
        # Show security status
        print("📊 Security System Status:")
        print(f"   🌍 Environment: {status['environment']}")
        print(f"   🔑 Total Keys: {status['key_manager_stats']['total_keys']}")
        print(f"   🛡️  Security Level: {'PRODUCTION' if status['production_ready'] else 'DEVELOPMENT'}")
        print(f"   ✅ Required Keys: {'Present' if status['security_controls']['required_keys_present'] else 'Missing'}")
        print()
        
        # Show key breakdown
        print("🔑 Generated Keys by Type:")
        for key_type, count in status['key_manager_stats']['keys_by_type'].items():
            print(f"   • {key_type.replace('_', ' ').title()}: {count}")
        print()
        
        print("🎯 NEXT STEPS:")
        print("1. ✅ Key system is now initialized and ready to use")
        print("2. 📖 Read DEVELOPMENT_KEY_SETUP_GUIDE.md for usage instructions")
        print("3. 🔗 Integrate with your application using the examples in the guide")
        print("4. 🏭 For production deployment, see PRODUCTION_KEY_GUIDE.md")
        print()
        
        print("⚠️  IMPORTANT SECURITY NOTES:")
        print("• These are DEVELOPMENT keys - regenerate for production!")
        print("• Keys are stored in ./keys/ directory with secure permissions")
        print("• Master key encrypts all other keys for additional security")
        print("• Never commit the keys/ directory to version control")
        print()
        
        print("🔐 Your MediVote system is now cryptographically secure!")
        
        return 0
        
    except ImportError as e:
        print(f"❌ Error: Could not import key management system: {e}")
        print("   Make sure you're running from the MediVote project directory")
        return 1
        
    except Exception as e:
        print(f"❌ Error during key system initialization: {e}")
        print("   Check the error details above and try again")
        return 1

def show_key_info():
    """Show information about existing keys"""
    try:
        from backend.core.key_integration import get_security_manager
        
        security_manager = get_security_manager()
        status = security_manager.get_security_status()
        
        print("📊 Current Key System Status:")
        print(json.dumps(status, indent=2, default=str))
        
    except Exception as e:
        print(f"⚠️  Key system not initialized: {e}")
        print("   Run without arguments to initialize the key system")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        show_key_info()
    else:
        exit_code = main()
        sys.exit(exit_code) 