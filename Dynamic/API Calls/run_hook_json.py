#!/usr/bin/env python3
"""
Enhanced Python runner that loads JSON configuration and injects it into JavaScript.
Uses subprocess approach to avoid Java runtime timing issues with Frida Python bindings.
"""

import subprocess
import sys
import os
import json
import tempfile

PACKAGE_NAME = "com.example.testing_app"
CONFIG_FILE = "Frida Hook/API Calls/api_config.json"

def load_config():
    """Load the API configuration from JSON file"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: {CONFIG_FILE} not found")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] Error: Invalid JSON in {CONFIG_FILE}: {e}")
        return None

def inject_config_into_script(config):
    """Inject configuration into the existing hook_apis.js file"""
    script_path = "Frida Hook/API Calls/hook_apis.js"
    
    try:
        with open(script_path, 'r') as f:
            original_script = f.read()
    except FileNotFoundError:
        print(f"[!] Error: {script_path} not found")
        return None
    
    # Replace the empty apiConfig with actual config
    config_line = f"let apiConfig = {json.dumps(config, indent=2)};"
    modified_script = original_script.replace("let apiConfig = {};", config_line)
    
    # Also remove the RPC setconfig function since we're injecting directly
    # and call startHooking() immediately
    modified_script = modified_script.replace(
        "rpc.exports.setconfig = function(config) {\n  apiConfig = config;\n  console.log(\"=== Configuration loaded from api_config.json ===\");\n  startHooking();\n};",
        "// Configuration injected directly from Python script"
    )
    
    # Add immediate call to startHooking at the end
    modified_script += "\n\n// Start hooking immediately\nstartHooking();"
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(modified_script)
        return f.name

def main():
    temp_script = None
    try:
        print(f"[*] Loading configuration from {CONFIG_FILE}")
        config = load_config()
        if config is None:
            return 1
        
        print(f"[*] Loaded {len(config)} API categories")
        for category, apis in config.items():
            print(f"    - {category}: {len(apis)} classes")
        
        print(f"[*] Creating temporary script with injected configuration")
        temp_script = inject_config_into_script(config)
        if temp_script is None:
            return 1
        
        print(f"[*] Starting API monitoring for {PACKAGE_NAME}")
        print("[*] Press Ctrl+C to stop monitoring")
        print("=" * 60)
        
        # Build the frida command
        cmd = ["frida", "-U", "-f", PACKAGE_NAME, "-l", temp_script]
        
        # Run frida as a subprocess
        process = subprocess.run(cmd, text=True)
        
        print("\n[*] Monitoring stopped")
        return process.returncode
        
    except KeyboardInterrupt:
        print("\n[*] Monitoring interrupted by user")
        return 0
    except FileNotFoundError:
        print("[!] Error: frida command not found")
        print("    Make sure Frida is installed and in your PATH")
        return 1
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return 1
    finally:
        # Clean up temporary file
        if temp_script and os.path.exists(temp_script):
            try:
                os.unlink(temp_script)
                print("[*] Temporary files cleaned up")
            except:
                pass

if __name__ == "__main__":
    sys.exit(main())
