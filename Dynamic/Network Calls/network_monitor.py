#!/usr/bin/env python3

import subprocess
import sys
import os
import json
import tempfile

PACKAGE_NAME = "com.example.testing_app"
CONFIG_FILE = "Dynamic/Network Calls/network_config.json"

def load_config():
    """Load the network configuration from JSON file"""
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
    """Inject configuration from network_config.json into frida_hooks.js"""
    script_path = "Dynamic/Network Calls/frida_hooks.js"
    
    try:
        with open(script_path, 'r') as f:
            original_script = f.read()
    except FileNotFoundError:
        print(f"[!] Error: {script_path} not found")
        return None
    
    # Replace the placeholder with actual configuration
    config_line = f"let networkConfig = {json.dumps(config, indent=2)};"
    modified_script = original_script.replace("let networkConfig = {};", config_line)
    
    return modified_script

def create_temp_script(modified_script):
    """Create a temporary script file with the injected configuration"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(modified_script)
            return f.name
    except Exception as e:
        print(f"[!] Error creating temporary script: {e}")
        return None

def run_frida_hook(script_path, package_name):
    """Run Frida with the generated script"""
    try:
        # Run frida with the script
        cmd = ["frida", "-U", "-f", package_name, "-l", script_path]
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Frida failed with error code {e.returncode}")
        return False
    except KeyboardInterrupt:
        print("\n[*] Stopping network monitoring...")
        return True
    except FileNotFoundError:
        print("[!] Error: Frida not found. Please install Frida.")
        return False
    finally:
        # Clean up temporary file
        try:
            os.unlink(script_path)
        except:
            pass
    
    return True

def main():
    """Main function"""
    print("🌐 Network Monitor Starting...")
    print(f"📋 Loading configuration from: {CONFIG_FILE}")
    
    config = load_config()
    if config is None:
        sys.exit(1)
    
    print(f"✅ Configuration loaded successfully:")
    print(f"   - Connection classes: {len(config.get('connections', {}))}")
    print(f"   - Additional classes: {len(config.get('additionalClasses', {}))}")
    
    modified_script = inject_config_into_script(config)
    if modified_script is None:
        sys.exit(1)
    
    temp_script_path = create_temp_script(modified_script)
    if temp_script_path is None:
        sys.exit(1)
    
    package_name = sys.argv[1] if len(sys.argv) > 1 else PACKAGE_NAME
    print(f"📱 Monitoring package: {package_name}")
    print("=" * 60)
    
    success = run_frida_hook(temp_script_path, package_name)
    
    if success:
        print("\n[✓] Network monitoring completed")
    else:
        print("\n[!] Network monitoring failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
