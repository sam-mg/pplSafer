#!/usr/bin/env python3
"""
Enhanced Python runner for network/connection monitoring that loads JSON configuration 
and injects it into JavaScript. Uses subprocess approach to avoid Java runtime timing 
issues with Frida Python bindings.
"""

import subprocess
import sys
import os
import json
import tempfile

PACKAGE_NAME = "com.jd_s4nd_b0x.nullclass"
CONFIG_FILE = "Frida Hook/Network Calls/network_config.json"

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
    """Inject configuration into the existing hook_networks.js file"""
    script_path = "Frida Hook/Network Calls/hook_networks.js"
    
    try:
        with open(script_path, 'r') as f:
            original_script = f.read()
    except FileNotFoundError:
        print(f"[!] Error: {script_path} not found")
        return None
    
    # Replace the empty networkConfig with actual config
    config_line = f"let networkConfig = {json.dumps(config, indent=2)};"
    modified_script = original_script.replace("let networkConfig = {};", config_line)
    
    # Add immediate call to startHooking at the end
    modified_script += "\n\n// Auto-start hooking when script loads\nJava.perform(() => {\n  startHooking();\n});"
    
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
    print(f"[*] Starting network monitoring for package: {package_name}")
    print(f"[*] Using script: {script_path}")
    print(f"[*] Configuration loaded from: {CONFIG_FILE}")
    print("[*] Starting Frida...")
    
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
            print(f"[*] Cleaned up temporary script: {script_path}")
        except:
            pass
    
    return True

def main():
    """Main function"""
    print("=== Network/Connection API Monitor ===")
    print("Loading configuration and starting Frida hook...")
    
    # Load configuration
    config = load_config()
    if config is None:
        sys.exit(1)
    
    print(f"[✓] Loaded configuration with {len(config.get('connections', {}))} connection classes")
    print(f"[✓] Additional classes: {len(config.get('additionalClasses', {}))}")
    
    # Inject config into script
    modified_script = inject_config_into_script(config)
    if modified_script is None:
        sys.exit(1)
    
    print("[✓] Configuration injected into JavaScript")
    
    # Create temporary script
    temp_script_path = create_temp_script(modified_script)
    if temp_script_path is None:
        sys.exit(1)
    
    print(f"[✓] Temporary script created: {temp_script_path}")
    
    # Get package name from command line or use default
    package_name = sys.argv[1] if len(sys.argv) > 1 else PACKAGE_NAME
    
    # Run Frida
    success = run_frida_hook(temp_script_path, package_name)
    
    if success:
        print("[✓] Network monitoring completed successfully")
    else:
        print("[!] Network monitoring failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
