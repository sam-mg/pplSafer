#!/usr/bin/env python3

import subprocess
import sys
import os
import json
import tempfile
import signal
import time
import ast
import threading
import select
import tty
import termios

def get_package_name_from_analysis():
    """Load package name from apk_hash_checker_output.json"""
    analysis_file = "analysis/apk_hash_checker_output.json"
    
    try:
        with open(analysis_file, 'r') as f:
            data = json.load(f)
            package_name = data.get('package_name')
            if package_name:
                print(f"[*] Loaded package name: {package_name}")
                return package_name
            else:
                print(f"[!] No package_name found in {analysis_file}")
                sys.exit(1)
    except FileNotFoundError:
        print(f"[!] Analysis file not found: {analysis_file}")
        print("[!] Please run APK analysis first or check the file path")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in {analysis_file}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error reading {analysis_file}: {e}")
        sys.exit(1)

PACKAGE_NAME = get_package_name_from_analysis()
API_CONFIG_FILE = "analysis/dynamic/API Calls/api_config.json"
NETWORK_CONFIG_FILE = "analysis/dynamic/Network Calls/network_config.json"
API_OUTPUT_FILE = "analysis/dynamic/API Calls/api_monitor_output.json"
NETWORK_OUTPUT_FILE = "analysis/dynamic/Network Calls/network_monitor_output.json"

frida_process = None
shutdown_event = threading.Event()

def stop_frida_gracefully():
    """Stop Frida process gracefully"""
    global frida_process
    if frida_process:
        try:
            print("\n[*] Stopping Frida process...")
            frida_process.terminate()
            print("[*] Sent SIGTERM to Frida process")
            try:
                frida_process.wait(timeout=5)
                print("[*] Frida process terminated gracefully")
            except subprocess.TimeoutExpired:
                print("[*] Frida process didn't terminate gracefully, force killing...")
                frida_process.kill()
                frida_process.wait()
                print("[*] Frida process force killed")
        except Exception as e:
            print(f"[!] Error stopping Frida process: {e}")
    
    shutdown_event.set()

def keyboard_listener():
    """Listen for keyboard input in a separate thread"""
    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        
        while not shutdown_event.is_set():
            if select.select([sys.stdin], [], [], 0.1)[0]:
                ch = sys.stdin.read(1)
                if ch.lower() == 'e':
                    print("\n[*] Exit command received ('e')")
                    stop_frida_gracefully()
                    break
                elif ch == '\x03':
                    print("\n[*] Ctrl+C received - press 'e' to stop Frida monitoring")
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully - don't exit, just show options"""
    print("\n[*] Ctrl+C detected!")
    print("[*] Press 'e' to stop Frida monitoring")

def save_api_call_data(data):
    """Save API call data to JSON file"""
    try:
        if os.path.exists(API_OUTPUT_FILE):
            with open(API_OUTPUT_FILE, 'r') as f:
                existing_data = json.load(f)
        else:
            existing_data = []
        existing_data.append(data)
        with open(API_OUTPUT_FILE, 'w') as f:
            json.dump(existing_data, f, indent=2)
    except Exception as e:
        print(f"[!] Error saving API data to file: {e}")

def save_network_call_data(data):
    """Save network call data to JSON file"""
    try:
        if os.path.exists(NETWORK_OUTPUT_FILE):
            with open(NETWORK_OUTPUT_FILE, 'r') as f:
                existing_data = json.load(f)
        else:
            existing_data = []
        existing_data.append(data)
        with open(NETWORK_OUTPUT_FILE, 'w') as f:
            json.dump(existing_data, f, indent=2)
            
    except Exception as e:
        print(f"[!] Error saving network data to file: {e}")

def process_json_output(line):
    """Process JSON output from Frida script"""
    try:
        if 'message:' in line and "'type': 'send'" in line and "'payload':" in line:
            start_idx = line.find("message: ") + len("message: ")
            end_idx = line.find(" data:")
            if start_idx > 8 and end_idx > start_idx:
                message_str = line[start_idx:end_idx]
                message_data = ast.literal_eval(message_str)
                if message_data.get('type') == 'send' and 'payload' in message_data:
                    data = message_data['payload']
                    if 'fullMethodSignature' in data and 'category' in data:
                        print(f"\n[API_CALL] {data['fullMethodSignature']}")
                        print(f"[TIMESTAMP] {data['timestamp']}")
                        print(f"[CATEGORY] {data['category']}")
                        if data['arguments']:
                            print("[ARGUMENTS]")
                            for arg in data['arguments']:
                                print(f"  - {arg['name']}: {arg['value']} ({arg['type']})")
                        if data['returnValue'] and data['returnValue'] != "void":
                            print(f"[RETURN] {data['returnValue']}")
                        if data['exception']:
                            print(f"[EXCEPTION] {data['exception']}")
                        print("-" * 60)
                        save_api_call_data(data)
                    elif 'url' in data or 'host' in data or 'method' in data:
                        print(f"\n[NETWORK_CALL] {json.dumps(data, indent=2)}")
                        save_network_call_data(data)
                    return data
    except (ValueError, SyntaxError) as e:
        print(f"[!] Parse error: {e}")
    except Exception as e:
        print(f"[!] Error processing JSON: {e}")
    return None

def load_api_config():
    """Load the API configuration from JSON file"""
    possible_paths = [
        API_CONFIG_FILE,
        f"analysis/Dynamic/API Calls/api_config.json",
        f"Dynamic/API Calls/api_config.json",
        f"./analysis/Dynamic/API Calls/api_config.json",
        f"./Dynamic/API Calls/api_config.json"
    ]
    for config_path in possible_paths:
        try:
            if os.path.exists(config_path):
                print(f"[*] Found API config file at: {config_path}")
                with open(config_path, 'r') as f:
                    return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Error: Invalid JSON in {config_path}: {e}")
            continue
        except Exception as e:
            continue
    print(f"[!] No API config file found. Creating default config at: {API_CONFIG_FILE}")
    default_config = {
        "security": [
            "java.security.MessageDigest",
            "javax.crypto.Cipher",
            "java.security.SecureRandom"
        ],
        "network": [
            "java.net.URL",
            "java.net.HttpURLConnection",
            "okhttp3.OkHttpClient"
        ],
        "file": [
            "java.io.File",
            "java.io.FileInputStream",
            "java.io.FileOutputStream"
        ]
    }
    try:
        os.makedirs(os.path.dirname(API_CONFIG_FILE), exist_ok=True)
        with open(API_CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=2)
        print(f"[*] Created default API config file: {API_CONFIG_FILE}")
        return default_config
    except Exception as e:
        print(f"[!] Error creating default API config: {e}")
        return None

def load_network_config():
    """Load the network configuration from JSON file"""
    possible_paths = [
        NETWORK_CONFIG_FILE,
        f"analysis/Dynamic/Network Calls/network_config.json",
        f"Dynamic/Network Calls/network_config.json",
        f"./analysis/Dynamic/Network Calls/network_config.json",
        f"./Dynamic/Network Calls/network_config.json"
    ]
    for config_path in possible_paths:
        try:
            if os.path.exists(config_path):
                print(f"[*] Found network config file at: {config_path}")
                with open(config_path, 'r') as f:
                    return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Error: Invalid JSON in {config_path}: {e}")
            continue
        except Exception as e:
            continue
    print(f"[!] No network config file found. Creating default config at: {NETWORK_CONFIG_FILE}")
    default_config = {
        "urlPatterns": [
            "http://",
            "https://",
            "api.",
            ".com",
            ".net",
            ".org"
        ],
        "suspiciousKeywords": [
            "password",
            "token",
            "key",
            "secret",
            "auth",
            "login",
            "credential"
        ],
        "trackHeaders": [
            "Authorization",
            "Cookie",
            "User-Agent",
            "X-API-Key",
            "Content-Type"
        ],
        "maxResponseSize": 10240
    }
    try:
        os.makedirs(os.path.dirname(NETWORK_CONFIG_FILE), exist_ok=True)
        with open(NETWORK_CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=2)
        print(f"[*] Created default network config file: {NETWORK_CONFIG_FILE}")
        return default_config
    except Exception as e:
        print(f"[!] Error creating default network config: {e}")
        return None

def create_unified_script(api_config, network_config):
    """Create a unified JavaScript script that combines both API and Network monitoring"""
    api_script_paths = [
        "analysis/dynamic/API Calls/hook_apis.js",
        "Dynamic/API Calls/hook_apis.js",
        "./analysis/dynamic/API Calls/hook_apis.js",
        "./Dynamic/API Calls/hook_apis.js"
    ]
    
    api_script = None
    for path in api_script_paths:
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    api_script = f.read()
                    print(f"[*] Found API hook file at: {path}")
                    break
        except Exception as e:
            continue
    
    if api_script is None:
        print(f"[!] Error: hook_apis.js not found")
        return None
    
    network_script_paths = [
        "analysis/dynamic/Network Calls/frida_hooks.js",
        "Dynamic/Network Calls/frida_hooks.js",
        "./analysis/dynamic/Network Calls/frida_hooks.js",
        "./Dynamic/Network Calls/frida_hooks.js"
    ]
    
    network_script = None
    for path in network_script_paths:
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    network_script = f.read()
                    print(f"[*] Found Network hook file at: {path}")
                    break
        except Exception as e:
            continue
    
    if network_script is None:
        print(f"[!] Error: frida_hooks.js not found")
        return None
    
    bypass_script_paths = [
        "analysis/dynamic/Root and Emulator Detection Bypass.js",
        "Dynamic/Root and Emulator Detection Bypass.js",
        "./analysis/dynamic/Root and Emulator Detection Bypass.js",
        "./Dynamic/Root and Emulator Detection Bypass.js"
    ]
    
    bypass_script = None
    for path in bypass_script_paths:
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    bypass_script = f.read()
                    print(f"[*] Found Root and Emulator Detection Bypass file at: {path}")
                    break
        except Exception as e:
            continue
    
    if bypass_script is None:
        print(f"[!] Warning: Root and Emulator Detection Bypass.js not found - continuing without bypass")
        bypass_script = "// Root and Emulator Detection Bypass not found"
    
    unified_script = f"""
// ============ UNIFIED API AND NETWORK MONITORING WITH ROOT/EMULATOR BYPASS ============

// ============ ROOT AND EMULATOR DETECTION BYPASS ============
{bypass_script}

// API Configuration
let apiConfig = {json.dumps(api_config, indent=2)};

// Network Configuration  
let networkConfig = {json.dumps(network_config, indent=2)};

// ============ API MONITORING FUNCTIONS ============
{api_script.replace('let apiConfig = {};', '// API config already defined above')}

// ============ NETWORK MONITORING FUNCTIONS ============
{network_script.replace('let networkConfig = {};', '// Network config already defined above')}

// ============ UNIFIED STARTUP ============
Java.perform(() => {{
    console.log("[*] Starting unified monitoring with root/emulator bypass...");
    
    // Start API monitoring
    try {{
        console.log("[*] Initializing API monitoring...");
        startHooking();
        console.log("[*] API monitoring started successfully");
    }} catch (e) {{
        console.log("[!] Error starting API monitoring: " + e);
    }}
    
    // Start Network monitoring
    try {{
        console.log("[*] Initializing Network monitoring...");
        startNetworkMonitoring();
        console.log("[*] Network monitoring started successfully");
    }} catch (e) {{
        console.log("[!] Error starting Network monitoring: " + e);
    }}
    
    console.log("[*] Unified monitoring with bypass protections is now active!");
}});
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(unified_script)
        return f.name

def main():
    global frida_process
    temp_script = None
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("="*80)
    print("       UNIFIED API AND NETWORK MONITORING WITH ROOT/EMULATOR BYPASS")
    print("="*80)
    
    print(f"[*] Loading API configuration from {API_CONFIG_FILE}")
    api_config = load_api_config()
    if api_config is None:
        return 1
    
    print(f"[*] Loading Network configuration from {NETWORK_CONFIG_FILE}")
    network_config = load_network_config()
    if network_config is None:
        return 1
    
    print(f"[*] Loaded API configuration: {len(api_config)} categories")
    for category, apis in api_config.items():
        print(f"    - {category}: {len(apis)} classes")
    
    print(f"[*] Loaded Network configuration:")
    print(f"    - URL patterns: {len(network_config.get('urlPatterns', []))}")
    print(f"    - Suspicious keywords: {len(network_config.get('suspiciousKeywords', []))}")
    print(f"    - Tracked headers: {len(network_config.get('trackHeaders', []))}")
    
    try:
        print(f"[*] Creating unified monitoring script...")
        temp_script = create_unified_script(api_config, network_config)
        if temp_script is None:
            return 1
        
        package_name = sys.argv[1] if len(sys.argv) > 1 else PACKAGE_NAME
        
        print(f"[*] Starting unified monitoring with root/emulator bypass for {package_name}")
        print(f"[*] API calls will be logged to: {API_OUTPUT_FILE}")
        print(f"[*] Network calls will be logged to: {NETWORK_OUTPUT_FILE}")
        print(f"[*] Root/Emulator detection bypass active")
        print("[*] Press 'e' to stop Frida monitoring")
        print("=" * 80)
        
        cmd = ["frida", "-U", "-f", package_name, "-l", temp_script, "--runtime=v8"]
        
        frida_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        print(f"[*] Frida process started with PID: {frida_process.pid}")
        keyboard_thread = threading.Thread(target=keyboard_listener, daemon=True)
        keyboard_thread.start()
        while not shutdown_event.is_set():
            if frida_process.poll() is not None:
                print("[*] Frida process ended")
                break
            try:
                import select
                ready, _, _ = select.select([frida_process.stdout], [], [], 0.1)
                
                if ready:
                    line = frida_process.stdout.readline()
                    if line:
                        line = line.strip()
                        if line:
                            json_data = process_json_output(line)
                            if not json_data:
                                print(f"[FRIDA] {line}")
                else:
                    time.sleep(0.1)
            except Exception as e:
                if not shutdown_event.is_set():
                    print(f"[!] Error reading output: {e}")
                break
        if frida_process and frida_process.poll() is None:
            try:
                frida_process.terminate()
                frida_process.wait(timeout=3)
            except:
                try:
                    frida_process.kill()
                    frida_process.wait()
                except:
                    pass
        print("\n[*] Frida monitoring stopped. Script exiting...")
    except FileNotFoundError:
        print("[!] Error: frida command not found")
        print("    Make sure Frida is installed and in your PATH")
        return 1
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        if frida_process:
            try:
                frida_process.terminate()
                frida_process.wait(timeout=5)
            except:
                try:
                    frida_process.kill()
                    frida_process.wait()
                except:
                    pass
        return 1
    finally:
        if temp_script and os.path.exists(temp_script):
            try:
                os.unlink(temp_script)
            except:
                pass
    print("[*] Script terminated")
    print(f"[*] API monitoring results saved to: {API_OUTPUT_FILE}")
    print(f"[*] Network monitoring results saved to: {NETWORK_OUTPUT_FILE}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
