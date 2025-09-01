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

PACKAGE_NAME = "com.example.testing_app"
CONFIG_FILE = "analysis/Dynamic/Network Calls/network_config.json"
OUTPUT_FILE = "analysis/Dynamic/Network Calls/network_monitor_output.json"

# Global variables for signal handling
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
    # Save original terminal settings
    old_settings = termios.tcgetattr(sys.stdin)
    
    try:
        # Set terminal to raw mode for immediate key detection
        tty.setraw(sys.stdin.fileno())
        
        while not shutdown_event.is_set():
            if select.select([sys.stdin], [], [], 0.1)[0]:
                ch = sys.stdin.read(1)
                # Check for 'e' to exit Frida
                if ch.lower() == 'e':
                    print("\n[*] Exit command received ('e')")
                    stop_frida_gracefully()
                    break
                elif ch == '\x03':  # Ctrl+C
                    print("\n[*] Ctrl+C received - press 'e' to stop Frida monitoring")
    finally:
        # Restore terminal settings
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully - don't exit, just show options"""
    print("\n[*] Ctrl+C detected!")
    print("[*] Press 'e' to stop Frida monitoring")

def save_network_call_data(data):
    """Save network call data to JSON file"""
    try:
        # Load existing data or create empty list
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, 'r') as f:
                existing_data = json.load(f)
        else:
            existing_data = []
        
        # Append new data
        existing_data.append(data)
        
        # Save back to file
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(existing_data, f, indent=2)
            
    except Exception as e:
        pass  # Silent error handling

def process_json_output(line):
    """Process JSON output from Frida script"""
    try:
        # Check if the line contains Frida message data
        if 'message:' in line and "'type': 'send'" in line and "'payload':" in line:
            # Extract the message dict from the line using ast.literal_eval
            # Format: message: {'type': 'send', 'payload': {...}} data: None
            start_idx = line.find("message: ") + len("message: ")
            end_idx = line.find(" data:")
            if start_idx > 8 and end_idx > start_idx:
                message_str = line[start_idx:end_idx]
                # Use ast.literal_eval to parse Python dict literals safely
                message_data = ast.literal_eval(message_str)
                
                if message_data.get('type') == 'send' and 'payload' in message_data:
                    data = message_data['payload']
                    
                    # Output only JSON
                    print(json.dumps(data, indent=2))
                    
                    # Save to file
                    save_network_call_data(data)
                    
                    return data
    except (ValueError, SyntaxError) as e:
        pass  # Silent error handling
    except Exception as e:
        pass  # Silent error handling
    return None

def load_config():
    """Load the network configuration from JSON file"""
    # Try multiple possible paths
    possible_paths = [
        CONFIG_FILE,
        f"analysis/Dynamic/Network Calls/network_config.json",
        f"Dynamic/Network Calls/network_config.json",
        f"./analysis/Dynamic/Network Calls/network_config.json",
        f"./Dynamic/Network Calls/network_config.json"
    ]
    
    for config_path in possible_paths:
        try:
            if os.path.exists(config_path):
                print(f"[*] Found config file at: {config_path}")
                with open(config_path, 'r') as f:
                    return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Error: Invalid JSON in {config_path}: {e}")
            continue
        except Exception as e:
            continue
    
    # If no config file found, create a default one
    print(f"[!] No config file found. Creating default config at: {CONFIG_FILE}")
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
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        print(f"[*] Created default config file: {CONFIG_FILE}")
        return default_config
        
    except Exception as e:
        print(f"[!] Error creating default config: {e}")
        return None

def inject_config_into_script(config):
    """Inject configuration from network_config.json into frida_hooks.js"""
    possible_script_paths = [
        "analysis/Dynamic/Network Calls/frida_hooks.js",
        "Dynamic/Network Calls/frida_hooks.js",
        "./analysis/Dynamic/Network Calls/frida_hooks.js",
        "./Dynamic/Network Calls/frida_hooks.js"
    ]
    
    script_path = None
    original_script = None
    
    for path in possible_script_paths:
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    original_script = f.read()
                    script_path = path
                    print(f"[*] Found JavaScript hook file at: {path}")
                    break
        except Exception as e:
            continue
    
    if original_script is None:
        print(f"[!] Error: frida_hooks.js not found in any of the expected locations")
        print(f"[!] Searched in: {', '.join(possible_script_paths)}")
        return None
    
    # Replace the placeholder with actual configuration
    config_line = f"let networkConfig = {json.dumps(config, indent=2)};"
    modified_script = original_script.replace("let networkConfig = {};", config_line)
    
    # Add automatic startup
    modified_script += "\n\n// Start network monitoring immediately\nstartNetworkMonitoring();"
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(modified_script)
        return f.name

def main():
    global frida_process
    temp_script = None
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"[*] Loading configuration from {CONFIG_FILE}")
    config = load_config()
    if config is None:
        return 1
    
    print(f"[*] Network monitoring configuration loaded successfully")
    print(f"    - URL patterns: {len(config.get('urlPatterns', []))}")
    print(f"    - Suspicious keywords: {len(config.get('suspiciousKeywords', []))}")
    print(f"    - Tracked headers: {len(config.get('trackHeaders', []))}")
    
    try:
        temp_script = inject_config_into_script(config)
        if temp_script is None:
            return 1
        
        package_name = sys.argv[1] if len(sys.argv) > 1 else PACKAGE_NAME
        
        print(f"[*] Starting network monitoring for {package_name}")
        print(f"[*] Network calls will be logged to: {OUTPUT_FILE}")
        print("[*] Press 'e' to stop Frida monitoring")
        print("=" * 60)
        
        cmd = ["frida", "-U", "-f", package_name, "-l", temp_script, "--runtime=v8"]
        
        # Use Popen for persistent communication with line buffering
        frida_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout for easier handling
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )
        
        print(f"[*] Frida process started with PID: {frida_process.pid}")
        
        # Start keyboard listener thread
        keyboard_thread = threading.Thread(target=keyboard_listener, daemon=True)
        keyboard_thread.start()
        
        # Read output continuously
        while not shutdown_event.is_set():
            # Check if process is still running
            if frida_process.poll() is not None:
                print("[*] Frida process ended")
                break
                
            # Read stdout line by line with timeout
            try:
                # Use select for non-blocking read with timeout
                import select
                ready, _, _ = select.select([frida_process.stdout], [], [], 0.1)
                
                if ready:
                    line = frida_process.stdout.readline()
                    if line:
                        line = line.strip()
                        if line:
                            # Only process JSON data, ignore other Frida output
                            process_json_output(line)
                else:
                    time.sleep(0.1)
                    
            except Exception as e:
                if not shutdown_event.is_set():
                    print(f"[!] Error reading output: {e}")
                break
        
        # Clean up Frida process
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
        # Clean up temp script
        if temp_script and os.path.exists(temp_script):
            try:
                os.unlink(temp_script)
            except:
                pass
    
    print("[*] Script terminated")
    return 0

if __name__ == "__main__":
    sys.exit(main())
