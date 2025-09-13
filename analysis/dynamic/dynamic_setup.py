#!/usr/bin/env python3

import subprocess
import os
import sys
import time
from pathlib import Path

AVD_EXECUTABLE_PATH = os.path.expanduser("~/Library/Android/sdk/emulator/emulator")
GENYMOTION_EXECUTABLE_PATH = "/Applications/Genymotion.app/Contents/MacOS/gmtool"

class DynamicSetup:
    def __init__(self):
        self.uploads_dir = Path(__file__).parent.parent.parent / "uploads"
        self.apk_files = []
    
    def find_avd_emulators(self):
        """Finds and prints AVD emulator names."""
        if not os.path.exists(AVD_EXECUTABLE_PATH):
            return []

        try:
            result = subprocess.run(
                [AVD_EXECUTABLE_PATH, "-list-avds"],
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout.strip()
            
            avd_list = []
            if output:
                for line in output.splitlines():
                    avd_name = line.strip()
                    if avd_name:
                        avd_list.append(avd_name)
            
            return avd_list

        except (subprocess.CalledProcessError, Exception):
            return []

    def find_genymotion_emulators(self):
        """Finds and prints Genymotion emulator names."""
        if not os.path.exists(GENYMOTION_EXECUTABLE_PATH):
            return []

        try:
            result = subprocess.run(
                [GENYMOTION_EXECUTABLE_PATH, "admin", "list"],
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout.strip()
            
            lines = output.splitlines()
            genymotion_list = []
            if len(lines) > 2:
                for line in lines[2:]:
                    parts = line.split('|')
                    if len(parts) >= 4:
                        name = parts[3].strip()
                        if name:
                            genymotion_list.append(name)
            
            return genymotion_list
                
        except (subprocess.CalledProcessError, Exception):
            return []

    def start_avd_emulator(self, avd_name):
        """Start an AVD emulator."""
        try:
            subprocess.Popen(
                [AVD_EXECUTABLE_PATH, "-avd", avd_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return True
        except Exception:
            return False

    def start_genymotion_emulator(self, emulator_name):
        """Start a Genymotion emulator."""
        try:
            result = subprocess.run(
                [GENYMOTION_EXECUTABLE_PATH, "admin", "start", emulator_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False

    def list_available_emulators(self):
        """List all available emulators from both AVD and Genymotion."""
        avd_emulators = self.find_avd_emulators()
        genymotion_emulators = self.find_genymotion_emulators()
        
        return {
            'avd': avd_emulators,
            'genymotion': genymotion_emulators
        }
        
    def check_adb_available(self):
        """Check if adb command is available in the system."""
        try:
            result = subprocess.run(['adb', 'version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            print("✗ ADB not found. Please install Android SDK platform-tools")
            return False
    
    def get_available_devices(self):
        """Get list of available Android devices/emulators."""
        try:
            result = subprocess.run(['adb', 'devices'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=15)
            
            if result.returncode != 0:
                return []
            
            lines = result.stdout.strip().split('\n')
            devices = []
            
            for line in lines[1:]:
                if line.strip() and '\t' in line:
                    device_id, status = line.split('\t')
                    devices.append({
                        'id': device_id.strip(),
                        'status': status.strip()
                    })
            
            return devices
            
        except (subprocess.TimeoutExpired, Exception):
            return []
    
    def display_devices(self, devices):
        """Display available devices in a formatted way."""
        if not devices:
            return False
        
        print(f"Found {len(devices)} device: {devices[0]['id']}")
        return True
    
    def find_apk_files(self):
        """Find APK files in the uploads directory."""
        if not self.uploads_dir.exists():
            return []
        
        apk_files = list(self.uploads_dir.glob("*.apk"))
        if apk_files:
            print(f"Found {len(apk_files)} APK: {apk_files[0].name}")
        
        return apk_files
    
    def start_frida_server(self, device_id):
        """Start Frida server on the specified device."""
        try:
            subprocess.run(
                ['adb', '-s', device_id, 'shell', '/data/local/tmp/frida-server', '-D', '&'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return True
        except (subprocess.TimeoutExpired, Exception):
            return True

    def install_apk(self, device_id, apk_path):
        """Install APK on the specified device."""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'install', '-r', str(apk_path)], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=60)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    def auto_start_emulator(self, emulators):
        """Automatically start the first available emulator, preferring Genymotion."""
        print("Starting emulator...")
        
        if emulators['genymotion']:
            for emulator in emulators['genymotion']:
                if self.start_genymotion_emulator(emulator):
                    time.sleep(15)
                    return True
        
        if emulators['avd']:
            for emulator in emulators['avd']:
                if self.start_avd_emulator(emulator):
                    time.sleep(15)
                    return True
        
        return False

    def setup(self):
        """Main setup process."""
        emulators = self.list_available_emulators()
        
        if not self.check_adb_available():
            return False
        
        devices = self.get_available_devices()
        if not self.display_devices(devices):
            if not self.auto_start_emulator(emulators):
                return False
            
            devices = self.get_available_devices()
            if not self.display_devices(devices):
                return False
        
        connected_devices = [d for d in devices if d['status'] == 'device']
        if not connected_devices:
            return False
        
        for device in connected_devices:
            self.start_frida_server(device['id'])
        
        apk_files = self.find_apk_files()
        if not apk_files:
            return False
        
        success_count = 0
        for device in connected_devices:
            for apk_path in apk_files:
                if self.install_apk(device['id'], apk_path):
                    success_count += 1  
        if success_count > 0:
            print("Setup complete!")
        return success_count > 0

def main():
    """Main entry point."""
    setup = DynamicSetup()
    
    try:
        return 0 if setup.setup() else 1
    except KeyboardInterrupt:
        return 1
    except Exception:
        return 1

if __name__ == "__main__":
    sys.exit(main())