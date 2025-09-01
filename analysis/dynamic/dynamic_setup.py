#!/usr/bin/env python3

import subprocess
import os
import sys
import time
from pathlib import Path

class DynamicSetup:
    def __init__(self):
        self.uploads_dir = Path(__file__).parent.parent.parent / "uploads"
        self.apk_files = []
        
    def check_adb_available(self):
        """Check if adb command is available in the system."""
        try:
            result = subprocess.run(['adb', 'version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=10)
            if result.returncode == 0:
                print("ADB is available")
                return True
            else:
                print("✗ ADB command failed")
                return False
        except subprocess.TimeoutExpired:
            print("✗ ADB command timed out")
            return False
        except FileNotFoundError:
            print("✗ ADB not found. Please install Android SDK platform-tools")
            return False
        except Exception as e:
            print(f"✗ Error checking ADB: {e}")
            return False
    
    def get_available_devices(self):
        """Get list of available Android devices/emulators."""
        try:
            result = subprocess.run(['adb', 'devices'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=15)
            
            if result.returncode != 0:
                print(f"✗ Failed to get devices: {result.stderr}")
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
            
        except subprocess.TimeoutExpired:
            print("✗ ADB devices command timed out")
            return []
        except Exception as e:
            print(f"✗ Error getting devices: {e}")
            return []
    
    def display_devices(self, devices):
        """Display available devices in a formatted way."""
        if not devices:
            print("\n❌ No devices found!")
            print("Please start an Android emulator or connect a device with USB debugging enabled.")
            return False
        
        print(f"Found {len(devices)} device: {devices[0]['id']}")
        return True
    
    def find_apk_files(self):
        """Find APK files in the uploads directory."""
        if not self.uploads_dir.exists():
            print(f"✗ Uploads directory not found: {self.uploads_dir}")
            return []
        
        apk_files = list(self.uploads_dir.glob("*.apk"))
        if apk_files:
            print(f"Found {len(apk_files)} APK: {apk_files[0].name}")
        else:
            print(f"\n❌ No APK files found in {self.uploads_dir}")
        
        return apk_files
    
    def install_apk(self, device_id, apk_path):
        """Install APK on the specified device."""
        try:
            result = subprocess.run(['adb', '-s', device_id, 'install', '-r', str(apk_path)], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=60)
            
            if result.returncode == 0:
                print(f"Successfully installed {apk_path.name}")
                return True
            else:
                print(f"❌ Installation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"❌ Installation timed out for {apk_path.name}")
            return False
        except Exception as e:
            print(f"❌ Error installing APK: {e}")
            return False
    
    def setup(self):
        """Main setup process."""
        if not self.check_adb_available():
            return False
        
        devices = self.get_available_devices()
        if not self.display_devices(devices):
            return False
        
        connected_devices = [d for d in devices if d['status'] == 'device']
        if not connected_devices:
            print("\n⚠️  No devices are properly connected (status: 'device')")
            print("Available devices have status:", [d['status'] for d in devices])
            return False
        
        apk_files = self.find_apk_files()
        if not apk_files:
            return False
        
        success_count = 0
        total_installations = len(connected_devices) * len(apk_files)
        
        for device in connected_devices:
            for apk_path in apk_files:
                if self.install_apk(device['id'], apk_path):
                    success_count += 1
        
        return success_count > 0

def main():
    """Main entry point."""
    setup = DynamicSetup()
    
    try:
        success = setup.setup()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())