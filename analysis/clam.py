import subprocess
import re
import sys
import os
import json

def run_clamav_scan(filepath: str):
    if not os.path.exists(filepath):
        return {
            "status": "Error",
            "assessment": "ERROR",
            "message": f"File not found at path: {filepath}",
            "details": {}
        }
        
    try:
        result = subprocess.run(
            ["clamscan", filepath],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        output = result.stdout
        
        scan_result = {"status": "Unknown", "details": {}}
        
        file_result_match = re.search(rf"{re.escape(filepath)}: (.+)", output)
        if file_result_match:
            scan_status = file_result_match.group(1).strip()
            scan_result["status"] = scan_status
        
        summary_section = re.search(r"----------- SCAN SUMMARY -----------(.+?)(?:\n\n|\Z)", output, re.DOTALL)
        if summary_section:
            summary_text = summary_section.group(1)
            
            patterns = {
                "known_viruses": r"Known viruses:\s*(\d+)",
                "engine_version": r"Engine version:\s*([\d.]+)",
                "scanned_directories": r"Scanned directories:\s*(\d+)",
                "scanned_files": r"Scanned files:\s*(\d+)",
                "infected_files": r"Infected files:\s*(\d+)",
                "data_scanned": r"Data scanned:\s*(.+)",
                "data_read": r"Data read:\s*(.+)",
                "scan_time": r"Time:\s*(.+)",
                "start_date": r"Start Date:\s*(.+)",
                "end_date": r"End Date:\s*(.+)"
            }
            
            for key, pattern in patterns.items():
                match = re.search(pattern, summary_text)
                if match:
                    value = match.group(1).strip()
                    if key in ["known_viruses", "scanned_directories", "scanned_files", "infected_files"]:
                        try:
                            scan_result["details"][key] = int(value)
                        except ValueError:
                            scan_result["details"][key] = value
                    else:
                        scan_result["details"][key] = value
        
        if scan_result["status"] == "OK":
            scan_result["assessment"] = "CLEAN"
        elif "FOUND" in scan_result["status"]:
            scan_result["assessment"] = "MALWARE_DETECTED"
        else:
            scan_result["assessment"] = "UNKNOWN"
            
        scan_result["raw_output"] = output
        scan_result["command_exit_code"] = result.returncode
        
        return scan_result
        
    except subprocess.TimeoutExpired:
        return {
            "status": "Error",
            "assessment": "ERROR",
            "message": "ClamAV scan timed out after 5 minutes.",
            "details": {}
        }
    except FileNotFoundError:
        return {
            "status": "Error", 
            "assessment": "ERROR",
            "message": "ClamAV (clamscan) not found. Please ensure ClamAV is installed and in your system's PATH.",
            "details": {}
        }
    except Exception as e:
        return {
            "status": "Error",
            "assessment": "ERROR", 
            "message": f"An unexpected error occurred during the ClamAV scan: {str(e)}",
            "details": {}
        }

if __name__ == "__main__":
    apk_dir = "uploads/"

    apk_files = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]

    if not apk_files:
        print(f"No APK files found in {apk_dir}")
        sys.exit(1)

    file_to_scan = os.path.join(apk_dir, apk_files[0])
    filename = os.path.basename(file_to_scan)

    print(f"Starting ClamAV scan for: {file_to_scan}\n")

    analysis_output = run_clamav_scan(file_to_scan)

    save_path = "analysis/clamav_output.json"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    with open(save_path, "w") as f:
        json.dump(analysis_output, f, indent=4)
    
    print(f"Completed ClamAV scan...\n")
