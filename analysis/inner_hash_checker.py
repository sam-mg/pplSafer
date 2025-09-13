import sys
import os
import csv
import hashlib
import logging
import json
import time
import requests
from androguard.core.apk import APK
from loguru import logger
from dotenv import load_dotenv

logger.remove()

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HASH_ALGOS = ["md5", "sha1", "sha256", "sha512"]

class VirusTotal:
    def __init__(self):
        self.headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
        self.url = "https://www.virustotal.com/api/v3/"

    def check_hash_data(self, file_hash, filename):
        """Check file hash against VirusTotal database."""
        if not VT_API_KEY:
            return {"status": "No API Key", "filename": filename, "hash": file_hash}
            
        search_url = f"{self.url}files/{file_hash}"
        
        try:
            response = requests.get(search_url, headers=self.headers)
            
            if response.status_code == 404:
                return {"status": "Not Found", "filename": filename, "hash": file_hash}
            if response.status_code in [401, 403]:
                return {"status": "Error", "message": "Auth error with VirusTotal API"}
            if response.status_code != 200:
                return {"status": "Error", "message": f"VT API error ({response.status_code})"}

            result = response.json()
            
            attributes = result.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total_engines = sum(stats.values())

            status = "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")

            return {
                "status": status,
                "filename": filename,
                "hash": file_hash,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total_engines,
                "url": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        except Exception as e:
            return {"status": "Error", "message": f"VT query error: {e}"}

def compute_hashes(file_content):
    """Compute MD5, SHA1, SHA256, and SHA512 for given file content."""
    results = {}
    for algo in HASH_ALGOS:
        h = hashlib.new(algo)
        h.update(file_content)
        results[algo] = h.hexdigest()
    return results

def get_file_hashes_from_apk(apk_path):
    """Returns a dict mapping filename -> {algo: hash}."""
    file_hashes = {}
    try:
        a = APK(apk_path)
        
        if not a.is_valid_APK():
            return None
            
        for filename in a.get_files():
            try:
                file_content = a.get_file(filename)
                # Process all files regardless of size or content
                if file_content is not None:
                    file_hashes[filename] = compute_hashes(file_content)
                    
            except Exception as e:
                # Log which files are being skipped and why
                print(f"Skipping file {filename}: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Failed to parse APK: {e}")
        return None
    return file_hashes

def get_hashes_from_csv(csv_path):
    """Reads a CSV file and returns a dict {hash: url}."""
    csv_hashes = {}
    try:
        with open(csv_path, 'r', newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                key = row[0].strip().lower()
                if not key:
                    continue
                if len(row) >= 2:
                    csv_hashes[key] = row[1].strip()
                else:
                    csv_hashes[key] = None
                    
    except Exception as e:
        logger.error(f"CSV read error: {e}")
        return None
    return csv_hashes

def analyze_apk(apk_file, csv_file):
    vt = VirusTotal()

    apk_hashes = get_file_hashes_from_apk(apk_file)
    csv_hashes = get_hashes_from_csv(csv_file)

    if not apk_hashes:
        return {"error": "Could not extract hashes from APK"}

    all_files_checked = []
    threats_found = 0
    files_analyzed = len(apk_hashes)
    
    for filename, hashes in apk_hashes.items():
        file_matched_csv = False
        matched_url = None
        
        # Check against CSV threat intelligence
        for algo, digest in hashes.items():
            if csv_hashes and digest.lower() in csv_hashes:
                file_matched_csv = True
                matched_url = csv_hashes[digest.lower()]
                break
        
        # Always check against VirusTotal for SHA256
        try:
            vt_result = vt.check_hash_data(hashes["sha256"], filename)
        except Exception as e:
            print(f"VirusTotal API error for {filename}: {e}")
            vt_result = {"status": "API Error", "message": str(e)}
        
        # Determine if found in VirusTotal (1 or 0)
        found_in_virustotal = 1 if vt_result.get("status") in ["MALICIOUS", "SUSPICIOUS"] else 0
        found_in_csv = 1 if file_matched_csv else 0
        
        # Add to all files checked
        file_info = {
            "filename": filename,
            "found_in_virustotal": found_in_virustotal,
            "found_in_csv": found_in_csv
        }
        
        # Add additional details if threats found
        if found_in_virustotal or found_in_csv:
            threats_found += 1
            if found_in_csv and matched_url:
                file_info["matched_url"] = matched_url
            if found_in_virustotal:
                file_info["virus_total_details"] = vt_result
        
        all_files_checked.append(file_info)

    result = {
        "apk_file": os.path.basename(apk_file),
        "files_analyzed": files_analyzed,
        "threats_found": threats_found,
        "files_checked": all_files_checked
    }
        
    return result

if __name__ == "__main__":
    apk_dir = "uploads/"
    csv_file = "config/sha_md5_url.csv"

    apk_files = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]

    if not apk_files:
        print(f"No APK files found in {apk_dir}")
        sys.exit(1)

    apk_file = os.path.join(apk_dir, apk_files[0])
    filename = os.path.basename(apk_file)

    print("[+] Running inner hash checker analysis...")
    
    report = analyze_apk(apk_file, csv_file)
    
    save_path = "analysis/inner_hash_checker_output.json"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    with open(save_path, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"✅ Inner hash checker output saved to {save_path}")
    print("[+] Completed inner hash checker analysis...")
