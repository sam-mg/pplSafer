#!/usr/bin/env python3
import sys
import os
import hashlib
import json
import csv
import requests
from datetime import datetime
from loguru import logger
from dotenv import load_dotenv
from androguard.core.apk import APK

logger.remove()

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HASH_ALGOS = ["md5", "sha1", "sha256", "sha512"]

def extract_apk_info(apk_path):
    """Extract package name and other APK information using androguard."""
    try:
        apk = APK(apk_path)
        package_name = apk.get_package()
        app_name = apk.get_app_name()
        version_name = apk.get_androidversion_name()
        version_code = apk.get_androidversion_code()
        min_sdk = apk.get_min_sdk_version()
        target_sdk = apk.get_target_sdk_version()
        
        return {
            "package_name": package_name,
            "app_name": app_name,
            "version_name": version_name,
            "version_code": version_code,
            "min_sdk_version": min_sdk,
            "target_sdk_version": target_sdk
        }
    except Exception as e:
        logger.error(f"Failed to extract APK info: {e}")
        return {
            "package_name": "Unable to extract",
            "app_name": "Unable to extract",
            "version_name": "Unable to extract",
            "version_code": "Unable to extract",
            "min_sdk_version": "Unable to extract",
            "target_sdk_version": "Unable to extract"
        }

def compute_hashes(filepath):
    """Compute MD5, SHA1, SHA256, and SHA512 for given file."""
    results = {}
    try:
        hash_objects = {algo: hashlib.new(algo) for algo in HASH_ALGOS}
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for h in hash_objects.values():
                    h.update(chunk)
        for algo, h in hash_objects.items():
            results[algo] = h.hexdigest()
    except Exception as e:
        logger.error(f"Failed to compute hashes: {e}")
        return None
    return results

def check_virustotal(file_hash, filename):
    """Check hash against VirusTotal API."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "X-Apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return {"status": "Not Found", "message": "Hash not found in VirusTotal"}
        if response.status_code in [401, 403]:
            return {"status": "Error", "message": "Authentication error with VirusTotal API"}
        if response.status_code != 200:
            return {"status": "Error", "message": f"VT API error ({response.status_code})"}

        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_engines = sum(stats.values())

        status = "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")

        return {
            "status": status,
            "filename": filename,
            "hash": file_hash,
            "malicious_count": malicious,
            "total_engines": total_engines,
            "url": f"https://www.virustotal.com/gui/file/{file_hash}",
            "scan_date": attributes.get("last_analysis_date", "Unknown"),
        }
    except Exception as e:
        logger.error(f"VirusTotal API error: {e}")
        return {"status": "Error", "message": f"VT query error: {e}"}

def check_csv_threat_intel(hashes, csv_path):
    """Check hashes against CSV threat intelligence file."""
    if not os.path.exists(csv_path):
        return {"status": "Error", "message": "CSV file not found"}

    csv_hashes = {}
    try:
        with open(csv_path, "r", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    csv_hashes[row[0].strip().lower()] = row[1].strip()
                elif row:
                    csv_hashes[row[0].strip().lower()] = None
    except Exception as e:
        return {"status": "Error", "message": f"Failed to read CSV: {e}"}

    matches = []
    for algo, hash_value in hashes.items():
        if hash_value.lower() in csv_hashes:
            matches.append(
                {
                    "algorithm": algo.upper(),
                    "hash": hash_value,
                    "threat_intel_url": csv_hashes[hash_value.lower()],
                }
            )

    if matches:
        return {"status": "FOUND", "matches": matches}
    else:
        return {"status": "Not Found", "message": "No matches in threat intelligence CSV"}

if __name__ == "__main__":
    apk_dir = "uploads/"
    csv_file = "config/sha_md5_url.csv"

    apk_files = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]

    if not apk_files:
        print(f"No APK files found in {apk_dir}")
        sys.exit(1)

    apk_file = os.path.join(apk_dir, apk_files[0])
    filename = os.path.basename(apk_file)

    if not os.path.exists(apk_file):
        sys.exit(1)

    print("Starting APK hash analysis...")
    apk_info = extract_apk_info(apk_file)
    hashes = compute_hashes(apk_file)
    if not hashes:
        print("Failed to compute hashes.")
        sys.exit(1)

    vt_result = check_virustotal(hashes["sha256"], filename)

    csv_result = check_csv_threat_intel(hashes, csv_file)

    output = {
        "file": filename,
        "file_path": apk_file,
        "package_name": apk_info["package_name"],
        "app_name": apk_info["app_name"],
        "version_name": apk_info["version_name"],
        "version_code": apk_info["version_code"],
        "min_sdk_version": apk_info["min_sdk_version"],
        "target_sdk_version": apk_info["target_sdk_version"],
        "hashes": hashes,
        "virus_total": vt_result,
        "threat_intelligence": csv_result,
        "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "overall_threat_status": "CLEAN",
    }

    if (
        vt_result.get("status") in ["MALICIOUS", "SUSPICIOUS"]
        or csv_result.get("status") == "FOUND"
    ):
        output["overall_threat_status"] = "THREAT_DETECTED"

    save_path = "analysis/apk_hash_checker_output.json"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    with open(save_path, "w") as f:
        json.dump(output, f, indent=2)
    
    print("APK hash analysis completed...")