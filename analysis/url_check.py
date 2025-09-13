import sys
import os
import csv
import re
import hashlib
import zipfile
import json
import requests
from androguard.core.apk import APK
from loguru import logger

logger.remove()

def check_url_in_urlhaus(url_to_check):
    """Check URL against URLhaus database."""
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "url": url_to_check
    }
    
    try:
        response = requests.post(api_url, headers=headers, data=data, timeout=10)
        if response.status_code != 200:
            return False, f"API request failed with status code: {response.status_code}"
        
        json_data = response.json()
        if json_data.get("query_status", "").lower() == "ok":
            return True, {
                "id": json_data.get("id", "N/A"),
                "url_status": json_data.get("url_status", "N/A"),
                "host": json_data.get("host", "N/A"),
                "date_added": json_data.get("date_added", "N/A"),
                "last_online": json_data.get("last_online", "N/A"),
                "threat": json_data.get("threat", "N/A"),
                "tags": json_data.get("tags", "N/A")
            }
        else:
            return False, "URL not found in database"
            
    except Exception as e:
        return False, f"Error: {e}"

def extract_urls_from_apk(apk_path):
    """Extracts URLs by scanning through files inside APK."""
    urls = set()
    url_pattern = re.compile(rb'https?://[^\s\'"<>\x00-\x1f\x7f-\xff]+')
    
    with zipfile.ZipFile(apk_path, 'r') as apk:
        for file in apk.namelist():
            try:
                data = apk.read(file)
                found_urls = url_pattern.findall(data)
                for url in found_urls:
                    try:
                        decoded_url = url.decode('utf-8', errors='ignore')
                        # Basic validation: check if URL looks reasonable
                        if (len(decoded_url) > 7 and  # Minimum for http://x
                            '.' in decoded_url and
                            not decoded_url.startswith('http://schemas.android.com') and
                            not decoded_url.startswith('http://www.w3.org')):
                            urls.add(decoded_url)
                    except UnicodeDecodeError:
                        continue
            except (NotImplementedError, zipfile.BadZipFile, Exception):
                continue
    return urls

def read_urls_from_csv(csv_path):
    urls = set()
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row:
                urls.add(row[0].strip())
    return urls

if __name__ == "__main__":
    apk_dir = "uploads/"
    csv_path = "config/sha_md5_url.csv"

    apk_files = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]

    if not apk_files:
        print(f"No APK files found in {apk_dir}")
        sys.exit(1)

    apk_path = os.path.join(apk_dir, apk_files[0])
    filename = os.path.basename(apk_path)

    print("Running URL check analysis...")

    # Extract URLs from APK
    apk_urls = extract_urls_from_apk(apk_path)
    csv_urls = read_urls_from_csv(csv_path)
    
    print(f"Found {len(apk_urls)} URLs in APK")
    print(f"Loaded {len(csv_urls)} URLs from CSV database")

    url_results = []
    
    for url in apk_urls:
        print(f"Checking URL: {url}")
        
        # Check against CSV/Threat Intelligence database
        found_in_threat_intel = 1 if url in csv_urls else 0
        
        # Check against URLhaus
        found_in_urlhaus = 0
        is_malicious, result_data = check_url_in_urlhaus(url)
        if is_malicious:
            found_in_urlhaus = 1
        
        url_results.append({
            "url": url,
            "found_in_urlhaus": found_in_urlhaus,
            "found_in_threat_intelligence": found_in_threat_intel
        })
        
        print(f"  URLhaus: {'Found' if found_in_urlhaus else 'Not found'}")
        print(f"  Threat Intelligence: {'Found' if found_in_threat_intel else 'Not found'}")
    
    # Calculate summary
    total_urls = len(apk_urls)
    urlhaus_matches = sum(1 for result in url_results if result["found_in_urlhaus"] == 1)
    threat_intel_matches = sum(1 for result in url_results if result["found_in_threat_intelligence"] == 1)
    total_malicious = sum(1 for result in url_results if result["found_in_urlhaus"] == 1 or result["found_in_threat_intelligence"] == 1)
    
    # Prepare output data in same format as inner_hash_checker
    output_data = {
        "apk_file": filename,
        "urls_analyzed": total_urls,
        "threats_found": total_malicious,
        "urlhaus_matches": urlhaus_matches,
        "threat_intelligence_matches": threat_intel_matches,
        "urls_checked": url_results
    }
    
    save_path = "analysis/url_check_output.json"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    with open(save_path, "w") as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nCompleted URL check analysis:")
    print(f"  APK File: {filename}")
    print(f"  URLs analyzed: {total_urls}")
    print(f"  URLhaus matches: {urlhaus_matches}")
    print(f"  Threat Intelligence matches: {threat_intel_matches}")
    print(f"  Total threats found: {total_malicious}")
    print(f"Results saved to {save_path}")
