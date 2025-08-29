import os
import sys
import requests
import hashlib
import zipfile
import re
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

class VirusTotal:
    """A class to interact with the VirusTotal API v3."""
    def __init__(self):
        if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_REAL_VIRUSTOTAL_API_KEY":
            print("[ERROR] Please set VIRUSTOTAL_API_KEY in your .env file.")
            sys.exit(1)
        self.headers = {"accept": "application/json", "X-Apikey": VIRUSTOTAL_API_KEY}
        self.url = "https://www.virustotal.com/api/v3/"

    def check_hash(self, file_hash):
        print(f"[*] Submitting hash to VirusTotal: {file_hash}")
        search_url = self.url + "files/" + file_hash
        response = requests.get(search_url, headers=self.headers)
        if response.status_code == 404:
            print(f"    [!] Hash not found in VirusTotal's database.")
            print("-" * 50)
            return
        if response.status_code in [401, 403]:
            print(f"    [!] Authentication Error (Status Code: {response.status_code}).")
            print(f"    [!] Please check if your API key is correct and valid.")
            print("-" * 50)
            return
        if response.status_code != 200:
            print(f"    [!] API error occurred (Status Code: {response.status_code}).")
            print(f"    [!] Response: {response.text}")
            print("-" * 50)
            return
        try:
            result = response.json()
            attributes = result.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total_engines = sum(stats.values())
            if malicious > 0:
                print(f"    Status: MALICIOUS")
                print(f"    Detections: {malicious}/{total_engines} engines flagged as malicious.")
                report_link = f"https://www.virustotal.com/gui/file/{file_hash}"
                print(f"    Full Report: {report_link}")
                print("-" * 50)
                print("MALICIOUS")
                sys.exit(0)
            elif suspicious > 0:
                print(f"    Status: SUSPICIOUS")
            else:
                print(f"    Status: CLEAN")
            print(f"    Detections: {malicious}/{total_engines} engines flagged as malicious.")
            report_link = f"https://www.virustotal.com/gui/file/{file_hash}"
            print(f"    Full Report: {report_link}")
        except Exception as e:
            print(f"    [!] Could not parse the API response. Error: {e}")
        finally:
            print("-" * 50)

def get_file_hash(filepath):
    print(f"[*] Calculating SHA256 hash for: {filepath}")
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] File not found at the specified path: {filepath}")
        return None
    except Exception as e:
        print(f"[ERROR] Failed to read or hash the file: {e}")
        return None

def check_hash_in_malwarebazaar(file_hash):
    print(f"[*] Checking hash in MalwareBazaar: {file_hash}")
    
    if MALWAREBAZAAR_API_KEY is None:
        print("    [!] No API key found. Using public API (limited).")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        headers = {
            "Auth-Key": MALWAREBAZAAR_API_KEY.strip(),
            "Content-Type": "application/x-www-form-urlencoded"
        }
    
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": file_hash}
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=30)
        if response.status_code != 200:
            print(f"    [!] API error: {response.status_code}")
            print(f"    [!] Response: {response.text}")
            print("-" * 50)
            return False
        
        result = response.json()
        if result.get("query_status") == "ok":
            print(f"    Status: FOUND in MalwareBazaar - MALICIOUS")
            data_array = result.get("data", [])
            if data_array:
                entry = data_array[0]
                print(f"    Malware family: {entry.get('malware_family', 'N/A')}")
                print(f"    Signature: {entry.get('signature', 'N/A')}")
                print(f"    First seen: {entry.get('first_seen', 'N/A')}")
            print("-" * 50)
            print("MALICIOUS")
            sys.exit(0)
        elif result.get("query_status") == "no_results":
            print(f"    Status: Not found in MalwareBazaar - CLEAN")
        else:
            print(f"    Status: {result.get('query_status', 'Unknown')}")
    except Exception as e:
        print(f"    [!] Error querying MalwareBazaar: {e}")
    finally:
        print("-" * 50)
    return False

def extract_urls_from_apk(apk_path):
    print(f"[*] Extracting URLs from APK...")
    
    urls = set()
    
    url_patterns = [
        r'https://[^\s<>"\']+',
        r'http://[^\s<>"\']+',
        r'ws://[^\s<>"\']+',
        r'wss://[^\s<>"\']+',
        r'ftp://[^\s<>"\']+',
    ]
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            file_list = apk_zip.namelist()
            files_to_check = []
            
            for file_name in file_list:
                if (file_name.endswith('.xml') or file_name.endswith('.json') or file_name.endswith('.txt') or file_name.endswith('.properties') or 'resources.arsc' in file_name or file_name.endswith('.dex')):
                    files_to_check.append(file_name)
            
            print(f"    Examining {len(files_to_check)} files for URLs...")
            
            for file_name in files_to_check:
                try:
                    with apk_zip.open(file_name) as file:
                        content = file.read()
                        text_content = ""
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                        except:
                            try:
                                text_content = content.decode('latin-1', errors='ignore')
                            except:
                                text_content = str(content)
                        
                        for pattern in url_patterns:
                            matches = re.findall(pattern, text_content, re.IGNORECASE)
                            urls.update(matches)
                                
                except Exception as e:
                    continue
            
            cleaned_urls = set()
            for url in urls:
                url = url.strip('",\'();[]{}')
                url = re.sub(r'["\'>].*$', '', url)
                
                if (len(url) > 10 and 
                    not url.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.css', '.js')) and
                    '://' in url and
                    '.' in url.split('://')[1] if '://' in url else False):
                    cleaned_urls.add(url)
            
            print(f"    Found {len(cleaned_urls)} URLs")
            return list(cleaned_urls)
            
    except Exception as e:
        print(f"    [!] Error extracting URLs from APK: {e}")
        return []

def check_url_in_urlhaus(url):
    print(f"[*] Checking URL in URLhaus: {url}")
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {"url": url}
    try:
        response = requests.post(api_url, data=data)
        if response.status_code != 200:
            print(f"    [!] API error: {response.status_code}")
            print(f"    [!] Response: {response.text}")
            print("-" * 50)
            return
        result = response.json()
        if result.get("query_status") == "ok":
            print(f"    Status: FOUND in URLhaus - MALICIOUS")
            print(f"    Threat: {result.get('url_status', 'No status info')}")
        else:
            print(f"    Status: Not found in URLhaus - CLEAN")
    except Exception as e:
        print(f"    [!] Error querying URLhaus: {e}")
    finally:
        print("-" * 50)

def main():
    if len(sys.argv) < 2:
        print(f"\nUsage: python 3rd Party.py <path_to_your_apk_file.apk>")
        sys.exit(1)
    
    apk_filepath = sys.argv[1]
    
    file_hash = get_file_hash(apk_filepath)
    if not file_hash:
        print("[!] Halting script because no hash could be calculated from the file.")
        return
    
    malware_found = check_hash_in_malwarebazaar(file_hash)
    
    vt = VirusTotal()
    vt.check_hash(file_hash)
    
    urls = extract_urls_from_apk(apk_filepath)
    
    if urls:
        print(f"\n[*] Checking {len(urls)} extracted URLs in URLhaus...")
        for i, url in enumerate(urls, 1):
            print(f"    [{i}/{len(urls)}] Checking: {url}")
            is_malicious, result = check_url_in_urlhaus_detailed(url)
            if is_malicious:
                print(f"        MALICIOUS: {url}")
                print(f"        Threat: {result.get('threat', 'N/A')}")
                print(f"        Status: {result.get('url_status', 'N/A')}")
                print(f"        Date Added: {result.get('date_added', 'N/A')}")
                print("-" * 50)
                print("MALICIOUS")
                sys.exit(0)
            else:
                print(f"        Clean")

def check_url_in_urlhaus_detailed(url):
    """Check URL in URLhaus and return detailed info"""
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {"url": url}
    try:
        response = requests.post(api_url, data=data, timeout=10)
        if response.status_code != 200:
            return False, {}
        
        result = response.json()
        if result.get("query_status") == "ok":
            return True, {
                "id": result.get("id", "N/A"),
                "url_status": result.get("url_status", "N/A"),
                "host": result.get("host", "N/A"),
                "date_added": result.get("date_added", "N/A"),
                "threat": result.get("threat", "N/A"),
                "tags": result.get("tags", "N/A")
            }
        else:
            return False, {}
    except Exception as e:
        return False, {}

if __name__ == "__main__":
    main()
