import sys
import os
import hashlib
import json
import requests
import tempfile
import zipfile
import subprocess
import re
from datetime import datetime, timezone
from loguru import logger
from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from cryptography import x509
from collections import Counter

logger.remove()

API_KEY = "d6a812d25e432e3d11281ad21974cb62916a9a592ec4786f7557e93808b4b17e"
RULES_PATH = os.path.expanduser("config/rules_new.json")

LEGIT_DB_MAP = {
    "net.one97.paytm": ["AnumatiDatabase.db", "AppLocale.db", "barcode_scanner_history.db", "chatDb.db", "discoveryDb.db", "google_app_measurement.db", "google_app_measurement_local.db", "passbook.db", "paytm.db", "sendbird_master.db", "trustmanager.db", "webview.db", "webviewCache.db"],
    "com.dhanalakshmi": ["google_analytics_v4.db", "google_app_measurement.db", "google_app_measurement_local.db", "gtm_urls.db"],
    "com.hdfcbank.mobilebanking": ["google_app_measurement.db", "google_app_measurement_local.db"],
    "com.icicibank.imobile": ["AdMobOfflineBufferedPings.db", "OfflineUpload.db", "cbp_april.db", "com.google.android.gms.ads.db", "exoplayer_internal.db", "google_analytics_v4.db", "google_app_measurement.db", "google_app_measurement_local.db", "google_tagmanager.db", "gtm_urls.db", "webview.db", "webviewCache.db"],
    "com.bankofbaroda.mconnect": ["CredentialDatabase.db", "exoplayer_internal.db", "google_app_measurement.db", "google_app_measurement_local.db", "webview.db", "webviewCache.db"],
    "com.kotak.neobank": ["google_app_measurement.db", "google_app_measurement_local.db", "les.db", "newsroom.db", "rest_client.db", "security.db", "threatstore.db"],
    "com.google.android.apps.nbu.paisa.user": [".db", "_inbox_threads.notifications.db", "_optimized_threads.notifications.db", "_per_account_gnp_room.db", "_room_notifications.db", "_tasks.notifications.db", "_threads.notifications.db", "google_app_measurement.db", "google_app_measurement_local.db", "growthkit.db", "tekartik_sqflite.db"],
    "com.phonepe.app": [".db", "AccountAggregatorDatabase.db", "AdMobOfflineBufferedPings.db", "OfflineUpload.db", "chuck.db", "chucker.db", "com.google.android.gms.ads.db", "exoplayer_internal.db", "google_analytics_v4.db", "google_app_measurement.db", "google_app_measurement_local.db", "kn_generic.db", "search.db", "sqlite-jdbc-tmp-%d.db"],
    "com.axis.mobile": ["EzAccountsDatabase.db", "exoplayer_internal.db", "global.db", "google_analytics_v4.db", "google_app_measurement.db", "google_app_measurement_local.db", "google_tagmanager.db", "gtm_urls.db", "tekartik_sqflite.db"],
    "com.sbi.lotusintouch": ["barcode_scanner_history.db", "google_app_measurement.db", "google_app_measurement_local.db"]
}

all_db_names = [db for dbs in LEGIT_DB_MAP.values() for db in dbs]
db_counts = Counter(all_db_names)
UNIQUE_LEGIT_DB_NAMES = {db for db, count in db_counts.items() if count == 1}

def clean_method_name(name: str) -> str:
    return name.split("(")[0] if name and "(" in name else (name.strip() if name else "")


def clean_class_name(name: str) -> str:
    return name.strip() if name else ""


def get_hashes(filepath: str):
    hashes = {"md5": None, "sha1": None, "sha256": None}
    try:
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        hashes["md5"] = md5.hexdigest()
        hashes["sha1"] = sha1.hexdigest()
        hashes["sha256"] = sha256.hexdigest()
    except Exception as e:
        return {"error": f"Failed to compute hashes: {e}"}
    return hashes

def make_aware(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)

class VirusTotal:
    def __init__(self):
        self.headers = {"accept": "application/json", "X-Apikey": API_KEY}
        self.url = "https://www.virustotal.com/api/v3/"

    def check_hash_data(self, file_hash, filename):
        search_url = f"{self.url}files/{file_hash}"
        try:
            response = requests.get(search_url, headers=self.headers)
            if response.status_code == 404:
                return {"status": "Not Found", "message": "Hash not found"}
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
                "total_engines": total_engines,
                "url": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        except Exception as e:
            return {"status": "Error", "message": f"VT query error: {e}"}


def run_clamav_scan(apk_path: str):
    """
    Run ClamAV scan on the APK file and parse the output
    """
    try:
        # Run clamscan command
        result = subprocess.run(
            ["clamscan", apk_path],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        output = result.stdout
        
        # Parse the output
        scan_result = {"status": "Unknown", "details": {}}
        
        # Extract scan result (OK, FOUND, etc.)
        file_result_match = re.search(rf"{re.escape(apk_path)}: (.+)", output)
        if file_result_match:
            scan_status = file_result_match.group(1).strip()
            scan_result["status"] = scan_status
        
        # Parse scan summary
        summary_section = re.search(r"----------- SCAN SUMMARY -----------(.+?)(?:\n\n|\Z)", output, re.DOTALL)
        if summary_section:
            summary_text = summary_section.group(1)
            
            # Extract key metrics
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
                    # Convert numeric values
                    if key in ["known_viruses", "scanned_directories", "scanned_files", "infected_files"]:
                        try:
                            scan_result["details"][key] = int(value)
                        except ValueError:
                            scan_result["details"][key] = value
                    else:
                        scan_result["details"][key] = value
        
        # Determine overall assessment
        if scan_result["status"] == "OK":
            scan_result["assessment"] = "CLEAN"
        elif "FOUND" in scan_result["status"]:
            scan_result["assessment"] = "MALWARE_DETECTED"
        else:
            scan_result["assessment"] = "UNKNOWN"
        
        # Add raw output for debugging
        scan_result["raw_output"] = output
        scan_result["command_exit_code"] = result.returncode
        
        return scan_result
        
    except subprocess.TimeoutExpired:
        return {
            "status": "Error",
            "assessment": "ERROR",
            "message": "ClamAV scan timed out after 5 minutes",
            "details": {}
        }
    except FileNotFoundError:
        return {
            "status": "Error", 
            "assessment": "ERROR",
            "message": "ClamAV (clamscan) not found. Please install ClamAV.",
            "details": {}
        }
    except Exception as e:
        return {
            "status": "Error",
            "assessment": "ERROR", 
            "message": f"ClamAV scan failed: {str(e)}",
            "details": {}
        }


def extract_databases(apk_path: str):
    db_files = []
    try:
        with zipfile.ZipFile(apk_path, "r") as apk_zip:
            tmp_dir = tempfile.mkdtemp()
            for file in apk_zip.namelist():
                if file.endswith((".db", ".sqlite", ".realm")):
                    db_files.append(os.path.basename(file))
                    apk_zip.extract(file, tmp_dir)
    except Exception as e:
        logger.error(f"Database extraction failed: {e}")
    return db_files


def find_db_strings(apk_path):
    a, _, dx = AnalyzeAPK(apk_path)
    return sorted({
        s for s in dx.get_strings_analysis().keys()
        if isinstance(s, str) and s.endswith(".db")
    })


def analyze_rules(apk_path: str):
    if not os.path.exists(RULES_PATH):
        return {"rules": [], "permissions": []}

    with open(RULES_PATH, "r") as f:
        rules = json.load(f)

    try:
        a, _, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        return {"error": f"Failed to analyze APK: {e}"}

    apk_permissions = sorted([p.strip().lower() for p in a.get_permissions()])
    package_name = a.get_package()
    results = []

    db_files_zip = extract_databases(apk_path)
    db_strings_dx = find_db_strings(apk_path)
    all_db_names_found = list(set(db_files_zip + db_strings_dx))

    for rule in rules:
        rule_id = rule.get("rule_id", "Unknown")
        description = rule.get("description", "")
        target_permission = rule.get("target_permission")
        target_class = rule.get("target_class")
        target_classes = rule.get("target_classes")
        target_methods = rule.get("target_methods", [])
        target_strings = rule.get("target_strings", [])
        rule_type = rule.get("rule_type")

        score = 0
        matched_methods = set()
        class_referenced = False
        missing_methods = []
        matched_strings = []

        permission_present = False
        if target_permission:
            if isinstance(target_permission, list):
                permission_present = any(
                    p.lower() in apk_permissions for p in target_permission
                )
            elif isinstance(target_permission, str):
                permission_present = target_permission.lower() in apk_permissions

        COMMON_DB_NAMES = {
            "google_app_measurement_local.db",
            "google_app_measurement.db",
            "google_analytics_v4.db","tekartik_sqflite.db",".db","asset.db"
        }

        def analyze_rule_27(apk_path: str, package_name: str, all_db_names_found: list):
            print("\n[DEBUG][Rule 27] Starting custom DB analysis...")
            print(f"[DEBUG][Rule 27] APK package: {package_name}")
            print(f"[DEBUG][Rule 27] Databases found in APK before filtering: {all_db_names_found}")

            filtered_dbs = [db for db in all_db_names_found if db not in COMMON_DB_NAMES]
            print(f"[DEBUG][Rule 27] Databases after removing common DBs: {filtered_dbs}")

            flagged_dbs = []
            score = 0

            if not filtered_dbs:
                print("[DEBUG][Rule 27] No unique DBs found after filtering. Returning score 0.")
                return {
                    "rule_id": "rule_27",
                    "description": "Detects database impersonation by checking unique legitimate DBs.",
                    "databases_found_in_apk": all_db_names_found,
                    "flagged_unique_legit_databases": [],
                    "score": 0
                }

            for db_name in filtered_dbs:
                print(f"[DEBUG][Rule 27] Checking DB: {db_name}")
                db_matched = False
                for legit_pkg, legit_dbs in LEGIT_DB_MAP.items():
                    if db_name in legit_dbs:
                        db_matched = True
                        if legit_pkg == package_name:
                            status = "standard"
                            print(f"[DEBUG][Rule 27] DB {db_name} belongs to same package ({package_name}) -> standard")
                        else:
                            status = "impersonation"
                            score = 1
                            print(f"[DEBUG][Rule 27] DB {db_name} belongs to {legit_pkg}, not {package_name} -> impersonation, score set to 1")

                        flagged_dbs.append({
                            "db_name": db_name,
                            "legit_package_name": legit_pkg,
                            "input_package_name": package_name,
                            "status": status
                        })

                if not db_matched:
                    print(f"[DEBUG][Rule 27] DB {db_name} not found in LEGIT_DB_MAP -> unknown, score set to 1")
                    flagged_dbs.append({
                        "db_name": db_name,
                        "legit_package_name": "unknown",
                        "input_package_name": package_name,
                        "status": "unknown"
                    })
                    score = 1

            print(f"[DEBUG][Rule 27] Final flagged DBs: {flagged_dbs}")
            print(f"[DEBUG][Rule 27] Final score: {score}")

            return {
                "rule_id": "rule_27",
                "description": "Detects database impersonation by checking unique legitimate DBs.",
                "databases_found_in_apk": all_db_names_found,
                "flagged_unique_legit_databases": flagged_dbs,
                "score": score
            }

        if rule_type == "custom_db_check":
            rule27_result = analyze_rule_27(apk_path, package_name, all_db_names_found)
            results.append(rule27_result)
            continue

        if rule_type == "manifest_absence":
            score = 1
            try:
                for activity in a.get_activities():
                    intent_filters = a.get_intent_filters("activity", activity)
                    for actions, categories in zip(
                        intent_filters.get("action", []),
                        intent_filters.get("category", [])
                    ):
                        if "android.intent.action.MAIN" in actions and \
                           "android.intent.category.LAUNCHER" in categories:
                            score = 0
                            break
                    if score == 0:
                        break
            except Exception as e:
                logger.debug(f"Manifest check error: {e}")
            results.append({
                "rule_id": rule_id,
                "description": description,
                "has_launcher_activity": bool(score == 0),
                "score": score
            })
            continue

        if target_class or target_classes:
            classes_to_check = []
            if target_classes:
                for cls in target_classes:
                    if isinstance(cls, str):
                        classes_to_check.append({"class": cls, "methods": target_methods})
                    elif isinstance(cls, dict):
                        classes_to_check.append(cls)
            elif target_class:
                classes_to_check = [{"class": target_class, "methods": target_methods}]

            for class_info in classes_to_check:
                rule_class = class_info.get("class", "")
                rule_methods = class_info.get("methods", [])
                if not rule_class:
                    continue

                class_name_found = False
                for c in dx.classes.keys():
                    if clean_class_name(str(c)).strip("L;") == rule_class.strip("L;"):
                        class_name_found = True
                        class_referenced = True
                        for method in dx.classes[c].get_methods():
                            method_name = clean_method_name(method.name)
                            if method_name in rule_methods:
                                matched_methods.add(method_name)

                if not class_name_found:
                    for method in dx.get_methods():
                        for _, call, _ in method.get_xref_to():
                            call_class = clean_class_name(str(call.class_name)).strip("L;")
                            if call_class == rule_class.strip("L;"):
                                class_referenced = True
                                break

            all_rule_methods = []
            if target_classes:
                for cls_info in classes_to_check:
                    all_rule_methods.extend(cls_info.get("methods", []))
            elif target_methods:
                all_rule_methods = target_methods

            missing_methods = [m for m in all_rule_methods if m not in matched_methods]

            if permission_present and class_referenced and not missing_methods:
                score = 1

        if target_strings:
            strings_found = [s for s in target_strings if s in dx.get_strings_analysis().keys()]
            matched_strings.extend(strings_found)
            if strings_found:
                score = 1

        results.append({
            "rule_id": rule_id,
            "description": description,
            "permission_present": permission_present if target_permission is not None else "N/A",
            "class_referenced": class_referenced if target_class or target_classes else "N/A",
            "target_methods_present": sorted(list(matched_methods)) if target_class or target_classes else "N/A",
            "target_methods_missing": missing_methods if target_class or target_classes else "N/A",
            "matched_strings": matched_strings,
            "score": score
        })

    return {"rules": results, "permissions": apk_permissions, "databases": all_db_names_found}

def analyze_apk_certs(apk_path: str):
    try:
        a = APK(apk_path)
        certs_info = []
        certs = a.get_certificates_der_v3()
        if not certs:
            certs_info.append({"error": "No certificates found"})
        else:
            for cert_data in certs:
                cert = x509.load_der_x509_certificate(cert_data)
                certs_info.append({
                    "issuer": cert.issuer.rfc4514_string(),
                    "subject": cert.subject.rfc4514_string(),
                    "serial_number": cert.serial_number,
                    "hash_algorithm": cert.signature_hash_algorithm.name,
                    "valid_from": make_aware(getattr(cert, "not_valid_before", None)).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "valid_until": make_aware(getattr(cert, "not_valid_after", None)).strftime('%Y-%m-%d %H:%M:%S UTC'),
                })

        sig_versions = []
        if a.is_signed_v1(): sig_versions.append("v1")
        if a.is_signed_v2(): sig_versions.append("v2")
        if a.is_signed_v3(): sig_versions.append("v3")
        if hasattr(a, 'is_signed_v4') and a.is_signed_v4(): sig_versions.append("v4")

        return {"certificates": certs_info, "signature_schemes": sig_versions or ["None"]}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    apk_dir = "uploads/"

    apk_files = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]

    if not apk_files:
        print(f"No APK files found in {apk_dir}")
        sys.exit(1)

    apk_file = os.path.join(apk_dir, apk_files[0])
    filename = os.path.basename(apk_file)

    print(f"Using APK file: {filename}")

    hashes = get_hashes(apk_file)
    try:
        apk_obj = APK(apk_file)
        package_name = apk_obj.package
    except Exception:
        package_name = "Unknown"

    print("[+] Running VirusTotal hash check...")
    vt = VirusTotal()
    vt_data = vt.check_hash_data(hashes.get("sha256"), filename)

    print("[+] Running ClamAV scan...")
    clamav_data = run_clamav_scan(apk_file)

    print("[+] Running rule-based analysis...")
    rules_data = analyze_rules(apk_file)

    print("[+] Running certificate and signature analysis...")
    certs_data = analyze_apk_certs(apk_file)

    output = {
        "file": filename,
        "package_name": package_name,
        "hashes": hashes,
        "virus_total": vt_data,
        "clamav": clamav_data,
        "rules_analysis": rules_data,
        "certificates": certs_data,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    save_path = "analysis/static_output.json"

    os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)

    with open(save_path, "w") as f:
        json.dump(output, f, indent=4)

    print(f"✅ Output saved to {save_path}")