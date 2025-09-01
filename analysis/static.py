import sys
import os
import hashlib
import json
import requests
import tempfile
import zipfile
from datetime import datetime, timezone
from loguru import logger
from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from cryptography import x509

logger.remove()

API_KEY = "d6a812d25e432e3d11281ad21974cb62916a9a592ec4786f7557e93808b4b17e"
RULES_PATH = os.path.expanduser("config/rules_new.json")

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

# --- Database extraction logic ---
def extract_databases(apk_path: str):
    """
    Extracts .db, .sqlite, .realm files from APK and stores in /tmp for inspection.
    Returns list of database file paths inside the APK.
    """
    db_files = []
    try:
        with zipfile.ZipFile(apk_path, "r") as apk_zip:
            for file in apk_zip.namelist():
                if file.endswith((".db", ".sqlite", ".realm")):
                    db_files.append(file)
                    # extract to tmp dir for inspection if needed
                    tmp_dir = tempfile.mkdtemp()
                    apk_zip.extract(file, tmp_dir)
    except Exception as e:
        logger.error(f"Database extraction failed: {e}")
    return db_files

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
    results = []
    db_files = extract_databases(apk_path)

    for rule in rules:
        rule_id = rule.get("rule_id", "Unknown")
        description = rule.get("description", "")
        target_permission = rule.get("target_permission")
        target_class = rule.get("target_class")
        target_classes = rule.get("target_classes")
        target_methods = rule.get("target_methods", [])
        rule_type = rule.get("rule_type")

        permission_present = True
        if target_permission is not None:
            target_permissions_list = (
                [target_permission.strip().lower()]
                if isinstance(target_permission, str)
                else [p.strip().lower() for p in target_permission]
            )
            permission_present = any(p in apk_permissions for p in target_permissions_list)

        score = 0
        matched_methods = set()
        class_referenced = False
        missing_methods = []

        # --- Special handling for rule 27: Database presence ---
        if str(rule_id) == "27":
            if db_files:
                score = 1
            results.append({
                "rule_id": rule_id,
                "description": description,
                "databases_found": db_files,
                "score": score
            })
            continue

        # --- Special case: Manifest launcher activity presence ---
        if rule_type == "manifest_absence":
            score = 1  # assume missing launcher
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

        else:
            # --- General rule handling ---
            if not (target_class or target_classes):
                if permission_present:
                    score = 1
            else:
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
                    if not rule_class or not rule_methods:
                        continue

                    for method in dx.get_methods():
                        for _, call, _ in method.get_xref_to():
                            call_class = clean_class_name(str(call.class_name)).strip("L;")
                            call_method = clean_method_name(str(call.name))

                            if call_class == rule_class.strip("L;") or f"L{call_class}" == rule_class:
                                class_referenced = True
                                if call_method in rule_methods:
                                    matched_methods.add(call_method)
                
                all_rule_methods = []
                if target_classes:
                    for cls_info in classes_to_check:
                        all_rule_methods.extend(cls_info.get("methods", []))
                elif target_methods:
                    all_rule_methods = target_methods

                missing_methods = [m for m in all_rule_methods if m not in matched_methods]
                
                if permission_present and class_referenced and not missing_methods:
                    score = 1
        
        results.append({
            "rule_id": rule_id,
            "description": description,
            "permission_present": permission_present if target_permission is not None else "N/A",
            "class_referenced": class_referenced if target_class or target_classes else "N/A",
            "target_methods_present": sorted(list(matched_methods)) if target_class or target_classes else "N/A",
            "target_methods_missing": missing_methods if target_class or target_classes else "N/A",
            "score": score
        })

    return {"rules": results, "permissions": apk_permissions, "databases": db_files}

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
    apk_dir = "uploads/"  # change to your folder path

    # Find the APK file in the directory
    apk_files = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]

    if not apk_files:
        print(f"No APK files found in {apk_dir}")
        sys.exit(1)

    # Since there is only one APK, pick it
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

    print("[+] Running rule-based analysis...")
    rules_data = analyze_rules(apk_file)

    print("[+] Running certificate and signature analysis...")
    certs_data = analyze_apk_certs(apk_file)

    output = {
        "file": filename,
        "package_name": package_name,
        "hashes": hashes,
        "virus_total": vt_data,
        "rules_analysis": rules_data,
        "certificates": certs_data,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Define the path for the JSON file
    save_path = "analysis/static_output.json"  # or provide a full path like "/home/avis/results/output.json"

    # Ensure the directory exists
    os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)

    # Write to the JSON file (overwrites if it already exists)
    with open(save_path, "w") as f:
        json.dump(output, f, indent=4)

    print(f"✅ Output saved to {save_path}")
