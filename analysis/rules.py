import sys
import os
import json
import tempfile
import zipfile
import shutil
from datetime import datetime
from loguru import logger
from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from collections import Counter

logger.remove()
logger.add(sys.stderr, level="INFO")

RULES_PATH = os.path.expanduser("config/rules.json")
LEGIT_DB_MAP_PATH = os.path.expanduser("config/legit_db_map.json")

def load_legit_db_map():
    """Load legitimate database map from JSON configuration file."""
    try:
        if not os.path.exists(LEGIT_DB_MAP_PATH):
            logger.warning(f"Legitimate DB map file not found: {LEGIT_DB_MAP_PATH}")
            return {}
        
        with open(LEGIT_DB_MAP_PATH, "r", encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load legitimate DB map: {e}")
        return {}

def clean_method_name(name: str) -> str:
    """Clean method name by removing parameters."""
    if not name:
        return ""
    return name.split("(")[0] if "(" in name else name.strip()


def clean_class_name(name: str) -> str:
    """Clean class name by stripping whitespace."""
    return name.strip() if name else ""


def extract_databases(apk_path: str) -> list:
    """Extract database files from APK."""
    db_files = []
    tmp_dir = None
    
    try:
        if not os.path.exists(apk_path):
            logger.error(f"APK file not found: {apk_path}")
            return db_files
            
        with zipfile.ZipFile(apk_path, "r") as apk_zip:
            tmp_dir = tempfile.mkdtemp()
            for file_info in apk_zip.infolist():
                filename = file_info.filename
                if filename.endswith((".db", ".sqlite", ".sqlite3", ".realm")):
                    db_name = os.path.basename(filename)
                    if db_name and not db_name.startswith('.'):  # Avoid empty names and hidden files
                        db_files.append(db_name)
                        try:
                            apk_zip.extract(filename, tmp_dir)
                        except Exception as e:
                            logger.warning(f"Failed to extract {filename}: {e}")
            
    except zipfile.BadZipFile:
        logger.error(f"Invalid APK file: {apk_path}")
    except Exception as e:
        logger.error(f"Database extraction failed: {e}")
    finally:
        # Clean up temporary directory
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)
    
    return list(set(db_files))  # Remove duplicates

def find_db_strings(apk_path: str) -> list:
    """Find database-related strings in APK using Androguard."""
    try:
        if not os.path.exists(apk_path):
            logger.error(f"APK file not found: {apk_path}")
            return []
            
        a, d, dx = AnalyzeAPK(apk_path)
        db_strings = []
        
        # Get all strings and filter for database files
        strings_analysis = dx.get_strings_analysis()
        for string_obj in strings_analysis:
            string_val = str(string_obj)
            if (string_val.endswith('.db') or '.sqlite' in string_val.lower()) and len(string_val) > 2:
                db_strings.append(string_val)
        
        return sorted(list(set(db_strings)))
        
    except Exception as e:
        logger.error(f"String analysis failed: {e}")
        return []


def normalize_classes_to_check(target_classes, target_class, target_methods):
    """Normalize class specifications to a consistent format."""
    if target_classes:
        if all(isinstance(c, str) for c in target_classes):
            return [{"class": c, "methods": []} for c in target_classes]
        else:
            return target_classes
    elif target_class:
        return [{"class": target_class, "methods": target_methods or []}]
    return []


def analyze_rule_1_to_8_10_to_12_and_14(rule, dx, apk_permissions):
    rule_id = rule.get("rule_id", "Unknown")
    target_permission = rule.get("target_permission")
    target_class = rule.get("target_class")
    target_classes = rule.get("target_classes")
    target_methods = rule.get("target_methods", [])

    # Check permissions
    if isinstance(target_permission, list):
        permission_present = any(p.lower() in apk_permissions for p in target_permission)
    else:
        permission_present = target_permission and target_permission.lower() in apk_permissions
    
    # Normalize classes to check
    normalized_classes_to_check = normalize_classes_to_check(target_classes, target_class, target_methods)

    class_referenced = False
    is_all_methods_present = False
    matched_methods = set()

    if normalized_classes_to_check:
        classes_referenced_flags = []
        all_methods_present_flags = []
        
        for class_info in normalized_classes_to_check:
            rule_class = class_info.get("class", "").strip("L;")
            rule_methods = class_info.get("methods", [])
            
            class_found_in_dex = False
            matched_methods_for_this_class = set()

            # Check if class exists in DEX
            for c in dx.classes.keys():
                cleaned_class = clean_class_name(str(c)).strip("L;")
                if cleaned_class == rule_class:
                    class_found_in_dex = True
                    # Check methods within this class
                    for method in dx.classes[c].get_methods():
                        method_name = clean_method_name(method.name)
                        if method_name in rule_methods:
                            matched_methods_for_this_class.add(method_name)

            # If class not found in DEX directly, check method references
            if not class_found_in_dex:
                for method in dx.get_methods():
                    try:
                        for _, call, _ in method.get_xref_to():
                            call_class = clean_class_name(str(call.class_name)).strip("L;")
                            if call_class == rule_class:
                                class_found_in_dex = True
                                break
                    except:
                        continue
            
            classes_referenced_flags.append(class_found_in_dex)
            all_methods_present_flags.append(
                len(matched_methods_for_this_class) == len(rule_methods) if rule_methods else True
            )
            matched_methods.update(matched_methods_for_this_class)

        class_referenced = any(classes_referenced_flags)
        is_all_methods_present = all(all_methods_present_flags)
    
    score = 1 if permission_present and class_referenced and is_all_methods_present else 0

    return {
        "rule_id": rule_id,
        "description": rule.get("description", ""),
        "permission_present": permission_present,
        "class_referenced": class_referenced,
        "target_methods_present": sorted(list(matched_methods)),
        "target_methods_missing": [m for m in target_methods if m not in matched_methods],
        "score": score
    }


def analyze_rule_9_18_to_22(rule, dx):
    """
    Evaluates rules with only class and method requirements.
    Score is 1 if all classes are referenced and all methods are invoked.
    """
    rule_id = rule.get("rule_id", "Unknown")
    target_class = rule.get("target_class")
    target_classes = rule.get("target_classes")
    target_methods = rule.get("target_methods", [])

    normalized_classes_to_check = normalize_classes_to_check(target_classes, target_class, target_methods)

    class_referenced = False
    is_all_methods_present = False
    matched_methods = set()

    if normalized_classes_to_check:
        classes_referenced_flags = []
        all_methods_present_flags = []
        
        for class_info in normalized_classes_to_check:
            rule_class = class_info.get("class", "").strip("L;")
            rule_methods = class_info.get("methods", [])
            
            class_found_in_dex = False
            matched_methods_for_this_class = set()

            # Check if class exists in DEX
            for c in dx.classes.keys():
                cleaned_class = clean_class_name(str(c)).strip("L;")
                if cleaned_class == rule_class:
                    class_found_in_dex = True
                    # Check methods within this class
                    for method in dx.classes[c].get_methods():
                        method_name = clean_method_name(method.name)
                        if method_name in rule_methods:
                            matched_methods_for_this_class.add(method_name)

            # If class not found in DEX directly, check method references
            if not class_found_in_dex:
                for method in dx.get_methods():
                    try:
                        for _, call, _ in method.get_xref_to():
                            call_class = clean_class_name(str(call.class_name)).strip("L;")
                            if call_class == rule_class:
                                class_found_in_dex = True
                                break
                    except:
                        continue
            
            classes_referenced_flags.append(class_found_in_dex)
            all_methods_present_flags.append(
                len(matched_methods_for_this_class) == len(rule_methods) if rule_methods else True
            )
            matched_methods.update(matched_methods_for_this_class)

        class_referenced = all(classes_referenced_flags)
        is_all_methods_present = all(all_methods_present_flags)

    score = 1 if class_referenced and is_all_methods_present else 0

    return {
        "rule_id": rule_id,
        "description": rule.get("description", ""),
        "class_referenced": class_referenced,
        "target_methods_present": sorted(list(matched_methods)),
        "target_methods_missing": [m for m in target_methods if m not in matched_methods],
        "score": score
    }


def analyze_rule_13(rule, apk_permissions):
    """
    Evaluates rules with only permission requirements.
    Score is 1 if permission is present.
    """
    rule_id = rule.get("rule_id", "Unknown")
    target_permission = rule.get("target_permission")
    
    if isinstance(target_permission, list):
        permission_present = any(p.lower() in apk_permissions for p in target_permission)
    else:
        permission_present = target_permission and target_permission.lower() in apk_permissions
    
    score = 1 if permission_present else 0
    
    return {
        "rule_id": rule_id,
        "description": rule.get("description", ""),
        "permission_present": permission_present,
        "score": score
    }


def analyze_rule_15(rule, dx, apk_permissions):
    """
    Evaluates rules with all permissions, all classes, and all methods.
    Score is 1 if all are present.
    """
    rule_id = rule.get("rule_id", "Unknown")
    target_permissions = rule.get("target_permissions", [])
    target_classes = rule.get("target_classes", [])
    target_methods = rule.get("target_methods", [])

    # Check all permissions
    all_permissions_present = all(
        any(p.lower() in apk_permissions for p in (tp if isinstance(tp, list) else [tp])) 
        for tp in target_permissions
    )
    
    normalized_classes_to_check = normalize_classes_to_check(target_classes, None, target_methods)

    class_referenced = False
    is_all_methods_present = False
    matched_methods = set()

    if normalized_classes_to_check:
        class_referenced_flags = []
        all_methods_present_flags = []
        
        for class_info in normalized_classes_to_check:
            rule_class = class_info.get("class", "").strip("L;")
            rule_methods = class_info.get("methods", [])
            
            class_found_in_dex = False
            matched_methods_for_this_class = set()

            # Check if class exists in DEX
            for c in dx.classes.keys():
                cleaned_class = clean_class_name(str(c)).strip("L;")
                if cleaned_class == rule_class:
                    class_found_in_dex = True
                    # Check methods within this class
                    for method in dx.classes[c].get_methods():
                        method_name = clean_method_name(method.name)
                        if method_name in rule_methods:
                            matched_methods_for_this_class.add(method_name)

            # If class not found in DEX directly, check method references
            if not class_found_in_dex:
                for method in dx.get_methods():
                    try:
                        for _, call, _ in method.get_xref_to():
                            call_class = clean_class_name(str(call.class_name)).strip("L;")
                            if call_class == rule_class:
                                class_found_in_dex = True
                                break
                    except:
                        continue
            
            class_referenced_flags.append(class_found_in_dex)
            all_methods_present_flags.append(
                len(matched_methods_for_this_class) == len(rule_methods) if rule_methods else True
            )
            matched_methods.update(matched_methods_for_this_class)

        class_referenced = all(class_referenced_flags)
        is_all_methods_present = all(all_methods_present_flags)

    score = 1 if all_permissions_present and class_referenced and is_all_methods_present else 0

    return {
        "rule_id": rule_id,
        "description": rule.get("description", ""),
        "permissions_present": all_permissions_present,
        "class_referenced": class_referenced,
        "target_methods_present": sorted(list(matched_methods)),
        "target_methods_missing": [m for m in target_methods if m not in matched_methods],
        "score": score
    }


def analyze_rule_16(rule, dx):
    """
    Evaluates rules with only string requirements.
    Score is 1 if all strings are present.
    """
    rule_id = rule.get("rule_id", "Unknown")
    target_strings = rule.get("target_strings", [])
    
    strings_analysis = dx.get_strings_analysis()
    matched_strings = [s for s in target_strings if s in strings_analysis.keys()]
    is_all_strings_present = (len(matched_strings) == len(target_strings))
    
    score = 1 if is_all_strings_present else 0
    
    return {
        "rule_id": rule_id,
        "description": rule.get("description", ""),
        "matched_strings": matched_strings,
        "missing_strings": [s for s in target_strings if s not in matched_strings],
        "score": score
    }


def analyze_rule_17(rule, a):
    """
    Evaluates rule for launcher activity absence.
    Score is 1 if no launcher activity is found.
    """
    rule_id = rule.get("rule_id", "Unknown")
    has_launcher_activity = False
    
    try:
        for activity in a.get_activities():
            intent_filters = a.get_intent_filters("activity", activity)
            actions = intent_filters.get("action", [])
            categories = intent_filters.get("category", [])
            
            for action_list, category_list in zip(actions, categories):
                if ("android.intent.action.MAIN" in action_list and 
                    "android.intent.category.LAUNCHER" in category_list):
                    has_launcher_activity = True
                    break
            
            if has_launcher_activity:
                break
                
    except Exception as e:
        logger.debug(f"Manifest check error: {e}")
    
    score = 0 if has_launcher_activity else 1
    
    return {
        "rule_id": rule_id,
        "description": rule.get("description", ""),
        "has_launcher_activity": has_launcher_activity,
        "score": score
    }


def analyze_rule_23(rule, apk_path, package_name, all_db_names_found):
    """
    Custom rule for database impersonation check.
    """
    rule_id = rule.get("rule_id", "Unknown")
    description = rule.get("description", "")
    
    print("\n[DEBUG][Rule 23] Starting custom DB analysis...")
    print(f"[DEBUG][Rule 23] APK package: {package_name}")
    print(f"[DEBUG][Rule 23] Databases found in APK before filtering: {all_db_names_found}")

    # Load legitimate database map from configuration
    LEGIT_DB_MAP = load_legit_db_map()
    if not LEGIT_DB_MAP:
        logger.warning("No legitimate database map loaded, rule_23 will not function properly")
        return {
            "rule_id": "rule_23",
            "description": description,
            "databases_found_in_apk": all_db_names_found,
            "flagged_unique_legit_databases": [],
            "score": 0
        }

    # Common database names that should be filtered out
    COMMON_DB_NAMES = {
        "google_app_measurement_local.db",
        "google_app_measurement.db",
        "google_analytics_v4.db",
        "tekartik_sqflite.db",
        ".db",
        "asset.db"
    }
    
    # Filter out common database names
    filtered_dbs = [db for db in all_db_names_found if db not in COMMON_DB_NAMES]
    print(f"[DEBUG][Rule 23] Databases after removing common DBs: {filtered_dbs}")

    flagged_dbs = []
    score = 0

    if not filtered_dbs:
        print("[DEBUG][Rule 23] No unique DBs found after filtering. Returning score 0.")
        return {
            "rule_id": "rule_23",
            "description": description,
            "databases_found_in_apk": all_db_names_found,
            "flagged_unique_legit_databases": [],
            "score": 0
        }

    for db_name in filtered_dbs:
        print(f"[DEBUG][Rule 23] Checking DB: {db_name}")
        db_matched = False
        
        for legit_pkg, legit_dbs in LEGIT_DB_MAP.items():
            if db_name in legit_dbs:
                db_matched = True
                if legit_pkg == package_name:
                    status = "standard"
                    print(f"[DEBUG][Rule 23] DB {db_name} belongs to same package ({package_name}) -> standard")
                else:
                    status = "impersonation"
                    score = 1
                    print(f"[DEBUG][Rule 23] DB {db_name} belongs to {legit_pkg}, not {package_name} -> impersonation, score set to 1")

                flagged_dbs.append({
                    "db_name": db_name,
                    "legit_package_name": legit_pkg,
                    "input_package_name": package_name,
                    "status": status
                })

        if not db_matched:
            print(f"[DEBUG][Rule 23] DB {db_name} not found in LEGIT_DB_MAP -> unknown, score set to 1")
            flagged_dbs.append({
                "db_name": db_name,
                "legit_package_name": "unknown",
                "input_package_name": package_name,
                "status": "unknown"
            })
            score = 1

    print(f"[DEBUG][Rule 23] Final flagged DBs: {flagged_dbs}")
    print(f"[DEBUG][Rule 23] Final score: {score}")

    return {
        "rule_id": "rule_23",
        "description": description,
        "databases_found_in_apk": all_db_names_found,
        "flagged_unique_legit_databases": flagged_dbs,
        "score": score
    }


def analyze_rule_24(rule, dx):
    """
    Evaluates rule for all classes, all strings, and all methods.
    Score is 1 if all are present.
    """
    rule_id = rule.get("rule_id", "Unknown")
    target_classes = rule.get("target_classes", [])
    target_methods = rule.get("target_methods", [])
    target_strings = rule.get("target_strings", [])

    # Check strings
    strings_analysis = dx.get_strings_analysis()
    matched_strings = [s for s in target_strings if s in strings_analysis.keys()]
    is_all_strings_present = (len(matched_strings) == len(target_strings))
    
    class_referenced = False
    is_all_methods_present = False
    matched_methods = set()

    if target_classes:
        class_referenced_flags = []
        for rule_class in target_classes:
            class_found_in_dex = False
            rule_class_clean = rule_class.strip("L;")
            
            # Check if class exists in DEX
            for c in dx.classes.keys():
                cleaned_class = clean_class_name(str(c)).strip("L;")
                if cleaned_class == rule_class_clean:
                    class_found_in_dex = True
                    break
                    
            # If class not found in DEX directly, check method references
            if not class_found_in_dex:
                for method in dx.get_methods():
                    try:
                        for _, call, _ in method.get_xref_to():
                            call_class = clean_class_name(str(call.class_name)).strip("L;")
                            if call_class == rule_class_clean:
                                class_found_in_dex = True
                                break
                    except:
                        continue
            
            class_referenced_flags.append(class_found_in_dex)

        class_referenced = all(class_referenced_flags)

    # Check methods
    if target_methods:
        for method in dx.get_methods():
            method_name = clean_method_name(method.name)
            if method_name in target_methods:
                matched_methods.add(method_name)
        is_all_methods_present = (len(matched_methods) == len(target_methods))
    else:
        is_all_methods_present = True
    
    score = 1 if class_referenced and is_all_methods_present and is_all_strings_present else 0

    return {
        "rule_id": rule_id,
        "description": rule.get("description", ""),
        "class_referenced": class_referenced,
        "target_methods_present": sorted(list(matched_methods)),
        "target_methods_missing": [m for m in target_methods if m not in matched_methods],
        "matched_strings": matched_strings,
        "missing_strings": [s for s in target_strings if s not in matched_strings],
        "score": score
    }


def analyze_rule_25(rule, dx):
    """
    Evaluates rule for methods and strings.
    Score is 1 if all are present.
    """
    rule_id = rule.get("rule_id", "Unknown")
    target_methods = rule.get("target_methods", [])
    target_strings = rule.get("target_strings", [])

    # Check strings
    strings_analysis = dx.get_strings_analysis()
    matched_strings = [s for s in target_strings if s in strings_analysis.keys()]
    is_all_strings_present = (len(matched_strings) == len(target_strings))
    
    # Check methods
    matched_methods = set()
    if target_methods:
        for method in dx.get_methods():
            method_name = clean_method_name(method.name)
            if method_name in target_methods:
                matched_methods.add(method_name)
        is_all_methods_present = (len(matched_methods) == len(target_methods))
    else:
        is_all_methods_present = True
    
    score = 1 if is_all_methods_present and is_all_strings_present else 0

    return {
        "rule_id": rule_id,
        "description": rule.get("description", ""),
        "target_methods_present": sorted(list(matched_methods)),
        "target_methods_missing": [m for m in target_methods if m not in matched_methods],
        "matched_strings": matched_strings,
        "missing_strings": [s for s in target_strings if s not in matched_strings],
        "score": score
    }


def analyze_rules(apk_path: str) -> dict:
    """Analyze APK against all rules in the rules file."""
    if not os.path.exists(RULES_PATH):
        logger.error(f"Rules file not found: {RULES_PATH}")
        return {"error": f"Rules file not found: {RULES_PATH}"}

    try:
        with open(RULES_PATH, "r", encoding='utf-8') as f:
            rules = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load rules file: {e}")
        return {"error": f"Failed to load rules file: {e}"}

    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        logger.error(f"Failed to analyze APK with Androguard: {e}")
        return {"error": f"Failed to analyze APK: {e}"}

    # Get APK information
    try:
        apk_permissions = sorted([p.strip().lower() for p in a.get_permissions()])
        package_name = a.get_package()
    except Exception as e:
        logger.error(f"Failed to extract APK metadata: {e}")
        apk_permissions = []
        package_name = "Unknown"

    results = []

    # Extract database information
    db_files_zip = extract_databases(apk_path)
    db_strings_dx = find_db_strings(apk_path)
    all_db_names_found = list(set(db_files_zip + db_strings_dx))

    # Analyze each rule
    for rule in rules:
        rule_id = rule.get("rule_id", "Unknown")
        
        try:
            if rule_id in ["rule_1", "rule_2", "rule_3", "rule_4", "rule_5", "rule_6", 
                          "rule_7", "rule_8", "rule_10", "rule_11", "rule_12", "rule_14"]:
                results.append(analyze_rule_1_to_8_10_to_12_and_14(rule, dx, apk_permissions))
                
            elif rule_id in ["rule_9", "rule_18", "rule_19", "rule_20", "rule_21", "rule_22"]:
                results.append(analyze_rule_9_18_to_22(rule, dx))
                
            elif rule_id == "rule_13":
                results.append(analyze_rule_13(rule, apk_permissions))
                
            elif rule_id == "rule_15":
                results.append(analyze_rule_15(rule, dx, apk_permissions))
                
            elif rule_id == "rule_16":
                results.append(analyze_rule_16(rule, dx))
                
            elif rule_id == "rule_17":
                results.append(analyze_rule_17(rule, a))
                
            elif rule_id == "rule_23":
                results.append(analyze_rule_23(rule, apk_path, package_name, all_db_names_found))
                
            elif rule_id == "rule_24":
                results.append(analyze_rule_24(rule, dx))
                
            elif rule_id == "rule_25":
                results.append(analyze_rule_25(rule, dx))
                
            else:
                logger.warning(f"No specific evaluation function for rule ID: {rule_id}. Skipping.")
                results.append({
                    "rule_id": rule_id,
                    "description": rule.get("description", ""),
                    "error": "No evaluation function implemented",
                    "score": 0
                })
                
        except Exception as e:
            logger.error(f"Error analyzing rule {rule_id}: {e}")
            results.append({
                "rule_id": rule_id,
                "description": rule.get("description", ""),
                "error": str(e),
                "score": 0
            })
    
    return {
        "rules": results, 
        "permissions": apk_permissions, 
        "databases": all_db_names_found,
        "package_name": package_name
    }


def main():
    """Main execution function."""
    # Check if APK directory exists
    apk_dir = "uploads/"
    
    if not os.path.exists(apk_dir):
        print(f"Error: APK directory not found: {apk_dir}")
        sys.exit(1)

    # Find APK files
    try:
        apk_files = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]
    except Exception as e:
        print(f"Error reading APK directory: {e}")
        sys.exit(1)

    if not apk_files:
        print(f"No APK files found in {apk_dir}")
        sys.exit(1)

    # Use first APK file found
    apk_file = os.path.join(apk_dir, apk_files[0])
    filename = os.path.basename(apk_file)
    print(f"Running rules-based analysis on: {filename}")

    # Run rules-based analysis only
    print("[+] Running rule-based analysis...")
    rules_data = analyze_rules(apk_file)

    # Prepare minimal output data focused only on rules
    output = {
        "file": filename,
        "rules_analysis": rules_data,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Save results
    save_path = "analysis/rules_output.json"
    try:
        os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
        with open(save_path, "w", encoding='utf-8') as f:
            json.dump(output, f, indent=4, ensure_ascii=False)
        print(f"✅ Rules analysis completed and saved to {save_path}")
    except Exception as e:
        print(f"Error saving output: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()