import os
import json
from loguru import logger
from androguard.misc import AnalyzeAPK

# Disable androguard debug noise
logger.remove()

APK_PATH = os.path.expanduser("~/Downloads/BANKING/app.apk")
RULES_PATH = os.path.expanduser("~/Downloads/BANKING/Scripts/rules_new.json")

def clean_method_name(name: str) -> str:
    """
    Normalize method name by stripping arguments/return type.
    Example: 'getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;'
             -> 'getLastKnownLocation'
    """
    if "(" in name:
        return name.split("(")[0]
    return name

def analyze_apk_with_rules():
    results = {}

    # Load rules
    with open(RULES_PATH, "r") as f:
        rules = json.load(f)

    # Analyze APK
    a, d, dx = AnalyzeAPK(APK_PATH)
    apk_permissions = set(a.get_permissions())

    # Apply rules
    for rule in rules:
        rule_id = rule.get("rule_id", "N/A")
        target_class = rule.get("target_class")
        target_methods = rule.get("target_methods", [])
        target_permission = rule.get("target_permission")

        # Normalize permissions (handle str or list)
        if isinstance(target_permission, str):
            target_permissions = [target_permission]
        elif isinstance(target_permission, list):
            target_permissions = target_permission
        else:
            target_permissions = []

        # Check permission match
        permission_match = any(p in apk_permissions for p in target_permissions)

        matched_methods = set()
        class_referenced = False
        call_locations = {}

        if permission_match:
            for method in dx.get_methods():
                for _, call, _ in method.get_xref_to():
                    call_class = str(call.class_name)
                    call_method = clean_method_name(str(call.name))

                    if call_class == target_class:
                        class_referenced = True
                        if call_method in target_methods:
                            matched_methods.add(call_method)
                            call_locations.setdefault(call_method, []).append(
                                str(method.class_name)
                            )

        # scoring: require class + at least one method
        score = 1 if class_referenced and matched_methods else 0

        results[rule_id] = {
            "score": score,
            "target_permission": target_permissions,
            "target_class": target_class,
            "required_methods": target_methods,
            "matched_methods": sorted(list(matched_methods)),
            "class_referenced": class_referenced,
            "call_locations": call_locations
        }

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    analyze_apk_with_rules()
