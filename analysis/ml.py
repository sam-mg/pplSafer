import sys
import os
import joblib
import numpy as np
import json
import xgboost
from androguard.misc import AnalyzeAPK
from loguru import logger

logger.remove()

MODEL_PATH = "models/xgboost_apk_model.pkl"
FEATURES_CONFIG_PATH = "config/ml_features.json"

def load_ml_features():
    """Load ML features from JSON configuration file."""
    try:
        if not os.path.exists(FEATURES_CONFIG_PATH):
            logger.error(f"ML features configuration file not found: {FEATURES_CONFIG_PATH}")
            return set()
        
        with open(FEATURES_CONFIG_PATH, "r", encoding='utf-8') as f:
            features_list = json.load(f)
            return set(features_list)
    except Exception as e:
        logger.error(f"Failed to load ML features: {e}")
        return set()

# Load features from configuration
FEATURES_SET = load_ml_features()
if not FEATURES_SET:
    print("❌ Failed to load ML features from configuration.")
    sys.exit(1)

ALL_FEATURES_LIST = sorted(list(FEATURES_SET))

xgb_model = joblib.load(MODEL_PATH)
print("✅ Model loaded successfully.")
print(f"✅ Loaded {len(FEATURES_SET)} features from configuration.")

def extract_features(apk_path):
    found_features = set()
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        for perm in a.get_permissions():
            for feature in FEATURES_SET:
                if perm.endswith(feature):
                    found_features.add(feature)
        components = {
            'activities': a.get_activities(),
            'services': a.get_services(),
            'receivers': a.get_receivers()
        }
        for comp_type in components:
            for item in components[comp_type]:
                intent_filters = a.get_intent_filters(comp_type, item)
                if intent_filters:
                    for action in intent_filters.get('action', []):
                        if action in FEATURES_SET:
                            found_features.add(action)
        for s_obj in dx.get_strings():
            s = s_obj.get_value()
            if isinstance(s, bytes):
                s = s.decode('utf-8', 'ignore')
            for feature in FEATURES_SET:
                if feature in s:
                    found_features.add(feature)
        for method in dx.get_external_methods():
            class_name = method.class_name
            method_name = method.name
            pretty_class_name = class_name[1:-1].replace('/', '.')
            checks = [
                method_name,
                pretty_class_name,
                f"{pretty_class_name.split('.')[-1]}.{method_name}",
                f"L{pretty_class_name}.{method_name}"
            ]
            for check in checks:
                if check in FEATURES_SET:
                    found_features.add(check)
    except Exception as e:
        print(f"Error processing {apk_path}: {e}", file=sys.stderr)
        return None
    return found_features

APK_FOLDER_PATH = "uploads/"

apk_path = None
try:
    for filename in os.listdir(APK_FOLDER_PATH):
        if filename.endswith(".apk"):
            apk_path = os.path.join(APK_FOLDER_PATH, filename)
            break
except FileNotFoundError:
    print(f"❌ Error: The directory '{APK_FOLDER_PATH}' was not found.")
    sys.exit(1)

if apk_path is None:
    print(f"❌ No APK file found in '{APK_FOLDER_PATH}'.")
    sys.exit(1)

found_features = extract_features(apk_path)
if found_features is None:
    print("❌ Failed to extract features.")
    sys.exit(1)

feature_vector = np.array([1 if f in found_features else 0 for f in ALL_FEATURES_LIST]).reshape(1, -1)

pred_proba = xgb_model.predict_proba(feature_vector)[0][1]
pred_percent = pred_proba * 100

if pred_percent >= 30:
    label = "Malware"
else:
    label = "Benign (low confidence)"

result = {
    "prediction": label,
    "malware_probability_percent": float(round(pred_percent, 2))
}

save_path = "analysis/ml_output.json"

os.makedirs(os.path.dirname(save_path), exist_ok=True)

with open(save_path, "w") as f:
    json.dump(result, f, indent=4)

print(f"✅ Result written to {save_path}")
