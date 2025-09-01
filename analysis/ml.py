# === 1. Imports ===
import sys
import os
import joblib
import numpy as np
from androguard.misc import AnalyzeAPK

# === 2. Load your trained model ===
MODEL_PATH = "models/xgboost_apk_model.pkl"
xgb_model = joblib.load(MODEL_PATH)
print("✅ Model loaded successfully.")

# === 3. Define full features list (sorted) ===
FEATURES_SET = {
    'transact', 'onServiceConnected', 'bindService', 'attachInterface', 'ServiceConnection',
    'android.os.Binder', 'SEND_SMS', 'Ljava.lang.Class.getCanonicalName', 'Ljava.lang.Class.getMethods',
    'Ljava.lang.Class.cast', 'Ljava.net.URLDecoder', 'android.content.pm.Signature',
    'android.telephony.SmsManager', 'READ_PHONE_STATE', 'getBinder', 'ClassLoader',
    'Landroid.content.Context.registerReceiver', 'Ljava.lang.Class.getField',
    'Landroid.content.Context.unregisterReceiver', 'GET_ACCOUNTS', 'RECEIVE_SMS',
    'Ljava.lang.Class.getDeclaredField', 'READ_SMS', 'getCallingUid', 'Ljavax.crypto.spec.SecretKeySpec',
    'android.intent.action.BOOT_COMPLETED', 'USE_CREDENTIALS', 'MANAGE_ACCOUNTS',
    'android.content.pm.PackageInfo', 'KeySpec', 'TelephonyManager.getLine1Number',
    'DexClassLoader', 'HttpGet.init', 'SecretKey', 'Ljava.lang.Class.getMethod',
    'System.loadLibrary', 'android.intent.action.SEND', 'Ljavax.crypto.Cipher', 'WRITE_SMS',
    'READ_SYNC_SETTINGS', 'AUTHENTICATE_ACCOUNTS', 'android.telephony.gsm.SmsManager',
    'WRITE_HISTORY_BOOKMARKS', 'TelephonyManager.getSubscriberId', 'mount', 'INSTALL_PACKAGES',
    'Runtime.getRuntime', 'CAMERA', 'Ljava.lang.Object.getClass', 'WRITE_SYNC_SETTINGS',
    'READ_HISTORY_BOOKMARKS', 'Ljava.lang.Class.forName', 'INTERNET',
    'android.intent.action.PACKAGE_REPLACED', 'Binder', 'android.intent.action.SEND_MULTIPLE',
    'RECORD_AUDIO', 'IBinder', 'android.os.IBinder', 'createSubprocess', 'NFC',
    'ACCESS_LOCATION_EXTRA_COMMANDS', 'URLClassLoader', 'WRITE_APN_SETTINGS', 'abortBroadcast',
    'BIND_REMOTEVIEWS', 'android.intent.action.TIME_SET', 'READ_PROFILE',
    'TelephonyManager.getDeviceId', 'MODIFY_AUDIO_SETTINGS', 'getCallingPid', 'READ_SYNC_STATS',
    'BROADCAST_STICKY', 'android.intent.action.PACKAGE_REMOVED', 'android.intent.action.TIMEZONE_CHANGED',
    'WAKE_LOCK', 'RECEIVE_BOOT_COMPLETED', 'RESTART_PACKAGES', 'Ljava.lang.Class.getPackage',
    'chmod', 'Ljava.lang.Class.getDeclaredClasses', 'android.intent.action.ACTION_POWER_DISCONNECTED',
    'android.intent.action.PACKAGE_ADDED', 'PathClassLoader', 'TelephonyManager.getSimSerialNumber',
    'Runtime.load', 'TelephonyManager.getCallState', 'BLUETOOTH', 'READ_CALENDAR', 'READ_CALL_LOG',
    'SUBSCRIBED_FEEDS_WRITE', 'READ_EXTERNAL_STORAGE', 'TelephonyManager.getSimCountryIso',
    'sendMultipartTextMessage', 'PackageInstaller', 'VIBRATE', 'remount',
    'android.intent.action.ACTION_SHUTDOWN', 'sendDataMessage', 'ACCESS_NETWORK_STATE', 'chown',
    'HttpPost.init', 'Ljava.lang.Class.getClasses', 'SUBSCRIBED_FEEDS_READ',
    'TelephonyManager.isNetworkRoaming', 'CHANGE_WIFI_MULTICAST_STATE', 'WRITE_CALENDAR',
    'android.intent.action.PACKAGE_DATA_CLEARED', 'MASTER_CLEAR', 'HttpUriRequest',
    'UPDATE_DEVICE_STATS', 'WRITE_CALL_LOG', 'DELETE_PACKAGES', 'GET_TASKS', 'GLOBAL_SEARCH',
    'DELETE_CACHE_FILES', 'WRITE_USER_DICTIONARY', 'android.intent.action.PACKAGE_CHANGED',
    'android.intent.action.NEW_OUTGOING_CALL', 'REORDER_TASKS', 'WRITE_PROFILE', 'SET_WALLPAPER',
    'BIND_INPUT_METHOD', 'divideMessage', 'READ_SOCIAL_STREAM', 'READ_USER_DICTIONARY',
    'PROCESS_OUTGOING_CALLS', 'CALL_PRIVILEGED', 'Runtime.exec', 'BIND_WALLPAPER',
    'RECEIVE_WAP_PUSH', 'DUMP', 'BATTERY_STATS', 'ACCESS_COARSE_LOCATION', 'SET_TIME',
    'android.intent.action.SENDTO', 'WRITE_SOCIAL_STREAM', 'WRITE_SETTINGS', 'REBOOT',
    'BLUETOOTH_ADMIN', 'TelephonyManager.getNetworkOperator', '/system/bin', 'MessengerService',
    'BIND_DEVICE_ADMIN', 'WRITE_GSERVICES', 'IRemoteService', 'KILL_BACKGROUND_PROCESSES',
    'SET_ALARM', 'ACCOUNT_MANAGER', '/system/app', 'android.intent.action.CALL', 'STATUS_BAR',
    'TelephonyManager.getSimOperator', 'PERSISTENT_ACTIVITY', 'CHANGE_NETWORK_STATE', 'onBind',
    'Process.start', 'android.intent.action.SCREEN_ON', 'Context.bindService', 'RECEIVE_MMS',
    'SET_TIME_ZONE', 'android.intent.action.BATTERY_OKAY', 'CONTROL_LOCATION_UPDATES',
    'BROADCAST_WAP_PUSH', 'BIND_ACCESSIBILITY_SERVICE', 'ADD_VOICEMAIL', 'CALL_PHONE',
    'ProcessBuilder', 'BIND_APPWIDGET', 'FLASHLIGHT', 'READ_LOGS', 'Ljava.lang.Class.getResource',
    'defineClass', 'SET_PROCESS_LIMIT', 'android.intent.action.PACKAGE_RESTARTED',
    'MOUNT_UNMOUNT_FILESYSTEMS', 'BIND_TEXT_SERVICE', 'INSTALL_LOCATION_PROVIDER',
    'android.intent.action.CALL_BUTTON', 'android.intent.action.SCREEN_OFF', 'findClass',
    'SYSTEM_ALERT_WINDOW', 'MOUNT_FORMAT_FILESYSTEMS', 'CHANGE_CONFIGURATION',
    'CLEAR_APP_USER_DATA', 'intent.action.RUN', 'android.intent.action.SET_WALLPAPER',
    'CHANGE_WIFI_STATE', 'READ_FRAME_BUFFER', 'ACCESS_SURFACE_FLINGER', 'Runtime.loadLibrary',
    'BROADCAST_SMS', 'EXPAND_STATUS_BAR', 'INTERNAL_SYSTEM_WINDOW',
    'android.intent.action.BATTERY_LOW', 'SET_ACTIVITY_WATCHER', 'WRITE_CONTACTS',
    'android.intent.action.ACTION_POWER_CONNECTED', 'BIND_VPN_SERVICE', 'DISABLE_KEYGUARD',
    'ACCESS_MOCK_LOCATION', 'GET_PACKAGE_SIZE', 'MODIFY_PHONE_STATE',
    'CHANGE_COMPONENT_ENABLED_STATE', 'CLEAR_APP_CACHE', 'SET_ORIENTATION', 'READ_CONTACTS',
    'DEVICE_POWER', 'HARDWARE_TEST', 'ACCESS_WIFI_STATE', 'WRITE_EXTERNAL_STORAGE',
    'ACCESS_FINE_LOCATION', 'SET_WALLPAPER_HINTS', 'SET_PREFERRED_APPLICATIONS', 'WRITE_SECURE_SETTINGS'
}
ALL_FEATURES_LIST = sorted(list(FEATURES_SET))

# === 4. Feature extraction function ===
def extract_features(apk_path):
    found_features = set()
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        # Permissions
        for perm in a.get_permissions():
            for feature in FEATURES_SET:
                if perm.endswith(feature):
                    found_features.add(feature)
        # Intent filters
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
        # Strings
        for s_obj in dx.get_strings():
            s = s_obj.get_value()
            if isinstance(s, bytes):
                s = s.decode('utf-8', 'ignore')
            for feature in FEATURES_SET:
                if feature in s:
                    found_features.add(feature)
        # External methods
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

# === 5. Find APK in the specified folder ===
APK_FOLDER_PATH = "uploads/" # <-- Path is now hardcoded

apk_path = None
try:
    for filename in os.listdir(APK_FOLDER_PATH):
        if filename.endswith(".apk"):
            apk_path = os.path.join(APK_FOLDER_PATH, filename)
            print(f"✅ Found APK: {apk_path}")
            break # Stop after finding the first one
except FileNotFoundError:
    print(f"❌ Error: The directory '{APK_FOLDER_PATH}' was not found.")
    sys.exit(1)

if apk_path is None:
    print(f"❌ No APK file found in '{APK_FOLDER_PATH}'.")
    sys.exit(1)

# === 6. Extract features and build vector ===
found_features = extract_features(apk_path)
if found_features is None:
    print("❌ Failed to extract features.")
    sys.exit(1)

feature_vector = np.array([1 if f in found_features else 0 for f in ALL_FEATURES_LIST]).reshape(1, -1)

# === 7. Make prediction with confidence threshold ===
pred_proba = xgb_model.predict_proba(feature_vector)[0][1]  # probability of malware class
pred_percent = pred_proba * 100  # convert to percentage

if pred_percent >= 30:
    label = "Malware"
else:
    label = "Benign (low confidence)"

# Prepare JSON output
import json
import os

result = {
    "prediction": label,
    "malware_probability_percent": float(round(pred_percent, 2))
}

# Define your desired path
save_path = "analysis/ml_output.json"

# Ensure directory exists
os.makedirs(os.path.dirname(save_path), exist_ok=True)

# Save (overwrite) JSON file
with open(save_path, "w") as f:
    json.dump(result, f, indent=4)

print(f"✅ Result written to {save_path}")
