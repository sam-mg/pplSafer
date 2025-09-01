let apiConfig = {};

function getCurrentCategory(className) {
  for (const category in apiConfig) {
    if (apiConfig[category][className]) {
      return category;
    }
  }
  return "Unknown";
}

rpc.exports.setconfig = function(config) {
  apiConfig = config;
  console.log("=== Configuration loaded from api_config.json ===");
  startHooking();
};

function parseMethodSignature(signature) {
  const methodName = signature.split("(")[0];
  const paramString = signature.substring(signature.indexOf("(") + 1, signature.indexOf(")"));
  const paramTypes = paramString ? paramString.split(",").map(p => p.trim()) : [];
  return { methodName, paramTypes };
}

function hookMethod(className, methodSignature) {
  try {
    const { methodName, paramTypes } = parseMethodSignature(methodSignature);
    
    let targetClass;
    try {
      targetClass = Java.use(className);
    } catch (classError) {
      if (classError.message.includes("ClassNotFoundException")) {
        console.log(`[i] Skipping ${className} - class not found in this app`);
        return;
      }
      throw classError;
    }

    const isConstructor = methodName === "$init";
    const overloadTarget = isConstructor ? targetClass.$init : targetClass[methodName];

    if (!overloadTarget) {
      console.error(`[-] Method not found: ${className}.${methodName}`);
      return;
    }

    let overload;
    if (paramTypes.length === 0) {
      overload = overloadTarget.overload();
    } else {
      overload = overloadTarget.overload(...paramTypes);
    }

    overload.implementation = function (...args) {
      const timestamp = new Date().toISOString();
      const fqMethodName = `${className}.${methodName}`;
      
      // Create JSON data structure
      const apiCallData = {
        timestamp: timestamp,
        className: className,
        methodName: methodName,
        fullMethodSignature: `${className}.${methodName}(${paramTypes.join(", ")})`,
        parameterTypes: paramTypes,
        arguments: [],
        returnValue: null,
        exception: null,
        category: getCurrentCategory(className)
      };

      console.log(`\n[+] API Used: ${className}.${methodName}(${paramTypes.join(", ")})`);

      const argNames = {
        "android.telephony.SmsManager.sendTextMessage": ["phoneNumber", "scAddress", "text", "sentIntent", "deliveryIntent"],

        "android.media.MediaRecorder.setAudioSource": ["source"],
        "android.media.MediaRecorder.setOutputFormat": ["format"],
        "android.media.MediaRecorder.setOutputFile": ["path"],
        "android.media.MediaRecorder.setAudioEncoder": ["encoder"],

        "androidx.core.content.ContextCompat.checkSelfPermission": ["context", "permission"],

        "androidx.core.app.ActivityCompat.requestPermissions": ["activity", "permissions", "requestCode"],

        "java.net.HttpURLConnection.setRequestMethod": ["method"],

        "java.io.InputStreamReader.$init": ["inputStream"],

        "android.os.Bundle.get": ["key"],

        "android.telephony.SmsMessage.createFromPdu": ["pdu"],
        "android.telephony.SmsMessage.getMessageBody": [],
        "android.telephony.SmsMessage.getOriginatingAddress": [],

        "android.content.BroadcastReceiver.onReceive": ["context", "intent"],

        "android.content.Intent.getExtras": [],

        "android.content.Context.getExternalFilesDir": ["type"],

        "java.security.MessageDigest.getInstance": ["algorithm"],
        "java.security.MessageDigest.update": ["input"],
        "java.security.MessageDigest.digest": ["input"],
        "javax.crypto.Cipher.getInstance": ["transformation"],
        "javax.crypto.Cipher.init": ["opmode", "key"],
        "javax.crypto.Cipher.doFinal": ["input"],
        "javax.crypto.Cipher.update": ["input"],
        "javax.crypto.KeyGenerator.getInstance": ["algorithm"],
        "javax.crypto.KeyGenerator.generateKey": [],

        "androidx.biometric.BiometricPrompt.authenticate": ["promptInfo", "cryptoObject"],
        "android.hardware.fingerprint.FingerprintManager.authenticate": ["crypto", "cancel", "flags", "callback", "handler"],

        "android.location.LocationManager.requestLocationUpdates": ["provider", "minTime", "minDistance", "listener"],
        "android.location.LocationManager.getLastKnownLocation": ["provider"],
        "android.location.LocationManager.getBestProvider": ["criteria", "enabledOnly"],

        "android.content.ContentResolver.query": ["uri", "projection", "selection", "selectionArgs", "sortOrder"],
        "android.content.ContentResolver.insert": ["uri", "values"],
        "android.content.ContentResolver.delete": ["uri", "where", "selectionArgs"],

        "android.app.admin.DevicePolicyManager.isAdminActive": ["admin"],
        "android.app.admin.DevicePolicyManager.lockNow": [],
        "android.app.admin.DevicePolicyManager.resetPassword": ["password", "flags"],
        "android.app.admin.DevicePolicyManager.wipeData": ["flags"],

        "android.content.ClipboardManager.setPrimaryClip": ["clip"],
        "android.content.ClipboardManager.getPrimaryClip": [],
        "android.content.ClipboardManager.hasPrimaryClip": [],

        "java.lang.Runtime.exec": ["command", "envp"],

        "java.security.KeyPairGenerator.getInstance": ["algorithm"],
        "java.security.KeyPairGenerator.generateKeyPair": [],

        "com.google.android.gms.location.FusedLocationProviderClient.getLastLocation": [],
        "com.google.android.gms.location.FusedLocationProviderClient.requestLocationUpdates": ["request", "callback", "looper"],

        "android.hardware.Camera.open": [],
        "android.hardware.Camera.setPreviewDisplay": ["holder"],
        "android.hardware.Camera.startPreview": [],
        "android.hardware.Camera.takePicture": ["shutter", "raw", "jpeg"],

        "android.hardware.camera2.CameraManager.getCameraIdList": [],
        "android.hardware.camera2.CameraManager.openCamera": ["cameraId", "callback", "handler"],

        "android.content.pm.PackageManager.getInstalledApplications": ["flags"],
        "android.content.pm.PackageManager.getInstalledPackages": ["flags"],
        "android.content.pm.PackageManager.getApplicationInfo": ["packageName", "flags"],
        "android.content.pm.PackageManager.checkPermission": ["permName", "pkgName"],

        "android.app.ActivityManager.getRunningAppProcesses": [],
        "android.app.ActivityManager.getRunningTasks": ["maxNum"],
        "android.app.ActivityManager.killBackgroundProcesses": ["packageName"],

        "android.app.NotificationManager.notify": ["id", "notification"],
        "android.app.NotificationManager.cancel": ["id"],
        "android.app.NotificationManager.areNotificationsEnabled": [],

        "java.security.KeyStore.getInstance": ["type"],
        "java.security.KeyStore.load": ["stream", "password"],
        "java.security.KeyStore.getKey": ["alias", "password"],
        "java.security.KeyStore.setKeyEntry": ["alias", "key", "password", "chain"],

        "android.net.ConnectivityManager.getActiveNetworkInfo": [],
        "android.net.ConnectivityManager.getAllNetworkInfo": [],
        "android.net.ConnectivityManager.registerNetworkCallback": ["request", "callback"],

        "android.net.wifi.WifiManager.getConnectionInfo": [],
        "android.net.wifi.WifiManager.getScanResults": [],
        "android.net.wifi.WifiManager.startScan": [],

        "java.lang.ProcessBuilder.start": [],
        "java.lang.ProcessBuilder.command": ["command"],

        "java.lang.Class.forName": ["className"],
        "java.lang.Class.getMethod": ["name", "parameterTypes"],
        "java.lang.Class.getDeclaredMethod": ["name", "parameterTypes"],

        "java.lang.reflect.Method.invoke": ["obj", "args"],
      };

      const names = argNames[fqMethodName] || [];

      args.forEach((arg, i) => {
        const label = names[i] || `arg[${i}]`;
        try {
          const argValue = arg ? arg.toString() : "null";
          console.log(`    ├─ ${label}: ${argValue}`);
          apiCallData.arguments.push({
            name: label,
            value: argValue,
            type: typeof arg
          });
        } catch (e) {
          console.log(`    ├─ ${label}: <unable to display>`);
          apiCallData.arguments.push({
            name: label,
            value: "<unable to display>",
            type: "unknown"
          });
        }
      });

      let retval;
      try {
        retval = overload.apply(this, args);
      } catch (err) {
        console.log(`    └─ Exception Thrown: ${err}`);
        apiCallData.exception = err.toString();
        // Send JSON data for exception
        send(apiCallData);
        throw err;
      }

      try {
        const retStr = (retval !== undefined && retval !== null) ? retval.toString() : "void";
        console.log(`    └─ Return: ${retStr}`);
        apiCallData.returnValue = retStr;
      } catch (e) {
        console.log(`    └─ Return: <unable to stringify>`);
        apiCallData.returnValue = "<unable to stringify>";
      }

      // Send JSON data using Frida's send function
      send(apiCallData);

      return retval;
    };
  } catch (err) {
    console.error(`[-] Failed to hook ${className}.${methodSignature}: ${err}`);
  }
}

function startHooking() {
  if (typeof Java === 'undefined') {
    console.log("[-] Java runtime not available yet, retrying in 500ms...");
    setTimeout(startHooking, 500);
    return;
  }

  Java.perform(() => {
    console.log("=== Starting API Monitoring ===");

    for (const category in apiConfig) {
      const classMap = apiConfig[category];
      console.log(`[*] Processing category: ${category}`);
      for (const className in classMap) {
        const methodList = classMap[className];
        methodList.forEach(methodSignature => {
          if (!methodSignature.includes("(")) return;
          hookMethod(className, methodSignature);
        });
      }
    }

    console.log("=== API Hooking Complete ===");
  });
}