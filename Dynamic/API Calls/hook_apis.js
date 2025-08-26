// API configuration will be injected by the Python script
let apiConfig = {};

// Function to set the configuration (called from Python)
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
    const targetClass = Java.use(className);

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

        "android.content.Context.getExternalFilesDir": ["type"]
      };

      const fqMethodName = `${className}.${methodName}`;
      const names = argNames[fqMethodName] || [];

      args.forEach((arg, i) => {
        const label = names[i] || `arg[${i}]`;
        try {
          console.log(`    ├─ ${label}: ${arg}`);
        } catch (e) {
          console.log(`    ├─ ${label}: <unable to display>`);
        }
      });

      let retval;
      try {
        retval = overload.apply(this, args);
      } catch (err) {
        console.log(`    └─ Exception Thrown: ${err}`);
        throw err;
      }

      try {
        const retStr = (retval !== undefined && retval !== null) ? retval.toString() : "void";
        console.log(`    └─ Return: ${retStr}`);
      } catch (e) {
        console.log(`    └─ Return: <unable to stringify>`);
      }

      return retval;
    };
  } catch (err) {
    console.error(`[-] Failed to hook ${className}.${methodSignature}: ${err}`);
  }
}

function startHooking() {
  // Check if Java is available
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