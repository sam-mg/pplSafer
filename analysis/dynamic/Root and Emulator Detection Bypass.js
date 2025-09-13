Java.perform(function(){
    try {
        var Root = Java.use("de.cyberkatze.iroot.IRoot");
        if (Root) {
            console.log("CyberKatze IRoot detected");
            Root.isDeviceRooted.overload().implementation = function(){
                return false;
            };
        } else {
            console.log("CyberKatze IRoot Not detected");
        }
    } catch (error) {
        console.error("An error occurred:", error);
    }
});
Java.perform(function(){
    try {
        var Root = Java.use("com.stericson.RootShell.RootShell");
        if (Root) {
            console.log("Stericson Root detected");
            Root.isRootAvailable.overload().implementation = function(){
                return false;
            };
        } else {
            console.log("Stericson Root not detected");
        }
    } catch (error) {
        console.error("An error occurred:", error);
    }
});
Java.perform(function(){
    try {
        var Root = Java.use("com.gantix.JailMonkey.Rooted");
        if (Root) {
            console.log("JailMonkey Root detected");
            Root.RootedCheck.overload().implementation = function(){
                return false;
            };
        }
    } catch (error) {
        console.error("An error occurred:", error);
    }
});
Java.perform(() => {
    try {
        const klass = Java.use("com.gantix.JailMonkey.JailMonkeyModule");
        const hashmap_klass = Java.use("java.util.HashMap");
        const false_obj = Java.use("java.lang.Boolean").FALSE.value;
        klass.getConstants.implementation = function () {
            var h = hashmap_klass.$new();
            h.put("isJailBroken", false_obj);
            h.put("hookDetected", false_obj);
            h.put("canMockLocation", false_obj);
            h.put("isOnExternalStorage", false_obj);
            h.put("AdbEnabled", false_obj);
            return h;
        };
    } catch (error) {
        console.error("An error occurred:", error);
    }
});
Java.perform(function(){
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        var Utils = Java.use("com.scottyab.rootbeer.util.Utils"); 
        if (RootBeer) {
            console.log("RootBeer Root detected");
            RootBeer.detectRootManagementApps.overload().implementation = function(){
                return false;
            };
            RootBeer.detectPotentiallyDangerousApps.overload().implementation = function(){
        return false;
    };
    RootBeer.detectTestKeys.overload().implementation = function(){
        return false;
    };
    RootBeer.checkForBusyBoxBinary.overload().implementation = function(){
        return false;
    };
    RootBeer.checkForSuBinary.overload().implementation = function(){
        return false;
    };
    RootBeer.checkSuExists.overload().implementation = function(){
        return false;
    };
    RootBeer.checkForRWPaths.overload().implementation = function(){
        return false;
    };
    RootBeer.checkForDangerousProps.overload().implementation = function(){
        return false;
    };
    RootBeer.checkForRootNative.overload().implementation = function(){
        return false;
    };
    RootBeer.detectRootCloakingApps.overload().implementation = function(){
        return false;
    };
    Utils.isSelinuxFlagInEnabled.overload().implementation = function(){
        return false;
    };
    RootBeer.checkForMagiskBinary.overload().implementation = function(){
        return false;
    };
            RootBeer.isRooted.overload().implementation = function(){
                return false;
            };
        } else {
            console.log("RootBeer Root not detected");
        }
    } catch (error) {
        console.error("An error occurred:", error);
    }
});
Java.perform(function() {
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ];
    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk", "frida-server", "frida-agent"];
    var EmulatorFiles = [
        "/dev/qemu_pipe",
        "/dev/socket/qemud",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props"
    ];
    var CustomProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1",
        "ro.kernel.qemu": "0",
        "ro.build.fingerprint": "samsung/starltexx/starlte:10/QP1A.190711.020/G960FXXSDFUG5:user/release-keys",
        "ro.product.brand": "samsung",
        "ro.product.manufacturer": "samsung",
        "ro.product.model": "SM-G960F",
        "ro.product.device": "starlte",
        "ro.hardware": "samsungexynos9810",
        "ro.product.name": "starltexx",
        "ro.serialno": "R28M30XXXX",
        "ro.build.tags": "release-keys",
        "ro.build.type": "user"
    };
    var CustomPropertiesKeys = [];
    for (var k in CustomProperties) CustomPropertiesKeys.push(k);
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    var Runtime = Java.use('java.lang.Runtime');
    var NativeFile = Java.use('java.io.File');
    var String = Java.use('java.lang.String');
    var SystemProperties = Java.use('android.os.SystemProperties');
    var BufferedReader = Java.use('java.io.BufferedReader');
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    var Secure = Java.use('android.provider.Settings$Secure');
    var Build = Java.use('android.os.Build');
    Build.DEVICE.value = "starlte";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    Build.MODEL.value = "SM-G960F";
    Build.HARDWARE.value = "samsungexynos9810";
    Build.PRODUCT.value = "starltexx";
    Build.FINGERPRINT.value = "samsung/starltexx/starlte:10/QP1A.190711.020/G960FXXSDFUG5:user/release-keys";
    Build.TAGS.value = "release-keys";
    Build.SERIAL.value = "R28M30XXXX";
    Build.SUPPORTED_ABIS.value = ["armeabi-v7a", "armeabi"];
    Build.CPU_ABI.value = "armeabi-v7a";
    Build.CPU_ABI2.value = "armeabi";
    TelephonyManager.getDeviceId.overload().implementation = function() {
        send("Bypass getDeviceId");
        return "359872070XXXXXX";
    };
    if (TelephonyManager.getImei) {
        TelephonyManager.getImei.overload().implementation = function() {
            send("Bypass getImei");
            return "359872070XXXXXX";
        };
    }
    TelephonyManager.getSubscriberId.overload().implementation = function() {
        send("Bypass getSubscriberId");
        return "310260000000000";
    };
    TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
        send("Bypass getNetworkOperatorName");
        return "T-Mobile";
    };
    TelephonyManager.getSimOperatorName.overload().implementation = function() {
        send("Bypass getSimOperatorName");
        return "T-Mobile";
    };
    TelephonyManager.getPhoneType.overload().implementation = function() {
        send("Bypass getPhoneType");
        return this.PHONE_TYPE_GSM.value;
    };
    TelephonyManager.getNetworkCountryIso.overload().implementation = function() {
        send("Bypass getNetworkCountryIso");
        return "us";
    };
    TelephonyManager.getSimCountryIso.overload().implementation = function() {
        send("Bypass getSimCountryIso");
        return "us";
    };
    Secure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(contentResolver, name) {
        if (name == Secure.ANDROID_ID.value) {
            send("Bypass getString ANDROID_ID");
            return "9774d56d682e549c";
        }
        return this.getString(contentResolver, name);
    };
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };
    NativeFile.exists.implementation = function() {
        var path = NativeFile.getAbsolutePath.call(this);
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1 || EmulatorFiles.indexOf(path) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for file: " + path);
            return false;
        } else {
            return this.exists.call(this);
        }
    };
    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');
    var suspiciousCommands = ["getprop", "mount", "build.prop", "id", "sh", "cat /proc/cpuinfo", "ifconfig", "ip addr"];
    function shouldBypassCommand(cmd) {
        for (var i = 0; i < suspiciousCommands.length; i++) {
            if (cmd.indexOf(suspiciousCommands[i]) != -1) {
                return true;
            }
        }
        return false;
    }
    exec1.implementation = function(cmd) {
        if (shouldBypassCommand(cmd)) {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "invalid_command";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };
    exec.overloads.forEach(function(overload) {
        overload.implementation = function() {
            var cmd = arguments[0];
            if (cmd instanceof Array) {
                for (var i = 0; i < cmd.length; i++) {
                    if (shouldBypassCommand(cmd[i])) {
                        var fakeCmd = ["grep"];
                        send("Bypass " + cmd.join(" ") + " command");
                        return exec.call(this, fakeCmd);
                    }
                    if (cmd[i] == "su") {
                        var fakeCmd = ["invalid_command"];
                        send("Bypass " + cmd.join(" ") + " command");
                        return exec.call(this, fakeCmd);
                    }
                }
            } else if (typeof cmd === 'string') {
                if (shouldBypassCommand(cmd)) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmd + " command");
                    return exec.call(this, fakeCmd);
                }
                if (cmd == "su") {
                    var fakeCmd = "invalid_command";
                    send("Bypass " + cmd + " command");
                    return exec.call(this, fakeCmd);
                }
            }
            return exec.apply(this, arguments);
        };
    });
    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };
    var get = SystemProperties.get.overload('java.lang.String');
    get.implementation = function(name) {
        if (CustomPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return CustomProperties[name];
        }
        return this.get.call(this, name);
    };
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            var shouldFakeReturn = (RootBinaries.indexOf(path) > -1 || EmulatorFiles.indexOf(path) > -1);
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("Bypass native fopen for " + path);
            }
        },
        onLeave: function(retval) {

        }
    });
    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (shouldBypassCommand(cmd)) {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "invalid_command");
            }
        },
        onLeave: function(retval) {

        }
    });
    BufferedReader.readLine.overload('boolean').implementation = function() {
        var text = this.readLine.overload('boolean').call(this);
        if (text === null) {
        } else {
            if (text.indexOf("ro.build.tags=test-keys") > -1) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
            var suspiciousWords = ["goldfish", "ranchu", "generic", "intel", "qemu"];
            for (var i = 0; i < suspiciousWords.length; i++) {
                if (text.indexOf(suspiciousWords[i]) > -1) {
                    send("Bypass emulator detection in file read");
                    text = "";
                    break;
                }
            }
        }
        return text;
    };
    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i++) {
            var tmp_cmd = cmd.get(i).toString();
            if (shouldBypassCommand(tmp_cmd)) {
                shouldModifyCommand = true;
                break;
            }
            if (tmp_cmd == "su") {
                shouldModifyCommand = true;
                break;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        return this.start.call(this);
    };
});
setTimeout(function() {
    Java.perform(function() {
        console.log("");
        console.log("[.] Cert Pinning Bypass/Re-Pinning");
        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var BufferedInputStream = Java.use("java.io.BufferedInputStream");
        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        var KeyStore = Java.use("java.security.KeyStore");
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        console.log("[+] Loading our CA...")
        var cf = CertificateFactory.getInstance("X.509");
        try {
            var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
        } catch (err) {
            console.log("[o] " + err);
        }
        var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
        var ca = cf.generateCertificate(bufferedInputStream);
        bufferedInputStream.close();
        var certInfo = Java.cast(ca, X509Certificate);
        console.log("[o] Our CA Info: " + certInfo.getSubjectDN());
        console.log("[+] Creating a KeyStore for our CA...");
        var keyStoreType = KeyStore.getDefaultType();
        var keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);
        console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
        var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);
        console.log("[+] Our TrustManager is ready...");
        console.log("[+] Hijacking SSLContext methods now...")
        console.log("[-] Waiting for the app to invoke SSLContext.init()...")
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a, b, c) {
            console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
            SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
            console.log("[+] SSLContext initialized with our custom TrustManager!");
        }
    });
}, 0);