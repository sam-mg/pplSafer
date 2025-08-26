// Enhanced connection monitoring script with detailed network analysis
const apiConfig = {
  "connections": [
    {
      "type": "JDBC (Database Connections)",
      "class": "java.sql.Connection",
      "methods": [
        "close()",
        "commit()",
        "rollback()",
        "createStatement()",
        "prepareStatement(java.lang.String)",
        "prepareStatement(java.lang.String, int)",
        "prepareStatement(java.lang.String, int, int)",
        "prepareCall(java.lang.String)",
        "prepareCall(java.lang.String, int, int)",
        "getMetaData()",
        "getAutoCommit()",
        "setAutoCommit()",
        "getWarnings()",
        "setTransactionIsolation()",
        "getTransactionIsolation()",
        "setTypeMap()",
        "getTypeMap()",
        "clearWarnings()",
        "isClosed()",
        "setSavepoint()",
        "releaseSavepoint()",
        "rollback(java.sql.Savepoint)",
        "prepareStatement(java.lang.String, int)",
        "prepareStatement(java.lang.String, [I)",
        "prepareStatement(java.lang.String, [Ljava.lang.String;)",
        "createBlob()",
        "createClob()",
        "isValid()"
      ]
    },
    {
      "type": "HTTP Connections",
      "class": "java.net.HttpURLConnection",
      "methods": [
        "connect()",
        "disconnect()",
        "getInputStream()",
        "getOutputStream()",
        "getResponseCode()",
        "getResponseMessage()",
        "getHeaderField(java.lang.String)",
        "getHeaderFieldKey(int)",
        "setRequestMethod(java.lang.String)",
        "setRequestProperty(java.lang.String, java.lang.String)",
        "setInstanceFollowRedirects(boolean)",
        "setFollowRedirects(boolean)",
        "setChunkedStreamingMode(int)",
        "setFixedLengthStreamingMode(int)",
        "setFixedLengthStreamingMode(long)",
        "getRequestMethod()",
        "getResponseCode()",
        "getResponseMessage()",
        "getHeaderField(java.lang.String)",
        "getHeaderFieldKey(int)",
        "getPermission()",
        "usingProxy()",
        "getErrorStream()",
        "getInstanceFollowRedirects()",
        "getFollowRedirects()"
      ]
    },
    {
      "type": "Android HTTP Client",
      "class": "java.net.URLConnection",
      "methods": [
        "connect()",
        "getInputStream()",
        "getOutputStream()",
        "setRequestProperty(java.lang.String, java.lang.String)",
        "getHeaderField(java.lang.String)",
        "setDoInput(boolean)",
        "setDoOutput(boolean)"
      ]
    }
  ]
};

// Global storage for connection details
let connectionDetails = new Map();
let connectionCounter = 0;

function getConnectionId(obj) {
  if (!obj._connectionId) {
    obj._connectionId = ++connectionCounter;
  }
  return obj._connectionId;
}

function extractUrlDetails(urlConnection) {
  try {
    const url = urlConnection.getURL();
    const protocol = url.getProtocol();
    const host = url.getHost();
    const port = url.getPort() === -1 ? (protocol === "https" ? 443 : 80) : url.getPort();
    const path = url.getPath();
    const query = url.getQuery();
    
    return {
      protocol: protocol,
      host: host,
      port: port,
      path: path,
      query: query,
      fullUrl: url.toString()
    };
  } catch (e) {
    return null;
  }
}

function readInputStream(inputStream, maxBytes = 8192) {
  try {
    const BufferedReader = Java.use("java.io.BufferedReader");
    const InputStreamReader = Java.use("java.io.InputStreamReader");
    const StringBuilder = Java.use("java.lang.StringBuilder");
    
    const reader = BufferedReader.$new(InputStreamReader.$new(inputStream));
    const sb = StringBuilder.$new();
    let line;
    let bytesRead = 0;
    
    while ((line = reader.readLine()) !== null && bytesRead < maxBytes) {
      sb.append(line).append("\n");
      bytesRead += line.length();
    }
    
    return sb.toString();
  } catch (e) {
    return `<Error reading stream: ${e.message}>`;
  }
}

function getResponseHeaders(urlConnection) {
  try {
    const headers = {};
    let i = 0;
    let key, value;
    
    while (true) {
      key = urlConnection.getHeaderFieldKey(i);
      value = urlConnection.getHeaderField(i);
      
      if (key === null && value === null) break;
      if (key === null) key = "Status-Line";
      
      headers[key] = value;
      i++;
    }
    
    return headers;
  } catch (e) {
    return {};
  }
}

function parseMethodSignature(signature) {
  const methodName = signature.split("(")[0];
  const paramString = signature.substring(signature.indexOf("(") + 1, signature.indexOf(")"));
  let paramTypes = [];
  
  if (paramString && paramString.trim() !== "") {
    paramTypes = paramString.split(",").map(p => p.trim()).filter(p => p !== "");
    // Convert common parameter types to Java internal representations
    paramTypes = paramTypes.map(type => {
      switch (type) {
        case "String": return "java.lang.String";
        case "int": return "int";
        case "long": return "long";
        case "boolean": return "boolean";
        case "Savepoint": return "java.sql.Savepoint";
        case "int[]": return "[I";
        case "String[]": return "[Ljava.lang.String;";
        case "[I": return "[I";
        case "[Ljava.lang.String;": return "[Ljava.lang.String;";
        default: return type;
      }
    });
  }
  
  return { methodName, paramTypes };
}

function hookMethod(className, methodSignature, connectionType) {
  try {
    const { methodName, paramTypes } = parseMethodSignature(methodSignature);
    
    // Try to get the class first
    let targetClass;
    try {
      targetClass = Java.use(className);
    } catch (classError) {
      console.log(`[-] Class not found: ${className} - ${classError.message}`);
      return;
    }

    if (!targetClass[methodName]) {
      console.log(`[-] Method not found: ${className}.${methodName}`);
      return;
    }

    let overload;
    try {
      if (paramTypes.length === 0) {
        overload = targetClass[methodName].overload();
      } else {
        overload = targetClass[methodName].overload(...paramTypes);
      }
    } catch (overloadError) {
      try {
        // Try without explicit overload specification
        overload = targetClass[methodName];
      } catch (fallbackError) {
        console.log(`[-] No suitable overload found for ${className}.${methodName}(${paramTypes.join(", ")})`);
        console.log(`    Available overloads: ${targetClass[methodName].overloads ? targetClass[methodName].overloads.map(o => o.argumentTypes.map(t => t.className).join(", ")).join(" | ") : "none"}`);
        return;
      }
    }

    overload.implementation = function (...args) {
      const timestamp = new Date().toISOString();
      const connId = getConnectionId(this);
      
      console.log(`\n[${'='.repeat(80)}]`);
      console.log(`[+] CONNECTION API CALLED [${timestamp}]`);
      console.log(`    Connection ID: #${connId}`);
      console.log(`    Type: ${connectionType}`);
      console.log(`    Class: ${className}`);
      console.log(`    Method: ${methodName}(${paramTypes.join(", ")})`);

      // Store connection details
      if (!connectionDetails.has(connId)) {
        connectionDetails.set(connId, {
          type: connectionType,
          className: className,
          requestMethod: null,
          headers: {},
          requestBody: null,
          responseCode: null,
          responseMessage: null,
          responseHeaders: {},
          responseBody: null,
          urlDetails: null
        });
      }
      const connDetail = connectionDetails.get(connId);

      // Extract URL details for HTTP connections
      if (className === "java.net.HttpURLConnection" || className === "java.net.URLConnection") {
        const urlDetails = extractUrlDetails(this);
        if (urlDetails) {
          connDetail.urlDetails = urlDetails;
          console.log(`    🌐 URL Details:`);
          console.log(`        Protocol: ${urlDetails.protocol}`);
          console.log(`        Host: ${urlDetails.host}`);
          console.log(`        Port: ${urlDetails.port}`);
          console.log(`        Path: ${urlDetails.path}`);
          if (urlDetails.query) {
            console.log(`        Query: ${urlDetails.query}`);
          }
          console.log(`        Full URL: ${urlDetails.fullUrl}`);
        }
      }

      // Handle method-specific logic
      if (methodName === "setRequestMethod" && args.length > 0) {
        connDetail.requestMethod = args[0];
        console.log(`    📤 HTTP Method Set: ${args[0]}`);
      }

      if (methodName === "setRequestProperty" && args.length >= 2) {
        connDetail.headers[args[0]] = args[1];
        console.log(`    📋 Header Set: ${args[0]} = ${args[1]}`);
      }

      // Display arguments
      const argNames = {
        "java.sql.Connection.setAutoCommit": ["autoCommit"],
        "java.sql.Connection.setTransactionIsolation": ["level"],
        "java.sql.Connection.prepareStatement": ["sql", "resultSetType", "resultSetConcurrency"],
        "java.sql.Connection.prepareCall": ["sql"],
        "java.sql.Connection.rollback": ["savepoint"],
        "java.sql.Connection.setSavepoint": ["name"],
        "java.sql.Connection.releaseSavepoint": ["savepoint"],
        "java.sql.Connection.setTypeMap": ["map"],
        "java.sql.Connection.isValid": ["timeout"],
        "java.net.HttpURLConnection.setRequestMethod": ["method"],
        "java.net.HttpURLConnection.setRequestProperty": ["key", "value"],
        "java.net.HttpURLConnection.setInstanceFollowRedirects": ["followRedirects"],
        "java.net.HttpURLConnection.setFollowRedirects": ["set"],
        "java.net.HttpURLConnection.setChunkedStreamingMode": ["chunklen"],
        "java.net.HttpURLConnection.setFixedLengthStreamingMode": ["contentLength"],
        "java.net.HttpURLConnection.getHeaderField": ["name"],
        "java.net.HttpURLConnection.getHeaderFieldKey": ["n"],
        "java.net.URLConnection.setRequestProperty": ["key", "value"],
        "java.net.URLConnection.getHeaderField": ["name"],
        "java.net.URLConnection.setDoInput": ["doInput"],
        "java.net.URLConnection.setDoOutput": ["doOutput"]
      };

      const fqMethodName = `${className}.${methodName}`;
      const names = argNames[fqMethodName] || [];

      if (args.length > 0) {
        console.log(`    📥 Arguments:`);
        args.forEach((arg, i) => {
          const label = names[i] || `arg[${i}]`;
          try {
            let displayValue = arg;
            if (arg === null) {
              displayValue = "null";
            } else if (arg === undefined) {
              displayValue = "undefined";
            } else if (typeof arg === "string") {
              displayValue = `"${arg}"`;
              // For SQL queries, show them prominently
              if (label === "sql") {
                console.log(`        🗃️  SQL Query: ${arg}`);
                return;
              }
            } else if (typeof arg === "object") {
              displayValue = `[Object: ${arg.getClass().getName()}]`;
            }
            console.log(`        ├─ ${label}: ${displayValue}`);
          } catch (e) {
            console.log(`        ├─ ${label}: <unable to display - ${e.message}>`);
          }
        });
      }

      // Call the original method
      let retval;
      try {
        retval = overload.apply(this, args);
      } catch (err) {
        console.log(`    ❌ Exception Thrown: ${err}`);
        throw err;
      }

      // Handle return values and responses
      if (methodName === "getResponseCode") {
        connDetail.responseCode = retval;
        console.log(`    📊 Response Code: ${retval}`);
      }

      if (methodName === "getResponseMessage") {
        connDetail.responseMessage = retval;
        console.log(`    📝 Response Message: ${retval}`);
      }

      if (methodName === "getInputStream") {
        try {
          // Clone the stream to read it without consuming it
          const responseHeaders = getResponseHeaders(this);
          connDetail.responseHeaders = responseHeaders;
          
          console.log(`    📨 Response Headers:`);
          Object.keys(responseHeaders).forEach(key => {
            console.log(`        ${key}: ${responseHeaders[key]}`);
          });

          // Try to read response (this might consume the stream)
          if (retval) {
            console.log(`    📄 Response Body: <InputStream available - use getInputStream() to read>`);
          }
        } catch (e) {
          console.log(`    📄 Response Body: <Error accessing: ${e.message}>`);
        }
      }

      if (methodName === "getOutputStream") {
        console.log(`    📤 Output Stream Available: Ready to write request body`);
      }

      if (methodName === "connect") {
        console.log(`    🔗 Connection Established`);
        if (connDetail.urlDetails) {
          console.log(`        Target: ${connDetail.urlDetails.host}:${connDetail.urlDetails.port}`);
        }
        if (connDetail.requestMethod) {
          console.log(`        Method: ${connDetail.requestMethod}`);
        }
        if (Object.keys(connDetail.headers).length > 0) {
          console.log(`        Request Headers:`);
          Object.keys(connDetail.headers).forEach(key => {
            console.log(`            ${key}: ${connDetail.headers[key]}`);
          });
        }
      }

      if (methodName === "disconnect") {
        console.log(`    🔌 Connection Closed`);
        // Print summary
        if (connDetail.urlDetails) {
          console.log(`    📊 Connection Summary:`);
          console.log(`        URL: ${connDetail.urlDetails.fullUrl}`);
          console.log(`        Method: ${connDetail.requestMethod || 'GET'}`);
          console.log(`        Response Code: ${connDetail.responseCode || 'N/A'}`);
          console.log(`        Response Message: ${connDetail.responseMessage || 'N/A'}`);
        }
      }

      // Display return value
      try {
        let retStr;
        if (retval === undefined || retval === null) {
          retStr = retval === null ? "null" : "void";
        } else if (typeof retval === "boolean" || typeof retval === "number") {
          retStr = retval.toString();
        } else if (typeof retval === "string") {
          retStr = `"${retval}"`;
        } else {
          retStr = `[Object: ${retval.getClass().getName()}]`;
        }
        console.log(`    ↩️  Return Value: ${retStr}`);
      } catch (e) {
        console.log(`    ↩️  Return Value: <unable to stringify - ${e.message}>`);
      }

      console.log(`[${'='.repeat(80)}]\n`);
      return retval;
    };

    console.log(`[✓] Hooked: ${className}.${methodName}`);
  } catch (err) {
    console.error(`[-] Failed to hook ${className}.${methodSignature}: ${err.message}`);
  }
}

// Additional hooks for network-related classes
function hookAdditionalNetworkClasses() {
  // Hook URL class for more details
  try {
    const URL = Java.use("java.net.URL");
    URL.$init.overload('java.lang.String').implementation = function(spec) {
      console.log(`\n[🌐] URL Created: ${spec}`);
      return this.$init(spec);
    };
  } catch (e) {
    console.log("[-] Could not hook URL constructor");
  }

  // Hook Socket connections
  try {
    const Socket = Java.use("java.net.Socket");
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
      console.log(`\n[🔌] Socket Connection: ${host}:${port}`);
      return this.$init(host, port);
    };
  } catch (e) {
    console.log("[-] Could not hook Socket constructor");
  }

  // Hook OutputStream.write for request body capture
  try {
    const OutputStream = Java.use("java.io.OutputStream");
    OutputStream.write.overload('[B').implementation = function(bytes) {
      try {
        const String = Java.use("java.lang.String");
        const content = String.$new(bytes);
        if (content.length() > 0 && content.length() < 2048) {
          console.log(`\n[📤] Request Body Written: ${content}`);
        } else if (content.length() >= 2048) {
          console.log(`\n[📤] Request Body Written: ${content.substring(0, 500)}... [${content.length()} bytes total]`);
        }
      } catch (e) {
        console.log(`\n[📤] Request Body Written: [${bytes.length} bytes - binary data]`);
      }
      return this.write(bytes);
    };
  } catch (e) {
    console.log("[-] Could not hook OutputStream.write");
  }
}

Java.perform(() => {
  console.log("=== Enhanced Connection API Monitoring Started ===");
  console.log(`=== Timestamp: ${new Date().toISOString()} ===`);
  console.log("=== Configuration loaded from connection_methods.json ===");

  // Hook additional network classes first
  hookAdditionalNetworkClasses();

  apiConfig.connections.forEach(connection => {
    const connectionType = connection.type;
    const className = connection.class;
    const methods = connection.methods;

    console.log(`\n[*] Processing: ${connectionType}`);
    console.log(`    Class: ${className}`);
    console.log(`    Methods: ${methods.length}`);

    methods.forEach(methodSignature => {
      if (!methodSignature.includes("(")) {
        console.log(`[!] Skipping invalid method signature: ${methodSignature}`);
        return;
      }
      hookMethod(className, methodSignature, connectionType);
    });
  });

  console.log("\n=== Enhanced Connection API Hooking Complete ===");
  console.log("[*] Monitoring active - perform network actions in the app");
  console.log("[*] Detailed information will be captured for each connection");
});