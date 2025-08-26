// Network configuration will be injected by the Python script
let networkConfig = {};

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
        case "Map": return "java.util.Map";
        case "SocketAddress": return "java.net.SocketAddress";
        default: return type;
      }
    });
  }
  
  return { methodName, paramTypes };
}

function getConnectionType(className) {
  if (className === "java.sql.Connection") return "JDBC Database Connection";
  if (className === "java.net.HttpURLConnection") return "HTTP Connection";
  if (className === "java.net.URLConnection") return "URL Connection";
  if (className === "java.net.Socket") return "Socket Connection";
  if (className === "java.net.URL") return "URL";
  if (className === "java.io.OutputStream") return "Output Stream";
  if (className === "java.io.InputStream") return "Input Stream";
  return "Network/Connection";
}

function hookMethod(className, methodSignature) {
  try {
    const { methodName, paramTypes } = parseMethodSignature(methodSignature);
    const connectionType = getConnectionType(className);
    
    // Try to get the class first
    let targetClass;
    try {
      targetClass = Java.use(className);
    } catch (classError) {
      console.log(`[-] Class not found: ${className} - ${classError.message}`);
      return;
    }

    const isConstructor = methodName === "$init";
    const overloadTarget = isConstructor ? targetClass.$init : targetClass[methodName];

    if (!overloadTarget) {
      console.log(`[-] Method not found: ${className}.${methodName}`);
      return;
    }

    let overload;
    try {
      if (paramTypes.length === 0) {
        overload = overloadTarget.overload();
      } else {
        overload = overloadTarget.overload(...paramTypes);
      }
    } catch (overloadError) {
      try {
        // Try without explicit overload specification
        overload = overloadTarget;
      } catch (fallbackError) {
        console.log(`[-] No suitable overload found for ${className}.${methodName}(${paramTypes.join(", ")})`);
        if (overloadTarget.overloads) {
          console.log(`    Available overloads: ${overloadTarget.overloads.map(o => o.argumentTypes.map(t => t.className).join(", ")).join(" | ")}`);
        }
        return;
      }
    }

    overload.implementation = function (...args) {
      const timestamp = new Date().toISOString();
      const connId = getConnectionId(this);
      
      console.log(`\n[${'='.repeat(80)}]`);
      console.log(`[+] NETWORK/CONNECTION API CALLED [${timestamp}]`);
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

      // Display arguments with proper labeling
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
        "java.net.URLConnection.setDoOutput": ["doOutput"],
        "java.net.URL.$init": ["spec"],
        "java.net.Socket.$init": ["host", "port"],
        "java.io.OutputStream.write": ["bytes"]
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
              // For URLs, show them prominently
              if (label === "spec" && className === "java.net.URL") {
                console.log(`        🌐 URL: ${arg}`);
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

      if (methodName === "disconnect" || methodName === "close") {
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

      // Handle special output stream writes
      if (methodName === "write" && className === "java.io.OutputStream") {
        try {
          if (args[0] && typeof args[0] === "object" && args[0].length !== undefined) {
            const String = Java.use("java.lang.String");
            const content = String.$new(args[0]);
            if (content.length() > 0 && content.length() < 2048) {
              console.log(`    📤 Request Body: ${content}`);
            } else if (content.length() >= 2048) {
              console.log(`    📤 Request Body: ${content.substring(0, 500)}... [${content.length()} bytes total]`);
            }
          } else {
            console.log(`    📤 Data Written: [${args[0]} - single byte or non-array data]`);
          }
        } catch (e) {
          console.log(`    📤 Data Written: [binary data - ${e.message}]`);
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

function startHooking() {
  console.log("=== Enhanced Network Connection API Monitoring Started ===");
  console.log(`=== Timestamp: ${new Date().toISOString()} ===`);
  
  // Hook main connection classes
  Object.keys(networkConfig.connections).forEach(className => {
    const methods = networkConfig.connections[className];
    console.log(`\n[*] Processing Connection Class: ${className}`);
    console.log(`    Methods: ${methods.length}`);

    methods.forEach(methodSignature => {
      if (!methodSignature.includes("(")) {
        console.log(`[!] Skipping invalid method signature: ${methodSignature}`);
        return;
      }
      hookMethod(className, methodSignature);
    });
  });

  // Hook additional network classes
  Object.keys(networkConfig.additionalClasses).forEach(className => {
    const methods = networkConfig.additionalClasses[className];
    console.log(`\n[*] Processing Additional Class: ${className}`);
    console.log(`    Methods: ${methods.length}`);

    methods.forEach(methodSignature => {
      if (!methodSignature.includes("(")) {
        console.log(`[!] Skipping invalid method signature: ${methodSignature}`);
        return;
      }
      hookMethod(className, methodSignature);
    });
  });

  console.log("\n=== Enhanced Network Connection API Hooking Complete ===");
  console.log("[*] Monitoring active - perform network actions in the app");
  console.log("[*] Detailed information will be captured for each connection");
}

Java.perform(() => {
});
