let networkConfig = {};

Java.perform(() => {
  console.log("=== Enhanced Connection API Monitoring Started ===");
  console.log(`=== Timestamp: ${new Date().toISOString()} ===`);
  console.log("=== Configuration loaded from network_config.json ===");

  let sessions = new Map();
  let sessionCounter = 0;
  let connectionTracker = new Map();
  let lastKnownURL = null;
  
  function getOrCreateSession(url) {
    if (!url) return null;
    
    if (!sessions.has(url)) {
      sessionCounter++;
      sessions.set(url, {
        id: sessionCounter,
        url: url,
        method: null,
        host: null,
        port: null,
        path: null,
        requestData: [],
        responseData: [],
        headers: {},
        timestamp: new Date().toISOString(),
        hasOutput: false,
        totalRequestBytes: 0,
        totalResponseBytes: 0
      });
    }
    
    return sessions.get(url);
  }

  try {
    const OutputStream = Java.use("java.io.OutputStream");
    const originalWrite = OutputStream.write.overload('[B');
    
    originalWrite.implementation = function(bytes) {
      try {
        const String = Java.use("java.lang.String");
        const content = String.$new(bytes, "UTF-8");
        if (content.length() > 0 && content.toString().trim().length > 0) {
          
          let targetURL = null;
          if (lastKnownURL) {
            targetURL = lastKnownURL.url;
          } else if (connectionTracker.size > 0) {
            const connections = Array.from(connectionTracker.values());
            const latestConnection = connections[connections.length - 1];
            targetURL = latestConnection.url;
          }
          
          if (targetURL) {
            const session = getOrCreateSession(targetURL);
            if (session) {
              if (lastKnownURL) {
                session.host = lastKnownURL.host;
                session.port = lastKnownURL.port;
                session.path = lastKnownURL.path;
              }
              
              session.requestData.push(content.toString());
              session.totalRequestBytes += content.length();
              session.hasOutput = true;
              
              console.log(`📤 Request Data Added to Session ${session.id}: ${content.length()} bytes`);
            }
          }
        }
      } catch (e) {
        let targetURL = null;
        if (lastKnownURL) {
          targetURL = lastKnownURL.url;
        } else if (connectionTracker.size > 0) {
          const connections = Array.from(connectionTracker.values());
          const latestConnection = connections[connections.length - 1];
          targetURL = latestConnection.url;
        }
        
        if (targetURL) {
          const session = getOrCreateSession(targetURL);
          if (session) {
            session.requestData.push(`[${bytes.length} bytes - binary data]`);
            session.totalRequestBytes += bytes.length;
            session.hasOutput = true;
            
            console.log(`📤 Request Data Added to Session ${session.id}: ${bytes.length} bytes (binary)`);
          }
        }
      }
      return originalWrite.call(this, bytes);
    };
  } catch (e) {
    console.log(`[-] Could not hook OutputStream.write: ${e.message}`);
  }

  try {
    const InputStream = Java.use("java.io.InputStream");
    const originalRead = InputStream.read.overload('[B');
    
    originalRead.implementation = function(bytes) {
      const result = originalRead.call(this, bytes);
      
      if (result > 0) {
        try {
          const String = Java.use("java.lang.String");
          const content = String.$new(bytes, 0, result, "UTF-8");
          const contentStr = content.toString();
          
          if (contentStr.length > 0 && contentStr.trim().length > 0) {
            if (contentStr.includes('{') || contentStr.includes('[') || contentStr.includes('HTTP/')) {
              console.log(`📥 Response Data Captured: ${result} bytes`);
              console.log(`📄 Response Content: ${contentStr}`);
              
              if (lastKnownURL) {
                console.log(`🔗 Associated with URL: ${lastKnownURL.url}`);
              }
            }
          }
        } catch (e) {
          console.log(`📥 Response Data Captured: ${result} bytes (binary)`);
        }
      }
      
      return result;
    };
  } catch (e) {
    console.log(`[-] Could not hook InputStream.read: ${e.message}`);
  }

  try {
    const BufferedReader = Java.use("java.io.BufferedReader");
    const originalReadLine = BufferedReader.readLine.overload();
    
    originalReadLine.implementation = function() {
      const result = originalReadLine.call(this);
      
      if (result && lastKnownURL) {
        const line = result.toString();
        
        if (line.includes('{') || line.includes('[') || line.includes('HTTP/') || 
            line.includes('"') || line.includes('}')) {
          
          const session = getOrCreateSession(lastKnownURL.url);
          if (session) {
            session.responseData.push(line);
            session.totalResponseBytes += line.length;
            session.hasInput = true;
            
            console.log(`📥 Response Data Added to Session ${session.id}: ${line.length} bytes`);
            
            // Check if this looks like the end of a JSON response
            if (line.includes('}') && (line.includes('"id"') || line.includes('"userId"') || line.includes('"title"'))) {
              console.log(`\n🔍 [COMPLETE NETWORK SESSION ${session.id} DETECTED]`);
              printNetworkSession(session);
            }
          }
        }
      }
      
      return result;
    };
  } catch (e) {
    console.log(`[-] Could not hook BufferedReader.readLine: ${e.message}`);
  }

  try {
    const InputStreamReader = Java.use("java.io.InputStreamReader");
    const originalRead = InputStreamReader.read.overload();
    
    originalRead.implementation = function() {
      const result = originalRead.call(this);
      
      if (result > 0) {
        console.log(`📚 [InputStreamReader] Character: ${String.fromCharCode(result)}`);
      }
      
      return result;
    };
  } catch (e) {
    console.log(`[-] Could not hook InputStreamReader.read: ${e.message}`);
  }

  function printNetworkSession(session) {
    let displayPort = session.port;
    if (!displayPort && session.url) {
      const urlMatch = session.url.match(/:(\d+)/);
      if (urlMatch) {
        displayPort = urlMatch[1];
      } else if (session.url.startsWith('https://')) {
        displayPort = '443';
      } else if (session.url.startsWith('http://')) {
        displayPort = '80';
      }
    }

    console.log(`\n╔══════════════════════════════════════════════════════════════════════════════════════╗`);
    console.log(`║                           🌐 NETWORK SESSION ${session.id} SUMMARY                           ║`);
    console.log(`╠══════════════════════════════════════════════════════════════════════════════════════╣`);
    console.log(`║ 🎯 Target: ${session.url || 'Unknown'}`);
    console.log(`║ 🌍 Host: ${session.host || 'Unknown'}:${displayPort || 'Unknown'}`);
    console.log(`║ 📍 Path: ${session.path || 'Unknown'}`);
    console.log(`║ 🔄 Method: ${session.method || (session.requestData.length > 0 ? 'POST (inferred from data)' : 'GET')}`);
    console.log(`║ ⏰ Time: ${session.timestamp}`);
    console.log(`║ 📊 Total Request Bytes: ${session.totalRequestBytes}`);
    console.log(`║ 📊 Total Response Bytes: ${session.totalResponseBytes}`);
    console.log(`╠══════════════════════════════════════════════════════════════════════════════════════╣`);
    
    if (session.requestData.length > 0) {
      console.log(`║ 📤 REQUEST DATA:`);
      session.requestData.forEach((data, index) => {
        if (data.trim()) {
          const lines = data.split('\n');
          lines.slice(0, 5).forEach(line => {
            if (line.trim()) {
              console.log(`║    [${index + 1}] ${line}`);
            }
          });
          if (lines.length > 5) {
            console.log(`║    [${index + 1}] ... (${lines.length - 5} more lines)`);
          }
        }
      });
    }
    
    if (session.responseData.length > 0) {
      if (session.requestData.length > 0) {
        console.log(`║`);
      }
      console.log(`║ 📥 RESPONSE DATA:`);
      session.responseData.forEach((line, index) => {
        if (line.trim()) {
          console.log(`║    [${index + 1}] ${line}`);
        }
      });
    }
    
    console.log(`╚══════════════════════════════════════════════════════════════════════════════════════╝\n`);
  }

  function printAllSessions() {
    if (sessions.size === 0) {
      console.log("\n📊 No network sessions captured yet.");
      return;
    }
    
    console.log(`\n📊 === CONSOLIDATED SESSION SUMMARY (${sessions.size} targets) ===`);
    for (const [url, session] of sessions) {
      if (session.hasOutput || session.hasInput) {
        printNetworkSession(session);
      }
    }
  }

  // Print sessions every 10 seconds to show accumulated data
  setInterval(() => {
    if (sessions.size > 0) {
      let hasActiveData = false;
      for (const [url, session] of sessions) {
        if (session.hasOutput || session.hasInput) {
          hasActiveData = true;
          break;
        }
      }
      if (hasActiveData) {
        printAllSessions();
      }
    }
  }, 10000);

  function hookMethod(className, methodSignature, category) {
    try {
      let targetClass;
      try {
        targetClass = Java.use(className);
      } catch (classError) {
        console.log(`[-] Class not found: ${className}`);
        return;
      }

      const methodName = methodSignature.split('(')[0];
      const paramMatch = methodSignature.match(/\(([^)]*)\)/);
      const paramTypes = paramMatch && paramMatch[1] ? 
        paramMatch[1].split(',').map(p => p.trim()).filter(p => p.length > 0) : [];

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
          overload = targetClass[methodName];
        } catch (fallbackError) {
          console.log(`[-] No suitable overload found for ${className}.${methodName}`);
          return;
        }
      }

      overload.implementation = function (...args) {
        let result;
        
        result = overload.apply(this, args);
        
        try {
          if (className === "java.net.URL" && methodName === "$init") {
            const urlString = args[0];
            console.log(`🔗 URL Created: ${urlString}`);
            
            lastKnownURL = {
              url: urlString,
              timestamp: new Date().toISOString()
            };
            
            try {
              const urlMatch = urlString.match(/^(https?):\/\/([^\/]+)(\/.*)?$/);
              if (urlMatch) {
                const protocol = urlMatch[1];
                const hostPart = urlMatch[2];
                const pathPart = urlMatch[3] || '/';
                
                const hostPortMatch = hostPart.match(/^([^:]+)(?::(\d+))?$/);
                if (hostPortMatch) {
                  lastKnownURL.host = hostPortMatch[1];
                  lastKnownURL.port = hostPortMatch[2] || (protocol === 'https' ? '443' : '80');
                }
                lastKnownURL.path = pathPart;
                lastKnownURL.protocol = protocol;
              }
            } catch (e) {
              console.log(`[!] Error parsing URL: ${e.message}`);
            }
          }
          
          if (methodName === "connect" || methodName === "getOutputStream" || methodName === "getInputStream") {
            if (methodName === "getInputStream" && lastKnownURL) {
              console.log(`📥 Starting to read response from: ${lastKnownURL.url}`);
            }
            
            try {
              if (this.getURL && typeof this.getURL === 'function') {
                const url = this.getURL();
                if (url) {
                  connectionTracker.set(this, {
                    url: url.toString(),
                    host: url.getHost() || 'Unknown',
                    port: url.getPort() !== -1 ? url.getPort() : (url.getProtocol() === 'https' ? 443 : 80),
                    path: url.getPath() || '/'
                  });
                }
              }
            } catch (urlRetrievalError) {
              // URL retrieval failed, but connection tracking is maintained
            }
          }
          
          if (className.includes("URLConnection") || className.includes("HttpURLConnection")) {
            if (methodName === "getResponseCode") {
              console.log(`📊 HTTP Response Code: ${result}`);
              if (lastKnownURL) {
                console.log(`🔗 For URL: ${lastKnownURL.url}`);
              }
            }
          }
          
        } catch (trackingError) {
          console.log(`[!] Error in tracking: ${trackingError.message}`);
        }
        
        return result;
      };

      console.log(`[✓] Hooked: ${className}.${methodName}`);
    } catch (e) {
      console.log(`[!] Failed to hook ${className}.${methodName}: ${e.message}`);
    }
  }

  console.log("");
  for (const [categoryName, category] of Object.entries(networkConfig.connections)) {
    console.log(`[*] Processing: ${getCategoryDisplayName(categoryName)}`);
    console.log(`    Class: ${categoryName}`);
    console.log(`    Methods: ${category.length}`);
    
    category.forEach(methodSignature => {
      hookMethod(categoryName, methodSignature, getCategoryDisplayName(categoryName));
    });
  }

  console.log("");
  console.log(`[*] Processing Additional Classes:`);
  for (const [className, methods] of Object.entries(networkConfig.additionalClasses)) {
    console.log(`    Class: ${className} (${methods.length} methods)`);
    methods.forEach(methodSignature => {
      hookMethod(className, methodSignature, "Additional Network Class");
    });
  }

  function getCategoryDisplayName(className) {
    const categoryNames = {
      "java.sql.Connection": "JDBC (Database Connections)",
      "java.net.HttpURLConnection": "HTTP Connections", 
      "java.net.URLConnection": "Android HTTP Client"
    };
    return categoryNames[className] || className;
  }

  console.log("\n=== Enhanced Connection API Hooking Complete ===");
  console.log("[*] Monitoring active - perform network actions in the app");
  console.log("[*] Detailed information will be captured for each connection\n");
});
