let networkConfig = {};

function startNetworkMonitoring() {
  Java.perform(() => {

    let sessions = new Map();
    let sessionCounter = 0;
    let connectionTracker = new Map();
    let lastKnownURL = null;
    
    function sendNetworkData(data) {
      // Send structured network data via Frida's send mechanism
      send(data);
    }
    
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
          protocol: null,
          requestData: [],
          responseData: [],
          headers: {},
          timestamp: new Date().toISOString(),
          hasOutput: false,
          hasInput: false,
          totalRequestBytes: 0,
          totalResponseBytes: 0,
          responseCode: null,
          completed: false
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
          }
        }
      }
      return originalWrite.call(this, bytes);
    };
  } catch (e) {
    // Silent error handling
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
              // Silent data capture
              if (lastKnownURL) {
                // Associated with URL
              }
            }
          }
        } catch (e) {
          // Silent binary data capture
        }
      }
      
      return result;
    };
  } catch (e) {
    // Silent error handling
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
            
            // Check if this looks like the end of a JSON response
            if (line.includes('}') && (line.includes('"id"') || line.includes('"userId"') || line.includes('"title"'))) {
              session.completed = true;
              
              // Send structured JSON data
              const networkData = {
                type: "network_session",
                sessionId: session.id,
                timestamp: session.timestamp,
                url: session.url,
                host: session.host,
                port: session.port,
                path: session.path,
                protocol: session.protocol,
                method: session.method || (session.requestData.length > 0 ? 'POST' : 'GET'),
                requestData: session.requestData.join('\n'),
                responseData: session.responseData.join('\n'),
                headers: session.headers,
                totalRequestBytes: session.totalRequestBytes,
                totalResponseBytes: session.totalResponseBytes,
                responseCode: session.responseCode,
                completed: session.completed
              };
              
              sendNetworkData(networkData);
            }
          }
        }
      }
      
      return result;
    };
  } catch (e) {
    // Silent error handling
  }

  try {
    const InputStreamReader = Java.use("java.io.InputStreamReader");
    const originalRead = InputStreamReader.read.overload();
    
    originalRead.implementation = function() {
      const result = originalRead.call(this);
      
      if (result > 0) {
        // Silent character reading
      }
      
      return result;
    };
  } catch (e) {
    // Silent error handling
  }

  function hookMethod(className, methodSignature, category) {
    try {
      let targetClass;
      try {
        targetClass = Java.use(className);
      } catch (classError) {
        return;
      }

      const methodName = methodSignature.split('(')[0];
      const paramMatch = methodSignature.match(/\(([^)]*)\)/);
      const paramTypes = paramMatch && paramMatch[1] ? 
        paramMatch[1].split(',').map(p => p.trim()).filter(p => p.length > 0) : [];

      if (!targetClass[methodName]) {
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
          return;
        }
      }

      overload.implementation = function (...args) {
        let result;
        
        result = overload.apply(this, args);
        
        try {
          if (className === "java.net.URL" && methodName === "$init") {
            const urlString = args[0];
            
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
                
                // Send initial URL creation data
                const urlData = {
                  type: "url_created",
                  timestamp: lastKnownURL.timestamp,
                  url: urlString,
                  host: lastKnownURL.host,
                  port: lastKnownURL.port,
                  path: lastKnownURL.path,
                  protocol: protocol
                };
                
                sendNetworkData(urlData);
              }
            } catch (e) {
              // Silent error handling
            }
          }
          
          if (methodName === "connect" || methodName === "getOutputStream" || methodName === "getInputStream") {
            if (methodName === "getInputStream" && lastKnownURL) {
              // Silent response reading start
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
              // Silent response code capture
              if (lastKnownURL) {
                // Silent URL association
              }
            }
          }
          
        } catch (trackingError) {
          // Silent error handling
        }
        
        return result;
      };

    } catch (e) {
      // Silent error handling
    }
  }

  for (const [categoryName, category] of Object.entries(networkConfig.connections)) {
    category.forEach(methodSignature => {
      hookMethod(categoryName, methodSignature, getCategoryDisplayName(categoryName));
    });
  }

  for (const [className, methods] of Object.entries(networkConfig.additionalClasses)) {
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

  });
}
