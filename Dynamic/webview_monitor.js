// Aggressive WebView Content Monitor - Multiple hook points for maximum coverage
console.log("=== Aggressive WebView Content Monitor ===");
console.log(`=== Timestamp: ${new Date().toISOString()} ===`);

Java.perform(() => {
  // Selective SSL Bypass - Only bypass when needed, not for all connections
  console.log("[🔒] Initializing selective SSL bypass...");
  
  let sslBypassCount = 0;
  
  // Method 1: X509TrustManager bypass (only for specific error cases)
  try {
    const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    
    // Store original methods
    const originalCheckClientTrusted = X509TrustManager.checkClientTrusted;
    const originalCheckServerTrusted = X509TrustManager.checkServerTrusted;
    const originalGetAcceptedIssuers = X509TrustManager.getAcceptedIssuers;
    
    X509TrustManager.checkClientTrusted.implementation = function(chain, authType) {
      try {
        // Try the original method first
        return originalCheckClientTrusted.call(this, chain, authType);
      } catch (e) {
        // Only bypass if the original fails
        console.log("[🔓] SSL: X509TrustManager.checkClientTrusted bypassed due to error");
        return;
      }
    };
    
    X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
      try {
        // Try the original method first
        return originalCheckServerTrusted.call(this, chain, authType);
      } catch (e) {
        // Only bypass if the original fails
        console.log("[🔓] SSL: X509TrustManager.checkServerTrusted bypassed due to error");
        return;
      }
    };
    
    X509TrustManager.getAcceptedIssuers.implementation = function() {
      try {
        return originalGetAcceptedIssuers.call(this);
      } catch (e) {
        console.log("[🔓] SSL: X509TrustManager.getAcceptedIssuers bypassed due to error");
        return [];
      }
    };
    
    sslBypassCount++;
    console.log("[✓] SSL bypass method 1: X509TrustManager hooked (selective)");
  } catch (e) {
    console.log(`[!] SSL bypass method 1 failed: ${e.message}`);
  }

  // Method 2: HostnameVerifier bypass (only when verification fails)
  try {
    const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    const originalVerify = HostnameVerifier.verify;
    
    HostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
      try {
        // Try original verification first
        return originalVerify.call(this, hostname, session);
      } catch (e) {
        // Only bypass if original fails
        console.log(`[🔓] SSL: HostnameVerifier bypassed for ${hostname} due to error`);
        return true;
      }
    };
    
    sslBypassCount++;
    console.log("[✓] SSL bypass method 2: HostnameVerifier hooked (selective)");
  } catch (e) {
    console.log(`[!] SSL bypass method 2 failed: ${e.message}`);
  }

  // Method 3: WebView SSL error handler (only handle actual SSL errors)
  try {
    const WebViewClient = Java.use("android.webkit.WebViewClient");
    
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
      console.log("[🔓] SSL: WebViewClient SSL error intercepted - proceeding anyway");
      console.log(`[🔍] SSL Error details: ${error.toString()}`);
      handler.proceed();
    };
    
    sslBypassCount++;
    console.log("[✓] SSL bypass method 3: WebViewClient SSL error handler hooked");
  } catch (e) {
    console.log(`[!] SSL bypass method 3 failed: ${e.message}`);
  }

  // Remove the aggressive TrustManagerFactory hook that was breaking connections
  // Method 4: OkHttp3 CertificatePinner bypass (only if present)
  try {
    const CertificatePinner = Java.use("okhttp3.CertificatePinner");
    const originalCheck = CertificatePinner.check;
    
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
      try {
        return originalCheck.call(this, hostname, peerCertificates);
      } catch (e) {
        console.log(`[🔓] SSL: OkHttp3 CertificatePinner bypassed for ${hostname}`);
        return;
      }
    };
    
    sslBypassCount++;
    console.log("[✓] SSL bypass method 4: OkHttp3 CertificatePinner hooked (selective)");
  } catch (e) {
    console.log(`[!] SSL bypass method 4 failed (OkHttp3 not found): ${e.message}`);
  }

  // Method 5: Network Security Config bypass (if available)
  try {
    const NetworkSecurityPolicy = Java.use("android.security.net.config.NetworkSecurityPolicy");
    const originalGetInstance = NetworkSecurityPolicy.getInstance;
    
    NetworkSecurityPolicy.getInstance.implementation = function() {
      const policy = originalGetInstance.call(this);
      
      // Override isCleartextTrafficPermitted only when needed
      const originalIsCleartextTrafficPermitted = policy.isCleartextTrafficPermitted;
      policy.isCleartextTrafficPermitted.overload('java.lang.String').implementation = function(hostname) {
        try {
          return originalIsCleartextTrafficPermitted.call(this, hostname);
        } catch (e) {
          console.log(`[🔓] SSL: NetworkSecurityPolicy allowing cleartext for ${hostname}`);
          return true;
        }
      };
      
      return policy;
    };
    
    sslBypassCount++;
    console.log("[✓] SSL bypass method 5: NetworkSecurityPolicy hooked (selective)");
  } catch (e) {
    console.log(`[!] SSL bypass method 5 failed: ${e.message}`);
  }

  console.log(`[🔒] Selective SSL bypass complete: ${sslBypassCount}/5 methods successfully hooked`);
  
  if (sslBypassCount >= 2) {
    console.log("[✅] SSL bypass is active but non-intrusive - legitimate connections should work");
  } else if (sslBypassCount >= 1) {
    console.log("[⚠️] SSL bypass is minimal - some SSL errors may still occur");
  } else {
    console.log("[❌] SSL bypass failed - SSL errors will not be handled");
  }

  // Hook WebView.loadUrl
  try {
    const WebView = Java.use("android.webkit.WebView");
    const originalLoadUrl = WebView.loadUrl.overload('java.lang.String');
    originalLoadUrl.implementation = function(url) {
      console.log(`\n[🌐] WebView Loading: ${url}`);
      return originalLoadUrl.call(this, url);
    };
    console.log("[✓] WebView.loadUrl hooked");
  } catch (e) {
    console.log(`[!] WebView.loadUrl error: ${e.message}`);
  }

  // Hook WebViewClient.onPageFinished for reliable HTML extraction
  try {
    const WebViewClient = Java.use("android.webkit.WebViewClient");
    const originalOnPageFinished = WebViewClient.onPageFinished;
    originalOnPageFinished.implementation = function(view, url) {
      console.log(`\n[✅] Page finished loading: ${url}`);
      
      // Try to extract HTML content when page is fully loaded
      if (url && (url.includes('http://') || url.includes('https://')) && 
          !url.includes('.css') && !url.includes('.js') && !url.includes('.png') && 
          !url.includes('.jpg') && !url.includes('.gif') && !url.includes('.woff') &&
          !url.includes('.ico') && !url.includes('.svg') && !url.includes('.webp')) {
        
        console.log(`[🔍] Attempting to extract HTML for: ${url}`);
        
        // Multiple extraction attempts with different timings
        const extractHtml = (attempt) => {
          try {
            view.evaluateJavascript(`
              (function() {
                try {
                  console.log('FRIDA_DEBUG: Extraction attempt ${attempt} for ${url}');
                  console.log('FRIDA_DEBUG: Document ready state: ' + document.readyState);
                  
                  var html = '';
                  if (document.documentElement) {
                    html = document.documentElement.outerHTML;
                  } else if (document.body) {
                    html = document.body.outerHTML;
                  }
                  
                  console.log('FRIDA_DEBUG: HTML length: ' + html.length);
                  
                  if (html && html.length > 50) {
                    console.log('FRIDA_HTML_SUCCESS:' + html + ':FRIDA_HTML_SUCCESS_END');
                  } else {
                    console.log('FRIDA_DEBUG: HTML too short or empty, length: ' + html.length);
                    // Try alternative methods
                    var bodyText = document.body ? document.body.innerText : '';
                    var headContent = document.head ? document.head.innerHTML : '';
                    console.log('FRIDA_DEBUG: Body text length: ' + bodyText.length);
                    console.log('FRIDA_DEBUG: Head content length: ' + headContent.length);
                    
                    if (bodyText.length > 10 || headContent.length > 10) {
                      console.log('FRIDA_PARTIAL_CONTENT: Body: ' + bodyText.substring(0, 500) + ' | Head: ' + headContent.substring(0, 200));
                    }
                  }
                } catch(e) {
                  console.log('FRIDA_ERROR: HTML extraction failed - ' + e.message + ' - ' + e.stack);
                }
              })();
            `, null);
          } catch (e) {
            console.log(`[!] Extraction attempt ${attempt} failed: ${e.message}`);
          }
        };
        
        // Try extraction at different intervals
        setTimeout(() => extractHtml(1), 500);
        setTimeout(() => extractHtml(2), 1500);
        setTimeout(() => extractHtml(3), 3000);
      }
      
      return originalOnPageFinished.call(this, view, url);
    };
    console.log("[✓] WebViewClient.onPageFinished hooked");
  } catch (e) {
    console.log(`[!] Could not hook onPageFinished: ${e.message}`);
  }

  // Hook WebViewClient.shouldInterceptRequest - very simple version
  try {
    const WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.shouldInterceptRequest.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest').implementation = function(view, request) {
      try {
        const url = request.getUrl().toString();
        const method = request.getMethod();
        
        console.log(`\n[📤] ${method} ${url}`);
        
        // Get the response
        const response = this.shouldInterceptRequest(view, request);
        
        // For HTML pages, log detection only (extraction handled by onPageFinished)
        if ((url.includes('.html') || url.includes('.htm') || 
             (!url.includes('.css') && !url.includes('.js') && !url.includes('.png') && 
              !url.includes('.jpg') && !url.includes('.jpeg') && !url.includes('.gif') && 
              !url.includes('.woff') && !url.includes('.woff2') && !url.includes('.ttf') && 
              !url.includes('.svg') && !url.includes('.ico') && !url.includes('.webp') && 
              !url.includes('avatars.githubusercontent.com') && !url.includes('fonts.gstatic.com') &&
              !url.includes('fonts.googleapis.com'))) && 
            (url.includes('http://') || url.includes('https://'))) {
          console.log(`[📄] Potential HTML page: ${url}`);
        }
        
        return response;
      } catch (e) {
        console.log(`[!] Error in shouldInterceptRequest: ${e.message}`);
        return this.shouldInterceptRequest(view, request);
      }
    };
    console.log("[✓] WebViewClient.shouldInterceptRequest hooked");
  } catch (e) {
    console.log(`[!] Could not hook shouldInterceptRequest: ${e.message}`);
  }

  // Hook ALL InputStream.read operations with minimal filtering (safer version)
  try {
    const InputStream = Java.use("java.io.InputStream");
    const originalRead = InputStream.read.overload('[B', 'int', 'int');
    
    let streamCounter = 0;
    const seenContent = new Set();
    let htmlBuffer = "";
    
    originalRead.implementation = function(bytes, off, len) {
      const result = originalRead.call(this, bytes, off, len);
      
      if (result > 0) {
        try {
          const String = Java.use("java.lang.String");
          const content = String.$new(bytes, off, result, "UTF-8");
          const contentStr = content.toString();
          
          // Check for HTML content specifically
          if (contentStr.includes("<!DOCTYPE") || contentStr.includes("<html") || 
              contentStr.includes("<head>") || contentStr.includes("<body>")) {
            
            // This looks like HTML - accumulate it
            htmlBuffer += contentStr;
            
            // If we have a complete HTML document or a substantial chunk
            if (htmlBuffer.includes("</html>") || htmlBuffer.length > 2000) {
              const contentHash = htmlBuffer.substring(0, Math.min(100, htmlBuffer.length));
              if (!seenContent.has(contentHash)) {
                seenContent.add(contentHash);
                
                console.log(`\n${'='.repeat(80)}`);
                console.log(`[📄] HTML CONTENT CAPTURED (via InputStream)`);
                console.log(`${'='.repeat(80)}`);
                
                const truncated = htmlBuffer.length > 4000 ? htmlBuffer.substring(0, 4000) + "\n... [HTML truncated - showing first 4000 chars]" : htmlBuffer;
                console.log(truncated);
                console.log(`${'='.repeat(80)}\n`);
              }
              
              htmlBuffer = ""; // Reset buffer
            }
          } else {
            // Reset HTML buffer if we're not getting HTML content
            if (htmlBuffer.length > 0 && !contentStr.includes("<")) {
              htmlBuffer = "";
            }
            
            // Check for other web content
            if (contentStr.length > 30 && 
                (contentStr.includes("{") || contentStr.includes("function") || 
                 contentStr.includes("var ") || contentStr.includes("class") ||
                 contentStr.includes("HTTP") || contentStr.includes("Content-Type") ||
                 contentStr.includes("charset") || contentStr.includes("encoding"))) {
              
              const contentHash = contentStr.substring(0, Math.min(100, contentStr.length));
              if (!seenContent.has(contentHash)) {
                seenContent.add(contentHash);
                
                try {
                  console.log(`\n[📖] STREAM CONTENT #${++streamCounter} (${result} bytes):`);
                  console.log(`${'-'.repeat(50)}`);
                  
                  if (contentStr.includes("{") && (contentStr.includes('"') || contentStr.includes("'"))) {
                    console.log("[JSON/JS]");
                    const truncated = contentStr.length > 1000 ? contentStr.substring(0, 1000) + "\n... [truncated]" : contentStr;
                    console.log(truncated);
                  } else if (contentStr.includes("body{") || contentStr.includes(".class") || contentStr.includes("font-")) {
                    console.log("[CSS]");
                    const truncated = contentStr.length > 1000 ? contentStr.substring(0, 1000) + "\n... [truncated]" : contentStr;
                    console.log(truncated);
                  } else {
                    console.log("[OTHER]");
                    const truncated = contentStr.length > 800 ? contentStr.substring(0, 800) + "\n... [truncated]" : contentStr;
                    console.log(truncated);
                  }
                  
                  console.log(`${'-'.repeat(50)}\n`);
                } catch (printError) {
                  console.log(`[!] Error printing content: ${printError.message}`);
                }
              }
            }
          }
        } catch (e) {
          // Silently ignore encoding errors and other issues
        }
      }
      
      return result;
    };
    console.log("[✓] InputStream.read hooked (aggressive mode)");
  } catch (e) {
    console.log(`[!] InputStream hook error: ${e.message}`);
  }

  // Hook HttpURLConnection methods for direct HTTP capture with response reading
  try {
    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    
    if (HttpURLConnection.getInputStream) {
      const originalGetInputStream = HttpURLConnection.getInputStream;
      originalGetInputStream.implementation = function() {
        const inputStream = originalGetInputStream.call(this);
        
        try {
          const url = this.getURL().toString();
          const responseCode = this.getResponseCode();
          const contentType = this.getContentType();
          
          console.log(`\n[🔄] HTTP Response: ${responseCode} for ${url}`);
          console.log(`[📋] Content-Type: ${contentType || 'unknown'}`);
          
          // If this looks like HTML content, try to read it
          if ((url.includes('http://') || url.includes('https://')) && 
              (contentType && contentType.includes('text/html')) || 
              url.endsWith('/') || url.endsWith('.html') || url.endsWith('.htm')) {
            
            console.log(`[📖] Attempting to read HTTP response content for: ${url}`);
            
            // Create a wrapper to capture the content
            const BufferedReader = Java.use("java.io.BufferedReader");
            const InputStreamReader = Java.use("java.io.InputStreamReader");
            const StringBuilder = Java.use("java.lang.StringBuilder");
            
            try {
              const reader = BufferedReader.$new(InputStreamReader.$new(inputStream, "UTF-8"));
              const content = StringBuilder.$new();
              let line;
              let lineCount = 0;
              
              while ((line = reader.readLine()) !== null && lineCount < 100) { // Limit lines to prevent excessive output
                content.append(line).append("\n");
                lineCount++;
              }
              
              const htmlContent = content.toString();
              if (htmlContent.length > 50) {
                console.log(`\n${'='.repeat(80)}`);
                console.log(`[📄] HTTP RESPONSE CONTENT CAPTURED`);
                console.log(`[🌐] URL: ${url}`);
                console.log(`[📊] Response Code: ${responseCode}`);
                console.log(`${'='.repeat(80)}`);
                
                const truncated = htmlContent.length > 3000 ? htmlContent.substring(0, 3000) + "\n... [Content truncated - showing first 3000 chars]" : htmlContent;
                console.log(truncated);
                console.log(`${'='.repeat(80)}\n`);
              }
              
              reader.close();
            } catch (readError) {
              console.log(`[!] Error reading HTTP response: ${readError.message}`);
            }
          }
          
        } catch (e) {
          console.log(`[!] Error getting HTTP details: ${e.message}`);
        }
        
        return inputStream;
      };
      console.log("[✓] HttpURLConnection.getInputStream hooked");
    }
  } catch (e) {
    console.log(`[!] HttpURLConnection hook error: ${e.message}`);
  }

  // Hook WebChromeClient.onConsoleMessage to catch console output (enhanced version)
  try {
    const WebChromeClient = Java.use("android.webkit.WebChromeClient");
    const originalOnConsole = WebChromeClient.onConsoleMessage.overload('android.webkit.ConsoleMessage');
    originalOnConsole.implementation = function(consoleMessage) {
      try {
        const message = consoleMessage.message();
        
        // Check for our HTML content markers
        if (message && message.includes('FRIDA_HTML_SUCCESS:')) {
          const htmlMatch = message.match(/FRIDA_HTML_SUCCESS:(.*):FRIDA_HTML_SUCCESS_END/s);
          if (htmlMatch && htmlMatch[1]) {
            console.log(`\n${'='.repeat(80)}`);
            console.log(`[📄] HTML CONTENT CAPTURED SUCCESSFULLY`);
            console.log(`${'='.repeat(80)}`);
            
            const htmlContent = htmlMatch[1];
            const cleanHtml = htmlContent.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\'/g, "'");
            const truncated = cleanHtml.length > 4000 ? cleanHtml.substring(0, 4000) + "\n... [HTML truncated - showing first 4000 chars]" : cleanHtml;
            console.log(truncated);
            console.log(`${'='.repeat(80)}\n`);
          }
        }
        // Check for partial content
        else if (message && message.includes('FRIDA_PARTIAL_CONTENT:')) {
          console.log(`\n[�] PARTIAL CONTENT CAPTURED:`);
          console.log(`${'-'.repeat(50)}`);
          const content = message.replace('FRIDA_PARTIAL_CONTENT:', '');
          console.log(content);
          console.log(`${'-'.repeat(50)}\n`);
        }
        // Check for debug messages
        else if (message && message.includes('FRIDA_DEBUG:')) {
          const debugMsg = message.replace('FRIDA_DEBUG:', '');
          console.log(`[🐛] ${debugMsg}`);
        }
        // Check for errors
        else if (message && message.includes('FRIDA_ERROR:')) {
          console.log(`[!] HTML extraction error: ${message.replace('FRIDA_ERROR:', '')}`);
        }
        // Regular WebView console messages
        else if (message && !message.includes('FRIDA_')) {
          console.log(`[📱] WebView Console: ${message}`);
        }
      } catch (e) {
        console.log(`[!] Error in console message handler: ${e.message}`);
      }
      
      return originalOnConsole.call(this, consoleMessage);
    };
    console.log("[✓] WebChromeClient.onConsoleMessage hooked");
  } catch (e) {
    console.log(`[!] WebChromeClient hook error: ${e.message}`);
  }

  console.log("\n=== Aggressive WebView Monitor Ready ===");
  console.log("[*] Navigate to websites to capture ALL content");
  console.log("[*] HTML will be captured via stream monitoring");
  console.log("[*] All network requests and responses will be monitored");
});
