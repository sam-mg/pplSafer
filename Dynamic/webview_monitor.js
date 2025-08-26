// Aggressive WebView Content Monitor - Multiple hook points for maximum coverage
console.log("=== Aggressive WebView Content Monitor ===");
console.log(`=== Timestamp: ${new Date().toISOString()} ===`);

Java.perform(() => {
  // Simple SSL bypass
  try {
    const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    
    X509TrustManager.checkClientTrusted.implementation = function() {};
    X509TrustManager.checkServerTrusted.implementation = function() {};
    X509TrustManager.getAcceptedIssuers.implementation = function() { return []; };
    
    HostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function() { return true; };
    
    console.log("[✓] SSL bypass active");
  } catch (e) {
    console.log(`[!] SSL bypass error: ${e.message}`);
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
        
        // Use a longer timeout and more defensive approach
        setTimeout(() => {
          try {
            const retainedView = Java.retain(view);
            
            setTimeout(() => {
              try {
                retainedView.evaluateJavascript(`
                  (function() {
                    try {
                      if (document.readyState === 'complete') {
                        var html = document.documentElement.outerHTML;
                        if (html && html.length > 200) {
                          console.log('FRIDA_HTML_FINISHED:' + html + ':FRIDA_HTML_FINISHED_END');
                        } else {
                          console.log('FRIDA_INFO: Page loaded but HTML content is minimal');
                        }
                      } else {
                        console.log('FRIDA_INFO: Document not ready yet');
                      }
                    } catch(e) {
                      console.log('FRIDA_ERROR: onPageFinished HTML extraction failed - ' + e.message);
                    }
                  })();
                `, null);
              } catch (e) {
                console.log(`[!] Could not extract HTML on page finished: ${e.message}`);
              } finally {
                Java.release(retainedView);
              }
            }, 500);
            
          } catch (e) {
            console.log(`[!] Could not retain view for HTML extraction: ${e.message}`);
          }
        }, 2000); // Longer delay to ensure page is fully rendered
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
          console.log(`[📄] Potential HTML page: ${url} - will extract when page finishes loading`);
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

  // Hook HttpURLConnection methods for direct HTTP capture
  try {
    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    
    if (HttpURLConnection.getInputStream) {
      const originalGetInputStream = HttpURLConnection.getInputStream;
      originalGetInputStream.implementation = function() {
        const inputStream = originalGetInputStream.call(this);
        
        try {
          const url = this.getURL().toString();
          const responseCode = this.getResponseCode();
          
          console.log(`\n[🔄] HTTP Response: ${responseCode} for ${url}`);
          
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

  // Hook WebChromeClient.onConsoleMessage to catch console output (safer version)
  try {
    const WebChromeClient = Java.use("android.webkit.WebChromeClient");
    const originalOnConsole = WebChromeClient.onConsoleMessage.overload('android.webkit.ConsoleMessage');
    originalOnConsole.implementation = function(consoleMessage) {
      try {
        const message = consoleMessage.message();
        
        // Check if this is our HTML content from shouldInterceptRequest
        if (message && message.includes('FRIDA_HTML_START:')) {
          const htmlMatch = message.match(/FRIDA_HTML_START:(.*):FRIDA_HTML_END/);
          if (htmlMatch && htmlMatch[1]) {
            console.log(`\n${'='.repeat(80)}`);
            console.log(`[📄] HTML CONTENT CAPTURED (during request)`);
            console.log(`${'='.repeat(80)}`);
            
            const htmlContent = htmlMatch[1];
            const cleanHtml = htmlContent.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\'/g, "'");
            const truncated = cleanHtml.length > 4000 ? cleanHtml.substring(0, 4000) + "\n... [HTML truncated - showing first 4000 chars]" : cleanHtml;
            console.log(truncated);
            console.log(`${'='.repeat(80)}\n`);
          }
        }
        // Check if this is our HTML content from onPageFinished
        else if (message && message.includes('FRIDA_HTML_FINISHED:')) {
          const htmlMatch = message.match(/FRIDA_HTML_FINISHED:(.*):FRIDA_HTML_FINISHED_END/);
          if (htmlMatch && htmlMatch[1]) {
            console.log(`\n${'='.repeat(80)}`);
            console.log(`[📄] HTML CONTENT CAPTURED (page finished)`);
            console.log(`${'='.repeat(80)}`);
            
            const htmlContent = htmlMatch[1];
            const cleanHtml = htmlContent.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\'/g, "'");
            const truncated = cleanHtml.length > 4000 ? cleanHtml.substring(0, 4000) + "\n... [HTML truncated - showing first 4000 chars]" : cleanHtml;
            console.log(truncated);
            console.log(`${'='.repeat(80)}\n`);
          }
        }
        else if (message && message.includes('FRIDA_ERROR:')) {
          console.log(`[!] HTML extraction error: ${message.replace('FRIDA_ERROR:', '')}`);
        }
        else if (message && message.includes('FRIDA_INFO:')) {
          console.log(`[ℹ️] ${message.replace('FRIDA_INFO:', '')}`);
        }
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
