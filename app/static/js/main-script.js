// Tab switching functionality
function showTab(tabName) {
    // Hide all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        content.classList.remove('active');
    });

    // Remove active class from all nav tabs
    const navTabs = document.querySelectorAll('.nav-tab');
    navTabs.forEach(tab => {
        tab.classList.remove('active');
    });

    // Show selected tab content
    const selectedTab = document.getElementById(tabName);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Add active class to the correct nav tab
    const navTab = Array.from(document.querySelectorAll('.nav-tab')).find(tab => 
        tab.getAttribute('onclick') === `showTab('${tabName}')`
    );
    if (navTab) {
        navTab.classList.add('active');
    }

    // Stop results polling if switching away from results tab
    if (tabName !== 'results' && resultsPollingInterval) {
        clearInterval(resultsPollingInterval);
        resultsPollingInterval = null;
        console.log("Stopped results polling - switched to different tab");
    }

    // Load results data when results tab is clicked
    if (tabName === 'results') {
        loadResultsData();
    }
}

// Upload functionality
const fileInput = document.getElementById("fileInput");
const fileList = document.getElementById("fileList");
const emptyState = document.getElementById("emptyState");
const message = document.getElementById("message");
const uploadBtn = document.getElementById("uploadBtn");

let selectedFile = null;

// When a file is chosen
if (fileInput) {
    fileInput.addEventListener("change", () => {
        const file = fileInput.files[0];

        if (file) {
            selectedFile = file;
            renderFileList();
        }
    });
}

// Render file list with remove option
function renderFileList() {
    if (!fileList) return;
    
    fileList.innerHTML = "";

    if (!selectedFile) {
        if (emptyState) emptyState.style.display = "block";
        return;
    }

    if (emptyState) emptyState.style.display = "none";

    const fileItem = document.createElement("div");
    fileItem.className = "file-item";
    fileItem.innerHTML = `
        <div class="file-info">
            <div class="file-name">${selectedFile.name}</div>
            <div class="file-size">(${formatFileSize(selectedFile.size)})</div>
        </div>
        <button class="remove-btn" onclick="removeFile()">❌</button>
    `;

    fileList.appendChild(fileItem);
}

function removeFile() {
    selectedFile = null;
    if (fileInput) fileInput.value = "";
    renderFileList();
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Upload handler
async function uploadFiles() {
    if (!selectedFile) {
        showMessage("Please select a file first!", "error");
        return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
        showMessage("Uploading file...", "success");
        
        const response = await fetch("/upload", {
            method: "POST",
            body: formData,
        });

        const result = await response.json();
        showMessage(result.message, "success");
        
        // Start polling status and automatically switch to results when complete
        pollStatus();
        
    } catch (error) {
        showMessage("Upload failed.", "error");
    }
}

function showMessage(text, type) {
    if (!message) return;
    
    message.textContent = text;
    message.className = `message ${type}`;
    message.classList.remove('hidden');
}

function pollStatus() {
    const interval = setInterval(async () => {
        try {
            const res = await fetch("/status");
            const data = await res.json();

            showMessage(data.step, "success");

            if (data.step.includes("Completed")) {
                clearInterval(interval);
                showMessage("Analysis completed! Switching to results...", "success");
                // Auto-switch to results tab when analysis is complete
                setTimeout(() => {
                    showTab('results');
                }, 1500);
            } else if (data.step.includes("failed")) {
                clearInterval(interval);
                showMessage(data.step, "error");
            }
        } catch (error) {
            clearInterval(interval);
            showMessage("Error checking status", "error");
        }
    }, 2000);
}

// Upload button event listener
if (uploadBtn) {
    uploadBtn.addEventListener("click", uploadFiles);
}

// Results functionality
let resultsPollingInterval = null;

async function loadResultsData() {
    try {
        // Clear any existing polling interval
        if (resultsPollingInterval) {
            clearInterval(resultsPollingInterval);
            resultsPollingInterval = null;
        }

        // Load data from individual JSON files based on analysis order
        const hasAnyData = await loadAllAnalysisData();
        
        // If no data is available, start polling every 2 seconds
        if (!hasAnyData) {
            console.log("No analysis data found, starting polling...");
            resultsPollingInterval = setInterval(async () => {
                console.log("Polling for analysis data...");
                const dataFound = await loadAllAnalysisData();
                if (dataFound) {
                    console.log("Analysis data found, stopping polling");
                    clearInterval(resultsPollingInterval);
                    resultsPollingInterval = null;
                }
            }, 2000);
        }

        // Setup Monitor dropdown
        setupMonitorDropdown();

    } catch (err) {
        console.error("Error loading analysis data:", err);
    }
}

async function loadAllAnalysisData() {
    const results = await Promise.allSettled([
        loadGeneralInformation(),
        loadInnerHashResults(),
        loadClamAVResults(),
        loadURLCheckResults(),
        loadCertificateResults(),
        loadMLResults(),
        loadPermissionsData()
    ]);
    
    // Check if at least one analysis completed successfully
    return results.some(result => result.status === 'fulfilled' && result.value === true);
}

async function loadGeneralInformation() {
    try {
        const hashResp = await fetch("/api/results/apk_hash_checker_output.json", { cache: "no-store" });
        if (hashResp.ok) {
            const hashData = await hashResp.json();
            const generalTbody = document.getElementById("general-info-tbody");
            
            if (generalTbody) {
                generalTbody.innerHTML = `
                    <tr><td>File</td><td>${hashData.file || "N/A"}</td></tr>
                    <tr><td>Package Name</td><td>${hashData.package_name || "N/A"}</td></tr>
                    <tr><td>App Name</td><td>${hashData.app_name || "N/A"}</td></tr>
                    <tr><td>Version Name</td><td>${hashData.version_name || "N/A"}</td></tr>
                    <tr><td>Version Code</td><td>${hashData.version_code || "N/A"}</td></tr>
                    <tr><td>Min SDK</td><td>${hashData.min_sdk_version || "N/A"}</td></tr>
                    <tr><td>Target SDK</td><td>${hashData.target_sdk_version || "N/A"}</td></tr>
                    <tr><td>MD5</td><td>${hashData.hashes?.md5 || "N/A"}</td></tr>
                    <tr><td>SHA1</td><td>${hashData.hashes?.sha1 || "N/A"}</td></tr>
                    <tr><td>SHA256</td><td>${hashData.hashes?.sha256 || "N/A"}</td></tr>
                `;
            }

            // Load VirusTotal data from hash checker
            const vtTbody = document.getElementById("virustotal-tbody");
            if (vtTbody) {
                const vt = hashData.virus_total || {};
                vtTbody.innerHTML = `
                    <tr><td>Status</td><td>${vt.status || "N/A"}</td></tr>
                    <tr><td>Filename</td><td>${hashData.file || "N/A"}</td></tr>
                    <tr><td>Hash</td><td>${hashData.hashes?.sha256 || "N/A"}</td></tr>
                    <tr><td>Malicious Count</td><td>${vt.malicious_count ?? "N/A"}</td></tr>
                    <tr><td>Total Engines</td><td>${vt.total_engines ?? "N/A"}</td></tr>
                    <tr><td>Report URL</td>
                        <td>${vt.url ? `<a href="${vt.url}" target="_blank" style="color: #667eea; text-decoration: none;">${vt.url}</a>` : "N/A"}</td>
                    </tr>
                `;
            }
            return true; // Data found and loaded
        } else {
            const generalTbody = document.getElementById("general-info-tbody");
            if (generalTbody) {
                generalTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Analyzing APK file...</span></td></tr>`;
            }
            
            const vtTbody = document.getElementById("virustotal-tbody");
            if (vtTbody) {
                vtTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Checking with VirusTotal...</span></td></tr>`;
            }
            return false; // No data yet
        }
    } catch (err) {
        console.error("Error loading general information:", err);
        const generalTbody = document.getElementById("general-info-tbody");
        if (generalTbody) {
            generalTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Analyzing APK file...</span></td></tr>`;
        }
        
        const vtTbody = document.getElementById("virustotal-tbody");
        if (vtTbody) {
            vtTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Checking with VirusTotal...</span></td></tr>`;
        }
        return false; // No data yet
    }
}

async function loadInnerHashResults() {
    try {
        const innerHashResp = await fetch("/api/results/inner_hash_checker_output.json", { cache: "no-store" });
        if (innerHashResp.ok) {
            const innerHashData = await innerHashResp.json();
            const innerHashTbody = document.getElementById("inner-hash-tbody");
            const innerHashFilesTbody = document.getElementById("inner-hash-files-tbody");
            
            if (innerHashTbody && innerHashData) {
                const filesAnalyzed = innerHashData.files_analyzed || 0;
                const threatsFound = innerHashData.threats_found || 0;
                const status = threatsFound > 0 ? "THREATS DETECTED" : "CLEAN";
                
                innerHashTbody.innerHTML = `
                    <tr><td>Status</td><td>${status}</td></tr>
                    <tr><td>Files Analyzed</td><td>${filesAnalyzed}</td></tr>
                    <tr><td>Threats Detected</td><td>${threatsFound}</td></tr>
                `;
            }
            
            // Populate detailed files table
            if (innerHashFilesTbody && innerHashData.files_checked) {
                let filesHtml = '';
                
                innerHashData.files_checked.forEach(file => {
                    const virusTotalStatus = file.found_in_virustotal === 1 ? '<span style="color: red;">DETECTED</span>' : '<span style="color: green;">CLEAN</span>';
                    const csvStatus = file.found_in_csv === 1 ? '<span style="color: red;">DETECTED</span>' : '<span style="color: green;">CLEAN</span>';
                    
                    filesHtml += `
                        <tr>
                            <td title="${file.filename}">${file.filename.length > 50 ? file.filename.substring(0, 50) + '...' : file.filename}</td>
                            <td>${virusTotalStatus}</td>
                            <td>${csvStatus}</td>
                        </tr>
                    `;
                });
                
                innerHashFilesTbody.innerHTML = filesHtml;
            } else if (innerHashFilesTbody) {
                innerHashFilesTbody.innerHTML = '<tr><td colspan="3">No file data available</td></tr>';
            }
            return true; // Data found and loaded
        } else {
            // Handle case when JSON file is not available
            const innerHashTbody = document.getElementById("inner-hash-tbody");
            if (innerHashTbody) {
                innerHashTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Analyzing internal files...</span></td></tr>`;
            }
            
            const innerHashFilesTbody = document.getElementById("inner-hash-files-tbody");
            if (innerHashFilesTbody) {
                innerHashFilesTbody.innerHTML = '<tr><td colspan="3"><span style="color: #f59e0b;">⏳ Scanning internal files...</span></td></tr>';
            }
            return false; // No data yet
        }
    } catch (err) {
        console.error("Error loading inner hash results:", err);
        const innerHashTbody = document.getElementById("inner-hash-tbody");
        if (innerHashTbody) {
            innerHashTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Analyzing internal files...</span></td></tr>`;
        }
        
        const innerHashFilesTbody = document.getElementById("inner-hash-files-tbody");
        if (innerHashFilesTbody) {
            innerHashFilesTbody.innerHTML = '<tr><td colspan="3"><span style="color: #f59e0b;">⏳ Scanning internal files...</span></td></tr>';
        }
        return false; // No data yet
    }
}

async function loadClamAVResults() {
    try {
        const clamavResp = await fetch("/api/results/clamav_output.json", { cache: "no-store" });
        if (clamavResp.ok) {
            const clamavData = await clamavResp.json();
            const clamavTbody = document.getElementById("clamav-tbody");
            
            if (clamavTbody) {
                const details = clamavData.details || {};
                
                let assessmentDisplay = clamavData.assessment || "N/A";
                if (clamavData.assessment === "CLEAN") {
                    assessmentDisplay = `<span style="color: #10b981; font-weight: 600;">${clamavData.assessment}</span>`;
                } else if (clamavData.assessment === "MALWARE_DETECTED") {
                    assessmentDisplay = `<span style="color: #ef4444; font-weight: 600;">${clamavData.assessment}</span>`;
                }
                
                clamavTbody.innerHTML = `
                    <tr><td>Assessment</td><td>${assessmentDisplay}</td></tr>
                    <tr><td>Scan Date</td><td>${details.scan_date || "N/A"}</td></tr>
                    <tr><td>Scan Time</td><td>${details.scan_time || "N/A"}</td></tr>
                    <tr><td>Files Scanned</td><td>${details.files_scanned || "N/A"}</td></tr>
                    <tr><td>Infected Files</td><td>${details.infected_files || "N/A"}</td></tr>
                    <tr><td>Data Scanned</td><td>${details.data_scanned || "N/A"}</td></tr>
                    <tr><td>Time Taken</td><td>${details.time_taken || "N/A"}</td></tr>
                `;
            }
            return true; // Data found and loaded
        } else {
            const clamavTbody = document.getElementById("clamav-tbody");
            if (clamavTbody) {
                clamavTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Running ClamAV scan...</span></td></tr>`;
            }
            return false; // No data yet
        }
    } catch (err) {
        console.error("Error loading ClamAV results:", err);
        const clamavTbody = document.getElementById("clamav-tbody");
        if (clamavTbody) {
            clamavTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Running ClamAV scan...</span></td></tr>`;
        }
        return false; // No data yet
    }
}

async function loadURLCheckResults() {
    try {
        const urlResp = await fetch("/api/results/url_check_output.json", { cache: "no-store" });
        if (urlResp.ok) {
            const urlData = await urlResp.json();
            const urlTbody = document.getElementById("url-check-tbody");
            const urlDetailsTbody = document.getElementById("url-details-tbody");
            
            if (urlTbody && urlData) {
                const urlsAnalyzed = urlData.urls_analyzed || 0;
                const threatsFound = urlData.threats_found || 0;
                
                urlTbody.innerHTML = `
                    <tr><td>URLs Analyzed</td><td>${urlsAnalyzed}</td></tr>
                    <tr><td>Threats Found</td><td>${threatsFound}</td></tr>
                `;
            }
            
            // Populate detailed URL results table
            if (urlDetailsTbody && urlData.urls_checked) {
                urlDetailsTbody.innerHTML = "";
                
                if (urlData.urls_checked.length === 0) {
                    urlDetailsTbody.innerHTML = '<tr><td colspan="3">No URLs found in APK</td></tr>';
                } else {
                    urlData.urls_checked.forEach(urlResult => {
                        const row = document.createElement("tr");
                        
                        // Truncate long URLs for display
                        const displayUrl = urlResult.url.length > 80 ? 
                            urlResult.url.substring(0, 80) + '...' : 
                            urlResult.url;
                        
                        // Status indicators with colors
                        const urlhausStatus = urlResult.found_in_urlhaus === 1 ? 
                            '<span style="color: #ef4444; font-weight: 600;">DETECTED</span>' : 
                            '<span style="color: #10b981;">CLEAN</span>';
                        
                        const threatIntelStatus = urlResult.found_in_threat_intelligence === 1 ? 
                            '<span style="color: #ef4444; font-weight: 600;">DETECTED</span>' : 
                            '<span style="color: #10b981;">CLEAN</span>';
                        
                        row.innerHTML = `
                            <td title="${urlResult.url}" style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${displayUrl}</td>
                            <td>${urlhausStatus}</td>
                            <td>${threatIntelStatus}</td>
                        `;
                        
                        // Highlight malicious URLs
                        if (urlResult.found_in_urlhaus === 1 || urlResult.found_in_threat_intelligence === 1) {
                            row.style.backgroundColor = "#fef2f2";
                        }
                        
                        urlDetailsTbody.appendChild(row);
                    });
                }
            }
        } else {
            // Handle case when JSON file is not available
            const urlTbody = document.getElementById("url-check-tbody");
            if (urlTbody) {
                urlTbody.innerHTML = `<tr><td colspan="2">URL analysis not yet available</td></tr>`;
            }
            
            const urlDetailsTbody = document.getElementById("url-details-tbody");
            if (urlDetailsTbody) {
                urlDetailsTbody.innerHTML = `<tr><td colspan="3">Detailed URL results not yet available</td></tr>`;
            }
        }
    } catch (err) {
        console.error("Error loading URL check results:", err);
        const urlTbody = document.getElementById("url-check-tbody");
        if (urlTbody) {
            urlTbody.innerHTML = `<tr><td colspan="2">Error loading URL analysis</td></tr>`;
        }
        
        const urlDetailsTbody = document.getElementById("url-details-tbody");
        if (urlDetailsTbody) {
            urlDetailsTbody.innerHTML = `<tr><td colspan="3">Error loading detailed URL results</td></tr>`;
        }
    }
}

async function loadCertificateResults() {
    try {
        const certResp = await fetch("/api/results/cert_and_sign_output.json", { cache: "no-store" });
        if (certResp.ok) {
            const certData = await certResp.json();
            const certTbody = document.getElementById("certificates-tbody");
            
            if (certTbody && certData) {
                certTbody.innerHTML = `
                    <tr><td>Certificate Analysis</td><td>${certData.certificate_analysis || "N/A"}</td></tr>
                    <tr><td>Signature Analysis</td><td>${certData.signature_analysis || "N/A"}</td></tr>
                    <tr><td>Assessment</td><td>${certData.assessment || "N/A"}</td></tr>
                `;
            }
            return true; // Data found
        } else {
            const certTbody = document.getElementById("certificates-tbody");
            if (certTbody) {
                certTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Analyzing certificates...</span></td></tr>`;
            }
            return false; // No data yet
        }
    } catch (err) {
        const certTbody = document.getElementById("certificates-tbody");
        if (certTbody) {
            certTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Analyzing certificates...</span></td></tr>`;
        }
        return false; // No data yet
    }
}

async function populateCertificateTable(certData) {
    const certTbody = document.getElementById("certificates-tbody");
    
    if (certTbody) {
        certTbody.innerHTML = "";
        
        const certs = certData.certificates || [];
        const sigSchemes = certData.signature_schemes || [];
        
        if (certs.length === 0 || (certs.length === 1 && certs[0].error)) {
            certTbody.innerHTML = `<tr><td colspan="2">${certs[0]?.error || "No certificate data found"}</td></tr>`;
        } else {
            certs.forEach((cert, index) => {
                if (certs.length > 1) {
                    certTbody.innerHTML += `<tr><td colspan="2"><strong>Certificate ${index + 1}</strong></td></tr>`;
                }
                
                certTbody.innerHTML += `
                    <tr><td>Issuer</td><td>${cert.issuer || "N/A"}</td></tr>
                    <tr><td>Subject</td><td>${cert.subject || "N/A"}</td></tr>
                    <tr><td>Serial Number</td><td>${cert.serial_number || "N/A"}</td></tr>
                    <tr><td>Hash Algorithm</td><td>${cert.hash_algorithm || "N/A"}</td></tr>
                    <tr><td>Valid From</td><td>${cert.valid_from || "N/A"}</td></tr>
                    <tr><td>Valid Until</td><td>${cert.valid_until || "N/A"}</td></tr>
                `;
            });
        }
        
        certTbody.innerHTML += `
            <tr><td>Signature Schemes</td><td>${sigSchemes.length > 0 ? sigSchemes.join(", ") : "N/A"}</td></tr>
        `;
    }
}

async function loadMLResults() {
    try {
        const mlResp = await fetch("/api/results/ml_output.json", { cache: "no-store" });
        if (mlResp.ok) {
            const mlData = await mlResp.json();
            const mlTbody = document.getElementById("ml-prediction-tbody");
            
            if (mlTbody) {
                mlTbody.innerHTML = `
                    <tr><td>Prediction</td><td>${mlData.prediction || "N/A"}</td></tr>
                    <tr><td>Malware Probability (%)</td><td>${mlData.malware_probability_percent?.toFixed(2) || "N/A"}</td></tr>
                `;
            }
            return true; // Data found and loaded
        } else {
            // Handle case when JSON file is not available
            const mlTbody = document.getElementById("ml-prediction-tbody");
            if (mlTbody) {
                mlTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Running ML analysis...</span></td></tr>`;
            }
            return false; // No data yet
        }
    } catch (err) {
        console.error("Error loading ML Prediction data:", err);
        const mlTbody = document.getElementById("ml-prediction-tbody");
        if (mlTbody) {
            mlTbody.innerHTML = `<tr><td colspan="2"><span style="color: #f59e0b;">⏳ Running ML analysis...</span></td></tr>`;
        }
        return false; // No data yet
    }
}

async function loadPermissionsData() {
    try {
        const rulesResp = await fetch("/api/results/rules_output.json", { cache: "no-store" });
        if (rulesResp.ok) {
            const rulesData = await rulesResp.json();
            
            // Load permissions
            const permTbody = document.getElementById("permissions-tbody");
            if (permTbody && rulesData.rules_analysis?.permissions) {
                permTbody.innerHTML = "";
                rulesData.rules_analysis.permissions.forEach(permission => {
                    const row = document.createElement("tr");
                    row.innerHTML = `<td>${permission}</td>`;
                    permTbody.appendChild(row);
                });
            } else if (permTbody) {
                permTbody.innerHTML = '<tr><td>No permissions data available</td></tr>';
            }
            
            // Load rules analysis
            await loadRulesAnalysis(rulesData);
            
            // Load database analysis
            const dbTbody = document.getElementById("database-analysis-tbody");
            if (dbTbody && rulesData.rules_analysis?.database_files) {
                dbTbody.innerHTML = "";
                rulesData.rules_analysis.database_files.forEach(dbFile => {
                    const row = document.createElement("tr");
                    row.innerHTML = `<td>${dbFile}</td>`;
                    dbTbody.appendChild(row);
                });
            } else if (dbTbody) {
                dbTbody.innerHTML = '<tr><td>No database files found</td></tr>';
            }
            
            return true; // Data found
        } else {
            const permTbody = document.getElementById("permissions-tbody");
            if (permTbody) {
                permTbody.innerHTML = '<tr><td><span style="color: #f59e0b;">⏳ Analyzing permissions...</span></td></tr>';
            }
            
            const rulesTbody = document.getElementById("rules-analysis-tbody");
            if (rulesTbody) {
                rulesTbody.innerHTML = '<tr><td colspan="4"><span style="color: #f59e0b;">⏳ Running rules analysis...</span></td></tr>';
            }
            
            const dbTbody = document.getElementById("database-analysis-tbody");
            if (dbTbody) {
                dbTbody.innerHTML = '<tr><td><span style="color: #f59e0b;">⏳ Scanning for databases...</span></td></tr>';
            }
            
            return false; // No data yet
        }
    } catch (err) {
        console.error("Error loading permissions data:", err);
        const permTbody = document.getElementById("permissions-tbody");
        if (permTbody) {
            permTbody.innerHTML = '<tr><td><span style="color: #f59e0b;">⏳ Analyzing permissions...</span></td></tr>';
        }
        return false; // No data yet
    }
}

async function loadRulesAnalysis(rulesData) {
    try {
        const rulesBody = document.getElementById("rules-analysis-tbody");
        if (rulesBody && rulesData.rules_analysis?.rules) {
            rulesBody.innerHTML = "";
            const rules = rulesData.rules_analysis.rules;
            
            // Calculate summary statistics
            const totalRules = rules.length;
            const triggeredRules = rules.filter(rule => rule.score > 0).length;
            const riskScore = triggeredRules > 0 ? Math.round((triggeredRules / totalRules) * 100) : 0;
            
            // Add summary row
            const summaryRow = document.createElement("tr");
            summaryRow.style.backgroundColor = "#f8fafc";
            summaryRow.style.fontWeight = "600";
            summaryRow.innerHTML = `
                <td colspan="4">
                    <strong>Summary:</strong> ${triggeredRules}/${totalRules} rules triggered
                </td>
            `;
            rulesBody.appendChild(summaryRow);
            
            // Add individual rules
            rules.forEach(rule => {
                const row = document.createElement("tr");
                const status = rule.score > 0 ? 
                    '<span style="color: #ef4444; font-weight: 600;">TRIGGERED</span>' : 
                    '<span style="color: #10b981;">PASS</span>';
                
                row.innerHTML = `
                    <td>${rule.rule_id}</td>
                    <td>${rule.description}</td>
                    <td>${status}</td>
                    <td>${rule.score}</td>
                `;
                
                // Highlight triggered rules
                if (rule.score > 0) {
                    row.style.backgroundColor = "#fef2f2";
                }
                
                rulesBody.appendChild(row);
            });
        } else {
            // Handle case when rules data is not available
            const rulesBody = document.getElementById("rules-analysis-tbody");
            if (rulesBody) {
                rulesBody.innerHTML = `<tr><td colspan="4">Rules analysis data not available</td></tr>`;
            }
        }
    } catch (err) {
        console.error("Error loading rules analysis:", err);
        const rulesBody = document.getElementById("rules-analysis-tbody");
        if (rulesBody) {
            rulesBody.innerHTML = `<tr><td colspan="4">Error loading rules analysis</td></tr>`;
        }
    }
}

function setupMonitorDropdown() {
    const monitorSelect = document.getElementById("monitor-select");
    const monitorContainer = document.getElementById("monitor-table-container");

    if (!monitorSelect || !monitorContainer) return;

    monitorSelect.addEventListener("change", async function () {
        const file = monitorSelect.value;
        
        if (!file) {
            monitorContainer.innerHTML = `<p style="color: #6b7280; font-style: italic;">Select a monitor from the dropdown above to view dynamic analysis data</p>`;
            return;
        }

        // Show loading state
        monitorContainer.innerHTML = `<p style="color: #6b7280; font-style: italic;">Loading ${file.includes('api_monitor') ? 'API Monitor' : 'Network Monitor'} data...</p>`;

        try {
            const response = await fetch(`/api/results/${file}`);
            if (!response.ok) {
                if (response.status === 404) {
                    monitorContainer.innerHTML = `<p style="color: #f59e0b;">Dynamic analysis data not yet available. Please wait for the analysis to complete.</p>`;
                } else {
                    monitorContainer.innerHTML = `<p style="color: #ef4444;">Failed to load ${file.includes('api_monitor') ? 'API Monitor' : 'Network Monitor'} data (Status: ${response.status})</p>`;
                }
                return;
            }

            const data = await response.json();

            if (!data || data.length === 0) {
                monitorContainer.innerHTML = `<p style="color: #f59e0b;">No ${file.includes('api_monitor') ? 'API calls' : 'network activity'} detected during dynamic analysis</p>`;
                return;
            }

            const table = document.createElement("table");
            table.className = "info-table monitor-table";

            const headers = Object.keys(data[0] || {});
            const thead = document.createElement("thead");
            thead.innerHTML = `<tr>${headers.map(h => `<th>${h.toUpperCase()}</th>`).join("")}</tr>`;
            table.appendChild(thead);

            const tbody = document.createElement("tbody");
            data.forEach(entry => {
                const row = document.createElement("tr");
                headers.forEach(header => {
                    const cell = document.createElement("td");
                    const value = entry[header] ?? "";
                    
                    if (header.toLowerCase().includes('signature') || 
                        header.toLowerCase().includes('url') || 
                        header.toLowerCase().includes('arguments') ||
                        header.toLowerCase().includes('returnvalue')) {
                        cell.style.maxWidth = "200px";
                        cell.style.overflow = "hidden";
                        cell.style.textOverflow = "ellipsis";
                        cell.style.whiteSpace = "nowrap";
                        cell.title = value; // Show full value on hover
                    }
                    
                    if (typeof value === 'object') {
                        cell.textContent = JSON.stringify(value);
                    } else if (typeof value === 'string' && value.startsWith('http')) {
                        cell.innerHTML = `<a href="${value}" target="_blank" style="color: #667eea; text-decoration: none;">${value}</a>`;
                    } else {
                        cell.textContent = value;
                    }
                    
                    row.appendChild(cell);
                });
                tbody.appendChild(row);
            });

            table.appendChild(tbody);
            monitorContainer.appendChild(table);

        } catch (err) {
            console.error(`Error loading ${file}:`, err);
            monitorContainer.innerHTML = `<p style="color: #ef4444;">Error loading ${file.includes('api_monitor') ? 'API Monitor' : 'Network Monitor'} data: ${err.message}</p>`;
        }
    });
}

// Initialize the page - show upload tab by default
document.addEventListener("DOMContentLoaded", () => {
    showTab('upload');
});
