document.addEventListener("DOMContentLoaded", async () => {
    try {
        const [outputResp, categoriesResp] = await Promise.all([
            fetch("/api/results/static_output.json", { cache: "no-store" }),
            fetch("/api/results/categories.json", { cache: "no-store" })
        ]);

        const [outputData, categoriesData] = await Promise.all([
            outputResp.json(),
            categoriesResp.json()
        ]);

        const generalTbody = document.getElementById("general-info-tbody");
        if (generalTbody) {
            generalTbody.innerHTML = `
                <tr><td>File</td><td>${outputData.file || "N/A"}</td></tr>
                <tr><td>Package Name</td><td>${outputData.package_name || "N/A"}</td></tr>
                <tr><td>MD5</td><td>${outputData.hashes?.md5 || "N/A"}</td></tr>
                <tr><td>SHA1</td><td>${outputData.hashes?.sha1 || "N/A"}</td></tr>
                <tr><td>SHA256</td><td>${outputData.hashes?.sha256 || "N/A"}</td></tr>
            `;
        }

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
            } else {
                console.error("Failed to load ml_output.json");
            }
        } catch (err) {
            console.error("Error loading ML Prediction data:", err);
        }


        const certTbody = document.getElementById("certificates-tbody");
        if (certTbody) {
            certTbody.innerHTML = "";
        
            const certs = outputData.certificates?.certificates || [];
            const sigSchemes = outputData.certificates?.signature_schemes || [];
        
            if (certs.length === 0 && sigSchemes.length === 0) {
                certTbody.innerHTML = `<tr><td colspan="2">No certificate data found</td></tr>`;
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
            
                certTbody.innerHTML += `
                    <tr><td>Signature Schemes</td><td>${sigSchemes.length > 0 ? sigSchemes.join(", ") : "N/A"}</td></tr>
                `;
            }
        }

        const vtTbody = document.getElementById("virustotal-tbody");
        if (vtTbody) {
            const vt = outputData.virus_total || {};
            vtTbody.innerHTML = `
                <tr><td>Status</td><td>${vt.status || "N/A"}</td></tr>
                <tr><td>Filename</td><td>${vt.filename || "N/A"}</td></tr>
                <tr><td>Hash</td><td>${vt.hash || "N/A"}</td></tr>
                <tr><td>Malicious Count</td><td>${vt.malicious_count ?? "N/A"}</td></tr>
                <tr><td>Total Engines</td><td>${vt.total_engines ?? "N/A"}</td></tr>
                <tr><td>Report URL</td>
                    <td>${vt.url ? `<a href="${vt.url}" target="_blank">${vt.url}</a>` : "N/A"}</td>
                </tr>
            `;
        }

        const clamavTbody = document.getElementById("clamav-tbody");
        if (clamavTbody) {
            const clamav = outputData.clamav || {};
            const details = clamav.details || {};
            
            let assessmentDisplay = clamav.assessment || "N/A";
            if (clamav.assessment === "CLEAN") {
                assessmentDisplay = `<span class="assessment-badge clean">${clamav.assessment}</span>`;
            } else if (clamav.assessment === "MALWARE_DETECTED") {
                assessmentDisplay = `<span class="assessment-badge malware">${clamav.assessment}</span>`;
            } else if (clamav.assessment === "ERROR") {
                assessmentDisplay = `<span class="assessment-badge error">${clamav.assessment}</span>`;
            }
            
            clamavTbody.innerHTML = `
                <tr><td>Status</td><td>${clamav.status || "N/A"}</td></tr>
                <tr><td>Assessment</td><td>${assessmentDisplay}</td></tr>
                <tr><td>Known Viruses</td><td>${details.known_viruses?.toLocaleString() || "N/A"}</td></tr>
                <tr><td>Engine Version</td><td>${details.engine_version || "N/A"}</td></tr>
                <tr><td>Scanned Files</td><td>${details.scanned_files || "N/A"}</td></tr>
                <tr><td>Infected Files</td><td>${details.infected_files || "N/A"}</td></tr>
                <tr><td>Data Scanned</td><td>${details.data_scanned || "N/A"}</td></tr>
                <tr><td>Scan Time</td><td>${details.scan_time || "N/A"}</td></tr>
            `;
            
            if (clamav.message && clamav.assessment === "ERROR") {
                clamavTbody.innerHTML += `
                    <tr><td>Error Message</td><td class="error-message">${clamav.message}</td></tr>
                `;
            }
        }

        const permTbody = document.getElementById("permissions-tbody");
        if (permTbody) {
            permTbody.innerHTML = "";

            const perms = outputData.rules_analysis?.permissions || [];
            if (perms.length === 0) {
                permTbody.innerHTML = `<tr><td colspan="1">No permissions found</td></tr>`;
            } else {
                perms.forEach(perm => {
                    const row = document.createElement("tr");
                    row.innerHTML = `<td>${perm}</td>`;
                    permTbody.appendChild(row);
                });
            }
        }

        const monitorSelect = document.getElementById("monitor-select");
        const monitorContainer = document.getElementById("monitor-table-container");

        monitorSelect.addEventListener("change", async function () {
            const file = monitorSelect.value;
            monitorContainer.innerHTML = "";

            if (!file) return;

            try {
                const response = await fetch(`/api/results/${file}`);
                if (!response.ok) {
                    monitorContainer.innerHTML = `<p class="error">Failed to load ${file}</p>`;
                    return;
                }

                const data = await response.json();

                if (!data || data.length === 0) {
                    monitorContainer.innerHTML = `<p class="error">No data found in ${file}</p>`;
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
                            cell.className = "expandable";
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
                monitorContainer.innerHTML = `<p class="error">Error loading ${file}: ${err.message}</p>`;
            }
        });

    } catch (err) {
        console.error("Error loading analysis data:", err);
    }
});
