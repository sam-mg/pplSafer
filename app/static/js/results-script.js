document.addEventListener("DOMContentLoaded", async () => {
    try {
        // Load JSON files
        const [outputResp, categoriesResp, mitreResp] = await Promise.all([
            fetch("/api/results/static_output.json", { cache: "no-store" }),
            fetch("/api/results/categories.json", { cache: "no-store" }),
            fetch("/api/results/mitre.json", { cache: "no-store" })
        ]);

        const [outputData, categoriesData, mitreData] = await Promise.all([
            outputResp.json(),
            categoriesResp.json(),
            mitreResp.json()
        ]);

        /* -------------------------------
           Fill General Information table
        ------------------------------- */
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

        /* -------------------------------
           Fill Certificates Table
        ------------------------------- */
        const certTbody = document.getElementById("certificates-tbody");
        if (certTbody) {
            certTbody.innerHTML = ""; // clear placeholder
        
            const certs = outputData.certificates?.certificates || [];
            const sigSchemes = outputData.certificates?.signature_schemes || [];
        
            if (certs.length === 0 && sigSchemes.length === 0) {
                certTbody.innerHTML = `<tr><td colspan="2">No certificate data found</td></tr>`;
            } else {
                certs.forEach((cert, index) => {
                    // Label certs if more than one
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
            
                // Signature schemes (after all certs)
                certTbody.innerHTML += `
                    <tr><td>Signature Schemes</td><td>${sigSchemes.length > 0 ? sigSchemes.join(", ") : "N/A"}</td></tr>
                `;
            }
        }



        /* -------------------------------
           Fill VirusTotal Report table
        ------------------------------- */
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

        /* -------------------------------
           Fill Permissions Analysis table
        ------------------------------- */
        const permTbody = document.getElementById("permissions-tbody");
        if (permTbody) {
            permTbody.innerHTML = ""; // clear placeholder
        
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


        /* -------------------------------
           Fill MITRE ATT&CK Mapping table
        ------------------------------- */
        const mitreTbody = document.getElementById("mitre-tbody");
        if (mitreTbody) {
            mitreTbody.innerHTML = ""; // clear old rows

            const matchedRules = (outputData.rules_analysis?.rules || [])
                .filter(rule => rule.score === 1);

            matchedRules.forEach(ruleObj => {
                const ruleId = ruleObj.rule_id;
                for (const [category, ruleIds] of Object.entries(categoriesData)) {
                    if (ruleIds.includes(ruleId)) {
                        const mitreCategory = Object.keys(mitreData).find(
                            c => c.toLowerCase() === category.toLowerCase()
                        );
                        if (!mitreCategory) continue;

                        const mitreEntries = mitreData[mitreCategory];
                        mitreEntries.forEach(entry => {
                            const externalRef = entry.external_references?.[0] || null;
                            const row = document.createElement("tr");
                            row.innerHTML = `
                                <td>${externalRef ? externalRef.external_id : "N/A"}</td>
                                <td>${entry.name || "N/A"}</td>
                                <td>${category}</td>
                                <td>
                                    ${externalRef ? `<a href="${externalRef.url}" target="_blank">Reference</a>` : "N/A"}<br>
                                    ${entry.description || ""}
                                </td>
                            `;
                            mitreTbody.appendChild(row);
                        });
                    }
                }
            });
        }

    } catch (err) {
        console.error("Error loading analysis data:", err);
    }
});
