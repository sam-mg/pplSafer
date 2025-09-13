import sys
import os
import json
from datetime import datetime, timezone
from androguard.core.apk import APK
from cryptography import x509
from loguru import logger

logger.remove()

def make_aware(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)

def analyze_apk_certs(apk_path: str):
    try:
        a = APK(apk_path)
        certs_info = []
        certs = a.get_certificates_der_v3()
        if not certs:
            certs_info.append({"error": "No certificates found"})
        else:
            for cert_data in certs:
                try:
                    cert = x509.load_der_x509_certificate(cert_data)
                    certs_info.append({
                        "issuer": cert.issuer.rfc4514_string(),
                        "subject": cert.subject.rfc4514_string(),
                        "serial_number": str(cert.serial_number),
                        "hash_algorithm": cert.signature_hash_algorithm.name,
                        "valid_from": make_aware(getattr(cert, "not_valid_before", None)).strftime('%Y-%m-%d %H:%M:%S UTC'),
                        "valid_until": make_aware(getattr(cert, "not_valid_after", None)).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    })
                except ValueError as e:
                    certs_info.append({"error": f"Failed to parse certificate due to an unexpected value error: {e}"})
                except Exception as e:
                    certs_info.append({"error": f"An unexpected error occurred while processing a certificate: {e}"})

        sig_versions = []
        if a.is_signed_v1(): sig_versions.append("v1")
        if a.is_signed_v2(): sig_versions.append("v2")
        if a.is_signed_v3(): sig_versions.append("v3")
        if hasattr(a, 'is_signed_v4') and a.is_signed_v4(): sig_versions.append("v4")

        return {"certificates": certs_info, "signature_schemes": sig_versions or ["None"]}
    except Exception as e:
        return {"error": f"An unexpected error occurred during APK analysis: {str(e)}"}

if __name__ == "__main__":
    apk_dir = "uploads/"

    apk_files = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]

    if not apk_files:
        print(f"No APK files found in {apk_dir}")
        sys.exit(1)

    apk_file = os.path.join(apk_dir, apk_files[0])
    filename = os.path.basename(apk_file)

    print("Running certificate and signature analysis...")
    certs_data = analyze_apk_certs(apk_file)
    
    save_path = "analysis/cert_and_sign_output.json"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    with open(save_path, "w") as f:
        json.dump(certs_data, f, indent=4)
    
    print(f"Completed certificate and signature analysis...")