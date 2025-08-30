import sys
import os
import hashlib
import json
import requests
from datetime import datetime, timezone
from loguru import logger
from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from cryptography import x509
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER

logger.remove()

API_KEY = "d6a812d25e432e3d11281ad21974cb62916a9a592ec4786f7557e93808b4b17e"
RULES_PATH = os.path.expanduser("~/rules_new.json")

def clean_method_name(name: str) -> str:
    if not name:
        return ""
    return name.split("(")[0] if "(" in name else name.strip()


def clean_class_name(name: str) -> str:
    return name.strip() if name else ""


def get_file_hash(filepath: str) -> str:
    """Calculate SHA256 hash of the file efficiently."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)  # FIXED bug
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"[ERROR] Failed to read or hash the file: {e}"


def make_aware(dt):
    """Ensure datetime is timezone-aware in UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


class VirusTotal:
    """Interact with VirusTotal API v3."""

    def __init__(self):
        self.headers = {"accept": "application/json", "X-Apikey": API_KEY}
        self.url = "https://www.virustotal.com/api/v3/"

    def check_hash_data(self, file_hash, filename):
        """Return a structured dictionary of VirusTotal result."""
        search_url = self.url + "files/" + file_hash
        try:
            response = requests.get(search_url, headers=self.headers)
            if response.status_code == 404:
                return {"status": "Not Found", "message": "Hash not found in VirusTotal's database."}
            if response.status_code in [401, 403]:
                return {"status": "Error", "message": "Authentication error with VirusTotal API."}
            if response.status_code != 200:
                return {"status": "Error", "message": f"VirusTotal API error (Status {response.status_code})."}

            result = response.json()
            attributes = result.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total_engines = sum(stats.values())

            if malicious > 0:
                status = "MALICIOUS"
            elif suspicious > 0:
                status = "SUSPICIOUS"
            else:
                status = "CLEAN"

            return {
                "status": status,
                "filename": filename,
                "hash": file_hash,
                "malicious_count": malicious,
                "total_engines": total_engines,
                "url": f"https://www.virustotal.com/gui/file/{file_hash}"
            }

        except Exception as e:
            return {"status": "Error", "message": f"Error querying VirusTotal: {e}"}


def analyze_rules(apk_path: str):
    if not os.path.exists(RULES_PATH):
        return {"permissions": [], "rules_matches": [{"description": "[!] Rules file not found."}]}

    with open(RULES_PATH, "r") as f:
        rules = json.load(f)

    a, d, dx = AnalyzeAPK(apk_path)
    apk_permissions = sorted([p.strip().lower() for p in a.get_permissions()])
    rule_matches = []

    for rule in rules:
        target_class = rule.get("target_class")
        target_methods = rule.get("target_methods", [])
        target_permission = rule.get("target_permission")
        description = rule.get("description", "")

        if not target_class:
            continue

        target_permissions = []
        if isinstance(target_permission, str):
            target_permissions = [target_permission.strip().lower()]
        elif isinstance(target_permission, list):
            target_permissions = [p.strip().lower() for p in target_permission]

        permission_match = any(p in apk_permissions for p in target_permissions)
        matched_methods = set()
        class_referenced = False

        if permission_match:
            for method in dx.get_methods():
                for _, call, _ in method.get_xref_to():
                    call_class = clean_class_name(str(call.class_name))
                    call_method = clean_method_name(str(call.name))
                    if call_class == target_class or call_class.strip("L;") == target_class.strip("L;"):
                        class_referenced = True
                        if call_method in target_methods:
                            matched_methods.add(call_method)

        if permission_match and class_referenced and matched_methods:
            rule_matches.append({
                "description": description,
                "permissions_matched": list(set(target_permissions) & set(apk_permissions)),
                "class_referenced": target_class,
                "methods_used": sorted(list(matched_methods))
            })

    return {"permissions": apk_permissions, "rules_matches": rule_matches}


def analyze_apk_certs(apk_path: str):
    try:
        a = APK(apk_path)
        certs_info = []

        certs = a.get_certificates_der_v3()
        if not certs:
            certs_info.append({"error": "No certificates found. APK may be unsigned."})
        else:
            for cert_data in certs:
                cert = x509.load_der_x509_certificate(cert_data)
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                serial = cert.serial_number
                hash_algo = cert.signature_hash_algorithm.name
                valid_from = make_aware(getattr(cert, "not_valid_before", None))
                valid_until = make_aware(getattr(cert, "not_valid_after", None))
                now_utc = datetime.now(timezone.utc)

                status = "Unknown"
                if valid_from and valid_until:
                    if now_utc < valid_from:
                        status = "Not yet valid"
                    elif now_utc > valid_until:
                        status = "Expired"
                    else:
                        status = "Valid"

                certs_info.append({
                    "issuer": issuer,
                    "subject": subject,
                    "serial_number": serial,
                    "hash_algorithm": hash_algo,
                    "valid_from": valid_from.strftime('%Y-%m-%d %H:%M:%S UTC') if valid_from else "N/A",
                    "valid_until": valid_until.strftime('%Y-%m-%d %H:%M:%S UTC') if valid_until else "N/A",
                    "status": status
                })

        sig_versions = []
        if a.is_signed_v1():
            sig_versions.append("v1 (JAR signing)")
        if a.is_signed_v2():
            sig_versions.append("v2 (Full APK Signature)")
        if a.is_signed_v3():
            sig_versions.append("v3 (Key Rotation)")
        if hasattr(a, 'is_signed_v4') and a.is_signed_v4():
            sig_versions.append("v4 (FSVerity)")

        return {"certificates": certs_info, "signature_schemes": sig_versions if sig_versions else ["None Found"]}

    except Exception as e:
        return {"error": f"Error analyzing certificates: {e}"}


def save_to_pdf(vt_data, rules_data, certs_data, apk_path):
    report_name = os.path.splitext(os.path.basename(apk_path))[0] + "_analysis.pdf"
    doc = SimpleDocTemplate(report_name, pagesize=A4, rightMargin=inch, leftMargin=inch, topMargin=inch, bottomMargin=inch)
    styles = getSampleStyleSheet()


    styles.add(ParagraphStyle(name='ReportTitle', alignment=TA_CENTER, fontSize=24, spaceAfter=24, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SectionHeading', fontSize=18, spaceBefore=18, spaceAfter=12, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SubHeading', fontSize=14, spaceBefore=12, spaceAfter=8, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='BodyTextSmall', fontSize=10, leading=14))
    styles.add(ParagraphStyle(name='ListItemSmall', fontSize=10, leading=14, leftIndent=24))

    story = []

    story.append(Paragraph("Static Analysis Report", styles['ReportTitle']))
    story.append(Paragraph(f"Application: {os.path.basename(apk_path)}", styles['SectionHeading']))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['BodyTextSmall']))
    story.append(Spacer(1, 12))
    story.append(PageBreak())

    story.append(Paragraph("1. VirusTotal Analysis", styles['SectionHeading']))
    if vt_data.get("status") in ["Error", "Not Found"]:
        story.append(Paragraph(vt_data.get("message", "Error"), styles['BodyTextSmall']))
    else:
        story.append(Paragraph(f"<b>APK Name:</b> {vt_data['filename']}", styles['BodyTextSmall']))
        story.append(Paragraph(f"<b>SHA256 Hash:</b> {vt_data['hash']}", styles['BodyTextSmall']))
        story.append(Paragraph(f"<b>VirusTotal Status:</b> {vt_data['status']}", styles['BodyTextSmall']))
        story.append(Paragraph(f"<b>Detection Ratio:</b> {vt_data['malicious_count']} / {vt_data['total_engines']}", styles['BodyTextSmall']))
        story.append(Paragraph(f"<b>Full Report URL:</b> <a href='{vt_data['url']}'>{vt_data['url']}</a>", styles['BodyTextSmall']))
    story.append(Spacer(1, 12))


    story.append(Paragraph("2. Rule-Based Analysis", styles['SectionHeading']))
    if rules_data.get("rules_matches"):
        for match in rules_data['rules_matches']:
            story.append(Paragraph(f"<b>Description:</b> {match.get('description', 'N/A')}", styles['BodyTextSmall']))
            story.append(Paragraph(f"<b>Permissions Matched:</b> {', '.join(match.get('permissions_matched', ['N/A']))}", styles['ListItemSmall']))
            story.append(Paragraph(f"<b>Class Referenced:</b> {match.get('class_referenced', 'N/A')}", styles['ListItemSmall']))
            story.append(Paragraph(f"<b>Methods Used:</b> {', '.join(match.get('methods_used', ['N/A']))}", styles['ListItemSmall']))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No specific malicious patterns found based on the provided rules.", styles['BodyTextSmall']))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Permissions Declared in Manifest:", styles['SubHeading']))
    if rules_data.get("permissions"):
        story.append(Paragraph(", ".join(rules_data["permissions"]), styles['BodyTextSmall']))
    else:
        story.append(Paragraph("No permissions found.", styles['BodyTextSmall']))
    story.append(PageBreak())

    story.append(Paragraph("3. Certificate and Signature Analysis", styles['SectionHeading']))
    if certs_data.get("error"):
        story.append(Paragraph(certs_data["error"], styles['BodyTextSmall']))
    else:
        story.append(Paragraph("<b>Signature Schemes:</b>", styles['SubHeading']))
        story.append(Paragraph(", ".join(certs_data['signature_schemes']), styles['BodyTextSmall']))
        story.append(Spacer(1, 12))
        story.append(Paragraph("<b>Certificate Information:</b>", styles['SubHeading']))
        for cert_info in certs_data.get('certificates', []):
            story.append(Paragraph(f"<b>Issuer:</b> {cert_info.get('issuer', 'N/A')}", styles['BodyTextSmall']))
            story.append(Paragraph(f"<b>Subject:</b> {cert_info.get('subject', 'N/A')}", styles['BodyTextSmall']))
            story.append(Paragraph(f"<b>Serial Number:</b> {cert_info.get('serial_number', 'N/A')}", styles['BodyTextSmall']))
            story.append(Paragraph(f"<b>Hash Algorithm:</b> {cert_info.get('hash_algorithm', 'N/A')}", styles['BodyTextSmall']))
            story.append(Paragraph(f"<b>Valid From:</b> {cert_info.get('valid_from', 'N/A')}", styles['BodyTextSmall']))
            story.append(Paragraph(f"<b>Valid Until:</b> {cert_info.get('valid_until', 'N/A')}", styles['BodyTextSmall']))
            story.append(Paragraph(f"<b>Status:</b> {cert_info.get('status', 'N/A')}", styles['BodyTextSmall']))
            story.append(Spacer(1, 12))

    doc.build(story)
    print(f"[+] Report saved as {report_name}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path_to_apk>")
        sys.exit(1)

    apk_file = sys.argv[1]
    filename = os.path.basename(apk_file)

    print("[+] Running VirusTotal hash check...")
    file_hash = get_file_hash(apk_file)
    vt_data = {}
    if file_hash and not file_hash.startswith("[ERROR]"):
        vt = VirusTotal()
        vt_data = vt.check_hash_data(file_hash, filename)
    else:
        vt_data = {"status": "Error", "message": "Failed to calculate file hash."}

    print("[+] Running rule-based analysis...")
    rules_data = analyze_rules(apk_file)

    print("[+] Running certificate and signature analysis...")
    certs_data = analyze_apk_certs(apk_file)

    save_to_pdf(vt_data, rules_data, certs_data, apk_file)
