from flask import Blueprint, request, jsonify, render_template, send_from_directory, current_app
import os
import subprocess
import webbrowser
import threading

main = Blueprint('main', __name__)

status = {"step": "idle"}

def run_analysis_scripts():
    global status
    try:
        status["step"] = "Starting analysis..."

        status["step"] = "Calculating Hash and verifying with 3rd parties..."
        subprocess.run(["python", "analysis/apk_hash_checker.py"], check=True)

        status["step"] = "Calculating Hash of files inside the APK and verifying with 3rd parties..."
        subprocess.run(["python", "analysis/inner_hash_checker.py"], check=True)

        status["step"] = "Running ClamAV scan..."
        subprocess.run(["python", "analysis/clam.py"], check=True)

        status["step"] = "Checking APK URLs for malicious content..."
        subprocess.run(["python", "analysis/url_check.py"], check=True)

        status["step"] = "Verifying the Authenticity of Certificates..."
        subprocess.run(["python", "analysis/cert_and_sign.py"], check=True)

        status["step"] = "Static analysis running..."
        subprocess.run(["python", "analysis/rules.py"], check=True)

        status["step"] = "Machine Learning model testing in place..."
        subprocess.run(["python", "analysis/ml.py"], check=True)

        status["step"] = "Setting up for Dynamic analysis..."
        subprocess.run(["python", "analysis/dynamic/dynamic_setup.py"], check=True)

        status["step"] = "Monitoring API and Network Calls (unified)..."
        subprocess.run(["python", "analysis/dynamic/unified_monitor.py"], check=True)

        status["step"] = "Analysis Completed, viewing results..."

    except Exception as e:
        status["step"] = f"Analysis failed: {str(e)}"

@main.route("/")
def index():
    return render_template("main.html")

@main.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400

    file = request.files["file"]

    if file.filename == "" or not file.filename.endswith(".apk"):
        return jsonify({"status": "error", "message": "No file selected or invalid file type"}), 400

    if file and file.filename.endswith(".apk"):
        upload_dir = current_app.config['UPLOAD_FOLDER']
        for existing_file in os.listdir(upload_dir):
            if existing_file.endswith(".apk"):
                os.remove(os.path.join(upload_dir, existing_file))

        save_path = os.path.join(upload_dir, file.filename)
        file.save(save_path)

        global status
        status["step"] = "File uploaded ✅"

        thread = threading.Thread(target=run_analysis_scripts)
        thread.start()

        return jsonify({"status": "success", "message": f"File {file.filename} uploaded, analysis started"})

@main.route("/status")
def get_status():
    return jsonify(status)

@main.route("/api/results/<path:filename>")
def serve_result_data(filename):
    """Serve analysis result JSON files"""
    base_dir = os.path.dirname(os.path.dirname(__file__))
    analysis_dir = os.path.join(base_dir, 'analysis')
    config_dir = os.path.join(base_dir, 'config')
    
    file_path = os.path.join(analysis_dir, filename)
    if os.path.exists(file_path):
        rel_dir = os.path.dirname(filename)
        base_filename = os.path.basename(filename)
        if rel_dir:
            full_dir = os.path.join(analysis_dir, rel_dir)
        else:
            full_dir = analysis_dir
        return send_from_directory(full_dir, base_filename)
    
    file_path = os.path.join(config_dir, filename)
    if os.path.exists(file_path):
        return send_from_directory(config_dir, filename)
    
    return jsonify({"error": f"File not found: {filename}"}), 404