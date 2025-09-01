from flask import Blueprint, request, jsonify, render_template, send_from_directory, current_app
import os
import subprocess
import webbrowser

main = Blueprint('main', __name__)

@main.route("/")
def index():
    return render_template("index.html")

@main.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400

    file = request.files["file"]

    if file.filename == "" or not file.filename.endswith(".apk"):
        return jsonify({"status": "error", "message": "No file selected or invalid file type"}), 400

    if file and file.filename.endswith(".apk"):
        # Clear existing APKs
        upload_dir = current_app.config['UPLOAD_FOLDER']
        for existing_file in os.listdir(upload_dir):
            if existing_file.endswith(".apk"):
                os.remove(os.path.join(upload_dir, existing_file))

        # Save the new file
        save_path = os.path.join(upload_dir, file.filename)
        file.save(save_path)

        # Run analysis scripts
        try:
            subprocess.run(["python", "analysis/ml.py"], check=True)
            subprocess.run(["python", "analysis/json_rules.py"], check=True)
            
            # Don't auto-open browser in production
            if os.environ.get('FLASK_ENV') != 'production':
                port = os.environ.get('PORT', 5001)
                webbrowser.open(f"http://127.0.0.1:{port}/results")

        except Exception as e:
            return jsonify({"status": "error", "message": f"Analysis failed: {str(e)}"}), 500

        return jsonify({"status": "success", "message": f"File {file.filename} uploaded and analyzed!"})

@main.route("/results")
def results():
    return render_template("results.html")

@main.route("/api/results/<path:filename>")
def serve_result_data(filename):
    """Serve analysis result JSON files"""
    # Look for results in analysis output or config directories
    analysis_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'analysis')
    config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config')
    
    # Check analysis directory first
    file_path = os.path.join(analysis_dir, filename)
    if os.path.exists(file_path):
        return send_from_directory(analysis_dir, filename)
    
    # Check config directory
    file_path = os.path.join(config_dir, filename)
    if os.path.exists(file_path):
        return send_from_directory(config_dir, filename)
    
    return jsonify({"error": "File not found"}), 404
