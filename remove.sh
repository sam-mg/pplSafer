rm -rf "PplSafer"
rm -rf .vscode
rm -f uploads/*
find . -name "*.pyc" -delete
find . -name "__pycache__" -type d -exec rm -rf {} +
rm -f .DS_Store
rm analysis/ml_output.json 
rm analysis/apk_hash_checker_output.json 
rm analysis/cert_and_sign_output.json 
rm analysis/clamav_output.json 
rm analysis/url_check_output.json 
rm analysis/inner_hash_checker_output.json 
rm analysis/Dynamic/Network\ Calls/network_monitor_output.json 
rm analysis/Dynamic/API\ Calls/api_monitor_output.json 
rm analysis/rules_output.json
find . -name "*.egg-info" -type d -exec rm -rf {} +
