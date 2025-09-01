rm -rf "PplSafer"
rm -rf .vscode
rm -f uploads/*
find . -name "*.pyc" -delete
find . -name "__pycache__" -type d -exec rm -rf {} +
rm -f .DS_Store
rm -f analysis/ml_output.json analysis/static_output.json
find . -name "*.egg-info" -type d -exec rm -rf {} +
