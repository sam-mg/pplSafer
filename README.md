# APK Malware Analysis Tool

A web-based application for analyzing Android APK files for potential malware using machine learning and static analysis.

## Features

- **File Upload Interface**: Easy drag-and-drop APK file upload
- **ML-based Detection**: XGBoost model for malware classification
- **Static Analysis**: Custom rules-based analysis with MITRE ATT&CK mapping
- **VirusTotal Integration**: Hash-based malware detection
- **Detailed Reports**: Comprehensive analysis results with visualizations

## Technology Stack

- **Backend**: Flask (Python)
- **ML Model**: XGBoost for malware classification
- **APK Analysis**: Androguard library
- **Frontend**: HTML, CSS, JavaScript
- **APIs**: VirusTotal API integration

## Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd apk-malware-analysis
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure VirusTotal API:
   - Get an API key from VirusTotal
   - Update the `API_KEY` variable in `static/json_rules.py`

4. Run the application:
```bash
python run.py
```

5. Open your browser and navigate to `http://localhost:5001`

## Usage

1. Upload an APK file through the web interface
2. The application will automatically:
   - Extract features from the APK
   - Run ML-based malware detection
   - Perform static analysis with custom rules
   - Query VirusTotal for known threats
   - Generate a comprehensive report

## Project Structure

```
apk-malware-analyzer/
├── app/                          # Flask application
│   ├── __init__.py              # App factory
│   ├── routes.py                # URL routes and views
│   ├── static/                  # Static assets
│   │   ├── css/                 # Stylesheets
│   │   │   ├── styles.css       # Upload page styles
│   │   │   └── results-styles.css # Results page styles
│   │   └── js/                  # JavaScript files
│   │       ├── script.js        # Upload page scripts
│   │       └── results-script.js # Results page scripts
│   └── templates/               # HTML templates
│       ├── index.html           # Upload interface
│       └── results.html         # Results display
├── analysis/                    # Analysis modules
│   ├── message.py              # ML-based malware detection
│   └── json_rules.py           # Rules-based analysis
├── config/                     # Configuration files
│   ├── rules_new.json          # Analysis rules
│   ├── categories.json         # Category mappings
│   └── mitre.json             # MITRE ATT&CK mappings
├── models/                     # ML models (use Git LFS)
│   └── xgboost_apk_model.pkl  # Trained XGBoost model
├── uploads/                    # Upload directory (gitignored)
├── run.py                      # Application entry point
├── requirements.txt            # Python dependencies
├── Procfile                    # Deployment configuration
├── runtime.txt                 # Python version
├── README.md                   # Documentation
└── .gitignore                  # Git ignore rules
```

## Security Notes

- This tool is for educational and research purposes
- Always scan APK files in a secure, isolated environment
- The ML model may have false positives/negatives
- VirusTotal API has rate limits

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]
