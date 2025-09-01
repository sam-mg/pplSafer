#!/usr/bin/env python3
"""
Main application entry point
"""
import os
import webbrowser
from app import create_app

app = create_app()

if __name__ == "__main__":
    # Get port from environment variable or default to 5001
    port = int(os.environ.get('PORT', 5001))
    
    # Only open browser in local development
    if os.environ.get('FLASK_ENV') != 'production':
        webbrowser.open(f"http://127.0.0.1:{port}")
    
    app.run(debug=False, host='0.0.0.0', port=port)
