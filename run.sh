#!/bin/bash
# Setup and run script for PplSafer APK Analysis Application

set -e  # Exit on any error

echo "🚀 Setting up PplSafer environment..."

# Create virtual environment if it doesn't exist
if [ ! -d "PplSafer" ]; then
    echo "📦 Creating virtual environment 'PplSafer'..."
    python3 -m venv PplSafer
    echo "✅ Virtual environment created successfully!"
else
    echo "✅ Virtual environment 'PplSafer' already exists!"
fi

# Install dependencies
echo "📥 Installing dependencies from requirements.txt..."
source "PplSafer/bin/activate"
pip install --upgrade pip
pip install -r requirements.txt
echo "✅ Dependencies installed successfully!"

# Run the application
echo "🏃 Starting the application..."
echo "📍 Python location: $(which python)"
echo "🌐 Application will be available at: http://localhost:5000"
echo ""
python run.py
