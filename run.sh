#!/bin/bash
# AuthRecorder Pro Launcher for Linux/Mac
# =======================================

echo ""
echo "🚀 AuthRecorder Pro Launcher"
echo "============================="
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "❌ Python not found"
        echo "   Please install Python 3.8+ and add it to PATH"
        echo "   Install with: sudo apt install python3 (Ubuntu/Debian)"
        echo "   Or: brew install python (macOS)"
        exit 1
    else
        PYTHON_CMD="python"
    fi
else
    PYTHON_CMD="python3"
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python $REQUIRED_VERSION or higher required"
    echo "   Current version: $PYTHON_VERSION"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION found"

# Make sure we're in the right directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Run the launcher
$PYTHON_CMD run.py

# Check exit status
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ AuthRecorder Pro failed to start"
    echo "   Check the error messages above"
    exit 1
fi
