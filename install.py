#!/usr/bin/env python3
"""
AuthRecorder Pro Installation Script
====================================

This script installs all required dependencies and sets up AuthRecorder Pro.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"📦 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"   Error: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 or higher is required")
        print(f"   Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def install_dependencies():
    """Install Python dependencies"""
    dependencies = [
        "requests",
        "playwright", 
        "rich",
        "jinja2",
        "tqdm"
    ]
    
    print("🔧 Installing Python dependencies...")
    
    for dep in dependencies:
        if not run_command(f"pip install {dep}", f"Installing {dep}"):
            return False
    
    return True

def install_playwright_browsers():
    """Install Playwright browsers"""
    print("🌐 Installing Playwright browsers...")
    
    browsers = ["chromium", "firefox", "webkit"]
    for browser in browsers:
        if not run_command(f"playwright install {browser}", f"Installing {browser}"):
            print(f"⚠️  Warning: Failed to install {browser}")
    
    return True

def check_mitmproxy():
    """Check if mitmproxy is available"""
    print("🔍 Checking for mitmproxy...")
    
    try:
        result = subprocess.run(["mitmdump", "--version"], capture_output=True, text=True)
        print("✅ mitmproxy is available")
        return True
    except FileNotFoundError:
        print("⚠️  mitmproxy not found - MITM features will be limited")
        print("   Install with: pip install mitmproxy")
        return False

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    
    directories = ["outputs", "logs", "scripts"]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"   Created: {directory}/")
    
    return True

def test_installation():
    """Test the installation"""
    print("🧪 Testing installation...")
    
    try:
        # Test imports
        import requests
        import playwright
        import rich
        import jinja2
        import tqdm
        
        print("✅ All Python dependencies imported successfully")
        
        # Test Playwright
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        
        print("✅ Playwright browsers working correctly")
        return True
        
    except Exception as e:
        print(f"❌ Installation test failed: {e}")
        return False

def main():
    """Main installation process"""
    print("🚀 AuthRecorder Pro Installation")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Failed to install dependencies")
        sys.exit(1)
    
    # Install Playwright browsers
    if not install_playwright_browsers():
        print("⚠️  Some browsers failed to install, but continuing...")
    
    # Check mitmproxy
    check_mitmproxy()
    
    # Create directories
    if not create_directories():
        print("❌ Failed to create directories")
        sys.exit(1)
    
    # Test installation
    if not test_installation():
        print("❌ Installation test failed")
        sys.exit(1)
    
    print("\n🎉 Installation completed successfully!")
    print("\n📖 Quick Start:")
    print("   GUI Mode:    python authrecorder_complete.py")
    print("   CLI Mode:    python authrecorder_complete.py --cli --target-url https://example.com/login")
    print("   Help:        python authrecorder_complete.py --help")
    print("\n📚 Documentation: See README.md for detailed usage instructions")

if __name__ == "__main__":
    main()
