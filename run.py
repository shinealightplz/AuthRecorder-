#!/usr/bin/env python3
"""
AuthRecorder Pro Launcher
=========================

Simple launcher script that handles environment setup and runs AuthRecorder Pro.
"""

import sys
import os
from pathlib import Path

def check_dependencies():
    """Check if all required dependencies are installed"""
    missing = []
    
    try:
        import requests
    except ImportError:
        missing.append("requests")
    
    try:
        import playwright
    except ImportError:
        missing.append("playwright")
    
    try:
        import rich
    except ImportError:
        missing.append("rich")
    
    try:
        import jinja2
    except ImportError:
        missing.append("jinja2")
    
    try:
        import tqdm
    except ImportError:
        missing.append("tqdm")
    
    if missing:
        print("❌ Missing dependencies:")
        for dep in missing:
            print(f"   - {dep}")
        print("\n🔧 Install with: pip install -r requirements.txt")
        print("   Or run: python install.py")
        return False
    
    return True

def check_playwright_browsers():
    """Check if Playwright browsers are installed"""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            # Try to launch chromium
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False

def main():
    """Main launcher function"""
    print("🚀 AuthRecorder Pro Launcher")
    print("=" * 30)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check Playwright browsers
    if not check_playwright_browsers():
        print("⚠️  Playwright browsers not installed")
        print("   Run: playwright install")
        print("   Or run: python install.py")
        
        response = input("\nContinue anyway? (y/N): ").lower()
        if response != 'y':
            sys.exit(1)
    
    # Import and run AuthRecorder
    try:
        # Add current directory to path
        current_dir = Path(__file__).parent
        sys.path.insert(0, str(current_dir))
        
        # Import the main module
        from authrecorder_complete import main as authrecorder_main
        
        # Run AuthRecorder
        authrecorder_main()
        
    except ImportError as e:
        print(f"❌ Failed to import AuthRecorder: {e}")
        print("   Make sure authrecorder_complete.py is in the same directory")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error running AuthRecorder: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
