#!/usr/bin/env python3
"""
AuthRecorder Pro Test Suite
===========================

Comprehensive test suite to verify AuthRecorder Pro functionality.
"""

import sys
import subprocess
import time
from pathlib import Path

def test_imports():
    """Test if all required modules can be imported"""
    print("🧪 Testing imports...")
    
    try:
        import requests
        print("  ✅ requests")
    except ImportError as e:
        print(f"  ❌ requests: {e}")
        return False
    
    try:
        import playwright
        print("  ✅ playwright")
    except ImportError as e:
        print(f"  ❌ playwright: {e}")
        return False
    
    try:
        import rich
        print("  ✅ rich")
    except ImportError as e:
        print(f"  ❌ rich: {e}")
        return False
    
    try:
        import jinja2
        print("  ✅ jinja2")
    except ImportError as e:
        print(f"  ❌ jinja2: {e}")
        return False
    
    try:
        import tqdm
        print("  ✅ tqdm")
    except ImportError as e:
        print(f"  ❌ tqdm: {e}")
        return False
    
    return True

def test_playwright_browsers():
    """Test if Playwright browsers are working"""
    print("🌐 Testing Playwright browsers...")
    
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            # Test Chromium
            try:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto("https://httpbin.org/get")
                browser.close()
                print("  ✅ Chromium")
            except Exception as e:
                print(f"  ❌ Chromium: {e}")
                return False
            
            # Test Firefox
            try:
                browser = p.firefox.launch(headless=True)
                page = browser.new_page()
                page.goto("https://httpbin.org/get")
                browser.close()
                print("  ✅ Firefox")
            except Exception as e:
                print(f"  ⚠️  Firefox: {e}")
            
            # Test WebKit
            try:
                browser = p.webkit.launch(headless=True)
                page = browser.new_page()
                page.goto("https://httpbin.org/get")
                browser.close()
                print("  ✅ WebKit")
            except Exception as e:
                print(f"  ⚠️  WebKit: {e}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Playwright test failed: {e}")
        return False

def test_authrecorder_import():
    """Test if AuthRecorder can be imported"""
    print("📦 Testing AuthRecorder import...")
    
    try:
        # Add current directory to path
        current_dir = Path(__file__).parent
        sys.path.insert(0, str(current_dir))
        
        from authrecorder_complete import (
            record_authentication,
            CaptureResult,
            RequestsScriptGenerator,
            CookieScriptGenerator,
            AuthRecorderGUI
        )
        print("  ✅ AuthRecorder modules imported successfully")
        return True
        
    except Exception as e:
        print(f"  ❌ AuthRecorder import failed: {e}")
        return False

def test_basic_capture():
    """Test basic capture functionality"""
    print("🎯 Testing basic capture...")
    
    try:
        from authrecorder_complete import record_authentication
        
        # Test with a simple URL
        result = record_authentication(
            target_url="https://httpbin.org/get",
            browser_type="chromium",
            timeout=30
        )
        
        if result and len(result.requests) > 0:
            print("  ✅ Basic capture successful")
            print(f"     Captured {len(result.requests)} requests")
            print(f"     Captured {len(result.cookies)} cookies")
            return True
        else:
            print("  ❌ No requests captured")
            return False
            
    except Exception as e:
        print(f"  ❌ Basic capture failed: {e}")
        return False

def test_script_generation():
    """Test script generation"""
    print("📝 Testing script generation...")
    
    try:
        from authrecorder_complete import CaptureResult, CapturedRequest, RequestsScriptGenerator, CookieScriptGenerator
        
        # Create a mock capture result
        mock_request = CapturedRequest(
            method="GET",
            url="https://httpbin.org/get",
            headers={"User-Agent": "test"},
            timestamp=time.time()
        )
        
        result = CaptureResult(
            requests=[mock_request],
            cookies=[{"name": "test", "value": "cookie", "domain": "httpbin.org"}]
        )
        
        # Test script generation
        output_dir = Path("test_output")
        output_dir.mkdir(exist_ok=True)
        
        requests_gen = RequestsScriptGenerator(result, output_dir)
        cookie_gen = CookieScriptGenerator(result, output_dir)
        
        request_files = requests_gen.generate()
        cookie_files = cookie_gen.generate()
        
        if request_files and cookie_files:
            print("  ✅ Script generation successful")
            print(f"     Generated {len(request_files)} request scripts")
            print(f"     Generated {len(cookie_files)} cookie scripts")
            
            # Clean up test files
            import shutil
            shutil.rmtree(output_dir, ignore_errors=True)
            return True
        else:
            print("  ❌ No scripts generated")
            return False
            
    except Exception as e:
        print(f"  ❌ Script generation failed: {e}")
        return False

def test_cli_mode():
    """Test CLI mode"""
    print("💻 Testing CLI mode...")
    
    try:
        # Test help command
        result = subprocess.run([
            sys.executable, "authrecorder_complete.py", "--help"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and "AuthRecorder Pro" in result.stdout:
            print("  ✅ CLI help command works")
            return True
        else:
            print("  ❌ CLI help command failed")
            print(f"     Error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"  ❌ CLI test failed: {e}")
        return False

def test_gui_import():
    """Test GUI import (without actually opening GUI)"""
    print("🖥️  Testing GUI import...")
    
    try:
        from authrecorder_complete import AuthRecorderGUI
        print("  ✅ GUI module imported successfully")
        return True
        
    except Exception as e:
        print(f"  ❌ GUI import failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 AuthRecorder Pro Test Suite")
    print("=" * 40)
    print()
    
    tests = [
        ("Import Test", test_imports),
        ("Playwright Browsers", test_playwright_browsers),
        ("AuthRecorder Import", test_authrecorder_import),
        ("Basic Capture", test_basic_capture),
        ("Script Generation", test_script_generation),
        ("CLI Mode", test_cli_mode),
        ("GUI Import", test_gui_import),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"Running {test_name}...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} ERROR: {e}")
        print()
    
    print("=" * 40)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! AuthRecorder Pro is ready to use.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
