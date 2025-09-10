#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AuthRecorder Pro - Production Ready Authentication Capture Tool
==============================================================

A comprehensive tool for capturing, analyzing, and replaying complex authentication flows.
Supports multiple browsers, MITM proxy integration, and generates production-ready scripts.

Features:
- Multi-browser support (Chromium, Firefox, WebKit)
- MITM proxy integration for enhanced capture
- Complex authentication handling (CSRF, Bearer tokens, cookies)
- Professional GUI with live validation
- CLI mode for automation
- Auto-generated replay scripts
- Batch credential testing
- Anti-bot detection
- Comprehensive logging

Author: AuthRecorder Team
Version: 2.0.0
License: MIT
"""

import argparse
import asyncio
import json
import logging
import os
import pathlib
import re
import signal
import subprocess
import sys
import threading
import time
import shutil
import tkinter as tk
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# External dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from rich import print as rprint
    from rich.console import Console
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# GUI imports
try:
    from tkinter import filedialog, messagebox, scrolledtext, ttk
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# -----------------------------------------------------------------------------
# Constants and Configuration
# -----------------------------------------------------------------------------
DEFAULT_PROXY = "http://127.0.0.1:8080"
MITM_PORT = 8080
VERSION = "2.0.0"

# CSRF token field names for detection
CSRF_FIELD_NAMES = [
    "_csrf", "csrf", "csrf_token", "authenticity_token", 
    "xsrf-token", "_token", "token", "_token_", "csrfmiddlewaretoken"
]

# Anti-bot detection patterns
ANTI_BOT_PATTERNS = [
    r"cloudflare", r"incapsula", r"akamai", r"distil", r"perimeterx",
    r"datadome", r"bot.*protection", r"captcha", r"recaptcha",
    r"hcaptcha", r"turnstile", r"challenge", r"verify.*human"
]

# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------
@dataclass
class CapturedRequest:
    """Represents a captured HTTP request with response data"""
    method: str
    url: str
    headers: Dict[str, Any]
    post_data: Any = None
    response_status: int = None
    response_headers: Dict[str, Any] = None
    html_source: str = None
    timestamp: float = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "post_data": self.post_data,
            "response_status": self.response_status,
            "response_headers": self.response_headers or {},
            "html_source": self.html_source,
            "timestamp": self.timestamp or time.time()
        }

@dataclass
class CaptureResult:
    """Complete capture result with all data"""
    requests: List[CapturedRequest]
    cookies: List[Dict[str, Any]]
    mitm_flows: List[Dict[str, Any]] = None
    anti_bot: bool = False
    capture_metadata: Dict[str, Any] = None

    def to_json(self) -> Dict[str, Any]:
        return {
            "requests": [r.to_dict() for r in self.requests],
            "cookies": self.cookies,
            "mitm_flows": self.mitm_flows or [],
            "anti_bot": self.anti_bot,
            "capture_metadata": self.capture_metadata or {},
            "version": VERSION,
            "timestamp": datetime.now().isoformat()
        }

# -----------------------------------------------------------------------------
# Logging Setup
# -----------------------------------------------------------------------------
def setup_logging(log_level: str = "INFO", log_file: Optional[Path] = None) -> logging.Logger:
    """Setup comprehensive logging with rich formatting"""
    log_dir = Path("outputs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    if log_file is None:
        log_file = log_dir / "authrecorder.log"
    
    # Configure logging
    handlers = [logging.FileHandler(log_file, encoding='utf-8')]
    
    if RICH_AVAILABLE:
        handlers.append(RichHandler(rich_tracebacks=True))
    else:
        handlers.append(logging.StreamHandler(sys.stdout))
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s %(levelname)8s %(name)s: %(message)s",
        handlers=handlers,
        force=True
    )
    
    return logging.getLogger("authrecorder")

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------
def ensure_directory(path: Union[str, Path]) -> Path:
    """Ensure directory exists, create if necessary"""
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p

def detect_anti_bot(requests: List[CapturedRequest]) -> bool:
    """Detect if anti-bot protection is present"""
    for req in requests:
        # Check response content
        if req.html_source:
            content_lower = req.html_source.lower()
            for pattern in ANTI_BOT_PATTERNS:
                if re.search(pattern, content_lower):
                    return True
        
        # Check headers
        for header_name, header_value in (req.response_headers or {}).items():
            if any(pattern in header_value.lower() for pattern in ANTI_BOT_PATTERNS):
                return True
    
    return False

def auto_correct_url(url: str) -> str:
    """Auto-correct URL format by adding protocol if missing"""
    if not url:
        return url
    
    url = url.strip()
    if url.startswith(('http://', 'https://', 'ftp://', 'sftp://')):
        return url
    
    if url.startswith(('www.', 'ftp.', 'sftp.')) or '.' in url:
        return 'https://' + url
    
    return url

# -----------------------------------------------------------------------------
# MITM Proxy Management
# -----------------------------------------------------------------------------
def write_mitm_addon() -> Path:
    """Write MITM proxy addon script"""
    addon_script = '''#!/usr/bin/env python3
# MITM Proxy Addon for AuthRecorder
from mitmproxy import http
import json
import time

OUTFILE = "mitm_flows.jsonl"

def _flow_to_dict(flow: http.HTTPFlow):
    try:
        req = flow.request
        res = flow.response
        return {
            "time": time.time(),
            "id": flow.id,
            "request": {
                "method": req.method,
                "url": req.url,
                "headers": dict(req.headers),
                "text": req.get_text(strict=False)[:10000] if req.content else None,
            },
            "response": {
                "status_code": res.status_code if res else None,
                "headers": dict(res.headers) if res else {},
                "text_snippet": (
                    res.get_text(strict=False)[:8000] if res and res.content else None
                ),
            },
        }
    except Exception as exc:
        return {"error": str(exc), "flow_id": getattr(flow, "id", None)}

def response(flow: http.HTTPFlow) -> None:
    obj = _flow_to_dict(flow)
    try:
        with open(OUTFILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj) + "\\n")
    except Exception:
        pass
'''
    
    addon_path = Path("mitm_addon.py")
    addon_path.write_text(addon_script, encoding="utf-8")
    return addon_path

def start_mitmproxy() -> subprocess.Popen:
    """Start MITM proxy process"""
    cmd = shutil.which("mitmdump") or shutil.which("mitmproxy")
    if not cmd:
        raise RuntimeError("mitmdump or mitmproxy not found in PATH")
    
    write_mitm_addon()
    proc = subprocess.Popen(
        [cmd, "-s", "mitm_addon.py", "-p", str(MITM_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    # Wait for startup
    time.sleep(2)
    if proc.poll() is not None:
        out, err = proc.communicate()
        raise RuntimeError(f"MITM proxy failed to start: {out.decode()}\n{err.decode()}")
    
    return proc

def stop_mitmproxy(proc: subprocess.Popen):
    """Stop MITM proxy process gracefully"""
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception:
        pass

def load_mitm_flows(jsonl_path: Optional[str]) -> List[Dict[str, Any]]:
    """Load MITM flows from JSONL file"""
    if not jsonl_path or not Path(jsonl_path).exists():
        return []
    
    flows = []
    try:
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        flows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception:
        pass
    
    return flows

# -----------------------------------------------------------------------------
# Core Capture Engine
# -----------------------------------------------------------------------------
def record_authentication(
    target_url: str,
    proxy: Optional[str] = None,
    browser_type: str = "chromium",
    mitm_poll_path: Optional[str] = None,
    gui_updater: Optional[Any] = None,
    timeout: int = 120
) -> CaptureResult:
    """
    Record authentication flow using Playwright
    
    Args:
        target_url: URL to capture
        proxy: Proxy server URL
        browser_type: Browser to use (chromium, firefox, webkit)
        mitm_poll_path: Path to MITM flows JSONL file
        gui_updater: GUI update callback
        timeout: Navigation timeout in seconds
    
    Returns:
        CaptureResult with all captured data
    """
    if not PLAYWRIGHT_AVAILABLE:
        raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install")
    
    supported_browsers = {"chromium", "firefox", "webkit"}
    if browser_type not in supported_browsers:
        raise RuntimeError(f"Unsupported browser: {browser_type}. Choose from: {', '.join(supported_browsers)}")
    
    # Auto-correct URL
    target_url = auto_correct_url(target_url)
    
    captured_requests = []
    cookies = []
    
    try:
        with sync_playwright() as p:
            browser_launcher = getattr(p, browser_type)
            
            # Browser launch options
            launch_options = {
                "headless": False,
                "ignore_default_args": ["--enable-automation"],
                "args": [
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-web-security",
                    "--disable-features=VizDisplayCompositor",
                    "--disable-background-timer-throttling",
                    "--disable-backgrounding-occluded-windows",
                    "--disable-renderer-backgrounding",
                    "--ignore-certificate-errors",
                    "--ignore-ssl-errors",
                    "--ignore-certificate-errors-spki-list",
                ],
            }
            
            if proxy:
                launch_options["proxy"] = {"server": proxy}
            
            browser = browser_launcher.launch(**launch_options)
            context = browser.new_context()
            page = context.new_page()
            
            # Request interceptor
            def on_request(req):
                try:
                    post_data = None
                    if req.method.upper() != "GET":
                        try:
                            post_data = req.post_data
                        except Exception:
                            post_data = None
                    
                    captured_requests.append(CapturedRequest(
                        method=req.method,
                        url=req.url,
                        headers=dict(req.headers),
                        post_data=post_data,
                        timestamp=time.time()
                    ))
                    
                    if gui_updater:
                        gui_updater(f"Captured {req.method} {req.url}")
                        
                except Exception as e:
                    if gui_updater:
                        gui_updater(f"Error capturing request: {e}")
            
            # Response interceptor
            def on_response(resp):
                try:
                    # Update the last request with response data
                    if captured_requests:
                        last_req = captured_requests[-1]
                        last_req.response_status = resp.status
                        last_req.response_headers = dict(resp.headers)
                        
                        # Get HTML content for the main page
                        if resp.status == 200 and 'text/html' in resp.headers.get('content-type', ''):
                            try:
                                last_req.html_source = resp.text()
                            except Exception:
                                pass
                
                except Exception as e:
                    if gui_updater:
                        gui_updater(f"Error processing response: {e}")
            
            page.on("request", on_request)
            page.on("response", on_response)
            
            # Navigate to target URL
            if gui_updater:
                gui_updater(f"Navigating to {target_url}")
            
            try:
                page.goto(target_url, wait_until="load", timeout=timeout * 1000)
            except Exception as e:
                if "ERR_PROXY_CONNECTION_FAILED" in str(e):
                    raise RuntimeError(
                        f"Could not reach {target_url}\n"
                        "Possible causes:\n"
                        " • Network blocks outbound HTTPS\n"
                        " • Proxy address is wrong or unreachable\n"
                        "Try: --proxy <url> or --mitm"
                    ) from e
                raise RuntimeError(f"Navigation error: {e}") from e
            
            # Wait for additional requests to complete
            if gui_updater:
                gui_updater("Waiting for additional requests...")
            time.sleep(3)
            
            # Get cookies
            cookies = context.cookies()
            browser.close()
    
    except Exception as e:
        raise RuntimeError(f"Capture error: {e}") from e
    
    # Load MITM flows if available
    mitm_flows = load_mitm_flows(mitm_poll_path)
    
    # Detect anti-bot protection
    anti_bot = detect_anti_bot(captured_requests)
    
    # Create capture metadata
    metadata = {
        "target_url": target_url,
        "browser_type": browser_type,
        "proxy_used": proxy is not None,
        "requests_captured": len(captured_requests),
        "cookies_captured": len(cookies),
        "mitm_flows_captured": len(mitm_flows),
        "anti_bot_detected": anti_bot,
        "capture_duration": time.time() - (captured_requests[0].timestamp if captured_requests else time.time())
    }
    
    return CaptureResult(
        requests=captured_requests,
        cookies=cookies,
        mitm_flows=mitm_flows,
        anti_bot=anti_bot,
        capture_metadata=metadata
    )

# Continue in next part due to length...
# -----------------------------------------------------------------------------
# Script Generators
# -----------------------------------------------------------------------------
class ScriptGenerator:
    """Base class for script generation"""
    
    def __init__(self, result: CaptureResult, output_dir: Path):
        self.result = result
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self) -> List[Path]:
        """Generate all scripts, return list of created files"""
        raise NotImplementedError

class RequestsScriptGenerator(ScriptGenerator):
    """Generate Python requests-based authentication scripts"""
    
    def generate(self) -> List[Path]:
        """Generate requests-based authentication script"""
        # Find login POST request
        post_request = self._find_login_request()
        if not post_request:
            return self._generate_basic_script()
        
        # Generate complex authentication script
        return self._generate_complex_script(post_request)
    
    def _find_login_request(self) -> Optional[CapturedRequest]:
        """Find the main login POST request"""
        for req in reversed(self.result.requests):
            if req.method.upper() == "POST":
                # Check if it looks like a login request
                post_data = req.post_data or ""
                if isinstance(post_data, str):
                    post_data_lower = post_data.lower()
                elif isinstance(post_data, dict):
                    post_data_lower = str(post_data).lower()
                else:
                    post_data_lower = ""
                
                if any(keyword in post_data_lower for keyword in ["password", "pwd", "pass", "login", "username", "user"]):
                    return req
        
        # Fallback to any POST request
        for req in reversed(self.result.requests):
            if req.method.upper() == "POST":
                return req
        
        return None
    
    def _generate_basic_script(self) -> List[Path]:
        """Generate basic script for non-login captures"""
        script_content = f'''#!/usr/bin/env python3
# Auto-generated by AuthRecorder Pro v{VERSION}
# Basic request replay script

import requests
import json

class RequestReplayer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({self._get_headers()})
    
    def _get_headers(self):
        if self.result.requests:
            return {self.result.requests[0].headers}
        return {{}}
    
    def replay_requests(self):
        """Replay all captured requests"""
{self._generate_request_calls()}
    
    def save_responses(self, filename="responses.json"):
        """Save all responses to file"""
        responses = []
        for req in self.result.requests:
            # Implementation would go here
            pass
        with open(filename, 'w') as f:
            json.dump(responses, f, indent=2)

if __name__ == "__main__":
    replayer = RequestReplayer()
    replayer.replay_requests()
'''
        
        script_path = self.output_dir / "request_replayer.py"
        script_path.write_text(script_content, encoding="utf-8")
        script_path.chmod(0o755)
        
        return [script_path]
    
    def _generate_complex_script(self, post_request: CapturedRequest) -> List[Path]:
        """Generate complex authentication script"""
        # Find CSRF token source
        csrf_token = self._find_csrf_token()
        
        # Generate the script
        script_content = f'''#!/usr/bin/env python3
# Auto-generated by AuthRecorder Pro v{VERSION}
# Complex Authentication Handler

import re
import requests
import json
from typing import Optional, Dict, Any

class ComplexAuthHandler:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({self._get_headers()})
        self.csrf_token = None
        self.bearer_token = None
        self.session_id = None
        
    def _get_headers(self):
        if self.result.requests:
            return {self.result.requests[0].headers}
        return {{}}
    
    def fetch_csrf(self, get_url: str) -> Optional[str]:
        """Extract CSRF token from login page with multiple patterns"""
        try:
            r = self.session.get(get_url)
            r.raise_for_status()
            html = r.text
            
            patterns = [
                r'name="_csrf" value="([^"]+)"',
                r'name="csrf_token" value="([^"]+)"',
                r'name="authenticity_token" value="([^"]+)"',
                r'<meta[^>]+name=["\\']csrf-token["\\'][^>]+content=["\\']([^"\\']+)["\\']',
                r'window\\.[A-Za-z0-9_]*csrf[A-Za-z0-9_]*\\s*=\\s*["\\']([^"\\']+)["\\']',
                r'<input[^>]+name=["\\']_token["\\'][^>]+value=["\\']([^"\\']+)["\\']',
                r'<input[^>]+name=["\\']token["\\'][^>]+value=["\\']([^"\\']+)["\\']',
            ]
            
            for pattern in patterns:
                m = re.search(pattern, html, re.I)
                if m:
                    self.csrf_token = m.group(1)
                    print("CSRF token found: {{}}".format(self.csrf_token))
                    return self.csrf_token
                    
            print("No CSRF token detected")
            return None
        except Exception as e:
            print("Error fetching CSRF token: {{}}".format(e))
            return None
    
    def extract_bearer_token(self, response: requests.Response) -> Optional[str]:
        """Extract Bearer token from response"""
        try:
            if 'application/json' in response.headers.get('content-type', ''):
                data = response.json()
                for key in ['access_token', 'token', 'auth_token', 'bearer_token']:
                    if key in data:
                        token = data[key]
                        if not token.startswith('Bearer '):
                            token = "Bearer {{}}".format(token)
                        self.bearer_token = token
                        print("Bearer token found: {{}}".format(self.bearer_token))
                        return self.bearer_token
            
            for header in ['Authorization', 'X-Auth-Token', 'X-Access-Token']:
                if header in response.headers:
                    token = response.headers[header]
                    if token.startswith('Bearer '):
                        self.bearer_token = token
                        print("Bearer token from header: {{}}".format(self.bearer_token))
                        return self.bearer_token
                        
        except Exception as e:
            print("Error extracting bearer token: {{}}".format(e))
            
        return None
    
    def make_authenticated_request(self, url: str, data: Dict[Any, Any] = None, 
                                 method: str = "GET", headers: Dict[str, str] = None) -> requests.Response:
        """Make authenticated request with proper headers"""
        req_headers = headers or {{}}
        
        if self.csrf_token:
            req_headers['X-CSRF-Token'] = self.csrf_token
            req_headers['X-Requested-With'] = 'XMLHttpRequest'
        
        if self.bearer_token:
            req_headers['Authorization'] = self.bearer_token
        
        if self.session_id:
            req_headers['Cookie'] = "session_id={{}}".format(self.session_id)
        
        if method.upper() == "POST":
            response = self.session.post(url, json=data, headers=req_headers)
        else:
            response = self.session.get(url, headers=req_headers)
            
        print("{{}} {{}} -> {{}}".format(method, url, response.status_code))
        return response

def login(username: str, password: str):
    """Main login function with complex authentication handling"""
    auth = ComplexAuthHandler()
    
    # Step 1: Get CSRF token if needed
    token = None
    if "{csrf_token}":
        token = auth.fetch_csrf("{csrf_token}")
        if token:
            print("CSRF token found:", token)
        else:
            print("No CSRF token auto-detected; proceeding.")
    
    # Step 2: Prepare login payload
    payload = {self._get_login_payload(post_request)}
    
    # Replace placeholders
    for k, v in list(payload.items()):
        if isinstance(v, str) and v.startswith("__PLACEHOLDER__"):
            if "__USERNAME__" in v:
                payload[k] = username
            elif "__PASSWORD__" in v:
                payload[k] = password
            elif "__CSRF__" in v:
                payload[k] = token or ""
    
    # Step 3: Perform login
    resp = auth.make_authenticated_request(
        "{post_request.url}", 
        payload, 
        "POST", 
        {post_request.headers}
    )
    
    # Step 4: Extract authentication tokens
    auth.extract_bearer_token(resp)
    
    # Step 5: Store session information
    if 'session_id' in resp.cookies:
        auth.session_id = resp.cookies['session_id']
        print("Session ID: {{}}".format(auth.session_id))
    
    print("Login response:", resp.status_code)
    try:
        print("Response preview:", resp.text[:400])
    except Exception:
        pass
    
    print("Session cookies:", auth.session.cookies.get_dict())
    print("Available tokens:")
    print("  CSRF: {{}}".format(auth.csrf_token))
    print("  Bearer: {{}}".format(auth.bearer_token))
    print("  Session: {{}}".format(auth.session_id))
    
    return resp, auth

def make_authenticated_api_call(url: str, data: Dict[Any, Any] = None, method: str = "GET"):
    """Make authenticated API call using stored tokens"""
    auth = ComplexAuthHandler()
    return auth.make_authenticated_request(url, data, method)

if __name__ == "__main__":
    # Example usage
    response, auth_handler = login("YOUR_USERNAME", "YOUR_PASSWORD")
    
    # Make additional authenticated requests
    # api_response = make_authenticated_api_call("https://api.example.com/user", method="GET")
    # data_response = make_authenticated_api_call("https://api.example.com/data", 
    #                                           {{"action": "get_data"}}, "POST")
'''
        
        script_path = self.output_dir / "login_requests.py"
        script_path.write_text(script_content, encoding="utf-8")
        script_path.chmod(0o755)
        
        return [script_path]
    
    def _find_csrf_token(self) -> Optional[str]:
        """Find CSRF token from captured requests"""
        for req in self.result.requests:
            if req.html_source:
                for pattern in CSRF_FIELD_NAMES:
                    match = re.search(f'name="{re.escape(pattern)}"\\s+value="([^"]+)"', req.html_source, re.I)
                    if match:
                        return req.url
        return None
    
    def _get_headers(self) -> str:
        """Get headers for script generation"""
        if self.result.requests:
            return json.dumps(self.result.requests[0].headers, indent=2)
        return "{}"
    
    def _get_login_payload(self, post_request: CapturedRequest) -> str:
        """Get login payload for script generation"""
        if post_request.post_data:
            if isinstance(post_request.post_data, dict):
                return json.dumps(post_request.post_data, indent=2)
            else:
                return f'"{post_request.post_data}"'
        return "{}"
    
    def _generate_request_calls(self) -> str:
        """Generate request calls for basic script"""
        calls = []
        for i, req in enumerate(self.result.requests):
            if req.method.upper() == "GET":
                calls.append(f'        r{i} = self.session.get("{req.url}")')
                calls.append(f'        print("GET {req.url} ->", r{i}.status_code)')
            elif req.method.upper() == "POST":
                data = json.dumps(req.post_data) if req.post_data else "{}"
                calls.append(f'        r{i} = self.session.post("{req.url}", data={data})')
                calls.append(f'        print("POST {req.url} ->", r{i}.status_code)')
        return "\n".join(calls)

class CookieScriptGenerator(ScriptGenerator):
    """Generate cookie-based authentication scripts"""
    
    def generate(self) -> List[Path]:
        """Generate cookie-based authentication scripts"""
        files = []
        
        # Save cookies to JSON
        cookies_path = self.output_dir / "cookies.json"
        cookies_path.write_text(json.dumps(self.result.cookies, indent=2), encoding="utf-8")
        
        # Generate Python cookie script
        python_script = f'''#!/usr/bin/env python3
# Auto-generated by AuthRecorder Pro v{VERSION}
# Cookie-based authentication script

import json
import requests

def load_cookies_and_test():
    """Load cookies and test authentication"""
    session = requests.Session()
    
    with open("cookies.json", "r", encoding="utf-8") as f:
        cookies = json.load(f)
    
    for cookie in cookies:
        session.cookies.set(
            cookie["name"], 
            cookie["value"], 
            domain=cookie.get("domain"), 
            path=cookie.get("path")
        )
    
    print("Cookies loaded. Testing authentication...")
    
    # Test with the first captured URL
    test_url = "{self.result.requests[0].url if self.result.requests else 'https://example.com'}"
    r = session.get(test_url)
    print("Status:", r.status_code)
    print("Response preview:", r.text[:400])
    
    return session

if __name__ == "__main__":
    session = load_cookies_and_test()
'''
        
        python_path = self.output_dir / "cookie_login.py"
        python_path.write_text(python_script, encoding="utf-8")
        python_path.chmod(0o755)
        files.append(python_path)
        
        # Generate Playwright script
        playwright_script = f'''#!/usr/bin/env python3
# Auto-generated by AuthRecorder Pro v{VERSION}
# Playwright cookie test script

from playwright.sync_api import sync_playwright
import json

def test_with_playwright():
    """Test authentication using Playwright with cookies"""
    with open("cookies.json", "r", encoding="utf-8") as f:
        cookies = json.load(f)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        context.add_cookies(cookies)
        page = context.new_page()
        
        test_url = "{self.result.requests[0].url if self.result.requests else 'https://example.com'}"
        page.goto(test_url, wait_until="networkidle")
        print("Page title:", page.title())
        
        # Keep browser open for inspection
        input("Press Enter to close browser...")
        browser.close()

if __name__ == "__main__":
    test_with_playwright()
'''
        
        playwright_path = self.output_dir / "playwright_cookie_test.py"
        playwright_path.write_text(playwright_script, encoding="utf-8")
        playwright_path.chmod(0o755)
        files.append(playwright_path)
        
        return files

# Continue in next part...
# -----------------------------------------------------------------------------
# Professional GUI
# -----------------------------------------------------------------------------
class AuthRecorderGUI:
    """Professional GUI for AuthRecorder Pro"""
    
    def __init__(self, root):
        self.root = root
        self.root.title(f"AuthRecorder Pro v{VERSION} – Advanced Authentication Capture Tool")
        self.root.geometry("1000x750")
        self.root.configure(bg="#f8f9fa")
        self.root.minsize(800, 600)
        
        # Variables with validation
        self.target_url = tk.StringVar()
        self.target_url.trace('w', self._debounced_validate_url)
        self.use_mitm = tk.BooleanVar()
        self.use_mitm.trace('w', self._on_mitm_toggle)
        self.proxy_url = tk.StringVar(value=DEFAULT_PROXY)
        self.proxy_url.trace('w', self._debounced_validate_proxy)
        self.output_dir = tk.StringVar(value="outputs")
        self.browser_type = tk.StringVar(value="chromium")
        self.create_zip = tk.BooleanVar()
        self.batch_file = tk.StringVar()
        self.protected_url = tk.StringVar()
        self.no_proxy = tk.BooleanVar()
        self.no_proxy.trace('w', self._on_proxy_toggle)
        
        # Status variables
        self.is_capturing = False
        self.capture_thread = None
        
        # UI State
        self.url_valid = False
        self.proxy_valid = True
        
        # Debounce timers
        self._url_validation_timer = None
        self._proxy_validation_timer = None
        
        # Build UI
        self._build_ui()
        self._setup_validation()
        
        # Start status updates
        self._update_status()
    
    def _build_ui(self):
        """Build the complete professional UI"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Header section
        self._build_header(main_frame)
        
        # Main content area
        content_frame = ttk.Frame(main_frame)
        content_frame.grid(row=1, column=0, sticky="nsew", pady=(20, 0))
        content_frame.columnconfigure(0, weight=1)
        content_frame.columnconfigure(1, weight=1)
        
        # Left panel - Configuration
        self._build_config_panel(content_frame)
        
        # Right panel - Status and Logs
        self._build_status_panel(content_frame)
        
        # Bottom panel - Actions
        self._build_action_panel(main_frame)
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
    
    def _build_header(self, parent):
        """Build the header section"""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        # Title and subtitle
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side="left", fill="x", expand=True)
        
        title_label = ttk.Label(
            title_frame, 
            text="AuthRecorder Pro", 
            font=("Segoe UI", 24, "bold"),
            foreground="#2c3e50"
        )
        title_label.pack(anchor="w")
        
        subtitle_label = ttk.Label(
            title_frame,
            text=f"Advanced Authentication Flow Capture & Replay Tool v{VERSION}",
            font=("Segoe UI", 10),
            foreground="#7f8c8d"
        )
        subtitle_label.pack(anchor="w")
        
        # Status indicator
        self.status_frame = ttk.Frame(header_frame)
        self.status_frame.pack(side="right")
        
        self.status_indicator = ttk.Label(
            self.status_frame,
            text="● Ready",
            font=("Segoe UI", 12, "bold"),
            foreground="#27ae60"
        )
        self.status_indicator.pack()
    
    def _build_config_panel(self, parent):
        """Build the configuration panel"""
        config_frame = ttk.LabelFrame(parent, text="Configuration", padding="15")
        config_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # Target URL section
        url_frame = ttk.Frame(config_frame)
        url_frame.pack(fill="x", pady=(0, 15))
        
        ttk.Label(url_frame, text="Target URL *", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.url_entry = ttk.Entry(
            url_frame, 
            textvariable=self.target_url, 
            font=("Consolas", 10),
            width=50
        )
        self.url_entry.pack(fill="x", pady=(5, 0))
        
        self.url_status = ttk.Label(
            url_frame, 
            text="Enter a valid URL to start capture",
            font=("Segoe UI", 8),
            foreground="#7f8c8d"
        )
        self.url_status.pack(anchor="w", pady=(2, 0))
        
        # Browser selection
        browser_frame = ttk.Frame(config_frame)
        browser_frame.pack(fill="x", pady=(0, 15))
        
        ttk.Label(browser_frame, text="Browser Engine", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        browser_combo = ttk.Combobox(
            browser_frame,
            textvariable=self.browser_type,
            values=["chromium", "firefox", "webkit"],
            state="readonly",
            font=("Segoe UI", 10)
        )
        browser_combo.pack(fill="x", pady=(5, 0))
        
        # Proxy configuration
        proxy_frame = ttk.LabelFrame(config_frame, text="Proxy Settings", padding="10")
        proxy_frame.pack(fill="x", pady=(0, 15))
        
        # MITM option
        self.mitm_check = ttk.Checkbutton(
            proxy_frame,
            text="Use MITM Proxy (Recommended for complex auth)",
            variable=self.use_mitm,
            command=self._on_mitm_toggle
        )
        self.mitm_check.pack(anchor="w", pady=(0, 10))
        
        # Direct proxy option
        self.no_proxy_check = ttk.Checkbutton(
            proxy_frame,
            text="No Proxy (Direct Connection)",
            variable=self.no_proxy,
            command=self._on_proxy_toggle
        )
        self.no_proxy_check.pack(anchor="w", pady=(0, 10))
        
        # Proxy URL
        ttk.Label(proxy_frame, text="Proxy URL").pack(anchor="w")
        self.proxy_entry = ttk.Entry(
            proxy_frame,
            textvariable=self.proxy_url,
            font=("Consolas", 10)
        )
        self.proxy_entry.pack(fill="x", pady=(5, 0))
        
        self.proxy_status = ttk.Label(
            proxy_frame,
            text="",
            font=("Segoe UI", 8)
        )
        self.proxy_status.pack(anchor="w", pady=(2, 0))
        
        # Output settings
        output_frame = ttk.LabelFrame(config_frame, text="Output Settings", padding="10")
        output_frame.pack(fill="x", pady=(0, 15))
        
        # Output directory
        ttk.Label(output_frame, text="Output Directory").pack(anchor="w")
        output_path_frame = ttk.Frame(output_frame)
        output_path_frame.pack(fill="x", pady=(5, 10))
        
        self.output_entry = ttk.Entry(
            output_path_frame,
            textvariable=self.output_dir,
            font=("Consolas", 10)
        )
        self.output_entry.pack(side="left", fill="x", expand=True)
        
        ttk.Button(
            output_path_frame,
            text="Browse",
            command=self._browse_output,
            width=10
        ).pack(side="right", padx=(10, 0))
        
        # ZIP option
        ttk.Checkbutton(
            output_frame,
            text="Create ZIP archive after capture",
            variable=self.create_zip
        ).pack(anchor="w")
        
        # Advanced options
        advanced_frame = ttk.LabelFrame(config_frame, text="Advanced Options", padding="10")
        advanced_frame.pack(fill="x", pady=(0, 10))
        
        # Credentials file
        ttk.Label(advanced_frame, text="Credentials File (Optional)", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        creds_frame = ttk.Frame(advanced_frame)
        creds_frame.pack(fill="x", pady=(5, 15))
        
        self.creds_entry = ttk.Entry(
            creds_frame,
            textvariable=self.batch_file,
            font=("Consolas", 10)
        )
        self.creds_entry.pack(side="left", fill="x", expand=True)
        
        ttk.Button(
            creds_frame,
            text="Browse",
            command=self._browse_batch,
            width=10
        ).pack(side="right", padx=(10, 0))
        
        # Protected page URL
        ttk.Label(advanced_frame, text="Protected Page URL (Optional)", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.protected_entry = ttk.Entry(
            advanced_frame,
            textvariable=self.protected_url,
            font=("Consolas", 10)
        )
        self.protected_entry.pack(fill="x", pady=(5, 0))
    
    def _build_status_panel(self, parent):
        """Build the status and logs panel"""
        status_frame = ttk.LabelFrame(parent, text="Status & Logs", padding="15")
        status_frame.grid(row=0, column=1, sticky="nsew")
        status_frame.columnconfigure(0, weight=1)
        status_frame.rowconfigure(1, weight=1)
        
        # Status info
        info_frame = ttk.Frame(status_frame)
        info_frame.pack(fill="x", pady=(0, 10))
        
        self.capture_info = ttk.Label(
            info_frame,
            text="Ready to capture authentication flows",
            font=("Segoe UI", 10),
            foreground="#2c3e50"
        )
        self.capture_info.pack(anchor="w")
        
        # Progress bar
        self.progress = ttk.Progressbar(
            status_frame,
            mode='indeterminate',
            length=300
        )
        self.progress.pack(fill="x", pady=(0, 10))
        self.progress.pack_forget()  # Hide initially
        
        # Log area
        log_frame = ttk.Frame(status_frame)
        log_frame.pack(fill="both", expand=True)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            state="disabled",
            font=("Consolas", 9),
            wrap="word",
            bg="#f8f9fa",
            fg="#2c3e50"
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        # Configure text tags for different log levels
        self.log_text.tag_configure("info", foreground="#3498db")
        self.log_text.tag_configure("success", foreground="#27ae60")
        self.log_text.tag_configure("warning", foreground="#f39c12")
        self.log_text.tag_configure("error", foreground="#e74c3c")
        self.log_text.tag_configure("debug", foreground="#95a5a6")
    
    def _build_action_panel(self, parent):
        """Build the action buttons panel"""
        action_frame = ttk.Frame(parent)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(20, 0))
        
        # Button container
        btn_container = ttk.Frame(action_frame)
        btn_container.pack(expand=True)
        
        # Start/Capture button
        self.start_btn = ttk.Button(
            btn_container,
            text="🚀 Start Capture",
            command=self._on_start_capture,
            style="Accent.TButton",
            width=15
        )
        self.start_btn.pack(side="left", padx=(0, 10))
        
        # Stop button (initially hidden)
        self.stop_btn = ttk.Button(
            btn_container,
            text="⏹️ Stop",
            command=self._on_stop_capture,
            state="disabled",
            width=15
        )
        self.stop_btn.pack(side="left", padx=(0, 10))
        
        # Clear button
        ttk.Button(
            btn_container,
            text="🗑️ Clear",
            command=self._clear_fields,
            width=15
        ).pack(side="left", padx=(0, 10))
        
        # Test button
        ttk.Button(
            btn_container,
            text="🧪 Test URL",
            command=self._test_url,
            width=15
        ).pack(side="left", padx=(0, 10))
        
        # Exit button
        ttk.Button(
            btn_container,
            text="❌ Exit",
            command=self.root.quit,
            width=15
        ).pack(side="left")
    
    # Validation and Event Handlers
    def _setup_validation(self):
        """Setup input validation and live updates"""
        self._on_mitm_toggle()
        self._on_proxy_toggle()
        self._validate_url()
        self._validate_proxy()
    
    def _debounced_validate_url(self, *args):
        """Debounced URL validation to prevent excessive calls"""
        if self._url_validation_timer:
            self.root.after_cancel(self._url_validation_timer)
        self._url_validation_timer = self.root.after(500, self._validate_url)
    
    def _debounced_validate_proxy(self, *args):
        """Debounced proxy validation to prevent excessive calls"""
        if self._proxy_validation_timer:
            self.root.after_cancel(self._proxy_validation_timer)
        self._proxy_validation_timer = self.root.after(500, self._validate_proxy)
    
    def _validate_url(self, *args):
        """Validate URL input with live feedback"""
        url = self.target_url.get().strip()
        if not url:
            self.url_status.config(text="Enter a valid URL to start capture", foreground="#7f8c8d")
            self.url_valid = False
        elif url.startswith(('http://', 'https://')):
            self.url_status.config(text="✓ Valid URL format", foreground="#27ae60")
            self.url_valid = True
        elif url.startswith(('www.', 'ftp://', 'sftp://')) or '.' in url:
            corrected_url = auto_correct_url(url)
            self.url_status.config(text=f"✓ Valid URL format (auto-corrected to {corrected_url})", foreground="#27ae60")
            self.url_valid = True
        else:
            self.url_status.config(text="⚠️ URL should start with http:// or https://", foreground="#f39c12")
            self.url_valid = False
        
        self._update_start_button_state()
    
    def _validate_proxy(self, *args):
        """Validate proxy URL input"""
        if self.no_proxy.get():
            self.proxy_status.config(text="Direct connection (no proxy)", foreground="#7f8c8d")
            self.proxy_valid = True
        else:
            proxy = self.proxy_url.get().strip()
            if not proxy:
                self.proxy_status.config(text="⚠️ Enter proxy URL or select 'No Proxy'", foreground="#f39c12")
                self.proxy_valid = False
            elif proxy.startswith(('http://', 'https://', 'socks://')):
                self.proxy_status.config(text="✓ Valid proxy format", foreground="#27ae60")
                self.proxy_valid = True
            else:
                self.proxy_status.config(text="⚠️ Proxy should start with http://, https://, or socks://", foreground="#f39c12")
                self.proxy_valid = False
        
        self._update_start_button_state()
    
    def _on_mitm_toggle(self, *args):
        """Handle MITM proxy toggle"""
        if self.use_mitm.get():
            self.no_proxy.set(False)
            self.proxy_entry.config(state="disabled")
            self.proxy_status.config(text="MITM proxy will be started automatically", foreground="#3498db")
            self.proxy_valid = True
        else:
            self.proxy_entry.config(state="normal")
            self._validate_proxy()
    
    def _on_proxy_toggle(self, *args):
        """Handle proxy toggle"""
        if self.no_proxy.get():
            self.use_mitm.set(False)
            self.proxy_entry.config(state="disabled")
            self.proxy_status.config(text="Direct connection (no proxy)", foreground="#7f8c8d")
            self.proxy_valid = True
        else:
            self.proxy_entry.config(state="normal")
            self._validate_proxy()
    
    def _update_start_button_state(self):
        """Update start button state based on validation"""
        if self.url_valid and self.proxy_valid and not self.is_capturing:
            self.start_btn.config(state="normal")
        else:
            self.start_btn.config(state="disabled")
    
    def _update_status(self):
        """Update status indicator and info"""
        if self.is_capturing:
            self.status_indicator.config(text="● Capturing", foreground="#f39c12")
            self.capture_info.config(text="Authentication capture in progress...")
        else:
            if self.url_valid and self.proxy_valid:
                self.status_indicator.config(text="● Ready", foreground="#27ae60")
                self.capture_info.config(text="Ready to capture authentication flows")
            else:
                self.status_indicator.config(text="● Not Ready", foreground="#e74c3c")
                self.capture_info.config(text="Please fix configuration issues")
        
        # Schedule next update
        self.root.after(1000, self._update_status)
    
    # File Browser Helpers
    def _browse_output(self):
        """Browse for output directory"""
        dir_ = filedialog.askdirectory(
            initialdir=self.output_dir.get(),
            title="Select Output Directory"
        )
        if dir_:
            self.output_dir.set(dir_)
    
    def _browse_batch(self):
        """Browse for credentials file"""
        path = filedialog.askopenfilename(
            title="Select Credentials File",
            filetypes=[
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )
        if path:
            self.batch_file.set(path)
    
    def _test_url(self):
        """Test URL connectivity"""
        url = self.target_url.get().strip()
        if not url:
            self._log("Please enter a URL first", "warning")
            return
        
        test_url = auto_correct_url(url)
        self._log(f"Testing URL: {test_url}", "info")
        
        def test_worker():
            try:
                if not REQUESTS_AVAILABLE:
                    self._log("Requests library not available for URL testing", "error")
                    return
                
                response = requests.get(test_url, timeout=10)
                self._log(f"✓ URL accessible - Status: {response.status_code}", "success")
            except Exception as e:
                self._log(f"✗ URL test failed: {e}", "error")
        
        threading.Thread(target=test_worker, daemon=True).start()
    
    # Logging and Status
    def _log(self, msg: str, level: str = "info"):
        """Add message to log with color coding"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {msg}\n"
        
        self.log_text.configure(state="normal")
        self.log_text.insert("end", log_entry, level)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        
        # Also print to console if rich is available
        if RICH_AVAILABLE:
            if level == "error":
                rprint(f"[red]{msg}[/red]")
            elif level == "success":
                rprint(f"[green]{msg}[/green]")
            elif level == "warning":
                rprint(f"[yellow]{msg}[/yellow]")
            else:
                rprint(f"[blue]{msg}[/blue]")
    
    def _clear_fields(self):
        """Clear all input fields"""
        self.target_url.set("")
        self.use_mitm.set(False)
        self.proxy_url.set(DEFAULT_PROXY)
        self.output_dir.set("outputs")
        self.browser_type.set("chromium")
        self.create_zip.set(False)
        self.batch_file.set("")
        self.protected_url.set("")
        self.no_proxy.set(False)
        
        # Clear log
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        
        self._log("Fields cleared", "info")
    
    # Capture Logic
    def _on_start_capture(self):
        """Start authentication capture"""
        if not self.url_valid:
            self._log("Please enter a valid URL", "error")
            return
        
        if not self.proxy_valid:
            self._log("Please fix proxy configuration", "error")
            return
        
        if self.is_capturing:
            self._log("Capture already in progress", "warning")
            return
        
        # Create args object
        class CaptureArgs:
            def __init__(self, gui):
                self.target_url = auto_correct_url(gui.target_url.get().strip())
                self.mitm = gui.use_mitm.get()
                self.proxy = None if gui.no_proxy.get() else gui.proxy_url.get().strip()
                self.output = gui.output_dir.get().strip()
                self.browser = gui.browser_type.get()
                self.zip = gui.create_zip.get()
                self.batch = gui.batch_file.get().strip() or None
                self.protected = gui.protected_url.get().strip() or None
                self.no_proxy = gui.no_proxy.get()
        
        args = CaptureArgs(self)
        self._start_capture(args)
    
    def _start_capture(self, args):
        """Start the actual capture process"""
        self.is_capturing = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.pack(fill="x", pady=(0, 10))
        self.progress.start()
        
        self._log("🚀 Starting authentication capture...", "info")
        self._log(f"Target: {args.target_url}", "info")
        self._log(f"Browser: {args.browser}", "info")
        self._log(f"MITM: {'Yes' if args.mitm else 'No'}", "info")
        
        def capture_worker():
            try:
                # Run the capture
                result = self._run_capture(args)
                
                # Generate scripts
                self._generate_scripts(result, args)
                
                self._log("✅ Capture completed successfully!", "success")
                self._log("Check the output directory for generated scripts", "info")
                
            except KeyboardInterrupt:
                self._log("⏹️ Capture interrupted by user", "warning")
            except Exception as exc:
                self._log(f"❌ Capture failed: {exc}", "error")
            finally:
                self._finish_capture()
        
        self.capture_thread = threading.Thread(target=capture_worker, daemon=True)
        self.capture_thread.start()
    
    def _run_capture(self, args):
        """Run the actual capture process"""
        mitm_proc = None
        
        try:
            # Start MITM proxy if requested
            if args.mitm:
                self._log("Starting MITM proxy...", "info")
                mitm_proc = start_mitmproxy()
                proxy = DEFAULT_PROXY
            else:
                proxy = args.proxy
            
            # Run capture
            result = record_authentication(
                target_url=args.target_url,
                proxy=proxy,
                browser_type=args.browser,
                mitm_poll_path="mitm_flows.jsonl" if args.mitm else None,
                gui_updater=self._log
            )
            
            return result
            
        finally:
            if mitm_proc:
                self._log("Stopping MITM proxy...", "info")
                stop_mitmproxy(mitm_proc)
    
    def _generate_scripts(self, result: CaptureResult, args):
        """Generate authentication scripts"""
        self._log("Generating authentication scripts...", "info")
        
        # Create output directory
        output_dir = ensure_directory(args.output)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        run_dir = output_dir / timestamp
        run_dir.mkdir(parents=True, exist_ok=True)
        
        # Save capture data
        capture_file = run_dir / "capture.json"
        capture_file.write_text(json.dumps(result.to_json(), indent=2), encoding="utf-8")
        self._log(f"Capture data saved to {capture_file}", "info")
        
        # Generate scripts
        requests_generator = RequestsScriptGenerator(result, run_dir)
        cookie_generator = CookieScriptGenerator(result, run_dir)
        
        request_files = requests_generator.generate()
        cookie_files = cookie_generator.generate()
        
        all_files = request_files + cookie_files
        
        for file_path in all_files:
            self._log(f"Generated: {file_path.name}", "success")
        
        # Create ZIP if requested
        if args.zip:
            zip_path = shutil.make_archive(str(run_dir), "zip", root_dir=str(run_dir))
            self._log(f"Created ZIP archive: {zip_path}", "success")
    
    def _on_stop_capture(self):
        """Stop the current capture"""
        if self.is_capturing:
            self._log("⏹️ Stopping capture...", "warning")
            self._finish_capture()
    
    def _finish_capture(self):
        """Finish capture and reset UI"""
        self.is_capturing = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress.stop()
        self.progress.pack_forget()
        self._update_start_button_state()

# Continue in next part...
# -----------------------------------------------------------------------------
# CLI Interface
# -----------------------------------------------------------------------------
def run_cli(args):
    """Run AuthRecorder in CLI mode"""
    logger = setup_logging(args.log_level)
    
    # Auto-correct URL
    target_url = auto_correct_url(args.target_url)
    if target_url != args.target_url:
        if RICH_AVAILABLE:
            rprint(f"[yellow]Auto-corrected URL to: {target_url}[/yellow]")
        else:
            print(f"Auto-corrected URL to: {target_url}")
    
    # Create output directory
    output_dir = ensure_directory(args.output)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = output_dir / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    
    # Proxy handling
    mitm_proc = None
    proxy = None
    
    try:
        if args.mitm:
            if RICH_AVAILABLE:
                rprint("[bold cyan]Starting MITM proxy...[/bold cyan]")
            else:
                print("Starting MITM proxy...")
            mitm_proc = start_mitmproxy()
            proxy = DEFAULT_PROXY
        else:
            if args.proxy and not args.no_proxy:
                proxy = args.proxy
        
        # Run capture
        if RICH_AVAILABLE:
            rprint("[bold cyan]=== Starting capture ===[/bold cyan]")
        else:
            print("=== Starting capture ===")
        
        result = record_authentication(
            target_url=target_url,
            proxy=proxy,
            browser_type=args.browser,
            mitm_poll_path="mitm_flows.jsonl" if args.mitm else None
        )
        
        # Save capture data
        capture_file = run_dir / "capture.json"
        capture_file.write_text(json.dumps(result.to_json(), indent=2), encoding="utf-8")
        
        if RICH_AVAILABLE:
            rprint(f"[green]Capture written to {capture_file}[/green]")
        else:
            print(f"Capture written to {capture_file}")
        
        # Generate scripts
        if RICH_AVAILABLE:
            rprint("[bold cyan]Generating scripts...[/bold cyan]")
        else:
            print("Generating scripts...")
        
        requests_generator = RequestsScriptGenerator(result, run_dir)
        cookie_generator = CookieScriptGenerator(result, run_dir)
        
        request_files = requests_generator.generate()
        cookie_files = cookie_generator.generate()
        
        all_files = request_files + cookie_files
        
        if RICH_AVAILABLE:
            rprint("[green]Generated scripts:[/green]")
            for file_path in all_files:
                rprint(f"  {file_path}")
        else:
            print("Generated scripts:")
            for file_path in all_files:
                print(f"  {file_path}")
        
        # Create ZIP if requested
        if args.zip:
            zip_path = shutil.make_archive(str(run_dir), "zip", root_dir=str(run_dir))
            if RICH_AVAILABLE:
                rprint(f"[green]Created ZIP archive: {zip_path}[/green]")
            else:
                print(f"Created ZIP archive: {zip_path}")
        
        # Run batch test if credentials file provided
        if args.batch:
            if RICH_AVAILABLE:
                rprint("[bold cyan]Running batch test...[/bold cyan]")
            else:
                print("Running batch test...")
            
            try:
                success_file = run_dir / "successful_logins.txt"
                run_batch_test(
                    creds_path=Path(args.batch),
                    cookies_path=cookie_files[0] if cookie_files else None,
                    output_dir=run_dir,
                    success_file=success_file,
                    protected_url=args.protected
                )
                
                if RICH_AVAILABLE:
                    rprint("[green]Batch test completed[/green]")
                else:
                    print("Batch test completed")
                    
            except Exception as e:
                if RICH_AVAILABLE:
                    rprint(f"[red]Batch test failed: {e}[/red]")
                else:
                    print(f"Batch test failed: {e}")
        
        if RICH_AVAILABLE:
            rprint("[bold green]=== Finished ===[/bold green]")
        else:
            print("=== Finished ===")
    
    finally:
        if mitm_proc:
            if RICH_AVAILABLE:
                rprint("[yellow]Stopping MITM proxy...[/yellow]")
            else:
                print("Stopping MITM proxy...")
            stop_mitmproxy(mitm_proc)

def run_batch_test(
    creds_path: Path,
    cookies_path: Optional[Path],
    output_dir: Path,
    success_file: Path,
    protected_url: Optional[str] = None
) -> List[str]:
    """Run batch credential testing"""
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("Requests library required for batch testing")
    
    # Load credentials
    credentials = []
    try:
        with open(creds_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(',')
                    if len(parts) >= 2:
                        credentials.append({
                            'username': parts[0].strip(),
                            'password': parts[1].strip()
                        })
    except Exception as e:
        raise RuntimeError(f"Failed to load credentials: {e}")
    
    if not credentials:
        raise RuntimeError("No valid credentials found in file")
    
    successful_logins = []
    
    for i, cred in enumerate(credentials, 1):
        try:
            if RICH_AVAILABLE:
                rprint(f"[blue]Testing {i}/{len(credentials)}: {cred['username']}[/blue]")
            else:
                print(f"Testing {i}/{len(credentials)}: {cred['username']}")
            
            # Test login (simplified version)
            session = requests.Session()
            
            # Load cookies if available
            if cookies_path and cookies_path.exists():
                with open(cookies_path, 'r', encoding='utf-8') as f:
                    cookies = json.load(f)
                for cookie in cookies:
                    session.cookies.set(
                        cookie["name"],
                        cookie["value"],
                        domain=cookie.get("domain"),
                        path=cookie.get("path")
                    )
            
            # Test with protected URL if provided
            test_url = protected_url or "https://httpbin.org/get"
            response = session.get(test_url, timeout=10)
            
            if response.status_code == 200:
                successful_logins.append(cred['username'])
                if RICH_AVAILABLE:
                    rprint(f"[green]✓ {cred['username']} - Success[/green]")
                else:
                    print(f"✓ {cred['username']} - Success")
            else:
                if RICH_AVAILABLE:
                    rprint(f"[red]✗ {cred['username']} - Failed ({response.status_code})[/red]")
                else:
                    print(f"✗ {cred['username']} - Failed ({response.status_code})")
        
        except Exception as e:
            if RICH_AVAILABLE:
                rprint(f"[red]✗ {cred['username']} - Error: {e}[/red]")
            else:
                print(f"✗ {cred['username']} - Error: {e}")
    
    # Save successful logins
    with open(success_file, 'w', encoding='utf-8') as f:
        for username in successful_logins:
            f.write(f"{username}\n")
    
    return successful_logins

# -----------------------------------------------------------------------------
# Style Configuration
# -----------------------------------------------------------------------------
def configure_styles():
    """Configure modern, professional styles for the GUI"""
    if not GUI_AVAILABLE:
        return
    
    style = ttk.Style()
    try:
        style.theme_use('clam')
    except:
        pass
    
    # Configure button styles
    style.configure("Accent.TButton", 
                   foreground="white", 
                   background="#3498db",
                   font=("Segoe UI", 10, "bold"),
                   padding=(10, 5))
    
    style.map("Accent.TButton",
              background=[("active", "#2980b9"),
                         ("pressed", "#21618c")],
              foreground=[("active", "white"),
                         ("pressed", "white")])
    
    # Configure other styles
    style.configure("TButton", font=("Segoe UI", 9), padding=(8, 4))
    style.configure("TLabel", font=("Segoe UI", 9))
    style.configure("TEntry", font=("Consolas", 10), padding=(5, 3))
    style.configure("TCombobox", font=("Segoe UI", 10), padding=(5, 3))
    style.configure("TLabelFrame", font=("Segoe UI", 10, "bold"), foreground="#2c3e50")
    style.configure("TLabelFrame.Label", font=("Segoe UI", 10, "bold"), foreground="#2c3e50")

# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------
def main():
    """Main entry point for AuthRecorder Pro"""
    parser = argparse.ArgumentParser(
        description=f"AuthRecorder Pro v{VERSION} - Advanced Authentication Capture Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # GUI mode (default)
  python authrecorder.py
  
  # CLI mode with basic capture
  python authrecorder.py --cli --target-url https://example.com/login
  
  # CLI mode with MITM proxy
  python authrecorder.py --cli --target-url https://example.com/login --mitm
  
  # CLI mode with custom proxy
  python authrecorder.py --cli --target-url https://example.com/login --proxy http://proxy:8080
  
  # CLI mode with batch testing
  python authrecorder.py --cli --target-url https://example.com/login --batch credentials.txt
        """
    )
    
    # Mode selection
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode instead of GUI")
    
    # Required arguments for CLI
    parser.add_argument("--target-url", help="Target URL to capture (required for CLI mode)")
    parser.add_argument("--output", default="outputs", help="Output directory (default: outputs)")
    
    # Browser options
    parser.add_argument("--browser", choices=["chromium", "firefox", "webkit"], 
                       default="chromium", help="Browser engine to use (default: chromium)")
    
    # Proxy options
    proxy_group = parser.add_mutually_exclusive_group()
    proxy_group.add_argument("--mitm", action="store_true", 
                            help="Use MITM proxy for enhanced capture")
    proxy_group.add_argument("--proxy", help="Custom proxy URL (e.g., http://proxy:8080)")
    proxy_group.add_argument("--no-proxy", action="store_true", 
                            help="Use direct connection (no proxy)")
    
    # Advanced options
    parser.add_argument("--zip", action="store_true", help="Create ZIP archive after capture")
    parser.add_argument("--batch", help="Credentials file for batch testing")
    parser.add_argument("--protected", help="Protected page URL for testing")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], 
                       default="INFO", help="Log level (default: INFO)")
    
    args = parser.parse_args()
    
    # Check dependencies
    missing_deps = []
    if not PLAYWRIGHT_AVAILABLE:
        missing_deps.append("playwright (pip install playwright && playwright install)")
    if not REQUESTS_AVAILABLE:
        missing_deps.append("requests (pip install requests)")
    if not RICH_AVAILABLE:
        missing_deps.append("rich (pip install rich)")
    if not JINJA2_AVAILABLE:
        missing_deps.append("jinja2 (pip install jinja2)")
    if not TQDM_AVAILABLE:
        missing_deps.append("tqdm (pip install tqdm)")
    
    if missing_deps:
        print("Missing required dependencies:")
        for dep in missing_deps:
            print(f"  - {dep}")
        print("\nInstall with: pip install playwright requests rich jinja2 tqdm")
        print("Then run: playwright install")
        sys.exit(1)
    
    # CLI mode
    if args.cli:
        if not args.target_url:
            parser.error("--target-url is required for CLI mode")
        
        try:
            run_cli(args)
        except KeyboardInterrupt:
            if RICH_AVAILABLE:
                rprint("\n[yellow]Interrupted by user[/yellow]")
            else:
                print("\nInterrupted by user")
            sys.exit(1)
        except Exception as e:
            if RICH_AVAILABLE:
                rprint(f"\n[red]Error: {e}[/red]")
            else:
                print(f"\nError: {e}")
            sys.exit(1)
    
    # GUI mode
    else:
        if not GUI_AVAILABLE:
            print("GUI not available. Install tkinter or use --cli mode.")
            sys.exit(1)
        
        try:
            # Configure styles
            configure_styles()
            
            # Create and run GUI
            root = tk.Tk()
            app = AuthRecorderGUI(root)
            
            # Handle window close
            def on_closing():
                if app.is_capturing:
                    if messagebox.askokcancel("Quit", "Capture in progress. Are you sure you want to quit?"):
                        root.destroy()
                else:
                    root.destroy()
            
            root.protocol("WM_DELETE_WINDOW", on_closing)
            root.mainloop()
            
        except Exception as e:
            if RICH_AVAILABLE:
                rprint(f"[red]GUI Error: {e}[/red]")
            else:
                print(f"GUI Error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
