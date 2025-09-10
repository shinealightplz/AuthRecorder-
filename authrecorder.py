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
