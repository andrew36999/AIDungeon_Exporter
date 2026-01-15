#!/usr/bin/env python3
"""
AI Dungeon Complete Account Exporter
=====================================

Exports all your AI Dungeon content:
- Adventures (played stories with actions, story, plot essentials, author's notes, world info)

Requirements:
- Python 3.8+
- Google Chrome

Usage:
    Simply run: python aidungeon_exporter.py
    
    The script will automatically:
    1. Launch Chrome with remote debugging
    2. Open AI Dungeon for you to log in
    3. Capture your session and start exporting
"""

import json
import os
import re
import sys
import subprocess
import urllib.request
import urllib.error
import gzip
import io
from datetime import datetime
from pathlib import Path
from time import sleep
import time

# =============================================================================
# Auto-install dependencies
# =============================================================================

def install_dependencies():
    """Check and install required packages."""
    required = ['bson']  # pymongo includes bson
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append('pymongo' if package == 'bson' else package)
    
    if missing:
        print(f"[*] Installing missing dependencies: {', '.join(missing)}")
        for pkg in missing:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg, '-q'])
        print("[+] Dependencies installed!")
        # Re-import after install
        global bson
        import bson

install_dependencies()
import bson

# =============================================================================
# Chrome Management
# =============================================================================

def find_chrome_path() -> str:
    """Find Chrome executable on Windows."""
    possible_paths = [
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # Try to find via registry or PATH
    try:
        result = subprocess.run(
            ["where", "chrome.exe"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
    except:
        pass
    
    return None


def kill_chrome():
    """Kill all running Chrome processes."""
    try:
        # Graceful close first
        subprocess.run(
            ["taskkill", "/IM", "chrome.exe"],
            capture_output=True, timeout=5
        )
        sleep(0.5)
        # Force kill any remaining
        subprocess.run(
            ["taskkill", "/F", "/IM", "chrome.exe"],
            capture_output=True, timeout=5
        )
        sleep(1)
    except:
        pass


def is_chrome_debug_running() -> bool:
    """Check if Chrome is running with debug port."""
    import socket
    # Try socket connection first
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('localhost', 9222))
        sock.close()
        if result == 0:
            return True
    except:
        pass
    
    # Fallback to HTTP request
    try:
        req = urllib.request.Request("http://localhost:9222/json")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return True
    except:
        pass
    
    return False


def launch_chrome_with_debugging() -> bool:
    """Launch Chrome with remote debugging and open AI Dungeon."""
    chrome_path = find_chrome_path()
    
    if not chrome_path:
        print("[!] Chrome not found. Please install Google Chrome.")
        return False
    
    print(f"[*] Found Chrome: {chrome_path}")
    print("[*] Closing any existing Chrome windows...")
    kill_chrome()
    
    # Delete any saved tokens to force fresh login
    script_dir = Path(__file__).parent
    token_file = script_dir / ".aidungeon_token"
    if token_file.exists():
        token_file.unlink()
    
    # Delete the debug profile to ensure fresh browser session
    debug_profile = script_dir / ".chrome_debug_profile"
    if debug_profile.exists():
        import shutil
        shutil.rmtree(debug_profile, ignore_errors=True)
    debug_profile.mkdir(exist_ok=True)
    
    print("[*] Launching Chrome with remote debugging...")
    
    try:
        # Launch Chrome with debugging port and AI Dungeon URL
        subprocess.Popen(
            [
                chrome_path,
                "--remote-debugging-port=9222",
                f"--user-data-dir={debug_profile}",
                "--no-first-run",
                "--no-default-browser-check",
                "https://play.aidungeon.com"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Wait for Chrome to start and debug port to become available
        print("[*] Waiting for debug port", end="", flush=True)
        for _ in range(15):
            sleep(1)
            print(".", end="", flush=True)
            if is_chrome_debug_running():
                print("")
                print("[+] Chrome ready!")
                return True
        
        print("")
        print("[+] Chrome launched!")
        return True
        
    except Exception as e:
        print(f"[!] Failed to launch Chrome: {e}")
        return False


def wait_for_aidungeon_login() -> str:
    """Wait for user to log into AI Dungeon and capture the token automatically."""
    print("\n" + "="*60)
    print("  WAITING FOR AI DUNGEON LOGIN")
    print("="*60)
    print("\nA Chrome window has opened with AI Dungeon.")
    print("Please log in - the script will detect it automatically.")
    print("\n  This is NOT malware - it reads your login session from")
    print("   Chrome to access the AI Dungeon API. Your credentials")
    print("   are only sent to AI Dungeon's own servers.")
    print("="*60)
    print("\n[*] Waiting for valid login", end="", flush=True)
    
    # Poll for valid token every 3 seconds for up to 3 minutes
    for i in range(60):
        sleep(3)
        print(".", end="", flush=True)
        
        token = refresh_token_from_browser()
        if token:
            # Validate the token actually works
            try:
                # Quick validation - try to get user info
                payload = {"query": "query { user { id username } }"}
                data = json.dumps(payload).encode('utf-8')
                headers = {
                    "content-type": "application/json",
                    "Authorization": token,
                }
                req = urllib.request.Request(API_URL, data=data, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    result = json.loads(resp.read().decode('utf-8'))
                    user = result.get("data", {}).get("user")
                    if user and user.get("username"):
                        print("")  # New line
                        print(f"[+] Logged in as: {user['username']}")
                        return token
            except:
                # Token not valid yet, keep waiting
                pass
    
    print("")  # New line
    print("[!] Timeout waiting for login after 3 minutes.")
    return None


# =============================================================================
# Configuration
# =============================================================================

API_URL = "https://api.aidungeon.com/graphql"
DATA_DIR = Path(__file__).parent / "Exports"

# Token will be obtained from browser
ACCESS_TOKEN = None

# Rough token estimation (GPT-style: ~4 chars per token on average)
CHARS_PER_TOKEN = 4

# =============================================================================
# GraphQL Queries - Based on actual API schema from network capture
# =============================================================================

# Query for a SINGLE adventure (with full details)
# Based on actual API: adventure(shortId: $shortId)
ADVENTURE_QUERY = """
query GetAdventure($shortId: String) {
    adventure(shortId: $shortId) {
        id
        publicId
        shortId
        title
        description
        image
        tags
        createdAt
        editedAt
        actionCount
        memory
        authorsNote
        thirdPerson
        nsfw
        contentRating
        user {
            username
        }
        state {
            instructions
        }
        storyCards {
            id
            ...StoryCard
        }
    }
}

fragment StoryCard on StoryCard {
    id
    type
    keys
    value
    title
    useForCharacterCreation
    description
    updatedAt
    deletedAt
}
"""

# Query to get adventure story content via batch URLs (ReadScreen)
# The actual story text is stored in S3 .bin files
READ_SCREEN_QUERY = """
query ReadScreenGetAdventure(
  $shortId: String, 
  $lastBatch: Int, 
  $actionsNeeded: Int, 
  $startFromEnd: Boolean, 
  $batchNumbers: [Int!]
) {
  adventure(shortId: $shortId) {
    id
    publicId
    shortId
    title
    readBatches(
      batchNumbers: $batchNumbers, 
      lastBatch: $lastBatch, 
      actionsNeeded: $actionsNeeded, 
      startFromEnd: $startFromEnd
    ) {
      batches {
        batchNumber
        url
      }
    }
    actionBatchInformation {
      batchNumber
      actionCount
    }
  }
}
"""

# Query to get current user info (to validate token)
USER_INFO_QUERY = """
query GetUserInfo {
    user {
        id
        username
    }
}
"""

# OpenSearch query for listing user content (adventures/scenarios)
# Discovered from network capture - uses SearchInput with username filter
OPEN_SEARCH_QUERY = """
fragment SearchResultFields on SearchableContent {
    id
    publicId
    contentId
    contentType
    shortId
    userId
    title
    description
    image
    published
    unlisted
    createdAt
    updatedAt
    editedAt
    voteCount
    saveCount
    actionCount
    isOwner
    user {
        id
        username
        profile {
            id
            title
            thumbImageUrl
        }
    }
}

query OpenSearch($input: SearchInput!) {
    search(input: $input) {
        items {
            ...SearchResultFields
        }
        total
        hasMore
        took
    }
}
"""

# =============================================================================
# Token Management
# =============================================================================

def refresh_token_from_browser() -> str:
    """Get auth token from Chrome browser via DevTools Protocol (pure Python)."""
    import urllib.request
    import json
    
    script_dir = Path(__file__).parent
    token_file = script_dir / ".aidungeon_token"
    

    
    try:
        # Get list of pages from Chrome
        req = urllib.request.Request("http://localhost:9222/json")
        with urllib.request.urlopen(req, timeout=5) as resp:
            pages = json.loads(resp.read().decode())
        
        # Find AI Dungeon page
        aid_page = None
        for page in pages:
            if "aidungeon" in page.get("url", "").lower():
                aid_page = page
                break
        
        if not aid_page:

            return None
        
        # Connect to the page's WebSocket to execute JavaScript
        ws_url = aid_page.get("webSocketDebuggerUrl")
        if not ws_url:

            return None
        
        # Use websocket to execute JS and get the token
        # We need to find the token in localStorage or cookies
        import http.client
        from urllib.parse import urlparse
        
        parsed = urlparse(ws_url)
        
        # Build the CDP command to evaluate JavaScript
        js_code = """
        (function() {
            // Try to find Firebase auth token in localStorage
            const keys = Object.keys(localStorage);
            for (const key of keys) {
                const val = localStorage.getItem(key);
                if (val && val.includes('eyJ') && val.length > 500) {
                    // Try to parse as JSON to get accessToken
                    try {
                        const parsed = JSON.parse(val);
                        if (parsed.accessToken) {
                            return parsed.accessToken;
                        }
                    } catch(e) {
                        // Not JSON, return raw value if it looks like a token
                        if (val.startsWith('eyJ') || val.startsWith('firebase ')) {
                            return val;
                        }
                    }
                }
            }
            // Check for firebase auth
            if (window.firebase && window.firebase.auth) {
                const user = window.firebase.auth().currentUser;
                if (user) {
                    return user.getIdToken();
                }
            }
            return null;
        })()
        """
        
        # Simple WebSocket implementation for CDP
        import socket
        import hashlib
        import base64
        import struct
        
        # Parse WebSocket URL
        ws_host = parsed.hostname
        ws_port = parsed.port or 80
        ws_path = parsed.path
        
        # Create WebSocket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ws_host, ws_port))
        
        # WebSocket handshake
        key = base64.b64encode(os.urandom(16)).decode()
        handshake = f"GET {ws_path} HTTP/1.1\r\n"
        handshake += f"Host: {ws_host}:{ws_port}\r\n"
        handshake += "Upgrade: websocket\r\n"
        handshake += "Connection: Upgrade\r\n"
        handshake += f"Sec-WebSocket-Key: {key}\r\n"
        handshake += "Sec-WebSocket-Version: 13\r\n\r\n"
        sock.send(handshake.encode())
        
        # Read response
        response = sock.recv(4096).decode()
        if "101" not in response:

            sock.close()
            return None
        
        # Send CDP Runtime.evaluate command
        msg_id = 1
        cdp_msg = json.dumps({
            "id": msg_id,
            "method": "Runtime.evaluate",
            "params": {
                "expression": js_code,
                "returnByValue": True
            }
        })
        
        # Frame the WebSocket message
        payload = cdp_msg.encode()
        frame = bytearray()
        frame.append(0x81)  # Text frame, FIN
        
        if len(payload) < 126:
            frame.append(0x80 | len(payload))  # Masked
        elif len(payload) < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack(">H", len(payload)))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack(">Q", len(payload)))
        
        # Mask key and masked payload
        mask = os.urandom(4)
        frame.extend(mask)
        for i, byte in enumerate(payload):
            frame.append(byte ^ mask[i % 4])
        
        sock.send(bytes(frame))
        
        # Read response (simplified - assumes small response)
        resp_data = sock.recv(65536)
        sock.close()
        
        # Parse WebSocket frame
        if len(resp_data) > 2:
            payload_start = 2
            payload_len = resp_data[1] & 0x7F
            if payload_len == 126:
                payload_start = 4
                payload_len = struct.unpack(">H", resp_data[2:4])[0]
            elif payload_len == 127:
                payload_start = 10
                payload_len = struct.unpack(">Q", resp_data[2:10])[0]
            
            ws_payload = resp_data[payload_start:payload_start+payload_len]
            try:
                cdp_resp = json.loads(ws_payload.decode())
                result = cdp_resp.get("result", {}).get("result", {}).get("value")
                
                if result and isinstance(result, str) and "eyJ" in result:
                    # Found token, add firebase prefix if needed
                    token = result if result.startswith("firebase ") else f"firebase {result}"
                    
                    # Save to file
                    token_file.write_text(token)

                    return token
            except:
                pass
        

        return None
        
    except urllib.error.URLError:
        return None
    except Exception:
        return None



# =============================================================================
# API Client
# =============================================================================

def estimate_tokens(text: str) -> int:
    """Estimate token count (rough GPT-style approximation)."""
    if not text:
        return 0
    return len(text) // CHARS_PER_TOKEN


def count_chars(text: str) -> int:
    """Count characters in text."""
    return len(text) if text else 0


class AIDungeonClient:
    def __init__(self, access_token: str):
        self.access_token = access_token
        self.username = None
        self.last_token_refresh = time.time()
    
    def refresh_token(self) -> bool:
        """Try to refresh the token from browser."""
        print("[*] Refreshing token...")
        new_token = refresh_token_from_browser()
        if new_token:
            self.access_token = new_token
            self.last_token_refresh = time.time()
            return True
        return False
    
    def ensure_fresh_token(self, max_age_seconds: int = 90) -> bool:
        """Ensure token is fresh, refresh if needed. Returns True if token is valid."""
        age = time.time() - self.last_token_refresh
        if age > max_age_seconds:
            return self.refresh_token()
        return True
    
    def make_query(self, query: str, variables: dict = None) -> dict:
        """Execute a GraphQL query against the AI Dungeon API."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        data = json.dumps(payload).encode('utf-8')
        
        # Build headers with Authorization
        headers = {
            "content-type": "application/json",
            "user-agent": "AIDungeon-Exporter/1.0",
            "Authorization": self.access_token,
            "x-access-token": self.access_token,  # Legacy fallback
        }
        
        req = urllib.request.Request(API_URL, data=data, headers=headers)
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else ""
            print(f"[ERROR] HTTP {e.code}: {e.reason}")
            print(f"[ERROR] Response: {error_body[:500]}")
            raise
        except urllib.error.URLError as e:
            print(f"[ERROR] Connection error: {e.reason}")
            raise
    
    def make_query_with_retry(self, query: str, variables: dict = None, max_retries: int = 3) -> dict:
        """Execute a GraphQL query with automatic retry and token refresh on failure."""
        for attempt in range(max_retries):
            try:
                result = self.make_query(query, variables)
                # Check for auth errors in the response
                if result.get("errors"):
                    for err in result["errors"]:
                        msg = err.get("message", "").lower()
                        if "unauthorized" in msg or "not authenticated" in msg or "token" in msg:
                            raise Exception(f"Auth error: {err.get('message')}")
                return result
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"[!] Request failed: {e}")
                    print(f"[*] Refreshing token and retrying (attempt {attempt + 2}/{max_retries})...")
                    if self.refresh_token():
                        sleep(1)  # Brief pause before retry
                        continue
                raise
    
    def validate_token(self) -> bool:
        """Validate the access token and get username."""
        print("[*] Validating access token...")
        try:
            result = self.make_query(USER_INFO_QUERY)
            if result.get("data", {}).get("user"):
                self.username = result["data"]["user"].get("username", "unknown")
                print(f"[+] Authenticated as: {self.username}")
                return True
            else:
                print("[!] Token validation failed - no user data returned")
                if "errors" in result:
                    for err in result["errors"]:
                        print(f"    Error: {err.get('message', err)}")
                return False
        except Exception as e:
            print(f"[!] Token validation failed: {e}")
            return False
    
    def get_adventures(self, saved: bool = False) -> list:
        """Get all adventures with pagination using OpenSearch."""
        content_type = "saved adventures" if saved else "adventures"
        print(f"\n[*] Fetching {content_type}...")
        
        if not self.username:
            print("[!] Username not set. Please validate token first.")
            return []
        
        adventures = []
        offset = 0
        limit = 30  # Match what the website uses
        
        while True:
            # OpenSearch with SearchInput structure (from network capture)
            variables = {
                "input": {
                    "contentType": ["adventure"],
                    "sortOrder": "updated",
                    "safe": False,
                    "contentRatingFilters": ["Unrated"],  # Get all ratings
                    "username": self.username,
                    "screen": "profile",
                    "limit": limit,
                    "offset": offset
                }
            }
            
            try:
                result = self.make_query_with_retry(OPEN_SEARCH_QUERY, variables)
                
                if "errors" in result:
                    print(f"[!] Query errors: {result['errors']}")
                    break
                
                # Response path: data.search.items
                search_result = result.get("data", {}).get("search", {})
                batch = search_result.get("items", [])
                has_more = search_result.get("hasMore", False)
                
                if not batch:
                    break
                
                adventures.extend(batch)
                print(f"    Got {len(adventures)} {content_type}...")
                offset += len(batch)
                
                # Stop if no more results
                if not has_more:
                    break
                
                # Small delay to be nice to the API
                sleep(0.5)
                
            except Exception as e:
                print(f"[!] Error fetching {content_type}: {e}")
                break
        
        print(f"[+] Total {content_type}: {len(adventures)}")
        return adventures
    
    def get_adventure_details(self, short_id: str) -> dict:
        """Fetch full adventure details including storyCards using shortId."""
        try:
            result = self.make_query_with_retry(ADVENTURE_QUERY, {"shortId": short_id})
            if "errors" in result:
                print(f"    [!] GraphQL errors: {result['errors']}")
            return result.get("data", {}).get("adventure", {})
        except Exception as e:
            print(f"[!] Error fetching adventure {short_id}: {e}")
            return {}
    
    def get_adventure_actions(self, short_id: str, limit: int = 10000) -> list:
        """Fetch adventure story content using ReadScreen batch URLs from S3."""
        all_actions = []
        
        try:
            # First get batch information
            result = self.make_query_with_retry(READ_SCREEN_QUERY, {
                "shortId": short_id,
                "batchNumbers": None,  # Get batch info first
            })
            
            # Debug: check for errors
            if "errors" in result:
                print(f"    API Error: {result['errors']}")
                return []
            
            adventure = result.get("data", {}).get("adventure", {})
            if not adventure:
                print(f"    No adventure data returned")
                return []
            
            batch_info = adventure.get("actionBatchInformation", [])
            
            if not batch_info:
                print("    No batch info found")
                return []
            
            # Get all batch numbers
            batch_numbers = [b.get("batchNumber") for b in batch_info if b.get("batchNumber") is not None]
            
            if not batch_numbers:
                print("    No batches to fetch")
                return []
            
            print(f"    Found {len(batch_numbers)} batches...")
            
            # Request all batches
            result = self.make_query(READ_SCREEN_QUERY, {
                "shortId": short_id,
                "batchNumbers": batch_numbers,
            })
            
            adventure = result.get("data", {}).get("adventure", {})
            read_batches = adventure.get("readBatches", {}).get("batches", [])
            
            if not read_batches:
                print("    No batch URLs returned")
                return []
            
            # Download each batch file from S3
            for batch in read_batches:
                url = batch.get("url")
                batch_num = batch.get("batchNumber", "?")
                
                if not url:
                    continue
                
                try:
                    req = urllib.request.Request(url, headers={
                        "User-Agent": "AIDungeon-Exporter/1.0"
                    })
                    with urllib.request.urlopen(req, timeout=60) as response:
                        content = response.read()
                        
                        # Decompress gzip (magic bytes 1f 8b)
                        if content[:2] == b'\x1f\x8b':
                            content = gzip.decompress(content)
                        
                        # Parse as BSON (the format AI Dungeon uses)
                        try:
                            doc = bson.decode(content)
                            actions = doc.get('actions', [])
                            all_actions.extend(actions)
                            print(f"    Batch {batch_num}: {len(actions)} actions")
                        except Exception as e:
                            # Fallback: try JSON
                            try:
                                data = json.loads(content.decode('utf-8'))
                                if isinstance(data, list):
                                    all_actions.extend(data)
                                elif isinstance(data, dict) and 'actions' in data:
                                    all_actions.extend(data['actions'])
                                print(f"    Batch {batch_num}: JSON format")
                            except:
                                print(f"    Could not decode batch {batch_num}: {e}")
                    
                except Exception as e:
                    print(f"    Error downloading batch {batch_num}: {e}")
                
                sleep(0.2)
            
        except Exception as e:
            print(f"[!] Error fetching story content for {short_id}: {e}")
        
        return all_actions

# =============================================================================
# Export Functions
# =============================================================================

def sanitize_filename(name: str, max_length: int = 50) -> str:
    """Create a safe filename from a string."""
    if not name:
        return "untitled"
    # Remove/replace invalid characters
    safe = re.sub(r'[<>:"/\\|?*]', '', name)
    safe = re.sub(r'\s+', '_', safe)
    safe = safe.strip('_.')
    return safe[:max_length] if safe else "untitled"


def format_adventure_md(adventure: dict) -> str:
    """Format an adventure as raw story text."""
    lines = []
    
    # Story Actions (the main content)
    if adventure.get("actions"):
        for action in adventure["actions"]:
            text = action.get("text", "").strip()
            action_type = action.get("type", "unknown")
            
            if action_type == "story":
                # Initial AI output
                lines.append(text)
                lines.append("")
            elif action_type == "continue":
                # Continue action - AI output in response to "continue"
                if text:
                    lines.append(text)
                    lines.append("")
            else:
                # Player input (do, say, etc.)
                prefix = f"[{action_type.upper()}] " if action_type != "do" else "> "
                lines.append(f"{prefix}{text}")
                lines.append("")
    
    return "\n".join(lines)


def format_adventure_readable(adventure: dict) -> str:
    """Format an adventure as clean, book-like readable text.
    
    - Story text flows as natural paragraphs
    - 'Say' actions appear as quoted dialogue with spacing
    - 'Do' actions are integrated naturally
    - No markdown tags or prefixes
    """
    lines = []
    
    if adventure.get("actions"):
        for action in adventure["actions"]:
            raw_text = action.get("text", "").strip()
            action_type = action.get("type", "unknown")
            
            if not raw_text and action_type == "continue":
                continue
            
            # Clean the text of AI Dungeon prefixes that appear in raw text
            text = raw_text
            prefixes_to_strip = [
                '[SAY] > You say ',
                '[DO] > You ',
                '> You say ',
                '> You ',
                '> ',
                '[SAY] ',
                '[DO] ',
                '[Continue]',
            ]
            for prefix in prefixes_to_strip:
                if text.startswith(prefix):
                    text = text[len(prefix):]
                    break
            
            text = text.strip()
            if not text:
                continue
            
            if action_type == "story":
                # AI story text - clean paragraphs
                for para in text.split('\n'):
                    para = para.strip()
                    if para:
                        lines.append(para)
                        lines.append("")
                        
            elif action_type == "say":
                # Player dialogue - extract just the quote
                if text.startswith('"') and text.endswith('"'):
                    lines.append(f'You say {text}')
                elif text.startswith('"'):
                    lines.append(f'You say {text}')
                else:
                    lines.append(f'You say "{text}"')
                lines.append("")
                
            elif action_type == "do":
                # Player action as narrative
                if text.lower().startswith("you "):
                    lines.append(text.capitalize())
                else:
                    lines.append(f"You {text}")
                lines.append("")
                
            elif action_type == "continue":
                # Continue is AI story output - treat same as story
                for para in text.split('\n'):
                    para = para.strip()
                    if para:
                        lines.append(para)
                        lines.append("")
                        
            else:
                if text:
                    lines.append(text)
                    lines.append("")
    
    # Clean up excessive blank lines
    result = "\n".join(lines)
    while "\n\n\n" in result:
        result = result.replace("\n\n\n", "\n\n")
    
    return result.strip()


def save_content(content: list, content_type: str, format_func) -> None:
    """Save content as both JSON and readable Markdown files."""
    if not content:
        print(f"[!] No {content_type} to save")
        return
    
    # Create directories
    type_dir = DATA_DIR / content_type
    readable_dir = type_dir / "readable"
    type_dir.mkdir(parents=True, exist_ok=True)
    readable_dir.mkdir(parents=True, exist_ok=True)
    
    # Save full JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = type_dir / f"{timestamp}_all_{content_type}.json"
    
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(content, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved JSON: {json_path}")
    
    # Save individual Markdown files
    for item in content:
        title = item.get("title", "untitled")
        pub_id = item.get("publicId", "unknown")[:8]
        
        safe_name = sanitize_filename(title)
        md_path = readable_dir / f"{safe_name}_{pub_id}.md"
        
        try:
            md_content = format_func(item)
            with open(md_path, 'w', encoding='utf-8') as f:
                f.write(md_content)
        except Exception as e:
            print(f"[!] Error saving {title}: {e}")
    
    print(f"[+] Saved {len(content)} {content_type} to: {readable_dir}")
    
    # Download cover images
    images_dir = type_dir / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    image_count = 0
    
    for item in content:
        image_url = item.get("image")
        if image_url:
            title = item.get("title", "untitled")
            pub_id = item.get("publicId", "unknown")[:8]
            safe_name = sanitize_filename(title)
            
            # Determine file extension from URL
            ext = ".jpg"  # Default
            if ".png" in image_url.lower():
                ext = ".png"
            elif ".webp" in image_url.lower():
                ext = ".webp"
            elif ".gif" in image_url.lower():
                ext = ".gif"
            
            image_path = images_dir / f"{safe_name}_{pub_id}{ext}"
            
            try:
                req = urllib.request.Request(
                    image_url,
                    headers={"User-Agent": "AIDungeon-Exporter/1.0"}
                )
                with urllib.request.urlopen(req, timeout=30) as response:
                    with open(image_path, 'wb') as f:
                        f.write(response.read())
                image_count += 1
            except Exception as e:
                # Silent fail for images - just note in summary
                pass
    
    if image_count > 0:
        print(f"[+] Downloaded {image_count} cover images to: {images_dir}")

# =============================================================================
# Main
# =============================================================================

def print_banner():
    print("""
+===============================================================+
|          AI DUNGEON COMPLETE ACCOUNT EXPORTER                 |
|                                                               |
|      Exports: Adventures, Memory, AN, Story Cards             |
+===============================================================+
    """)


def main():
    print_banner()
    
    # Always launch Chrome fresh to ensure we can get the token
    if not launch_chrome_with_debugging():
        print("\n[!] Failed to launch Chrome.")
        print("    Please make sure Google Chrome is installed.")
        sys.exit(1)
    
    # Wait for login and get token
    token = wait_for_aidungeon_login()
    
    if not token:
        print("[!] Could not get token from browser.")
        print("    Make sure you're logged into AI Dungeon in Chrome.")
        sys.exit(1)
    
    # Create client and validate
    client = AIDungeonClient(token)
    if not client.validate_token():
        print("[!] Token expired or invalid. Attempting auto-refresh...")
        if client.refresh_token():
            # Try validation again with new token
            if client.validate_token():
                print("[+] Token refreshed and validated!")
            else:
                print("[!] Still invalid after refresh.")
                print("    Make sure you're logged into AI Dungeon in Chrome.")
                sys.exit(1)
        else:
            print("[!] Could not refresh token.")
            print("    Make sure you're logged into AI Dungeon in Chrome.")
            sys.exit(1)
    
    # Create data directory
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    while True:
        print("\n" + "="*60)
        print("              AI DUNGEON ADVENTURE EXPORTER")
        print("="*60)
        print(f"  Output Directory: {DATA_DIR}")
        print("-"*60)
        print("  1. Export ALL Adventures")
        print("     (Story, Memory, AN, Story Cards, Images)")
        print("")
        print("  2. Search & Export Specific Adventure")
        print("     (Search by name, pick from list)")
        print("")
        print("  3. Export Most Recent Adventure (Debug)")
        print("     (Quick test to verify export works)")
        print("")
        print("  4. Export by URL")
        print("     (Paste any AI Dungeon adventure URL)")
        print("")
        print("  5. Exit")
        print("="*60)
        
        choice = input("\n[?] Enter your choice (1-5): ").strip()
        
        if choice == "1":
            # Export all adventures
            print("\n" + "="*60)
            print("EXPORTING ALL ADVENTURES...")
            print("="*60)
            adventures = client.get_adventures(saved=False)
            
            # Fetch full details and actions for each adventure
            print(f"\n[*] Fetching details and story content for {len(adventures)} adventures...")
            for i, adv in enumerate(adventures):
                # Refresh token periodically (every ~90 seconds)
                client.ensure_fresh_token(max_age_seconds=90)
                
                short_id = adv.get("shortId")
                title = adv.get("title", "untitled")
                action_count = adv.get("actionCount", 0)
                
                print(f"\n[{i+1}/{len(adventures)}] {title}")
                
                # Get full details
                details = client.get_adventure_details(short_id)
                if details:
                    adv.update({k: v for k, v in details.items() if k not in adv or not adv[k]})
                
                # Get actions if there are any
                if action_count > 0:
                    actions = client.get_adventure_actions(short_id, limit=10000)
                    adv["actions"] = actions
                    print(f"    → {len(actions)} actions")
                else:
                    adv["actions"] = []
                    print("    → No actions")
            
            save_content_verbose(adventures, "adventures", format_adventure_md)
            print("\nAll adventures exported!")
            
        elif choice == "2":
            # Search & Export Specific Adventure
            print("\n" + "="*60)
            print("SEARCH & EXPORT SPECIFIC ADVENTURE")
            print("="*60)
            
            search_term = input("\n[?] Enter search term (or press Enter to list all): ").strip().lower()
            
            print("\n[*] Fetching adventure list...")
            adventures_list = client.get_adventures(saved=False)
            
            if not adventures_list:
                print("[!] No adventures found!")
                continue
            
            # Filter by search term if provided
            if search_term:
                matches = [a for a in adventures_list if search_term in a.get("title", "").lower()]
            else:
                matches = adventures_list
            
            if not matches:
                print(f"[!] No adventures matching '{search_term}' found.")
                continue
            
            # Show numbered list (limit to 20 for readability)
            print(f"\n[*] Found {len(matches)} adventures" + (f" matching '{search_term}'" if search_term else "") + ":")
            print("-"*60)
            display_count = min(20, len(matches))
            for i, adv in enumerate(matches[:display_count]):
                title = adv.get("title", "Untitled")[:40]
                action_count = adv.get("actionCount", 0)
                print(f"  {i+1:2}. {title:<42} ({action_count} actions)")
            
            if len(matches) > 20:
                print(f"\n     ... and {len(matches) - 20} more. Use a search term to narrow down.")
            
            print("-"*60)
            
            # Let user pick
            selection = input(f"\n[?] Enter number (1-{display_count}) or 'b' to go back: ").strip()
            
            if selection.lower() == 'b':
                continue
            
            try:
                idx = int(selection) - 1
                if idx < 0 or idx >= display_count:
                    print("[!] Invalid selection.")
                    continue
            except ValueError:
                print("[!] Invalid input. Please enter a number.")
                continue
            
            selected = matches[idx]
            short_id = selected.get("shortId")
            title = selected.get("title", "untitled")
            action_count = selected.get("actionCount", 0)
            
            print(f"\n[*] Exporting: {title}")
            print(f"    Expected actions: {action_count}")
            print(f"[*] Fetching full details...")
            
            # Fetch full adventure details 
            full_adventure = client.get_adventure_details(short_id)
            if full_adventure:
                # Merge list metadata with full details
                full_adventure.update({k: v for k, v in selected.items() if k not in full_adventure or not full_adventure[k]})
                
                # Fetch actions (story content)
                if action_count > 0:
                    print(f"[*] Fetching story content ({action_count} expected)...")
                    actions = client.get_adventure_actions(short_id, limit=10000)
                    full_adventure["actions"] = actions
                    print(f"    Got {len(actions)} actions")
                else:
                    full_adventure["actions"] = []
                
                # Save it
                save_content_verbose([full_adventure], "adventures_selected", format_adventure_md)
                print("\nAdventure exported!")
            else:
                print(f"[!] Could not fetch details for {title}")
            
        elif choice == "3":
            # Debug: Export most recent adventure
            print("\n" + "="*60)
            print("EXPORTING MOST RECENT ADVENTURE (DEBUG)...")
            print("="*60)
            adventures_list = client.get_adventures(saved=False)
            if adventures_list:
                # Find an adventure with actual actions (story content)
                test_item = None
                for adv in adventures_list:
                    if adv.get("actionCount", 0) > 0:
                        test_item = adv
                        break
                
                if not test_item:
                    print("[!] No adventures with story content found. Using first adventure.")
                    test_item = adventures_list[0]
                
                short_id = test_item.get("shortId")
                title = test_item.get("title", "untitled")
                action_count = test_item.get("actionCount", 0)
                
                print(f"\n[*] Selected: {title}")
                print(f"    Expected actions: {action_count}")
                
                # Refresh token before fetching (it may have expired during list fetch)
                print(f"[*] Refreshing token...")
                client.refresh_token()
                
                # Start with existing item data
                full_adventure = dict(test_item)
                
                # Try to get additional details
                print(f"[*] Fetching full details...")
                details = client.get_adventure_details(short_id)
                if details:
                    full_adventure.update(details)
                else:
                    print("    (Using basic metadata only)")
                
                # Fetch actions (story content)
                print(f"[*] Fetching story actions ({action_count} expected)...")
                actions = client.get_adventure_actions(short_id, limit=10000)
                full_adventure["actions"] = actions
                print(f"    Got {len(actions)} actions")
                
                # Save it
                save_content_verbose([full_adventure], "adventures_debug", format_adventure_md)
                print("\nDebug export complete!")
            else:
                print("[!] No adventures found!")
            
        elif choice == "4":
            # Export by URL
            print("\n" + "="*60)
            print("EXPORT BY URL")
            print("="*60)
            print("\nSupported URL formats:")
            print("  - https://play.aidungeon.com/adventure/SHORTID/...")
            print("  - https://play.aidungeon.com/scenario/SHORTID/...")
            print("")
            
            url = input("[?] Enter AI Dungeon URL (or 'b' to go back): ").strip()
            
            if url.lower() == 'b':
                continue
            
            # Extract shortId from URL using regex
            # Patterns: /adventure/SHORTID/... or /scenario/SHORTID/...
            import re
            match = re.search(r'/(?:adventure|scenario)/([A-Za-z0-9]+)(?:/|$|\?)', url)
            
            if not match:
                print("[!] Could not extract ID from URL.")
                print("    Make sure the URL contains /adventure/ID or /scenario/ID")
                continue
            
            short_id = match.group(1)
            print(f"\n[*] Extracted ID: {short_id}")
            
            # Refresh token before fetching
            print(f"[*] Refreshing token...")
            client.refresh_token()
            
            print(f"[*] Fetching adventure details...")
            full_adventure = client.get_adventure_details(short_id)
            
            if not full_adventure:
                print("[!] Could not fetch adventure. It may not exist or you may not have access.")
                continue
            
            title = full_adventure.get("title", "Untitled")
            action_count = full_adventure.get("actionCount", 0)
            print(f"    Title: {title}")
            print(f"    Expected actions: {action_count}")
            
            # Fetch actions (story content)
            print(f"[*] Fetching story actions...")
            actions = client.get_adventure_actions(short_id, limit=10000)
            full_adventure["actions"] = actions
            print(f"    Got {len(actions)} actions")
            
            # Save it
            save_content_verbose([full_adventure], "adventure_url", format_adventure_md)
            print("\nURL export complete!")
            
        elif choice == "5":
            print("\n[*] Goodbye!")
            sys.exit(0)
        
        else:
            print("[!] Invalid choice. Please enter 1-5.")


def save_content_verbose(content: list, content_type: str, format_func) -> None:
    """Save content with hierarchical folder structure: Year/###_Title/"""
    if not content:
        print(f"[!] No {content_type} to save")
        return
    
    # Custom JSON encoder for BSON types
    class BSONEncoder(json.JSONEncoder):
        def default(self, obj):
            if hasattr(obj, 'isoformat'):
                return obj.isoformat()
            if hasattr(obj, '__str__'):
                return str(obj)
            return super().default(obj)
    
    # Sort adventures by creation date (oldest first)
    def get_created_date(item):
        created = item.get("createdAt", "")
        if isinstance(created, str) and created:
            return created
        return "9999-99-99"  # Put items without dates at the end
    
    sorted_content = sorted(content, key=get_created_date)
    
    # Group by year
    year_groups = {}
    for item in sorted_content:
        created = item.get("createdAt", "")
        if isinstance(created, str) and len(created) >= 4:
            year = created[:4]
        else:
            year = "Unknown"
        
        if year not in year_groups:
            year_groups[year] = []
        year_groups[year].append(item)
    
    print(f"\n Organizing {len(content)} adventures into {len(year_groups)} year folders...")
    print("-"*60)
    
    total_saved = 0
    grand_total_chars = 0
    grand_total_words = 0
    grand_total_tokens = 0
    
    for year in sorted(year_groups.keys()):
        adventures = year_groups[year]
        year_dir = DATA_DIR / year
        year_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n {year} ({len(adventures)} adventures)")
        
        for idx, item in enumerate(adventures, 1):
            title = item.get("title", "Untitled")
            
            # Create numbered adventure folder: 1_Title
            safe_title = sanitize_filename(title, max_length=45)
            folder_name = f"{idx}_{safe_title}"
            adv_dir = year_dir / folder_name
            adv_dir.mkdir(parents=True, exist_ok=True)
            
            # Progress display
            action_count = len(item.get("actions", []))
            card_count = len(item.get("storyCards", []))
            has_pe = "✓" if item.get("memory") else "-"
            has_an = "✓" if item.get("authorsNote") else "-"
            
            print(f"  [{idx}] {title[:45]}")
            print(f"         Actions:{action_count:>4} | Cards:{card_count:>2} | PE:{has_pe} AN:{has_an}")
            
            try:
                # Create subdirectories
                story_dir = adv_dir / "Main_Story"
                context_dir = adv_dir / "Context"
                info_dir = adv_dir / "Info"
                thumbnail_dir = adv_dir / "Thumbnail"
                
                story_dir.mkdir(exist_ok=True)
                context_dir.mkdir(exist_ok=True)
                info_dir.mkdir(exist_ok=True)
                
                # Main_Story/ - Raw.txt (story content with tags)
                raw_content = format_func(item)
                raw_path = story_dir / "Raw.txt"
                with open(raw_path, 'w', encoding='utf-8') as f:
                    f.write(raw_content)
                
                # Main_Story/ - Readable.txt (clean book-like format)
                readable_content = format_adventure_readable(item)
                readable_path = story_dir / "Readable.txt"
                with open(readable_path, 'w', encoding='utf-8') as f:
                    f.write(readable_content)
                
                # Info/ - metadata.json
                json_path = info_dir / "metadata.json"
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(item, f, ensure_ascii=False, indent=2, cls=BSONEncoder)
                
                # Info/ - Statistics.txt
                story_text = "\n".join(a.get("text", "") for a in item.get("actions", []))
                memory_text = item.get("memory", "")
                an_text = item.get("authorsNote", "")
                sc_text = "\n".join(w.get("value", "") for w in item.get("storyCards", []))
                total_text = f"{title}\n{item.get('description', '')}\n{memory_text}\n{an_text}\n{sc_text}\n{story_text}"
                total_chars = count_chars(total_text)
                total_words = len(total_text.split())
                total_tokens = estimate_tokens(total_text)
                
                # Track grand totals
                grand_total_chars += total_chars
                grand_total_words += total_words
                grand_total_tokens += total_tokens
                
                stats_content = [
                    "=" * 60,
                    f"TITLE: {title}",
                    "=" * 60,
                    f"Characters: {total_chars:,}",
                    f"Words: {total_words:,}",
                    f"Est. Tokens: {total_tokens:,}",
                    f"Actions: {action_count}",
                    f"Story Cards: {card_count}",
                ]
                if item.get("createdAt"):
                    stats_content.append(f"Created: {item['createdAt']}")
                if item.get("updatedAt"):
                    stats_content.append(f"Updated: {item['updatedAt']}")
                if item.get("publicId"):
                    stats_content.append(f"Public ID: {item['publicId']}")
                stats_content.append("=" * 60)
                
                stats_path = info_dir / "Statistics.txt"
                with open(stats_path, 'w', encoding='utf-8') as f:
                    f.write("\n".join(stats_content))
                
                # Context/ - Memory.txt (Plot Essentials)
                if item.get("memory"):
                    mem_path = context_dir / "Memory.txt"
                    with open(mem_path, 'w', encoding='utf-8') as f:
                        f.write(item["memory"])
                
                # Context/ - Authors_Note.txt
                if item.get("authorsNote"):
                    an_path = context_dir / "Authors_Note.txt"
                    with open(an_path, 'w', encoding='utf-8') as f:
                        f.write(item["authorsNote"])
                
                # Context/ - Instructions.txt (AI Instructions from state.instructions.custom)
                state = item.get("state", {})
                instructions = state.get("instructions") if state else {}
                ai_instructions = instructions.get("custom") if isinstance(instructions, dict) else None
                if ai_instructions:
                    instr_path = context_dir / "Instructions.txt"
                    with open(instr_path, 'w', encoding='utf-8') as f:
                        f.write(ai_instructions)
                
                # Story_Cards/ subfolder
                story_cards = item.get("storyCards", [])
                if story_cards:
                    cards_dir = adv_dir / "Story_Cards"
                    cards_dir.mkdir(exist_ok=True)
                    for i, card in enumerate(story_cards, 1):
                        card_title = card.get("title", card.get("type", "card"))
                        safe_card = sanitize_filename(card_title, max_length=30)
                        card_path = cards_dir / f"{i}_{safe_card}.txt"
                        
                        card_content = []
                        if card.get("title"):
                            card_content.append(f"Title: {card['title']}")
                        if card.get("type"):
                            card_content.append(f"Type: {card['type']}")
                        if card.get("keys"):
                            card_content.append(f"Triggers: {card['keys']}")
                        if card.get("description"):
                            card_content.append(f"Description: {card['description']}")
                        card_content.append("")
                        card_content.append(card.get("value", ""))
                        
                        with open(card_path, 'w', encoding='utf-8') as f:
                            f.write("\n".join(card_content))
                
                # Thumbnail/ - cover image
                image_url = item.get("image")
                if image_url:
                    thumbnail_dir.mkdir(exist_ok=True)
                    
                    # Cloudflare Image Delivery needs /public suffix if no variant specified
                    if 'imagedelivery.net' in image_url and not image_url.endswith('/public'):
                        image_url = image_url + '/public'
                    
                    try:
                        req = urllib.request.Request(image_url, headers={"User-Agent": "AIDungeon-Exporter/1.0"})
                        with urllib.request.urlopen(req, timeout=30) as response:
                            # Detect extension from content-type header
                            content_type = response.headers.get('Content-Type', 'image/jpeg')
                            if 'png' in content_type:
                                ext = ".png"
                            elif 'webp' in content_type:
                                ext = ".webp"
                            elif 'gif' in content_type:
                                ext = ".gif"
                            else:
                                ext = ".jpg"
                            
                            img_path = thumbnail_dir / f"Cover{ext}"
                            with open(img_path, 'wb') as f:
                                f.write(response.read())
                    except Exception as img_err:
                        print(f"         [!] Image download failed: {img_err}")
                
                chars = count_chars(raw_content)
                tokens = estimate_tokens(raw_content)
                print(f"         → Saved: {chars:,} chars, ~{tokens:,} tokens")
                total_saved += 1
                
            except Exception as e:
                print(f"         Error: {e}")
    
    # Calculate novel equivalents (average novel = 70,000-100,000 words, use 85,000 as midpoint)
    WORDS_PER_NOVEL = 85000
    novel_count = grand_total_words / WORDS_PER_NOVEL
    novel_range_low = grand_total_words / 100000
    novel_range_high = grand_total_words / 70000
    
    # Generate export stats file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stats_summary = [
        "=" * 60,
        "         AI DUNGEON EXPORT STATISTICS",
        "=" * 60,
        f"Export Date: {timestamp}",
        "",
        "-" * 60,
        "                   TOTALS",
        "-" * 60,
        f"Adventures Exported:  {total_saved:,}",
        f"Total Characters:     {grand_total_chars:,}",
        f"Total Words:          {grand_total_words:,}",
        f"Estimated Tokens:     {grand_total_tokens:,}",
        "",
        "-" * 60,
        "              NOVEL EQUIVALENTS",
        "-" * 60,
        f"Average Novel (85K words):  {novel_count:.1f} novels",
        f"Range: {novel_range_low:.1f} (at 100K) to {novel_range_high:.1f} (at 70K) novels",
        "",
        "=" * 60,
    ]
    
    stats_file_path = DATA_DIR / "export_stats.txt"
    with open(stats_file_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(stats_summary))
    
    print("\n" + "="*60)
    print(f"Exported {total_saved} adventures to: {DATA_DIR}")
    print("="*60)
    print(f"\n📊 EXPORT TOTALS:")
    print(f"   Characters: {grand_total_chars:,}")
    print(f"   Words:      {grand_total_words:,}")
    print(f"   Tokens:     {grand_total_tokens:,}")
    print(f"   Novels:     ~{novel_count:.1f} (at 85K words/novel)")
    print(f"\n   Stats saved to: {stats_file_path}")
    print("="*60)



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
