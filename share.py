"""
share.py — Lightweight single-file HTTP file server.

Features:
  - Browse, upload, and download files via a modern web UI
  - Admin login with server-side sessions and CSRF protection
  - Upload restrictions (max size, blocked extensions) persisted to config.json
  - Path traversal prevention, login rate limiting
  - Rotating file log for all significant events

Usage:
    set ADMIN_PASSWORD=yourpassword   # Windows
    export ADMIN_PASSWORD=yourpassword  # Linux/macOS
    python share.py

Requirements: Python 3.10+, no third-party packages.
"""

import http.server
import json
import logging
import logging.handlers
import os
import secrets
import shutil
import socketserver
import tempfile
import threading
import time
from email.message import Message
from http import cookies
from urllib.parse import parse_qs, quote, unquote, urlparse

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORT = 8000
BASE_DIR = r"C:\Share"
CHUNK = 1024 * 1024                                         # file streaming chunk size
LOG_FILE = "share.log"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
LOG_MAX_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 5
SESSION_TTL = 8 * 3600                                      # admin session lifetime (seconds)
MAX_FAILURES = 5                                            # failed logins before lockout
LOCKOUT_SECONDS = 300                                       # lockout duration

# config.json lives next to this script so it survives restarts
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("share")
logger.setLevel(logging.INFO)
_log_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
)
_log_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
logger.addHandler(_log_handler)


def human(size: float) -> str:
    """Convert a byte count to a human-readable string (e.g. 1.4 MB)."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

# ---------------------------------------------------------------------------
# Session store  (in-memory, thread-safe)
# ---------------------------------------------------------------------------

_sessions_lock = threading.Lock()
_sessions: dict[str, dict] = {}  # token -> {"expires": float, "csrf": str}


def _prune_sessions() -> None:
    """Remove expired sessions. Must be called with _sessions_lock held."""
    now = time.time()
    for t in [t for t, v in _sessions.items() if v["expires"] < now]:
        del _sessions[t]


def session_create() -> tuple[str, str]:
    """Create a new admin session and return (session_token, csrf_token)."""
    token = secrets.token_hex(32)
    csrf = secrets.token_hex(24)
    with _sessions_lock:
        _prune_sessions()
        _sessions[token] = {"expires": time.time() + SESSION_TTL, "csrf": csrf}
    return token, csrf


def session_get(token: str) -> dict | None:
    """Return the session dict if the token is valid and unexpired, else None."""
    with _sessions_lock:
        s = _sessions.get(token)
        if s and s["expires"] >= time.time():
            return s
        if s:
            del _sessions[token]
    return None


def session_delete(token: str) -> None:
    """Invalidate a session token."""
    with _sessions_lock:
        _sessions.pop(token, None)

# ---------------------------------------------------------------------------
# Login rate limiter  (per IP, in-memory)
# ---------------------------------------------------------------------------

_rl_lock = threading.Lock()
_rl: dict[str, tuple[int, float]] = {}  # ip -> (failure_count, window_start)


def rl_check(ip: str) -> bool:
    """Return True if the IP is currently locked out."""
    with _rl_lock:
        entry = _rl.get(ip)
        if not entry:
            return False
        count, start = entry
        if time.time() - start > LOCKOUT_SECONDS:
            del _rl[ip]
            return False
        return count >= MAX_FAILURES


def rl_fail(ip: str) -> None:
    """Record a failed login attempt for the given IP."""
    with _rl_lock:
        entry = _rl.get(ip)
        if entry and time.time() - entry[1] <= LOCKOUT_SECONDS:
            _rl[ip] = (entry[0] + 1, entry[1])
        else:
            _rl[ip] = (1, time.time())


def rl_reset(ip: str) -> None:
    """Clear the failure counter for the given IP after a successful login."""
    with _rl_lock:
        _rl.pop(ip, None)

# ---------------------------------------------------------------------------
# Upload configuration  (persisted to config.json)
# ---------------------------------------------------------------------------

class Config:
    """
    Runtime upload restrictions editable by the admin via /config.

    Settings are loaded from CONFIG_FILE at startup and saved back on every
    admin update, so they survive server restarts.
    """

    _lock = threading.Lock()
    max_upload_mb: int = 100         # MB; 0 = unlimited
    blocked_extensions: set = set() # e.g. {".exe", ".bat"}

    @classmethod
    def load(cls) -> None:
        """Load settings from CONFIG_FILE. Silent if the file does not exist."""
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                data = json.load(f)
            with cls._lock:
                cls.max_upload_mb = int(data.get("max_upload_mb", 0))
                cls.blocked_extensions = set(data.get("blocked_extensions", []))
        except FileNotFoundError:
            pass
        except Exception as exc:
            print(f"Warning: could not load {CONFIG_FILE}: {exc}")

    @classmethod
    def save(cls) -> None:
        """Persist current settings to CONFIG_FILE."""
        with cls._lock:
            data = {
                "max_upload_mb": cls.max_upload_mb,
                "blocked_extensions": sorted(cls.blocked_extensions),
            }
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            print(f"Warning: could not save {CONFIG_FILE}: {exc}")

    @classmethod
    def update(cls, max_mb: int, blocked: set) -> None:
        """Apply new settings and persist them immediately."""
        with cls._lock:
            cls.max_upload_mb = max_mb
            cls.blocked_extensions = blocked
        cls.save()

    @classmethod
    def check_upload(cls, filename: str, size: int) -> str | None:
        """
        Validate a pending upload against current restrictions.
        Returns an error message string if rejected, or None if allowed.
        """
        with cls._lock:
            if cls.max_upload_mb and size > cls.max_upload_mb * 1024 * 1024:
                return f"File too large (max {cls.max_upload_mb} MB)"
            ext = os.path.splitext(filename)[1].lower()
            if ext in cls.blocked_extensions:
                return f"Extension '{ext}' is blocked"
        return None

# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class Handler(http.server.SimpleHTTPRequestHandler):
    """
    Handles all HTTP traffic for the file server.

    Routes:
        GET  /              — directory listing (any user)
        GET  /login         — admin login form
        POST /login         — process login, set session cookie
        GET  /logout        — invalidate session, redirect to /
        GET  /config        — upload restriction settings (admin only)
        POST /config        — save upload restriction settings (admin only)
        GET  /<path>        — serve file or sub-directory listing
        POST /<path>        — upload file, or form actions (delete / rename /
                              mkdir / rmdir) via X-CSRF-Token header
    """

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def parse_path(self, raw_path: str) -> tuple[str, dict]:
        """Split a raw request path into (decoded_path, query_dict)."""
        parsed = urlparse(raw_path)
        return unquote(parsed.path), parse_qs(parsed.query)

    def translate(self, path: str) -> str | None:
        """
        Map a URL path to an absolute filesystem path inside BASE_DIR.
        Returns None if the resolved path escapes BASE_DIR (path traversal
        attempt), which the caller must treat as a 403.
        """
        clean = unquote(path.split("?")[0])
        full = os.path.normpath(os.path.join(BASE_DIR, clean.strip("/")))
        base = os.path.normpath(BASE_DIR)
        if full != base and not full.startswith(base + os.sep):
            return None
        return full

    def _session_token(self) -> str | None:
        """Extract the session token from the request Cookie header."""
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        m = jar.get("session")
        return m.value if m else None

    def is_admin(self) -> bool:
        """Return True if the request carries a valid, unexpired admin session."""
        token = self._session_token()
        return token is not None and session_get(token) is not None

    def _csrf_token(self) -> str | None:
        """Return the CSRF token for the current session, or None."""
        token = self._session_token()
        if not token:
            return None
        s = session_get(token)
        return s["csrf"] if s else None

    def _validate_csrf(self) -> bool:
        """
        Verify the X-CSRF-Token request header against the session's CSRF token.
        Uses a timing-safe comparison to prevent timing attacks.
        """
        expected = self._csrf_token()
        if not expected:
            return False
        provided = self.headers.get("X-CSRF-Token", "")
        return secrets.compare_digest(expected, provided)

    def send_html(self, html: str, status: int = 200,
                  extra_headers: dict | None = None) -> None:
        """Send an HTML response with optional additional headers."""
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(html.encode())

    def send_error_text(self, status: int, msg: str) -> None:
        """Send a plain-text error response."""
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(msg.encode())

    def redirect(self, location: str, extra_headers: dict | None = None) -> None:
        """Send a 303 See Other redirect."""
        self.send_response(303)
        self.send_header("Location", location)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

    def _session_cookie_header(self, token: str) -> str:
        """Build a Set-Cookie header value that creates a secure session cookie."""
        return f"session={token}; Path=/; HttpOnly; SameSite=Strict"

    def _expire_session_cookie(self) -> str:
        """Build a Set-Cookie header value that immediately expires the session cookie."""
        return "session=; Path=/; HttpOnly; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT"

    def serve_file(self, path: str) -> None:
        """Stream a file to the client in CHUNK-sized pieces."""
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK):
                self.wfile.write(chunk)

    def log_event(self, event_type: str, client_ip: str,
                  filename: str, size: int) -> None:
        """Write a structured event line to the rotating log file."""
        logger.info("%s ip=%s filename=%s size=%d",
                    event_type, client_ip, filename, size)

    def _build_breadcrumbs(self, request_path: str) -> str:
        """Return HTML breadcrumb links for the given URL path."""
        parts = [p for p in request_path.strip("/").split("/") if p]
        crumbs = ['<a href="/">📂 Share</a>']
        for i, part in enumerate(parts):
            href = "/" + "/".join(quote(p) for p in parts[:i + 1])
            crumbs.append(f'<a href="{href}">{part}</a>')
        return ' <span class="bc-sep">/</span> '.join(crumbs)

    # ------------------------------------------------------------------
    # Page renderers
    # ------------------------------------------------------------------

    def login_page(self, message: str = "") -> None:
        """Render the admin login form, optionally with an error message."""
        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {{
    --bg: linear-gradient(135deg,#0f172a,#020617);
    --surface: rgba(15,23,42,0.92); --surface2: #1e293b;
    --text: #e2e8f0; --border: #334155; --accent: #3b82f6; --danger: #fda4af;
}}
[data-theme="light"] {{
    --bg: linear-gradient(135deg,#e0e7ff,#f0f9ff);
    --surface: rgba(255,255,255,0.92); --surface2: #f1f5f9;
    --text: #1e293b; --border: #cbd5e1; --accent: #2563eb; --danger: #dc2626;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; min-height: 100vh; }}
.container {{ max-width: 420px; margin: 80px auto; padding: 28px; background: var(--surface); border-radius: 18px; border: 1px solid var(--border); }}
h2 {{ margin-bottom: 20px; }}
input {{ width: 100%; padding: 12px; margin: 8px 0 16px; border-radius: 10px; border: 1px solid var(--border); background: var(--surface2); color: var(--text); font-size: 15px; }}
button {{ width: 100%; padding: 12px; border: none; background: var(--accent); border-radius: 10px; color: white; cursor: pointer; font-size: 16px; }}
.message {{ margin-bottom: 14px; color: var(--danger); font-size: 14px; }}
</style>
</head>
<body>
<div class="container">
    <h2>👤 Admin Login</h2>
    {f'<div class="message">{message}</div>' if message else ''}
    <form method="POST" action="/login">
        <input type="password" name="password" placeholder="Password" autocomplete="off" required>
        <button type="submit">Login</button>
    </form>
</div>
<script>(function(){{const t=localStorage.getItem("theme")||"dark";document.documentElement.setAttribute("data-theme",t);}})();</script>
</body>
</html>"""
        self.send_html(html)

    def directory_listing(self, path: str, request_path: str) -> None:
        """Render the main file browser page for the given directory."""
        import time as _time

        items = os.listdir(path)
        admin = self.is_admin()
        csrf = self._csrf_token() or ""

        # Optional folder title / description from a .title file
        meta_title = ""
        meta_desc = ""
        meta_file = os.path.join(path, ".title")
        if os.path.isfile(meta_file):
            try:
                with open(meta_file, encoding="utf-8") as fh:
                    lines = fh.read().splitlines()
                if lines:
                    meta_title = lines[0]
                if len(lines) > 1:
                    meta_desc = " ".join(lines[1:])
            except Exception:
                pass

        # Build HTML rows for both card and detail (table) views
        card_rows = ""
        detail_rows = ""

        # Parent directory shortcut
        if request_path != "/":
            parent_parts = request_path.rstrip("/").split("/")[:-1]
            parent_href = "/".join(parent_parts) or "/"
            card_rows += f'''
            <div class="card" data-name=".." data-size="0" data-mtime="0">
                <div class="file"><div class="name">📁 <a href="{parent_href}">..</a></div></div>
            </div>'''
            detail_rows += f'''
            <tr class="detail-row" data-name=".." data-size="0" data-mtime="0">
                <td>📁 <a href="{parent_href}">..</a></td><td></td><td></td><td></td>
            </tr>'''

        for name in sorted(items, key=str.lower):
            if name == ".title":
                continue
            full = os.path.join(path, name)
            url = quote(os.path.join(request_path, name).replace("\\", "/"))
            mtime_ts = int(os.path.getmtime(full))
            mtime_str = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(mtime_ts))

            if os.path.isdir(full):
                del_btn = (
                    f'<button class="btn delete" data-action="rmdir" data-file="{quote(name)}">🗑</button>'
                    if admin else ""
                )
                card_rows += f'''
            <div class="card" data-name="{name}" data-size="0" data-mtime="{mtime_ts}">
                <div class="file">
                    <div class="name">📁 <a href="{url}">{name}</a></div>
                    <div class="meta">{mtime_str}</div>
                </div>
                <div class="actions">{del_btn}</div>
            </div>'''
                detail_rows += f'''
            <tr class="detail-row" data-name="{name}" data-size="0" data-mtime="{mtime_ts}">
                <td>📁 <a href="{url}">{name}</a></td>
                <td>Folder</td><td>{mtime_str}</td>
                <td class="actions">{del_btn}</td>
            </tr>'''
            else:
                fsize = os.path.getsize(full)
                size_text = human(fsize)
                action_btns = f'<button class="btn" data-action="download" data-url="{url}">⬇</button>'
                if admin:
                    action_btns += (
                        f'<button class="btn rename" data-action="rename" data-file="{quote(name)}">✏️</button>'
                        f'<button class="btn delete" data-action="delete" data-file="{quote(name)}">🗑</button>'
                    )
                card_rows += f'''
            <div class="card" data-name="{name}" data-size="{fsize}" data-mtime="{mtime_ts}">
                <div class="file">
                    <div class="name">{name}</div>
                    <div class="meta">{size_text} · {mtime_str}</div>
                </div>
                <div class="actions">{action_btns}</div>
            </div>'''
                detail_rows += f'''
            <tr class="detail-row" data-name="{name}" data-size="{fsize}" data-mtime="{mtime_ts}">
                <td class="dt-name">{name}</td>
                <td>{size_text}</td><td>{mtime_str}</td>
                <td class="actions">{action_btns}</td>
            </tr>'''

        auth_html = (
            '<a class="admin-link" href="/config">⚙ Config</a>'
            '<a class="admin-link" href="/logout">👤 Logout</a>'
            if admin else
            '<a class="admin-link" href="/login">👤 Admin login</a>'
        )

        folder_header = ""
        if meta_title:
            folder_header = f'<div class="folder-header"><div class="folder-title">{meta_title}</div>'
            if meta_desc:
                folder_header += f'<div class="folder-desc">{meta_desc}</div>'
            folder_header += "</div>"

        breadcrumbs = self._build_breadcrumbs(request_path)

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {{
    --bg: linear-gradient(135deg,#0f172a,#020617);
    --surface: rgba(30,41,59,0.7); --surface2: #1e293b;
    --text: #e2e8f0; --text-muted: #94a3b8; --border: #334155;
    --accent: #3b82f6; --accent-soft: rgba(59,130,246,0.12);
    --danger: #ef4444; --success: #10b981;
    --link: #93c5fd; --header-link: #a5b4fc;
    --drop-border: #475569; --table-head-bg: rgba(15,23,42,0.6);
}}
[data-theme="light"] {{
    --bg: linear-gradient(135deg,#e0e7ff,#f0f9ff);
    --surface: rgba(255,255,255,0.85); --surface2: #f1f5f9;
    --text: #1e293b; --text-muted: #64748b; --border: #cbd5e1;
    --accent: #2563eb; --accent-soft: rgba(37,99,235,0.10);
    --danger: #dc2626; --success: #059669;
    --link: #1d4ed8; --header-link: #4f46e5;
    --drop-border: #94a3b8; --table-head-bg: rgba(226,232,240,0.8);
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; min-height: 100vh; }}
a {{ color: var(--link); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
/* ── Header ── */
.header {{ max-width: 960px; margin: auto; padding: 18px 20px; display: flex; justify-content: space-between; align-items: center; font-size: 22px; font-weight: bold; gap: 12px; }}
.header-right {{ display: flex; align-items: center; gap: 10px; }}
.admin-link {{ color: var(--header-link); font-size: 15px; background: var(--accent-soft); padding: 8px 14px; border-radius: 999px; }}
.admin-link:hover {{ text-decoration: none; filter: brightness(1.15); }}
.icon-btn {{ background: var(--accent-soft); border: none; color: var(--text); width: 36px; height: 36px; border-radius: 50%; cursor: pointer; font-size: 16px; display: flex; align-items: center; justify-content: center; }}
.icon-btn:hover {{ filter: brightness(1.2); }}
/* ── Breadcrumb ── */
.breadcrumb {{ max-width: 960px; margin: 0 auto; padding: 0 20px 12px; font-size: 13px; color: var(--text-muted); }}
.breadcrumb a {{ color: var(--text-muted); }}
.breadcrumb a:hover {{ color: var(--link); }}
.bc-sep {{ margin: 0 4px; }}
/* ── Layout ── */
.container {{ max-width: 960px; margin: auto; padding: 0 20px 40px; }}
.folder-header {{ margin-bottom: 18px; padding: 16px 20px; background: var(--surface); border-radius: 14px; border: 1px solid var(--border); }}
.folder-title {{ font-size: 20px; font-weight: 700; }}
.folder-desc {{ margin-top: 4px; color: var(--text-muted); font-size: 14px; }}
/* ── Toolbar ── */
.toolbar {{ display: flex; gap: 10px; margin-bottom: 16px; align-items: center; }}
.search {{ flex: 1; padding: 10px 14px; border-radius: 10px; border: 1px solid var(--border); background: var(--surface2); color: var(--text); font-size: 15px; outline: none; }}
.search:focus {{ border-color: var(--accent); }}
.search::placeholder {{ color: var(--text-muted); }}
select.sort-select {{ padding: 9px 10px; border-radius: 10px; border: 1px solid var(--border); background: var(--surface2); color: var(--text); font-size: 14px; cursor: pointer; outline: none; }}
/* ── Card view ── */
#card-list {{ display: block; }}
#detail-list {{ display: none; }}
body.detail-mode #card-list {{ display: none; }}
body.detail-mode #detail-list {{ display: block; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 13px 16px; margin-bottom: 10px; display: flex; justify-content: space-between; gap: 12px; align-items: center; }}
.card:hover {{ filter: brightness(1.05); }}
.file {{ flex: 1; min-width: 0; }}
.name {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 15px; }}
.meta {{ font-size: 12px; color: var(--text-muted); margin-top: 3px; }}
/* ── Buttons ── */
.actions {{ display: flex; gap: 6px; flex-shrink: 0; align-items: center; }}
.btn {{ background: var(--accent); border: none; padding: 0 14px; height: 34px; border-radius: 8px; color: #fff; cursor: pointer; font-size: 15px; line-height: 1; display: inline-flex; align-items: center; justify-content: center; transition: filter 0.15s; white-space: nowrap; }}
.btn:hover {{ filter: brightness(1.15); }}
.btn.delete {{ background: var(--danger); }}
.btn.rename {{ background: #8b5cf6; }}
/* ── Detail table ── */
#detail-list table {{ width: 100%; border-collapse: collapse; font-size: 14px; table-layout: fixed; }}
#detail-list colgroup col.col-name {{ width: auto; }}
#detail-list colgroup col.col-size {{ width: 80px; }}
#detail-list colgroup col.col-date {{ width: 140px; }}
#detail-list colgroup col.col-actions {{ width: 110px; }}
#detail-list th {{ background: var(--table-head-bg); color: var(--text-muted); text-align: left; padding: 9px 12px; font-weight: 600; border-bottom: 1px solid var(--border); }}
#detail-list th:last-child {{ text-align: right; }}
#detail-list tr {{ border-bottom: 1px solid var(--border); }}
#detail-list td {{ padding: 6px 12px; vertical-align: middle; border: none; }}
#detail-list td.actions {{ padding: 6px 8px; text-align: right; }}
.detail-row:hover td {{ background: var(--surface2); }}
.dt-name {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: block; }}
/* ── Upload ── */
.drop {{ border: 2px dashed var(--drop-border); padding: 24px; text-align: center; border-radius: 12px; margin-top: 20px; color: var(--text-muted); }}
.drop.dragover {{ border-color: var(--accent); background: var(--accent-soft); }}
.progress {{ height: 8px; background: var(--surface2); border-radius: 6px; margin-top: 10px; overflow: hidden; }}
.bar {{ height: 100%; width: 0%; background: var(--accent); transition: width 0.1s; }}
.upload-btn {{ margin-top: 14px; display: inline-block; padding: 9px 16px; background: var(--success); border-radius: 8px; cursor: pointer; color: #fff; font-size: 14px; }}
input[type=file] {{ display: none; }}
/* ── Modals ── */
.modal-backdrop {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.55); z-index: 100; align-items: center; justify-content: center; }}
.modal-backdrop.open {{ display: flex; }}
.modal {{ background: var(--surface2); border: 1px solid var(--border); border-radius: 16px; padding: 28px; width: 340px; max-width: 92vw; }}
.modal h3 {{ font-size: 16px; margin-bottom: 16px; }}
.modal input {{ width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); background: var(--surface); color: var(--text); font-size: 15px; outline: none; }}
.modal input:focus {{ border-color: var(--accent); }}
.modal-actions {{ margin-top: 16px; display: flex; gap: 10px; justify-content: flex-end; }}
.modal-actions .btn {{ padding: 8px 18px; font-size: 14px; border-radius: 8px; border: none; cursor: pointer; color: #fff; }}
.modal-actions .btn-primary {{ background: var(--accent); }}
.modal-actions .btn-cancel {{ background: transparent; color: var(--text-muted); border: 1px solid var(--border); }}
</style>
</head>
<body data-csrf="{csrf}">

<!-- New Folder modal -->
<div class="modal-backdrop" id="mkdir-backdrop">
  <div class="modal">
    <h3>📁 New Folder</h3>
    <input type="text" id="mkdir-name" placeholder="Folder name" maxlength="200" autocomplete="off">
    <div class="modal-actions">
      <button class="btn btn-cancel" id="mkdir-cancel">Cancel</button>
      <button class="btn btn-primary" id="mkdir-ok">Create</button>
    </div>
  </div>
</div>

<!-- Rename modal -->
<div class="modal-backdrop" id="rename-backdrop">
  <div class="modal">
    <h3>✏️ Rename File</h3>
    <input type="text" id="rename-input" placeholder="New name" maxlength="200" autocomplete="off">
    <div class="modal-actions">
      <button class="btn btn-cancel" id="rename-cancel">Cancel</button>
      <button class="btn btn-primary" id="rename-ok">Rename</button>
    </div>
  </div>
</div>

<div class="header">
    <div>📂 File Share</div>
    <div class="header-right">
        <button class="icon-btn" id="theme-btn" title="Toggle theme">🌙</button>
        <button class="icon-btn" id="view-btn" title="Toggle view">☰</button>
        {auth_html}
    </div>
</div>

<div class="breadcrumb">{breadcrumbs}</div>

<div class="container">

{folder_header}

<div class="toolbar">
    <input class="search" id="search" placeholder="Search files…">
    <select class="sort-select" id="sort-select">
        <option value="name-asc">Name ↑</option>
        <option value="name-desc">Name ↓</option>
        <option value="size-asc">Size ↑</option>
        <option value="size-desc">Size ↓</option>
        <option value="date-asc">Date ↑</option>
        <option value="date-desc">Date ↓</option>
    </select>
    <button class="btn" id="mkdir-btn" style="flex-shrink:0;padding:8px 14px;font-size:13px;">📁 New Folder</button>
</div>

<div id="card-list">{card_rows}</div>

<div id="detail-list">
<table>
<colgroup>
  <col class="col-name">
  <col class="col-size">
  <col class="col-date">
  <col class="col-actions">
</colgroup>
<thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead>
<tbody>{detail_rows}</tbody>
</table>
</div>

<h3 style="margin-top:28px;margin-bottom:10px;color:var(--text-muted);font-size:15px;">📦 Upload</h3>
<div class="drop" id="drop">Drag &amp; drop files here</div>
<label class="upload-btn">📂 Browse Files<input type="file" id="fileInput" multiple></label>
<div class="progress"><div class="bar" id="bar"></div></div>

</div>

<script>
const CSRF = document.body.dataset.csrf || "";
const bar  = document.getElementById("bar");

// ── Theme ──────────────────────────────────────────────────────────────────
const themeBtn = document.getElementById("theme-btn");
function applyTheme(t) {{
    document.documentElement.setAttribute("data-theme", t);
    themeBtn.textContent = t === "light" ? "🌙" : "☀️";
}}
applyTheme(localStorage.getItem("theme") || "dark");
themeBtn.onclick = () => {{
    const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    localStorage.setItem("theme", next);
    applyTheme(next);
}};

// ── View toggle (card ↔ detail) ────────────────────────────────────────────
const viewBtn = document.getElementById("view-btn");
function applyView(mode) {{
    document.body.classList.toggle("detail-mode", mode === "detail");
    viewBtn.textContent = mode === "detail" ? "⊞" : "☰";
}}
applyView(localStorage.getItem("view") || "detail");
viewBtn.onclick = () => {{
    const next = document.body.classList.contains("detail-mode") ? "card" : "detail";
    localStorage.setItem("view", next);
    applyView(next);
}};

// ── Sort ───────────────────────────────────────────────────────────────────
const sortSel = document.getElementById("sort-select");
function sortItems(key) {{
    const [field, dir] = key.split("-");
    const asc = dir === "asc";
    function val(el) {{
        if (field === "name") return (el.dataset.name || "").toLowerCase();
        if (field === "size") return parseInt(el.dataset.size  || "0");
        return parseInt(el.dataset.mtime || "0");
    }}
    const cardList = document.getElementById("card-list");
    [...cardList.querySelectorAll(".card")]
        .sort((a, b) => {{ const av = val(a), bv = val(b); return av < bv ? (asc ? -1 : 1) : av > bv ? (asc ? 1 : -1) : 0; }})
        .forEach(c => cardList.appendChild(c));

    const tbody = document.querySelector("#detail-list tbody");
    [...tbody.querySelectorAll(".detail-row")]
        .sort((a, b) => {{ const av = val(a), bv = val(b); return av < bv ? (asc ? -1 : 1) : av > bv ? (asc ? 1 : -1) : 0; }})
        .forEach(r => tbody.appendChild(r));
}}
const savedSort = localStorage.getItem("sort") || "name-asc";
sortSel.value = savedSort;
sortItems(savedSort);
sortSel.onchange = () => {{ localStorage.setItem("sort", sortSel.value); sortItems(sortSel.value); }};

// ── Search ─────────────────────────────────────────────────────────────────
document.getElementById("search").oninput = e => {{
    const val = e.target.value.toLowerCase();
    document.querySelectorAll(".card").forEach(c => {{
        c.style.display = c.dataset.name.toLowerCase().includes(val) ? "" : "none";
    }});
    document.querySelectorAll(".detail-row").forEach(r => {{
        r.style.display = r.dataset.name.toLowerCase().includes(val) ? "" : "none";
    }});
}};

// ── CSRF-authenticated POST helper ─────────────────────────────────────────
function csrfPost(body) {{
    return fetch(window.location.pathname, {{
        method: "POST",
        headers: {{"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": CSRF}},
        body: new URLSearchParams(body)
    }});
}}

// ── File download with progress bar ───────────────────────────────────────
function download(url) {{
    const xhr = new XMLHttpRequest();
    xhr.open("GET", url);
    xhr.responseType = "blob";
    xhr.onprogress = e => {{ if (e.lengthComputable) bar.style.width = (e.loaded / e.total * 100) + "%"; }};
    xhr.onload = () => {{
        const a = document.createElement("a");
        a.href = URL.createObjectURL(xhr.response);
        a.download = decodeURIComponent(url.split("/").pop());
        a.click();
        bar.style.width = "0%";
    }};
    xhr.send();
}}

// ── Delegated action button handler ───────────────────────────────────────
document.addEventListener("click", e => {{
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;
    const file   = btn.dataset.file ? decodeURIComponent(btn.dataset.file) : "";

    if (action === "download") {{
        download(btn.dataset.url);
    }} else if (action === "delete") {{
        if (!confirm("Delete file '" + file + "'?")) return;
        csrfPost({{action: "delete", name: file}})
            .then(r => r.ok ? location.reload() : r.text().then(t => alert("Error: " + t)));
    }} else if (action === "rmdir") {{
        if (!confirm("Delete folder '" + file + "' and all its contents?")) return;
        csrfPost({{action: "rmdir", name: file}})
            .then(r => r.ok ? location.reload() : r.text().then(t => alert("Error: " + t)));
    }} else if (action === "rename") {{
        openRename(file);
    }}
}});

// ── New Folder modal ───────────────────────────────────────────────────────
(function() {{
    const backdrop = document.getElementById("mkdir-backdrop");
    const input    = document.getElementById("mkdir-name");
    const ok       = document.getElementById("mkdir-ok");
    const cancel   = document.getElementById("mkdir-cancel");
    const btn      = document.getElementById("mkdir-btn");
    if (!backdrop || !input || !ok || !cancel || !btn) return;

    btn.onclick     = () => {{ input.value = ""; backdrop.classList.add("open"); input.focus(); }};
    cancel.onclick  = () => backdrop.classList.remove("open");
    backdrop.onclick = e => {{ if (e.target === backdrop) backdrop.classList.remove("open"); }};
    input.onkeydown = e => {{ if (e.key === "Enter") ok.click(); if (e.key === "Escape") cancel.click(); }};
    ok.onclick = () => {{
        const name = input.value.trim();
        if (!name) return;
        csrfPost({{action: "mkdir", name}})
            .then(r => r.ok ? location.reload() : r.text().then(t => alert("Error: " + t)));
        backdrop.classList.remove("open");
    }};
}})();

// ── Rename modal ───────────────────────────────────────────────────────────
let _renameOld = "";
function openRename(oldName) {{
    const backdrop = document.getElementById("rename-backdrop");
    const input    = document.getElementById("rename-input");
    _renameOld = oldName;
    input.value = oldName;
    backdrop.classList.add("open");
    input.focus();
    input.select();
}}
(function() {{
    const backdrop = document.getElementById("rename-backdrop");
    const input    = document.getElementById("rename-input");
    const ok       = document.getElementById("rename-ok");
    const cancel   = document.getElementById("rename-cancel");
    if (!backdrop || !input || !ok || !cancel) return;

    cancel.onclick   = () => backdrop.classList.remove("open");
    backdrop.onclick = e => {{ if (e.target === backdrop) backdrop.classList.remove("open"); }};
    input.onkeydown  = e => {{ if (e.key === "Enter") ok.click(); if (e.key === "Escape") cancel.click(); }};
    ok.onclick = () => {{
        const newName = input.value.trim();
        if (!newName || newName === _renameOld) {{ backdrop.classList.remove("open"); return; }}
        csrfPost({{action: "rename", old: _renameOld, "new": newName}})
            .then(r => r.ok ? location.reload() : r.text().then(t => alert("Error: " + t)));
        backdrop.classList.remove("open");
    }};
}})();

// ── File upload ────────────────────────────────────────────────────────────
const drop = document.getElementById("drop");
drop.ondragover  = e => {{ e.preventDefault(); drop.classList.add("dragover"); }};
drop.ondragleave = () => drop.classList.remove("dragover");
drop.ondrop = e => {{
    e.preventDefault();
    drop.classList.remove("dragover");
    for (let file of e.dataTransfer.files) upload(file);
}};
document.getElementById("fileInput").onchange = e => {{
    for (let file of e.target.files) upload(file);
    e.target.value = "";
}};
function upload(file) {{
    const xhr = new XMLHttpRequest();
    xhr.upload.onprogress = e => {{ bar.style.width = (e.loaded / e.total * 100) + "%"; }};
    xhr.onload = () => {{
        bar.style.width = "0%";
        if (xhr.status === 200) location.reload();
        else alert("Upload rejected: " + xhr.responseText);
    }};
    const form = new FormData();
    form.append("file", file);
    xhr.open("POST", window.location.pathname);
    xhr.setRequestHeader("X-CSRF-Token", CSRF);
    xhr.send(form);
}}
</script>

</body>
</html>"""
        self.send_html(html)

    def config_page(self, message: str = "", error: bool = False) -> None:
        """
        Render the admin upload-restrictions settings page.

        If message is provided it is shown as a toast notification — green
        for success, red for error — that fades out after 3 seconds.
        """
        blocked  = ", ".join(sorted(Config.blocked_extensions))
        max_mb   = Config.max_upload_mb or ""
        csrf     = self._csrf_token() or ""
        toast_js = ""
        if message:
            color    = "#ef4444" if error else "#10b981"
            toast_js = f"""
const _toast = document.getElementById("toast");
_toast.textContent = {repr(message)};
_toast.style.background = "{color}";
_toast.style.opacity = "1";
_toast.style.transform = "translateY(0)";
setTimeout(() => {{
    _toast.style.opacity = "0";
    _toast.style.transform = "translateY(-16px)";
}}, 3000);"""

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {{
    --bg: linear-gradient(135deg,#0f172a,#020617); --surface: rgba(15,23,42,0.92); --surface2: #1e293b;
    --text: #e2e8f0; --text-muted: #94a3b8; --border: #334155;
    --accent: #3b82f6; --link: #93c5fd;
}}
[data-theme="light"] {{
    --bg: linear-gradient(135deg,#e0e7ff,#f0f9ff); --surface: rgba(255,255,255,0.92); --surface2: #f1f5f9;
    --text: #1e293b; --text-muted: #64748b; --border: #cbd5e1; --accent: #2563eb; --link: #1d4ed8;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; min-height: 100vh; }}
a {{ color: var(--link); text-decoration: none; }}
.header {{ max-width: 640px; margin: auto; padding: 18px 20px; display: flex; justify-content: space-between; align-items: center; font-size: 20px; font-weight: bold; }}
.container {{ max-width: 640px; margin: auto; padding: 0 20px 40px; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 28px; }}
h2 {{ font-size: 18px; margin-bottom: 22px; }}
label {{ display: block; font-size: 13px; color: var(--text-muted); margin-bottom: 6px; margin-top: 18px; }}
label:first-of-type {{ margin-top: 0; }}
input[type=number], input[type=text] {{ width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); background: var(--surface2); color: var(--text); font-size: 15px; outline: none; }}
input:focus {{ border-color: var(--accent); }}
.hint {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}
.actions {{ margin-top: 26px; display: flex; gap: 10px; }}
.btn {{ padding: 10px 20px; border: none; border-radius: 10px; color: #fff; cursor: pointer; font-size: 15px; }}
.btn-primary {{ background: var(--accent); }}
.btn-secondary {{ background: var(--surface2); color: var(--text); border: 1px solid var(--border); }}
#toast {{
    position: fixed; top: 24px; left: 50%; transform: translate(-50%, -16px);
    padding: 12px 24px; border-radius: 10px; color: #fff; font-size: 15px; font-weight: 500;
    opacity: 0; pointer-events: none; transition: opacity 0.4s ease, transform 0.4s ease;
    z-index: 999; white-space: nowrap;
}}
</style>
</head>
<body>
<div id="toast"></div>
<div class="header"><div>⚙ Config</div><a href="/">← Back</a></div>
<div class="container">
<div class="card">
<h2>Upload restrictions</h2>
<form method="POST" action="/config">
    <input type="hidden" name="csrf" value="{csrf}">
    <label for="max_mb">Max upload size (MB)</label>
    <input type="number" id="max_mb" name="max_mb" min="0" value="{max_mb}" placeholder="0 = unlimited">
    <div class="hint">Set to 0 to allow any size.</div>
    <label for="blocked">Blocked extensions</label>
    <input type="text" id="blocked" name="blocked" value="{blocked}" placeholder=".exe, .bat, .sh">
    <div class="hint">Comma-separated, e.g. .exe, .bat — leave empty to allow all.</div>
    <div class="actions">
        <button type="submit" class="btn btn-primary">Save</button>
        <a href="/" class="btn btn-secondary">Cancel</a>
    </div>
</form>
</div>
</div>
<script>
(function(){{const t=localStorage.getItem("theme")||"dark";document.documentElement.setAttribute("data-theme",t);}})();
{toast_js}
</script>
</body>
</html>"""
        self.send_html(html)

    # ------------------------------------------------------------------
    # GET handler
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        request_path, query = self.parse_path(self.path)

        if request_path == "/login":
            self.login_page()
            return

        if request_path == "/logout":
            token = self._session_token()
            if token:
                session_delete(token)
            self.redirect("/", extra_headers={"Set-Cookie": self._expire_session_cookie()})
            return

        if request_path == "/config":
            if not self.is_admin():
                self.redirect("/login")
                return
            msg   = query.get("msg",   [""])[0]
            error = query.get("error", [""])[0] == "1"
            self.config_page(msg, error)
            return

        path = self.translate(request_path)
        if path is None:
            self.send_error(403)
            return

        if os.path.isdir(path):
            self.directory_listing(path, request_path)
        elif os.path.exists(path):
            self.serve_file(path)
        else:
            self.send_error(404)

    # ------------------------------------------------------------------
    # POST handler
    # ------------------------------------------------------------------

    def do_POST(self) -> None:
        request_path, _ = self.parse_path(self.path)
        length       = int(self.headers.get("Content-Length", 0))
        client_ip    = self.client_address[0]
        content_type = self.headers.get("Content-Type", "")

        # Login — CSRF exempt because no session exists yet
        if request_path == "/login":
            body = self.rfile.read(length)
            if rl_check(client_ip):
                self.send_error_text(429, "Too many failed attempts. Try again later.")
                return
            post     = parse_qs(body.decode(), keep_blank_values=True)
            password = post.get("password", [""])[0]
            if password == ADMIN_PASSWORD:
                rl_reset(client_ip)
                token, _ = session_create()
                self.redirect("/", extra_headers={"Set-Cookie": self._session_cookie_header(token)})
            else:
                rl_fail(client_ip)
                self.login_page("Invalid password.")
            return

        # Config save — CSRF token carried in a hidden form field
        if request_path == "/config":
            if not self.is_admin():
                self.send_error(401, "Admin login required")
                return
            body     = self.rfile.read(length)
            post     = parse_qs(body.decode(), keep_blank_values=True)
            provided = post.get("csrf", [""])[0]
            expected = self._csrf_token() or ""
            if not secrets.compare_digest(expected, provided):
                self.send_error_text(403, "Invalid CSRF token")
                return
            try:
                max_mb = int(post.get("max_mb", ["0"])[0] or "0")
                if max_mb < 0:
                    raise ValueError
            except ValueError:
                self.redirect("/config?msg=Invalid+max+size+value&error=1")
                return
            raw_blocked = post.get("blocked", [""])[0]
            blocked = {
                ("." + e.strip().lstrip(".")).lower()
                for e in raw_blocked.split(",") if e.strip()
            }
            Config.update(max_mb, blocked)
            logger.info("CONFIG ip=%s max_mb=%d blocked=%s",
                        client_ip, max_mb, ",".join(sorted(blocked)))
            self.redirect("/")
            return

        path = self.translate(request_path)
        if path is None:
            self.send_error(403)
            return

        # Form-encoded actions
        if content_type.startswith("application/x-www-form-urlencoded"):
            body   = self.rfile.read(length)
            post   = parse_qs(body.decode(), keep_blank_values=True)
            action = post.get("action", [""])[0]

            # mkdir is open to all users — no session/CSRF required
            if action == "mkdir":
                raw_name    = post.get("name", [""])[0].strip()
                folder_name = os.path.basename(raw_name)
                if not folder_name or folder_name.startswith("."):
                    self.send_error_text(400, "Invalid folder name")
                    return
                target = os.path.join(path, folder_name)
                if os.path.exists(target):
                    self.send_error_text(400, "Folder already exists")
                    return
                os.makedirs(target)
                logger.info("MKDIR ip=%s path=%s", client_ip, target)
                self.send_response(200)
                self.end_headers()
                return

            # All other actions require a valid CSRF token and admin session
            if not self._validate_csrf():
                self.send_error_text(403, "Invalid or missing CSRF token")
                return

            if action == "delete":
                if not self.is_admin():
                    self.send_error_text(401, "Admin login required")
                    return
                filename = os.path.basename(post.get("name", [""])[0])
                target   = os.path.join(path, filename)
                if os.path.isfile(target):
                    size = os.path.getsize(target)
                    os.remove(target)
                    self.log_event("DELETE", client_ip, filename, size)
                    self.send_response(200)
                    self.end_headers()
                else:
                    self.send_error(404)
                return

            if action == "rmdir":
                if not self.is_admin():
                    self.send_error_text(401, "Admin login required")
                    return
                folder_name = os.path.basename(post.get("name", [""])[0])
                target      = os.path.join(path, folder_name)
                if os.path.isdir(target):
                    shutil.rmtree(target)
                    logger.info("RMDIR ip=%s path=%s", client_ip, target)
                    self.send_response(200)
                    self.end_headers()
                else:
                    self.send_error(404)
                return

            if action == "rename":
                if not self.is_admin():
                    self.send_error_text(401, "Admin login required")
                    return
                old_name = os.path.basename(post.get("old", [""])[0])
                new_name = os.path.basename(post.get("new", [""])[0])
                if not old_name or not new_name or new_name.startswith("."):
                    self.send_error_text(400, "Invalid name")
                    return
                src = os.path.join(path, old_name)
                dst = os.path.join(path, new_name)
                if not os.path.isfile(src):
                    self.send_error(404)
                    return
                if os.path.exists(dst):
                    self.send_error_text(400, "A file with that name already exists")
                    return
                os.rename(src, dst)
                logger.info("RENAME ip=%s old=%s new=%s", client_ip, old_name, new_name)
                self.send_response(200)
                self.end_headers()
                return

        # Multipart file upload — two-pass: validate all, then write atomically
        if os.path.isdir(path) and content_type.startswith("multipart/form-data"):
            msg = Message()
            msg["content-type"] = content_type
            boundary = msg.get_param("boundary")
            if not boundary:
                self.send_error_text(400, "Missing multipart boundary")
                return

            body           = self.rfile.read(length)
            boundary_bytes = boundary.encode()

            # Pass 1: stage each part in a temp file and validate
            tmp_files: list[tuple[str, str, int]] = []  # (tmp_path, final_name, size)
            errors: list[str] = []

            for part in body.split(b"--" + boundary_bytes):
                if b'filename="' not in part:
                    continue
                try:
                    header_raw, file_data = part.split(b"\r\n\r\n", 1)
                    file_data = file_data.rstrip(b"\r\n--")
                    filename  = os.path.basename(
                        header_raw.split(b'filename="')[1].split(b'"')[0]
                        .decode("utf-8", errors="replace")
                    )
                except (ValueError, IndexError):
                    errors.append("Malformed upload part")
                    continue

                err = Config.check_upload(filename, len(file_data))
                if err:
                    errors.append(f"{filename}: {err}")
                    logger.info("UPLOAD_REJECTED ip=%s filename=%s reason=%s",
                                client_ip, filename, err)
                    continue

                fd, tmp_path = tempfile.mkstemp(dir=path, prefix=".upload_")
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(file_data)
                    tmp_files.append((tmp_path, filename, len(file_data)))
                except Exception as exc:
                    os.close(fd)
                    os.unlink(tmp_path)
                    errors.append(f"{filename}: write error ({exc})")

            if errors:
                # Roll back all staged temp files before reporting the error
                for tmp_path, _, _ in tmp_files:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                self.send_error_text(400, "\n".join(errors))
                return

            # Pass 2: atomically rename staged files to their final names
            for tmp_path, filename, size in tmp_files:
                os.replace(tmp_path, os.path.join(path, filename))
                self.log_event("UPLOAD", client_ip, filename, size)

            self.send_response(200)
            self.end_headers()
            return

        self.send_error_text(400, "Bad request")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class Server(socketserver.ThreadingTCPServer):
    """TCP server with address reuse enabled for clean restarts."""
    allow_reuse_address = True


if __name__ == "__main__":
    os.makedirs(BASE_DIR, exist_ok=True)
    Config.load()
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        print(f"📂 File Server: http://localhost:{PORT}")
        httpd.serve_forever()
