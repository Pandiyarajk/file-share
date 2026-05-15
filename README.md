# File Share

A lightweight, single-file Python HTTP file server with a modern web UI. No dependencies beyond the Python standard library.

## Quick Start

```bash
# Set a strong admin password (recommended)
set ADMIN_PASSWORD=yourpassword     # Windows
export ADMIN_PASSWORD=yourpassword  # Linux / macOS

python share.py
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

## Configuration

All settings are constants at the top of `share.py`:

| Constant | Default | Description |
|---|---|---|
| `PORT` | `8000` | TCP port the server listens on |
| `BASE_DIR` | `C:\Share` | Root directory exposed to the browser |
| `ADMIN_PASSWORD` | `admin123` (env: `ADMIN_PASSWORD`) | Admin login password |
| `CHUNK` | `1 MB` | Read/write chunk size for file streaming |
| `SESSION_TTL` | `28800` (8 h) | Admin session lifetime in seconds |
| `MAX_FAILURES` | `5` | Failed login attempts before IP lockout |
| `LOCKOUT_SECONDS` | `300` (5 min) | IP lockout duration after too many failures |
| `LOG_FILE` | `share.log` | Log file path |
| `LOG_MAX_BYTES` | `5 MB` | Max log file size before rotation |
| `BACKUP_COUNT` | `5` | Number of rotated log files to keep |
| `CONFIG_FILE` | `config.json` (same folder as `share.py`) | Path where upload restrictions are persisted |

## Features

### File Browsing
- Lists files and folders inside `BASE_DIR` and any subfolder
- **Breadcrumb navigation** — clickable path segments at the top of every page for quick jumps up the directory tree
- **Search** — instant client-side filtering by filename across both view modes
- **Sort** — toolbar dropdown to sort by Name, Size, or Date (ascending or descending); choice is saved per browser

### Two View Modes
| Mode | Description |
|---|---|
| **Detail view** (default) | Compact table — Name, Size, Modified, actions |
| **Card view** | Larger tiles showing name and metadata |

Toggle with the **⊞ / ☰** button in the header. Preference is saved per browser.

### Light / Dark Theme
- Dark by default; toggle with the **☀️ / 🌙** button in the header
- Preference is saved per browser via `localStorage`

### File Download
- Click **⬇** on any file row to download with a live progress bar

### File Upload
- **Drag and drop** files onto the drop zone
- **Browse** with the file picker button (supports multi-file selection)
- Upload progress bar shown during transfer
- Uploads are written atomically via temporary files — a rejected or failed upload never leaves a partial file on disk
- All files in a batch are validated before any are written; if one fails, the entire batch is rejected

### Create Folder
- Available to **all users** (no login required)
- Click **📁 New Folder** in the toolbar, enter a name, then press Enter or click Create
- The folder is created inside whichever directory is currently open

### Folder Title and Description
Place a `.title` file inside any folder to show a custom heading at the top of its listing:

```
My Project Files
Shared assets for the Q1 2026 release
```

- Line 1 → folder title (large heading)
- Remaining lines → description (shown as smaller subtext)

The `.title` file itself is hidden from the file listing.

---

## Admin Features

Click **👤 Admin login** (top right) to log in. The session lasts 8 hours and is stored server-side — manually setting a cookie grants no access.

After login the header shows **⚙ Config** and **👤 Logout**.

### File and Folder Management

| Action | How |
|---|---|
| **Delete file** | Click 🗑 on any file row |
| **Delete folder** | Click 🗑 on any folder row — recursively removes all contents |
| **Rename file** | Click ✏️ to open an inline modal pre-filled with the current name |

### Upload Restrictions

Navigate to **⚙ Config** to set upload rules that apply to all users:

| Setting | Description |
|---|---|
| **Max upload size (MB)** | Reject files larger than this; `0` = unlimited |
| **Blocked extensions** | Comma-separated list, e.g. `.exe, .bat, .sh` |

Rejected files show an error alert in the browser. Changes take effect immediately without restarting the server.

Settings are **persisted to `config.json`** in the same directory as `share.py` and are automatically reloaded on the next server start. If `config.json` does not exist, the server starts with defaults (100 MB max upload size, no blocked extensions).

---

## Security

| Protection | Detail |
|---|---|
| **Server-side sessions** | Admin is verified via a cryptographically random token stored in server memory — the cookie holds only the token, not the admin flag |
| **Session expiry** | Tokens expire after 8 hours; expired tokens are pruned on each new login |
| **CSRF protection** | All state-changing requests (upload, delete, rename, mkdir) require a per-session `X-CSRF-Token` header injected by the page JS |
| **Path traversal prevention** | Every requested path is normalised with `os.path.normpath` and checked to remain inside `BASE_DIR`; requests outside return 403 |
| **Login rate limiting** | After 5 failed attempts the client IP is locked out for 5 minutes |
| **HttpOnly session cookie** | Cookie is `HttpOnly; SameSite=Strict` — not readable by JavaScript |

---

## Logging

All significant events are written to `share.log` (rotating, max 5 × 5 MB):

```
2026-05-15 10:23:01 UPLOAD          ip=192.168.1.5  filename=report.pdf   size=204800
2026-05-15 10:24:15 DELETE          ip=192.168.1.5  filename=old.zip      size=1048576
2026-05-15 10:25:00 MKDIR           ip=192.168.1.5  path=C:\Share\docs
2026-05-15 10:25:30 RMDIR           ip=192.168.1.5  path=C:\Share\temp
2026-05-15 10:26:00 RENAME          ip=192.168.1.5  old=draft.txt         new=final.txt
2026-05-15 10:26:45 CONFIG          ip=192.168.1.5  max_mb=50             blocked=.exe,.bat
2026-05-15 10:27:10 UPLOAD_REJECTED ip=192.168.1.5  filename=virus.exe    reason=Extension '.exe' is blocked
```

---

## Requirements

- Python 3.10+
- No third-party packages

---

## Running as a Background Service

**Windows — Task Scheduler:**
1. Create a Basic Task → trigger: At startup
2. Action: `python.exe`, argument: `d:\path\to\share.py`
3. Add `ADMIN_PASSWORD` as an environment variable in the task settings

**Linux — systemd:**

```ini
[Unit]
Description=File Share

[Service]
ExecStart=/usr/bin/python3 /opt/share/share.py
Environment=ADMIN_PASSWORD=yourpassword
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable --now fileshare
```
