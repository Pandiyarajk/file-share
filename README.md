# py-file-server

Lightweight HTTP file server with a modern web UI. Python 3.10+, no third-party dependencies.

## Install

```bash
pip install py-file-server
```

## Run

```bash
set ADMIN_PASSWORD=yourpassword
py-file-server
```

Open http://localhost:8113

### Options

```bash
py-file-server --port 9000 --dir D:\MyFiles
```

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | `8113` | TCP port |
| `--dir` | `./share` | Root folder exposed in the browser |

### Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | `admin123` | Admin login password — set this in production |

Upload settings live in `config.json` inside the shared folder. The file is created automatically on first run if missing (default: 100 MB max upload, `.sh` blocked).
