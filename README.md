# py-file-server

Lightweight HTTP file server with a modern web UI. Python 3.10+, no third-party dependencies.

> **Disclaimer.** Provided **AS IS**, without warranty of any kind, express or
> implied. **Use entirely at your own risk.** This tool exposes a folder on your
> machine over the network: anyone who can reach the port can list and download
> its files, and an authenticated admin can upload, rename and delete them. The
> author accepts no liability for data loss, corruption, unauthorised access or
> disclosure, business interruption, or consequential damages. You are
> responsible for checking which folder you expose, setting a strong
> `ADMIN_PASSWORD`, limiting the server to a network you trust, keeping tested
> backups, and being authorised to share the files. Not certified for regulated,
> forensic, safety-critical or high-assurance use. See [DISCLAIMER.md](DISCLAIMER.md);
> [LICENSE](LICENSE) is the governing text and prevails where the two differ.

## Install

```bash
pip install py-file-server
```

## Run

```bash
set ADMIN_PASSWORD=yourpassword
py-file-server
```

`pfs` is installed as a shorter alias for the same command:

```bash
pfs --dir D:\MyFiles
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

### Logging

Access lines and events go to both the console and `share.log`, a rotating file
capped at 5 MB with 5 backups. Clients that drop a connection (a browser
opening a speculative socket, or a cancelled download) are recorded at debug
level rather than raising a traceback.

Upload settings live in `config.json` inside the shared folder. The file is created automatically on first run if missing (default: 100 MB max upload, `.sh` blocked).
