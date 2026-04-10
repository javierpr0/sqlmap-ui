# SQLMap UI

A fully self-contained desktop application for [sqlmap](https://sqlmap.org/) — the automatic SQL injection and database takeover tool. Built with [Tauri](https://tauri.app/), React, and Rust.

**No Python installation required.** The app bundles sqlmap + Python as a standalone sidecar binary via PyInstaller.

## Features

### Core
- Full sqlmap configuration: URL, method, POST data, cookies, custom headers, level, risk, threads, DBMS, techniques, tamper scripts, extra arguments
- Real-time terminal output with smart syntax coloring (`[CRITICAL]`, `[WARNING]`, `[INFO]`, `injectable`, `Parameter`)
- Multi-tab: run multiple scans simultaneously with independent config and output per tab
- Interactive stdin: respond to sqlmap prompts (Y/n, etc.) directly in the UI
- Command preview tab

### Findings & Reporting
- **Findings panel**: auto-parses vulnerabilities from output — shows parameter, injection type, title, and payload in structured cards
- **Export HTML report**: download a styled report with config and color-coded output
- **Export Burp XML**: export findings as Burp Suite-compatible XML

### Productivity
- **Search** (Cmd+F): filter output lines with live highlighting
- **History**: last 50 scans stored in SQLite, click to re-open in a new tab
- **Profiles**: save, load, and delete named configurations
- **Batch scan**: paste multiple URLs to launch one tab per target
- **Import requests**: paste raw HTTP requests from Burp Suite or DevTools — auto-parses URL, method, headers, cookies, body
- **Burp XML import**: import Burp Suite XML exports directly
- **Drag & drop**: drop `.txt` files to open batch scan, drop `.req`/`.http` files to import requests

### UX
- **Light / Dark theme** with toggle (persisted)
- **Keyboard shortcuts**: Cmd+R (run), Cmd+. (stop), Cmd+T (new tab), Cmd+W (close tab), Cmd+F (search), Escape (close modals)
- **Resizable panels**: drag the border between config and terminal (280px–600px)
- **System notifications**: macOS notification when a scan completes
- **Auto-update**: checks GitHub Releases for new versions on startup
- **Custom icon**: SQL injection-themed app icon

## Requirements (for building)

- **Rust** 1.77+
- **Node.js** 20+ and **pnpm** 10+
- **Python 3** and **PyInstaller** (only for building the sidecar)

> End users don't need any of these — the built `.app` / `.dmg` / `.msi` / `.deb` is fully self-contained.

## Project Structure

```
sqlmap-ui/
├── src/                         # React frontend
│   ├── App.tsx                  # Main component (~1100 lines)
│   ├── styles.css               # Full dark + light theme
│   ├── main.tsx                 # React entry point
│   └── vite-env.d.ts
├── src-tauri/                   # Rust backend
│   ├── src/lib.rs               # Plugin setup, SQLite migrations
│   ├── Cargo.toml               # Rust dependencies
│   ├── tauri.conf.json          # App config, plugins, sidecar
│   ├── capabilities/            # Shell, notification, SQL, updater permissions
│   ├── binaries/                # sqlmap sidecar (PyInstaller binary)
│   └── icons/                   # Custom app icons (all platforms)
├── scripts/
│   └── build-sidecar.sh         # Build sidecar for current platform
├── .github/workflows/
│   └── build.yml                # CI: multi-platform builds
├── app-icon.png                 # Source icon (1024x1024)
├── index.html
├── vite.config.ts
├── tsconfig.json
└── package.json
```

## Quick Start

```bash
# Clone the repo
git clone <repo-url> sqlmap-ui
cd sqlmap-ui

# Install dependencies
pnpm install

# Build the sidecar (requires Python 3 + PyInstaller + sqlmap cloned nearby)
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ../sqlmap
pip install pyinstaller
bash scripts/build-sidecar.sh

# Run in development
pnpm tauri dev

# Build for production
pnpm tauri build
```

## Build Output

| Platform | Artifact | Size |
|----------|----------|------|
| macOS (arm64) | `SQLMap UI.app` | ~41 MB |
| macOS (arm64) | `SQLMap UI_x.x.x_aarch64.dmg` | ~34 MB |
| Linux | `.deb`, `.AppImage` | ~35 MB |
| Windows | `.msi`, `.exe` | ~35 MB |

## How It Works

1. **Sidecar binary**: sqlmap + Python 3.10 are compiled into a single standalone binary (~30 MB) using PyInstaller. Tauri bundles it inside the `.app` as an `externalBin`.

2. **Shell execution**: The React frontend uses `Command.sidecar()` from `@tauri-apps/plugin-shell` to spawn the sidecar. stdout/stderr are streamed to the terminal in real time. stdin is writable for interactive prompts.

3. **Persistence**: Scan history and profiles are stored in a SQLite database (`sqlmap-ui.db`) via `@tauri-apps/plugin-sql` with automatic schema migrations.

4. **Multi-tab architecture**: Each `ScanTab` holds its own config, output, child process reference, and view mode. Tabs are fully independent — you can run 5 scans against different targets simultaneously.

## Tech Stack

| Layer       | Technology                                    |
|-------------|-----------------------------------------------|
| Frontend    | React 19, TypeScript, Vite 8                  |
| Backend     | Rust, Tauri 2.10                               |
| Database    | SQLite (via tauri-plugin-sql)                  |
| Sidecar     | sqlmap 1.10 + Python 3.10 (PyInstaller)        |
| CI/CD       | GitHub Actions (macOS, Linux, Windows)          |
| Package     | pnpm 10                                        |

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+R` | Run scan |
| `Cmd+.` | Stop scan |
| `Cmd+T` | New tab |
| `Cmd+W` | Close tab |
| `Cmd+F` | Search output |
| `Escape` | Close modals / search |

## License

This project is a UI wrapper. sqlmap itself is licensed under [GPLv2](https://github.com/sqlmapproject/sqlmap/blob/master/LICENSE).
