# SQLMap UI

Desktop application built with [Tauri](https://tauri.app/) that provides a graphical interface for [sqlmap](https://sqlmap.org/), the automatic SQL injection and database takeover tool.

## Screenshots

The app features a dark theme with a configuration panel on the left and a real-time terminal output on the right. Multiple scans can run simultaneously in separate tabs.

## Features

- Full sqlmap configuration through a visual interface (target URL, POST data, cookies, detection level/risk, DBMS selection, techniques, tamper scripts, and more)
- Real-time terminal output with color-coded lines (stdout, stderr, info, errors)
- Multi-tab support: run multiple scans simultaneously, each with independent configuration and output
- Command preview: see the exact sqlmap command before executing
- Start/stop scan controls
- Tab labels auto-update to show the target hostname
- Native macOS application (~10MB)

## Requirements

- **Python 3** (for sqlmap)
- **Rust** (for building the Tauri backend)
- **Node.js** and **pnpm** (for building the frontend)

## Project Structure

```
tests/
├── sqlmap/                  # sqlmap (cloned from github)
│   ├── sqlmap.py            # Main sqlmap entry point
│   └── run.py               # Wrapper that fixes MySQLdb import issues
└── sqlmap-ui/               # Tauri desktop app
    ├── src/                 # React frontend
    │   ├── App.tsx          # Main component with multi-tab scan UI
    │   ├── styles.css       # Dark theme styles
    │   ├── main.tsx         # React entry point
    │   └── vite-env.d.ts    # Vite type declarations
    ├── src-tauri/           # Rust backend
    │   ├── src/lib.rs       # Tauri commands (sqlmap path resolution)
    │   ├── src/main.rs      # App entry point
    │   ├── Cargo.toml       # Rust dependencies
    │   ├── tauri.conf.json  # Tauri configuration
    │   └── capabilities/    # Shell permissions for spawning python3
    ├── index.html           # HTML entry point
    ├── vite.config.ts       # Vite configuration
    ├── tsconfig.json        # TypeScript configuration
    └── package.json         # Node dependencies and scripts
```

## Setup

```bash
# 1. Clone sqlmap (if not already done)
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap

# 2. Install frontend dependencies
cd sqlmap-ui
pnpm install
```

## Development

```bash
cd sqlmap-ui
pnpm tauri dev
```

This starts the Vite dev server on port 1420 with HMR and launches the Tauri window.

## Build

```bash
cd sqlmap-ui
pnpm tauri build
```

Build artifacts:
- **macOS app**: `src-tauri/target/release/bundle/macos/SQLMap UI.app`
- **DMG installer**: `src-tauri/target/release/bundle/dmg/SQLMap UI_0.1.0_aarch64.dmg`

## How It Works

1. **Path resolution**: The Rust backend (`lib.rs`) locates `sqlmap/run.py` by searching relative to the executable in multiple candidate paths (dev, release bundle, sibling directory), with a hardcoded fallback.

2. **Python wrapper**: `sqlmap/run.py` patches a broken `MySQLdb` import before delegating to the real `sqlmap.py`. This avoids crashes when `mysqlclient` is installed but its native library (`libmysqlclient`) is missing.

3. **Shell execution**: The frontend uses Tauri's `@tauri-apps/plugin-shell` to spawn `python3` as a subprocess. stdout/stderr are streamed to the terminal in real time.

4. **Multi-tab**: Each tab maintains its own state (config, output, running status, child process reference). Tabs can be created, switched, and closed independently.

## Tech Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| Frontend | React 19, TypeScript 6, Vite 8      |
| Backend  | Rust, Tauri 2.10                     |
| Tool     | sqlmap 1.10.x (Python 3)            |
| Package  | pnpm 10                             |

## License

This project is a UI wrapper. sqlmap itself is licensed under [GPLv2](https://github.com/sqlmapproject/sqlmap/blob/master/LICENSE).
