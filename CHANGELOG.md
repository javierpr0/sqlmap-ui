# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-04-09

### Fixed
- Remove deprecated macos-13 runner from CI pipeline
- Fix pnpm version conflict in GitHub Actions (packageManager vs action config)
- Release script now supports `--force` flag for re-releases
- Release script auto-detects remote name instead of hardcoding `origin`
- Fix ANSI escape codes showing as garbage characters in terminal output

## [0.3.0] - 2026-04-09

### Added
- Custom SQL injection-themed app icon for all platforms
- Auto-update plugin with GitHub Releases endpoint
- Light/dark theme toggle with persistence
- Interactive stdin input for responding to sqlmap prompts
- Findings panel that parses vulnerabilities from output
- SQLite persistence for scan history and profiles
- Multi-platform CI pipeline (macOS, Linux, Windows)
- Keyboard shortcuts (Cmd+R run, Cmd+. stop, Cmd+T/W tabs, Cmd+F search)
- Drag & drop support (.txt for batch URLs, .req for import)
- Burp Suite XML import and findings export
- PyInstaller build scripts inside the repo (scripts/)

## [0.2.0] - 2026-04-08

### Added
- Smart syntax coloring (CRITICAL, WARNING, INFO, injectable, Parameter)
- Search in output with Cmd+F and live highlighting
- Resizable config panel (280px-600px)
- System notifications when scan completes
- Scan history persisted in localStorage (max 50)
- Profiles/Templates (save, load, delete named configurations)
- Import raw HTTP requests from Burp Suite or DevTools
- Export HTML reports with color-coded output
- Batch scan (paste multiple URLs, one tab per target)
- Requests view tab for captured HTTP traffic
- HTTP method selector (GET, POST, PUT, DELETE, PATCH)
- Custom headers field
- SVG icons in header toolbar

## [0.1.0] - 2026-04-08

### Added
- Initial release
- Tauri v2 desktop app with React frontend
- Full sqlmap configuration UI (URL, POST data, cookies, level, risk, threads, DBMS, techniques, tamper scripts)
- Real-time terminal output
- Multi-tab support with independent scans
- Command preview tab
- Self-contained sidecar binary (sqlmap + Python bundled via PyInstaller)
- macOS .app and .dmg builds
- Initializing indicator while sidecar loads

[Unreleased]: https://github.com/javierpr0/sqlmap-ui/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/javierpr0/sqlmap-ui/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/javierpr0/sqlmap-ui/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/javierpr0/sqlmap-ui/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/javierpr0/sqlmap-ui/releases/tag/v0.1.0
