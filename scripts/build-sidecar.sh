#!/bin/bash
# Build sqlmap sidecar for the current platform.
# Run this on each target OS (macOS, Linux, Windows) to produce the correct binary.
#
# Usage:
#   ./scripts/build-sidecar.sh
#
# Output goes to src-tauri/binaries/sqlmap-sidecar-{target-triple}

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SQLMAP_DIR="$(dirname "$PROJECT_DIR")/sqlmap"
BINARIES_DIR="$PROJECT_DIR/src-tauri/binaries"

# Detect target triple
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  TARGET="aarch64-apple-darwin" ;;
  Darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
  Linux-x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
  MINGW*|MSYS*|CYGWIN*)
    case "$(uname -m)" in
      x86_64) TARGET="x86_64-pc-windows-msvc" ;;
      *)      TARGET="aarch64-pc-windows-msvc" ;;
    esac
    ;;
  *) echo "Unsupported platform: $(uname -s)-$(uname -m)"; exit 1 ;;
esac

echo "Building sqlmap sidecar for: $TARGET"
echo "sqlmap directory: $SQLMAP_DIR"
echo "Output: $BINARIES_DIR/sqlmap-sidecar-$TARGET"

if [ ! -f "$SQLMAP_DIR/sqlmap-bundle.spec" ]; then
  echo "Error: $SQLMAP_DIR/sqlmap-bundle.spec not found"
  echo "Make sure sqlmap is cloned next to sqlmap-ui/"
  exit 1
fi

cd "$SQLMAP_DIR"

python3 -m PyInstaller sqlmap-bundle.spec \
  --distpath "$BINARIES_DIR" \
  --clean -y

# Rename to include target triple
if [ -f "$BINARIES_DIR/sqlmap-sidecar" ]; then
  mv "$BINARIES_DIR/sqlmap-sidecar" "$BINARIES_DIR/sqlmap-sidecar-$TARGET"
  echo "Success: $BINARIES_DIR/sqlmap-sidecar-$TARGET"
  ls -lh "$BINARIES_DIR/sqlmap-sidecar-$TARGET"
elif [ -f "$BINARIES_DIR/sqlmap-sidecar.exe" ]; then
  mv "$BINARIES_DIR/sqlmap-sidecar.exe" "$BINARIES_DIR/sqlmap-sidecar-$TARGET.exe"
  echo "Success: $BINARIES_DIR/sqlmap-sidecar-$TARGET.exe"
  ls -lh "$BINARIES_DIR/sqlmap-sidecar-$TARGET.exe"
else
  echo "Error: sidecar binary not found after build"
  exit 1
fi
