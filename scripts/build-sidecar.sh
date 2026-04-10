#!/bin/bash
# Build sqlmap sidecar for the current platform.
#
# Prerequisites:
#   - Python 3 with PyInstaller installed (pip install pyinstaller)
#   - sqlmap cloned somewhere on disk
#
# Usage:
#   SQLMAP_ROOT=/path/to/sqlmap ./scripts/build-sidecar.sh
#
# If SQLMAP_ROOT is not set, it looks for sqlmap in ../sqlmap relative to the project.
# Output: src-tauri/binaries/sqlmap-sidecar-{target-triple}

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARIES_DIR="$PROJECT_DIR/src-tauri/binaries"

# Resolve sqlmap root
if [ -z "$SQLMAP_ROOT" ]; then
  SQLMAP_ROOT="$(dirname "$PROJECT_DIR")/sqlmap"
fi

export SQLMAP_ROOT

# Validate
if [ ! -f "$SQLMAP_ROOT/sqlmap.py" ]; then
  echo "Error: sqlmap.py not found at $SQLMAP_ROOT"
  echo "Clone sqlmap first: git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git $SQLMAP_ROOT"
  exit 1
fi

# Detect target triple
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64)  TARGET="aarch64-apple-darwin" ;;
      x86_64) TARGET="x86_64-apple-darwin" ;;
      *)      echo "Unsupported macOS arch: $(uname -m)"; exit 1 ;;
    esac
    ;;
  Linux)
    case "$(uname -m)" in
      x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
      aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
      *)       echo "Unsupported Linux arch: $(uname -m)"; exit 1 ;;
    esac
    ;;
  MINGW*|MSYS*|CYGWIN*)
    case "$(uname -m)" in
      x86_64) TARGET="x86_64-pc-windows-msvc" ;;
      *)      TARGET="aarch64-pc-windows-msvc" ;;
    esac
    ;;
  *) echo "Unsupported OS: $(uname -s)"; exit 1 ;;
esac

echo "=== Building sqlmap sidecar ==="
echo "Platform:    $TARGET"
echo "sqlmap:      $SQLMAP_ROOT"
echo "Spec:        $SCRIPT_DIR/sqlmap-bundle.spec"
echo "Output:      $BINARIES_DIR/sqlmap-sidecar-$TARGET"
echo ""

mkdir -p "$BINARIES_DIR"

python3 -m PyInstaller "$SCRIPT_DIR/sqlmap-bundle.spec" \
  --distpath "$BINARIES_DIR" \
  --workpath "$PROJECT_DIR/build/pyinstaller" \
  --clean -y

# Rename binary to include target triple
if [ -f "$BINARIES_DIR/sqlmap-sidecar" ]; then
  mv "$BINARIES_DIR/sqlmap-sidecar" "$BINARIES_DIR/sqlmap-sidecar-$TARGET"
elif [ -f "$BINARIES_DIR/sqlmap-sidecar.exe" ]; then
  mv "$BINARIES_DIR/sqlmap-sidecar.exe" "$BINARIES_DIR/sqlmap-sidecar-$TARGET.exe"
else
  echo "Error: sidecar binary not found after build"
  exit 1
fi

echo ""
echo "=== Success ==="
ls -lh "$BINARIES_DIR/sqlmap-sidecar-$TARGET"* 2>/dev/null
