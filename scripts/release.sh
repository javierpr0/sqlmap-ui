#!/bin/bash
# Release script for SQLMap UI.
# Validates changelog, syncs version across files, creates tag, and pushes.
#
# Usage:
#   ./scripts/release.sh 0.3.0              # New release
#   ./scripts/release.sh 0.3.0 --force      # Re-release (deletes existing tag)
#   ./scripts/release.sh 0.3.0 --dry-run    # Preview without changes
#
# Prerequisites:
#   - Clean working tree (no uncommitted changes)
#   - Version documented in CHANGELOG.md under ## [x.x.x] - YYYY-MM-DD
#   - Comparison link at bottom of CHANGELOG.md

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CHANGELOG="$PROJECT_DIR/CHANGELOG.md"
PACKAGE_JSON="$PROJECT_DIR/package.json"
TAURI_CONF="$PROJECT_DIR/src-tauri/tauri.conf.json"

VERSION=""
DRY_RUN=false
FORCE=false

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --force)   FORCE=true ;;
    -*)        echo -e "${RED}Unknown flag: $arg${NC}"; exit 1 ;;
    *)         VERSION="$arg" ;;
  esac
done

# ── Validate input ──

if [ -z "$VERSION" ]; then
  echo -e "${RED}Error: version required${NC}"
  echo ""
  echo "Usage: ./scripts/release.sh <version> [--dry-run] [--force]"
  echo ""
  echo "Examples:"
  echo "  ./scripts/release.sh 0.4.0           # New release"
  echo "  ./scripts/release.sh 0.3.0 --force   # Re-release existing version"
  echo "  ./scripts/release.sh 0.4.0 --dry-run # Preview"
  echo ""
  echo "Before running, document the release in CHANGELOG.md:"
  echo "  ## [x.x.x] - $(date +%Y-%m-%d)"
  exit 1
fi

# Strip leading 'v' if provided
VERSION="${VERSION#v}"

echo ""
echo "=== SQLMap UI Release v$VERSION ==="
if [ "$FORCE" = true ]; then
  echo -e "${YELLOW}(force mode: will replace existing tag)${NC}"
fi
echo ""

# ── Check clean working tree ──

if [ -n "$(git -C "$PROJECT_DIR" status --porcelain)" ]; then
  echo -e "${RED}Error: working tree is not clean${NC}"
  echo "Commit or stash your changes before releasing."
  git -C "$PROJECT_DIR" status --short
  exit 1
fi

# ── Validate CHANGELOG.md exists ──

if [ ! -f "$CHANGELOG" ]; then
  echo -e "${RED}Error: CHANGELOG.md not found${NC}"
  exit 1
fi

# ── Validate version is documented in CHANGELOG.md ──

CHANGELOG_ENTRY=$(grep -E "^## \[$VERSION\]" "$CHANGELOG" || true)

if [ -z "$CHANGELOG_ENTRY" ]; then
  echo -e "${RED}Error: version $VERSION not found in CHANGELOG.md${NC}"
  echo ""
  echo "Add an entry before releasing:"
  echo ""
  echo "  ## [$VERSION] - $(date +%Y-%m-%d)"
  echo ""
  echo "  ### Added"
  echo "  - ..."
  echo ""
  exit 1
fi

# Validate it has a date
if ! echo "$CHANGELOG_ENTRY" | grep -qE "[0-9]{4}-[0-9]{2}-[0-9]{2}"; then
  echo -e "${RED}Error: version $VERSION in CHANGELOG.md has no date${NC}"
  echo "Expected format: ## [$VERSION] - YYYY-MM-DD"
  exit 1
fi

# Validate comparison link exists
if ! grep -q "\[$VERSION\]:" "$CHANGELOG"; then
  echo -e "${YELLOW}Warning: no comparison link for [$VERSION] at bottom of CHANGELOG.md${NC}"
  echo "Add: [$VERSION]: https://github.com/javierpr0/sqlmap-ui/compare/vPREV...v$VERSION"
fi

echo -e "${GREEN}CHANGELOG.md:${NC} $CHANGELOG_ENTRY"

# ── Detect remote ──

REMOTE=$(git -C "$PROJECT_DIR" remote | head -1)
if [ -z "$REMOTE" ]; then
  echo -e "${RED}Error: no git remote configured${NC}"
  exit 1
fi
BRANCH=$(git -C "$PROJECT_DIR" branch --show-current)

# ── Check if tag already exists ──

TAG_EXISTS_LOCAL=$(git -C "$PROJECT_DIR" tag -l "v$VERSION")
TAG_EXISTS_REMOTE=$(git -C "$PROJECT_DIR" ls-remote --tags "$REMOTE" "v$VERSION" 2>/dev/null | head -1 || true)

if [ -n "$TAG_EXISTS_LOCAL" ] || [ -n "$TAG_EXISTS_REMOTE" ]; then
  if [ "$FORCE" = false ]; then
    echo -e "${RED}Error: tag v$VERSION already exists${NC}"
    echo "Use --force to re-release: ./scripts/release.sh $VERSION --force"
    exit 1
  fi
  echo -e "${YELLOW}Tag v$VERSION exists, will be replaced${NC}"
fi

# ── Show what will change ──

CURRENT_PKG=$(grep '"version"' "$PACKAGE_JSON" | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')
CURRENT_TAURI=$(grep '"version"' "$TAURI_CONF" | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')

echo ""
echo "Plan:"
if [ "$CURRENT_PKG" != "$VERSION" ] || [ "$CURRENT_TAURI" != "$VERSION" ]; then
  echo "  1. Update package.json:     $CURRENT_PKG -> $VERSION"
  echo "     Update tauri.conf.json:  $CURRENT_TAURI -> $VERSION"
  echo "     Commit version bump"
else
  echo "  1. Version already at $VERSION (no commit needed)"
fi
if [ -n "$TAG_EXISTS_LOCAL" ] || [ -n "$TAG_EXISTS_REMOTE" ]; then
  echo "  2. Delete existing tag v$VERSION (local + remote)"
  echo "  3. Create new tag v$VERSION"
else
  echo "  2. Create tag v$VERSION"
fi
echo "  *. Push $BRANCH + tags to $REMOTE"
echo "     -> GitHub Actions builds installers and creates release"
echo ""

if [ "$DRY_RUN" = true ]; then
  echo -e "${YELLOW}Dry run complete. No changes made.${NC}"
  exit 0
fi

# ── Confirm ──

read -p "Proceed with release v$VERSION? (y/N) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

# ── Update versions ──

if [ "$CURRENT_PKG" != "$VERSION" ]; then
  sed -i.bak "s/\"version\": \"$CURRENT_PKG\"/\"version\": \"$VERSION\"/" "$PACKAGE_JSON"
  rm -f "$PACKAGE_JSON.bak"
fi

if [ "$CURRENT_TAURI" != "$VERSION" ]; then
  sed -i.bak "s/\"version\": \"$CURRENT_TAURI\"/\"version\": \"$VERSION\"/" "$TAURI_CONF"
  rm -f "$TAURI_CONF.bak"
fi

# ── Commit version bump (only if there are changes) ──

cd "$PROJECT_DIR"
git add package.json src-tauri/tauri.conf.json

if git diff --cached --quiet; then
  echo -e "${YELLOW}Version already at $VERSION, no commit needed${NC}"
else
  git commit -m "chore: bump version to $VERSION"
  echo -e "${GREEN}Committed version bump${NC}"
fi

# ── Delete existing tag if force ──

if [ "$FORCE" = true ]; then
  if [ -n "$TAG_EXISTS_LOCAL" ]; then
    git tag -d "v$VERSION" 2>/dev/null || true
    echo -e "${YELLOW}Deleted local tag v$VERSION${NC}"
  fi
  if [ -n "$TAG_EXISTS_REMOTE" ]; then
    git push "$REMOTE" --delete "v$VERSION" 2>/dev/null || true
    echo -e "${YELLOW}Deleted remote tag v$VERSION${NC}"
  fi
fi

# ── Create tag ──

git tag -a "v$VERSION" -m "Release v$VERSION"
echo -e "${GREEN}Created tag v$VERSION${NC}"

# ── Push ──

echo ""
read -p "Push to $REMOTE? (y/N) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
  git push "$REMOTE" "$BRANCH" --tags
  echo -e "${GREEN}Pushed to $REMOTE. GitHub Actions will build and create the release.${NC}"
else
  echo ""
  echo "To push manually:"
  echo "  git push $REMOTE $BRANCH --tags"
fi

echo ""
echo -e "${GREEN}=== Release v$VERSION complete ===${NC}"
