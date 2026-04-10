#!/bin/bash
# Release script for SQLMap UI.
# Validates changelog, syncs version across files, creates tag, and pushes.
#
# Usage:
#   ./scripts/release.sh 0.3.0
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

VERSION="$1"
DRY_RUN=false

if [ "$2" = "--dry-run" ]; then
  DRY_RUN=true
fi

# ── Validate input ──

if [ -z "$VERSION" ]; then
  echo -e "${RED}Error: version required${NC}"
  echo ""
  echo "Usage: ./scripts/release.sh <version> [--dry-run]"
  echo "Example: ./scripts/release.sh 0.4.0"
  echo ""
  echo "Before running, document the release in CHANGELOG.md:"
  echo "  ## [$VERSION] - $(date +%Y-%m-%d)"
  exit 1
fi

# Strip leading 'v' if provided
VERSION="${VERSION#v}"

echo ""
echo "=== SQLMap UI Release v$VERSION ==="
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
if ! echo "$CHANGELOG_ENTRY" | grep -qE "\d{4}-\d{2}-\d{2}"; then
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

# ── Validate tag doesn't already exist ──

if git -C "$PROJECT_DIR" tag -l "v$VERSION" | grep -q "v$VERSION"; then
  echo -e "${RED}Error: tag v$VERSION already exists${NC}"
  exit 1
fi

# ── Show what will change ──

CURRENT_PKG=$(grep '"version"' "$PACKAGE_JSON" | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')
CURRENT_TAURI=$(grep '"version"' "$TAURI_CONF" | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')

echo ""
echo "Version updates:"
echo "  package.json:     $CURRENT_PKG -> $VERSION"
echo "  tauri.conf.json:  $CURRENT_TAURI -> $VERSION"
echo "  git tag:          v$VERSION"
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

# package.json
sed -i.bak "s/\"version\": \"$CURRENT_PKG\"/\"version\": \"$VERSION\"/" "$PACKAGE_JSON"
rm -f "$PACKAGE_JSON.bak"

# tauri.conf.json
sed -i.bak "s/\"version\": \"$CURRENT_TAURI\"/\"version\": \"$VERSION\"/" "$TAURI_CONF"
rm -f "$TAURI_CONF.bak"

echo -e "${GREEN}Updated versions in package.json and tauri.conf.json${NC}"

# ── Detect remote name ──

REMOTE=$(git -C "$PROJECT_DIR" remote | head -1)
if [ -z "$REMOTE" ]; then
  echo -e "${RED}Error: no git remote configured${NC}"
  exit 1
fi
BRANCH=$(git -C "$PROJECT_DIR" branch --show-current)
echo "Remote: $REMOTE ($BRANCH)"

# ── Commit version bump (only if there are changes) ──

cd "$PROJECT_DIR"
git add package.json src-tauri/tauri.conf.json

if git diff --cached --quiet; then
  echo -e "${YELLOW}Version already at $VERSION, no commit needed${NC}"
else
  git commit -m "chore: bump version to $VERSION"
  echo -e "${GREEN}Committed version bump${NC}"
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
