#!/usr/bin/env bash
#
# publish.example.sh — template for syncing this source tree into one or more
# git repositories (e.g. a public mirror + a separate downstream).
#
# Generic template. To use: copy to publish.sh (gitignored, never published),
# then set TARGETS (and any per-repo identity checks you want) for your setup.
#
# Flow:  preflight  →  show plan  →  ask y/N  →  commit/push/tag
#        →  ask "mark as Release?"  →  create GitHub Releases (non-fatal).
#
# Usage:
#   TARGETS="/path/to/repoA /path/to/repoB" ./publish.sh
#   TARGETS="/path/to/repoA"                ./publish.sh "version 1.2.3"
#   PUBLISH_YES=1 TARGETS="..."             ./publish.sh     # skip publish prompt (no releases)
#   PUBLISH_RELEASE=1 TARGETS="..."         ./publish.sh     # also auto-create GitHub Releases
#
set -euo pipefail

SRC="${SRC:-$(cd "$(dirname "$0")" && pwd)}"
COPY="$SRC/copy-to-github.sh"
TARGETS="${TARGETS:?set TARGETS to one or more repo working dirs}"
ASSUME_YES="${PUBLISH_YES:-0}"
RELEASE_YES="${PUBLISH_RELEASE:-0}"

# Version + tag from config.py; commit message may be overridden by an arg.
VER="$(grep -oE 'AntiBotWaf_GW_[0-9]+\.[0-9]+\.[0-9]+' "$SRC/config.py" | head -1 | sed 's/AntiBotWaf_GW_//')"
TAG="${VER:+v$VER}"
if [[ $# -ge 1 && -n "${1:-}" ]]; then MSG="$1"; else MSG="version ${VER:?could not read GW_VERSION from config.py}"; fi
[[ -x "$COPY" ]] || { echo "FATAL: $COPY not found/executable" >&2; exit 2; }

confirm() {
  [[ "$ASSUME_YES" == 1 ]] && return 0
  local ans=""
  read -r -p "Proceed with commit + push to ALL targets? [y/N] " ans || ans=""
  [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}

release_confirm() {
  [[ "$RELEASE_YES" == 1 ]] && return 0
  [[ "$ASSUME_YES"  == 1 ]] && return 1   # automation without PUBLISH_RELEASE=1 → no releases
  local ans=""
  read -r -p "Mark $TAG as a GitHub Release on all targets? [y/N] " ans || ans=""
  [[ "$ans" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# Phase 1 — preflight every target (all-or-nothing): repo + origin + author set.
for dst in $TARGETS; do
  [[ -d "$dst/.git" ]] || { echo "FATAL: $dst is not a git repo" >&2; exit 1; }
  [[ -n "$(git -C "$dst" remote get-url origin 2>/dev/null || true)" ]] || { echo "FATAL: $dst has no 'origin' remote" >&2; exit 1; }
  [[ -n "$(git -C "$dst" config user.email 2>/dev/null || true)" ]]    || { echo "FATAL: $dst has no user.email set" >&2; exit 1; }
done

# Phase 2 — prepare every target (pull + copy + stage) and show the plan.
echo "── what will happen (commit \"$MSG\", tag ${TAG:-none}) ──"
for dst in $TARGETS; do
  echo "── $dst"
  if ! git -C "$dst" pull --ff-only; then
    echo "FATAL: $dst pull not fast-forward (remote rewritten?)." >&2
    echo "  reconcile: git -C \"$dst\" fetch && git -C \"$dst\" reset --hard origin/main" >&2
    exit 1
  fi
  DEST="$dst" "$COPY" 2>&1 | sed 's/^/    /'
  git -C "$dst" add -A
  if git -C "$dst" diff --cached --quiet; then
    echo "  file changes: none"
  else
    git -C "$dst" diff --cached --stat | sed 's/^/    /'
  fi
done

# Phase 3 — confirm.
confirm || { echo "Aborted — nothing committed or pushed."; exit 0; }

# Phase 4 — apply: commit (if changed) + push. Tagging happens only at release.
for dst in $TARGETS; do
  if git -C "$dst" diff --cached --quiet; then
    echo "  $dst: no changes"
  else
    git -C "$dst" commit -q -m "$MSG"
    git -C "$dst" push
    echo "  $dst: pushed → $MSG"
  fi
done

# Phase 5 — optionally tag THIS commit as $TAG (create/force-move) + GitHub Release.
# Option B: tags mark only the commit you release. NON-FATAL — commits already pushed.
if [[ -n "$TAG" ]] && release_confirm; then
  for dst in $TARGETS; do
    head="$(git -C "$dst" rev-parse HEAD)"
    git -C "$dst" tag -f -a "$TAG" -m "$MSG" "$head" || { echo "  $dst: WARN tag failed"; continue; }
    git -C "$dst" push -f origin "$TAG"             || { echo "  $dst: WARN tag push failed"; continue; }
    echo "  $dst: tagged $TAG → ${head:0:9}"
    slug="$(git -C "$dst" remote get-url origin | sed -E 's#\.git$##; s#^.*[:/]([^/]+/[^/]+)$#\1#')"
    if ! command -v gh >/dev/null 2>&1; then
      echo "  $slug: gh not installed — gh release create $TAG -R $slug --generate-notes --verify-tag"
    elif gh release view "$TAG" -R "$slug" >/dev/null 2>&1; then
      echo "  $slug: release $TAG exists (now on the moved tag)"
    elif gh release create "$TAG" -R "$slug" --title "$TAG" --generate-notes --verify-tag >/dev/null 2>&1; then
      echo "  $slug: release $TAG created"
    else
      echo "  $slug: WARN could not create release — gh release create $TAG -R $slug --generate-notes --verify-tag"
    fi
  done
fi

echo "Done — all targets in sync at \"$MSG\""
