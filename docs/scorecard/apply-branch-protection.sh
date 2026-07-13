#!/usr/bin/env bash
#
# Applies the branch-protection rules in `branch-protection.json` to
# `main` on tarrinho/AntiBotGW using the GitHub REST API.
#
# Requirements:
#   - `gh` CLI logged in as a user with `admin:repo` scope on tarrinho/AntiBotGW,
#     OR a classic PAT / fine-grained token in $GITHUB_TOKEN with the same scope.
#   - `jq` for a quick sanity-echo of the result.
#
# Usage:
#   ./apply-branch-protection.sh                  # uses default owner/repo/branch
#   OWNER=tarrinho REPO=AntiBotGW BRANCH=main \
#     ./apply-branch-protection.sh
#
# Idempotent — a repeat run overwrites the same rules with the same JSON.
#
# SOLO-DEV NOTE:
#   `required_approving_review_count` in branch-protection.json is
#   deliberately 0. GitHub does not allow a PR author to approve their own
#   PR, so a value ≥ 1 would lock the sole maintainer out (no one to
#   approve). PR-flow, status checks, force-push block, deletion block, and
#   admin-enforcement remain active. Raise the value only after adding a
#   second maintainer. Also see `test_pure.py::
#   test_branch_protection_json_has_least_privilege_shape`.

set -euo pipefail

OWNER="${OWNER:-tarrinho}"
REPO="${REPO:-AntiBotGW}"
BRANCH="${BRANCH:-main}"

RULES_FILE="$(dirname "$0")/branch-protection.json"
[[ -f "$RULES_FILE" ]] || {
  echo "FATAL: $RULES_FILE missing" >&2
  exit 1
}

echo "→ applying branch protection to $OWNER/$REPO:$BRANCH"
echo "  rules: $RULES_FILE"

if command -v gh >/dev/null 2>&1; then
  gh api \
    --method PUT \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "/repos/$OWNER/$REPO/branches/$BRANCH/protection" \
    --input "$RULES_FILE"
elif [[ -n "${GITHUB_TOKEN:-}" ]]; then
  curl -sSL --fail \
    -X PUT \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/$OWNER/$REPO/branches/$BRANCH/protection" \
    -d @"$RULES_FILE"
else
  echo "FATAL: neither \`gh\` nor \$GITHUB_TOKEN available" >&2
  exit 1
fi

echo
echo "→ verification (GET /branches/$BRANCH/protection):"
if command -v gh >/dev/null 2>&1; then
  gh api "/repos/$OWNER/$REPO/branches/$BRANCH/protection" \
    | (command -v jq >/dev/null 2>&1 \
        && jq '{
             required_status_checks: .required_status_checks.contexts,
             reviews: .required_pull_request_reviews.required_approving_review_count,
             enforce_admins: .enforce_admins.enabled,
             linear_history: .required_linear_history.enabled,
             force_pushes: .allow_force_pushes.enabled,
             deletions: .allow_deletions.enabled
           }' || cat)
fi

echo
echo "✔ done. Next scorecard scan will lift Branch-Protection 0 → 10"
echo "  and Code-Review starts counting once PRs merge through the rules."
