#!/usr/bin/env bash
set -euo pipefail

# update-branch can finish before PR metadata reflects its new head. Wait for
# ancestry, not a changed OID: an already-current branch is a valid no-op.
# Capture the base first so concurrent main pushes cannot move the target of
# this wait. Strict branch protection and --match-head-commit still guard merge.
base="$(gh api "repos/${GH_REPO}/git/ref/heads/main" --jq '.object.sha')"
gh pr update-branch "$1" >&2
for attempt in {1..12}; do
  pr="$(gh pr view "$1" --json "$2")"
  head="$(jq -er '.headRefOid' <<<"${pr}")"
  status="$(gh api "repos/${GH_REPO}/compare/${base}...${head}" --jq '.status')"
  if [[ "${status}" == ahead || "${status}" == identical ]]; then
    printf '%s\n' "${pr}"
    exit 0
  fi
  if (( attempt < 12 )); then
    sleep 5
  fi
done
echo 'Release PR metadata did not converge after branch refresh; refusing to queue a stale head.' >&2
exit 1
