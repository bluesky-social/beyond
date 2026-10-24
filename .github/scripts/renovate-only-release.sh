#!/usr/bin/env bash
# Decides whether a Release Please PR may merge without a human.
#
# Usage: renovate-only-release.sh <release-pr-json> <base-version>
#   release-pr-json: `gh pr view --json number,title,author,baseRefName,
#                    headRefName,isCrossRepository,files,labels`
#   base-version:    the version in .release-please-manifest.json on main
#
# Exits 0 only when the PR is Release Please's own (bot author, release
# branch, touches only the manifest and changelog, no release:manual label)
# AND every commit between v<base-version> and main, merge commits included,
# arrived through a merged Renovate PR. Provenance comes from GitHub's
# commit->PR association, not git author metadata, which anyone can set. Any
# human change in the range means a human merges the release. Requires GH_TOKEN, GH_REPO, RELEASE_BRANCH.
set -euo pipefail

pr_json="$1"
base_version="$2"

if ! jq -e --arg release_branch "${RELEASE_BRANCH}" '
  .author.is_bot == true
  and (.author.login == "app/github-actions" or .author.login == "github-actions[bot]")
  and .baseRefName == "main"
  and .headRefName == $release_branch
  and .isCrossRepository == false
  and (.title | startswith("chore(main): release "))
  and ((.files | map(.path) | sort) == [".release-please-manifest.json", "CHANGELOG.md"])
  and ([.labels[].name] | index("release:manual") | not)
' <<<"${pr_json}" >/dev/null; then
  echo "not an unattended-eligible Release Please PR"
  exit 1
fi

main_sha="$(gh api "repos/${GH_REPO}/git/ref/heads/main" --jq '.object.sha')"
compare="$(gh api "repos/${GH_REPO}/compare/v${base_version}...${main_sha}")"
total="$(jq -r '.total_commits' <<<"${compare}")"
# compare pages at 250 commits; a range that large is not a dependency bump.
if [[ "${total}" -eq 0 || "${total}" -gt 250 ]]; then
  echo "unexpected range size ${total} since v${base_version}"
  exit 1
fi

# Merge commits are checked too: their tree can carry changes no parent has,
# and their associated PR is whatever they merged, so a human merge fails here.
while read -r sha; do
  if ! gh api "repos/${GH_REPO}/commits/${sha}/pulls" | jq -e '
    any(.[]; .user.login == "renovate[bot]" and .merged_at != null and .base.ref == "main")
  ' >/dev/null; then
    echo "commit ${sha} did not arrive through a merged Renovate PR"
    exit 1
  fi
done < <(jq -r '.commits[].sha' <<<"${compare}")

echo "all ${total} commits since v${base_version} are Renovate's"
