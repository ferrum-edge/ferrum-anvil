#!/usr/bin/env bash
# Require exactly the release's four build targets under <dist>.
#
#   scripts/release/check-targets.sh <dist>
#
# The jobs that download the build artifacts by the pattern `release-*`
# (sign-updater, publish) would otherwise go on with whatever is still there:
# an artifact that expired while a deployment approval waited, or was deleted,
# would silently drop a platform from the release. Lists every missing or
# unexpected target and fails; the fix is to re-run all jobs of the workflow.
set -euo pipefail
dist="${1:?usage: check-targets.sh <dist>}"
# Keep in step with the build matrix and bundle-windows/check-windows in
# .github/workflows/release.yml (scripts/tests/release-notes.test.mjs checks).
expected=(aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu x86_64-pc-windows-msvc)
shopt -s nullglob
found=()
for d in "$dist"/release-*/; do found+=("$(basename "$d")"); done
problems=()
for t in "${expected[@]}"; do
  [ -f "$dist/release-$t/build-info.json" ] || problems+=("release-$t is missing (or has no build-info.json)")
done
for f in "${found[@]}"; do
  ok=false
  for t in "${expected[@]}"; do [ "$f" = "release-$t" ] && ok=true; done
  [ "$ok" = true ] || problems+=("$f is not a target of this release")
done
if [ "${#problems[@]}" -gt 0 ]; then
  for p in "${problems[@]}"; do echo "::error::$p"; done
  echo "::error::the build artifacts are incomplete (an artifact expires after 35 days or can be deleted). Within 30 days of the run's start, re-run all jobs of this workflow run (re-running only the failed jobs reuses the missing inputs); after that, start a fresh full release run from the same tag (Run workflow from the tag, dry_run off, tag set)."
  exit 1
fi
echo "all four release targets present: ${expected[*]}"
