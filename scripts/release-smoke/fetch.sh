#!/usr/bin/env bash
# Fetch step of the clean-install release smoke (REL-001): download the
# release assets the targets install and check each one, writing every
# result to $DIR/fetch.json. Run by .github/workflows/release-smoke.yml.
#
# Each problem is classified like a target failure (record.py
# FAILURE_CLASSES):
#   package  the published release is wrong:
#            - an advertised asset is not in it;
#            - it has no SHA256SUMS;
#            - SHA256SUMS does not list an asset;
#            - the asset GitHub stores does not match SHA256SUMS.
#            The run continues: the targets that install the affected asset
#            fail their own asset_integrity step as a package failure, and
#            the others run.
#   harness  the API or a download failed, or the downloaded bytes differ
#            from the digest GitHub stores for the asset (a transfer error,
#            retried first). The fetch exits 1 and no target runs.
#
# Environment: TAG (anvil-vX.Y.Z), V (X.Y.Z), DIR (output directory),
# GITHUB_REPOSITORY, GH_TOKEN.
set -euo pipefail

: "${TAG:?}" "${V:?}" "${DIR:?}" "${GITHUB_REPOSITORY:?}"
mkdir -p "$DIR"
assets_log="$RUNNER_TEMP/fetch-assets.jsonl"
err="$RUNNER_TEMP/fetch-download.err"
: >"$assets_log"

names=(
  "Ferrum-Anvil_${V}_aarch64.dmg" "Ferrum-Anvil_${V}_x64.dmg"
  "Ferrum-Anvil_${V}_x64-setup.exe" "Ferrum-Anvil_${V}_x64_en-US.msi"
  "Ferrum-Anvil_${V}_amd64.deb" "Ferrum-Anvil-${V}-1.x86_64.rpm" "Ferrum-Anvil_${V}_amd64.AppImage"
  "anvil-cli-${V}-aarch64-apple-darwin.tar.gz" "anvil-cli-${V}-x86_64-apple-darwin.tar.gz"
  "anvil-cli-${V}-x86_64-pc-windows-msvc.zip" "anvil-cli-${V}-x86_64-unknown-linux-gnu.tar.gz"
)

# rec NAME STATUS CLASS DETAIL (CLASS empty for a verified asset)
rec() {
  jq -nc --arg name "$1" --arg status "$2" --arg class "$3" --arg detail "$4" \
    '{name: $name, status: $status, failure_class: (if $class == "" then null else $class end), detail: $detail}' >>"$assets_log"
  echo "[$2${3:+/$3}] $1: $4"
}

finish() { # $1 = harness error, or empty
  jq -s --arg tag "$TAG" --arg harness "$1" '{
      tag: $tag,
      assets: .,
      harness_error: (if $harness == "" then null else $harness end),
      package_failures: [.[] | select(.failure_class == "package") | .name],
      failure_class: (if $harness != "" then "harness"
                      elif any(.[]; .failure_class == "package") then "package"
                      else null end)
    }' "$assets_log" >"$DIR/fetch.json"
}

harness() {
  finish "$1"
  echo "::error title=fetch (harness failure)::$1"
  exit 1
}

sha() { sha256sum "$1" | cut -d' ' -f1; }

# The release's assets with the sha256 GitHub stores for each.
if ! gh api "repos/$GITHUB_REPOSITORY/releases/tags/$TAG" --jq '.assets[] | "\(.name)\t\(.digest // "" | sub("^sha256:"; ""))"' >"$RUNNER_TEMP/release-assets.tsv" 2>"$err"; then
  harness "could not list the assets of $TAG: $(tail -2 "$err" | tr '\n' ' ')"
fi
published() { awk -F'\t' -v n="$1" '$1 == n { found = 1 } END { exit !found }' "$RUNNER_TEMP/release-assets.tsv"; }
stored_digest() { awk -F'\t' -v n="$1" '$1 == n { print $2 }' "$RUNNER_TEMP/release-assets.tsv"; }

# Download one asset, retrying transfer errors, until its bytes match the
# digest GitHub stores (when it reports one). Returns 1 on a harness failure
# and leaves the reason in $why.
why=""
download() {
  local n="$1" want got attempt
  want="$(stored_digest "$n")"
  for attempt in 1 2 3; do
    if gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir "$DIR" --clobber -p "$n" >/dev/null 2>"$err"; then
      got="$(sha "$DIR/$n")"
      if [ -z "$want" ] || [ "$got" = "$want" ]; then return 0; fi
      why="downloaded $n has sha256 $got, but GitHub stores $want for it (transfer error)"
    else
      why="downloading $n failed: $(tail -2 "$err" | tr '\n' ' ')"
    fi
    echo "attempt $attempt: $why"
    sleep $((attempt * 5))
  done
  return 1
}

sums=""
if published SHA256SUMS; then
  download SHA256SUMS || harness "$why"
  sums="$DIR/SHA256SUMS"
else
  rec SHA256SUMS not_published package "the release has no SHA256SUMS asset"
fi

for n in "${names[@]}"; do
  if ! published "$n"; then
    rec "$n" not_published package "the release has no asset $n"
    continue
  fi
  download "$n" || harness "$why"
  got="$(sha "$DIR/$n")"
  if [ -z "$sums" ]; then
    rec "$n" unverified package "sha256 $got; the release has no SHA256SUMS to check it against"
    continue
  fi
  want="$(awk -v n="$n" '$2 == n || $2 == "*" n { print $1 }' "$sums")"
  if [ -z "$want" ]; then
    rec "$n" not_in_sums package "the release's SHA256SUMS does not list $n (sha256 $got)"
  elif [ "$want" != "$got" ]; then
    rec "$n" mismatch package "sha256 $got (as GitHub stores it), but the release's SHA256SUMS says $want"
  else
    rec "$n" ok "" "sha256 $got matches SHA256SUMS"
  fi
done

finish ""
jq -r '"fetch: \(.assets | length) assets checked; package problems: \(.package_failures | if length == 0 then "none" else join(", ") end)"' "$DIR/fetch.json"
