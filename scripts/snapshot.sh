#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# Capture the open-issue state of an organisation (or one of its
# repositories) as JSON, dropping excluded repositories. The triage
# workflow calls this twice: before and after the agent session.
#
# Arguments:
#   $1  output file for the snapshot JSON
#
# Environment:
#   ORG            (required) organisation or user to scan
#   REPOSITORY     restrict the scan to this repository name
#   EXCLUDE_REPOS  comma-separated repository names to skip;
#                  overrides EXCLUDE_FILE when non-empty
#   EXCLUDE_FILE   file of repository names to skip, one per line,
#                  '#' comments permitted
#   GH_TOKEN       token for the gh CLI
#
# Alongside the snapshot, the script writes the resolved exclusion
# list to excluded-repos.txt in the output directory, so later
# steps (prompt assembly, the report) share one source of truth.

set -euo pipefail

outfile="$1"
outdir="$(dirname "$outfile")"
mkdir -p "$outdir"

excludes=""
if [ -n "${EXCLUDE_REPOS:-}" ]; then
  excludes="$(printf '%s' "$EXCLUDE_REPOS" | tr ',' '\n')"
elif [ -n "${EXCLUDE_FILE:-}" ]; then
  if [ ! -f "$EXCLUDE_FILE" ]; then
    echo "Snapshot: configured EXCLUDE_FILE is not a regular file" >&2
    exit 1
  fi
  excludes="$(sed 's/#.*$//' "$EXCLUDE_FILE")"
fi
excludes="$(printf '%s\n' "$excludes" | sed \
  -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^$/d' \
  | tr '[:upper:]' '[:lower:]')"

# Stage beside the destination so the final snapshot rename is atomic.
# Failed queries leave any previously published evidence untouched.
tmpdir="$(mktemp -d "$outdir/.snapshot.XXXXXX")"
trap 'rm -rf -- "$tmpdir"' EXIT
printf '%s\n' "$excludes" > "$tmpdir/excluded-repos.txt"

# The packet travels to a runner that audits egress rather than
# blocking it (DESIGN.md section 7.1). That is acceptable for text the
# organisation already publishes and for nothing else, so the search
# asks for issues in public repositories alone. The filter runs
# server-side at fetch time: no separate listing to race against, and
# no listing cap to fall off.
limit=1000
args=(--owner "$ORG" --state open --visibility public --limit "$limit"
  --json 'repository,number,title,url,labels,createdAt,updatedAt')
if [ -n "${REPOSITORY:-}" ]; then
  args+=(--repo "$ORG/$REPOSITORY")
fi

# No unfiltered intermediate file touches disk. Slurping requires
# exactly one JSON array, even when gh exits successfully without data.
# Check the search ceiling before exclusions can disguise truncation.
gh search issues "${args[@]}" | jq -e -s \
  --arg excl "$excludes" --argjson limit "$limit" '
  if length != 1 or (.[0] | type) != "array" then
    error("snapshot response must be a single JSON array")
  else .[0] end
  | if length >= $limit then
      error("snapshot reached the \($limit)-result search limit; restrict the scan")
    else . end
  | ($excl | split("\n") | map(select(length > 0))) as $list
  | map(select(.repository.name | ascii_downcase as $n
      | ($list | index($n)) | not))
' > "$tmpdir/snapshot.json"

count="$(jq 'length' "$tmpdir/snapshot.json")"
mv -- "$tmpdir/excluded-repos.txt" "$outdir/excluded-repos.txt"
mv -- "$tmpdir/snapshot.json" "$outfile"
echo "Snapshot: $count open issue(s) -> $outfile"
