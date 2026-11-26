#!/usr/bin/env bash
# Checks that vendor/ holds exactly the files listed in vendor/SHA256SUMS, byte for byte:
# every listed file is present with its recorded SHA-256, and no other file exists.
# README.md, SHA256SUMS and this script are the records of the copies and are not listed.
# See vendor/README.md.
set -euo pipefail

cd "$(dirname "$0")"

if command -v sha256sum > /dev/null 2>&1; then
    sha256() { sha256sum "$@"; }
else
    sha256() { shasum -a 256 "$@"; }
fi

status=0

if ! sha256 --check --quiet --strict SHA256SUMS; then
    echo "vendor/check.sh: a listed file is missing or differs from SHA256SUMS" >&2
    status=1
fi

listed="$(sed -E 's/^[0-9a-f]{64}  //' SHA256SUMS | LC_ALL=C sort)"
present="$(find . -type f ! -path ./README.md ! -path ./SHA256SUMS ! -path ./check.sh \
    | sed 's|^\./||' | LC_ALL=C sort)"
if [ "$listed" != "$present" ]; then
    echo "vendor/check.sh: files under vendor/ do not match SHA256SUMS (< listed only, > present only):" >&2
    diff <(printf '%s\n' "$listed") <(printf '%s\n' "$present") | grep '^[<>]' >&2 || true
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "vendor/check.sh: $(printf '%s\n' "$listed" | wc -l | tr -d ' ') files match SHA256SUMS"
fi
exit "$status"
