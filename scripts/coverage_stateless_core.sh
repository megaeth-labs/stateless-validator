#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COV_DIR="${COV_DIR:-$ROOT_DIR/target/coverage/stateless-core}"
HTML_INDEX="$COV_DIR/html/index.html"
LCOV_PATH="$COV_DIR/lcov.info"
REPORT="$COV_DIR/report.txt"
IGNORE_FILENAME_REGEX="${IGNORE_FILENAME_REGEX:-(/tests/|/benches/|/examples/|/\.cargo/registry/|/rustc/)}"

if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "cargo-llvm-cov is required. Install it with 'cargo install cargo-llvm-cov --locked'." >&2
    exit 1
fi

cd "$ROOT_DIR"
rm -rf "$COV_DIR"
mkdir -p "$COV_DIR"

cargo llvm-cov clean --workspace

cargo llvm-cov \
    --locked \
    --package stateless-core \
    --no-default-features \
    --lib \
    --tests \
    --no-fail-fast \
    --no-report

cargo llvm-cov report \
    --package stateless-core \
    --ignore-filename-regex "$IGNORE_FILENAME_REGEX" \
    --lcov \
    --output-path "$LCOV_PATH"

cargo llvm-cov report \
    --package stateless-core \
    --ignore-filename-regex "$IGNORE_FILENAME_REGEX" \
    --html \
    --output-dir "$COV_DIR"

cargo llvm-cov report \
    --package stateless-core \
    --ignore-filename-regex "$IGNORE_FILENAME_REGEX" > "$REPORT"

echo
echo "Coverage artifacts written to $COV_DIR"
echo "Open $HTML_INDEX to inspect the HTML report."
echo "Upload $LCOV_PATH to Codecov to annotate pull requests."
