#!/bin/sh
# RUSTC_WRAPPER for coverage-replayer's instrumented build: instrument only the
# code the tool measures, and build everything else plain.
#
# Instrumentation anywhere else buys nothing and costs a great deal. Every
# basic block of an instrumented crate bumps a process-global counter; in tight
# loops that dwarfs the work itself (field arithmetic in k256, per-byte bincode
# encoding), and threads running the same code contend for the same counter
# cache lines. Measured on mainnet blocks, instrumenting only what is below
# replays a block several times faster than instrumenting everything and yields
# a byte-identical `report` — same denominators, same covered regions and
# branches.
#
# What must be instrumented:
#   - the mega-evm checkout and the crates in measured-crates.txt: the measured
#     code itself;
#   - this workspace: most of that code is generic (over the database, over
#     mega-evm's host), and a generic function is compiled — counters included —
#     in the crate that instantiates it. rustc drops the coverage statements of
#     an instance compiled without the flag, so an uninstrumented workspace
#     would silently lose exactly the code paths that matter. Nothing outside
#     the workspace depends on mega-evm, so nothing else can instantiate it.
# What need not be: the registry crates that depend on the measured revm crates
# (alloy-evm, alloy-op-evm, revm, revm-inspector, a few reth crates). Whatever
# they instantiate is over their own types, not mega-evm's, and mega-evm's
# execution path does not run it: instrumenting them as well was measured to
# leave every measured file's report unchanged, at a cost on every block.
# Host artifacts (build scripts, proc-macros) are skipped: instrumented, each
# run of theirs drops a default_*.profraw into the source tree. They are the
# rustc invocations without `--target`, which is why the build line passes one.
#
# Cargo cannot see what this wrapper decides: a crate added to
# measured-crates.txt is not recompiled, and stays uninstrumented, until
# `cargo clean -p <crate>` (backfill then fails naming its source root).
# Names are compared the way build.rs reads the file — trimmed, CRLF-safe.
here=$(cd "$(dirname "$0")" && pwd)
workspace=$(cd "$here/../.." && pwd)

targeted=no
for arg in "$@"; do
    [ "$arg" = "--target" ] && targeted=yes
done

instrument=no
if [ "$targeted" = yes ]; then
    case "${CARGO_MANIFEST_DIR:-}" in
    */git/checkouts/mega-evm-* | "$workspace" | "$workspace"/*) instrument=yes ;;
    esac
    if [ "$instrument" = no ] && [ -n "${CARGO_PKG_NAME:-}" ] &&
        tr -d '\r' <"$here/measured-crates.txt" |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//' |
            grep -qx -- "$CARGO_PKG_NAME"; then
        instrument=yes
    fi
fi

if [ "$instrument" = yes ]; then
    exec "$@" -C instrument-coverage -Z coverage-options=branch
fi
exec "$@"
