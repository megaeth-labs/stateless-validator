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
# Host artifacts (build scripts, proc-macros) are skipped: instrumented, each
# run of theirs drops a default_*.profraw into the source tree. They are the
# rustc invocations without `--target`, which is why the build line passes one.
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
        grep -qx -- "$CARGO_PKG_NAME" "$here/measured-crates.txt"; then
        instrument=yes
    fi
fi

if [ "$instrument" = yes ]; then
    exec "$@" -C instrument-coverage -Z coverage-options=branch
fi
exec "$@"
