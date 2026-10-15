#!/bin/sh
# RUSTC_WRAPPER for coverage-replayer's instrumented build: instrument only the code the
# tool measures and build everything else plain. Every instrumented basic block bumps a
# process-global counter, which in hot loops dwarfs the work and contends across threads.
#
# Must be instrumented:
#   - the mega-evm checkout and the crates in measured-crates.txt: the measured code;
#   - this workspace: a generic function is compiled, counters included, in the crate that
#     instantiates it, and rustc drops the coverage of an instance compiled without the
#     flag. Nothing outside the workspace depends on mega-evm, so nothing else can
#     instantiate it.
# Need not be: registry crates depending on the measured revm crates (alloy-evm, revm, a
# few reth crates); what they instantiate is over their own types, off mega-evm's path.
# Host artifacts (build scripts, proc-macros) are skipped, or each run drops a
# default_*.profraw into the source tree; they are the rustc invocations without
# `--target`, which is why the build line passes one.
#
# Cargo cannot see what this wrapper decides: a crate added to measured-crates.txt stays
# uninstrumented until `cargo clean -p <crate>`. Names are compared the way build.rs reads
# the file — trimmed, CRLF-safe.
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
