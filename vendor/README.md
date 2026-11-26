# vendor

Copies of six upstream crates that this workspace patches in from the root `Cargo.toml`.

## Why this directory exists

The workspace builds on the Paradigm reth v2.3.0 line with revm 43, alloy-evm 0.39, Alloy 2.5
and the Optimism crates at `f84988888034b4692715e528a1d9fc69de511eab`. The published manifests of
the crates below ask for other versions: reth v2.3.0 requires revm 40 and alloy-evm 0.36,
reth-primitives-traits 0.4.1 requires the revm 40 component crates (`revm-bytecode 11`,
`revm-primitives 24`, `revm-state 12`), and the Optimism crates require the reth-core 0.8 line.

Cargo `[patch]` can replace where a dependency comes from, but it cannot change the version
requirements written in a dependency's own manifest. So each of these crates is copied here with
its requirements changed, and the root `Cargo.toml` patches the upstream crate with the copy.

The copies are not workspace members (`[workspace].exclude`), so `cargo sort --workspace`,
`cargo fmt --all` and `cargo clippy --workspace` do not cover them. They still build as path
dependencies, so their compiler warnings are not capped.

## Copies

| Crate | Copy | Upstream | Revision | Upstream path |
|---|---|---|---|---|
| `reth-chainspec` | `paradigm-v2.3.0/crates/chainspec` | [paradigmxyz/reth](https://github.com/paradigmxyz/reth) | tag `v2.3.0` (`9384bc53d8c0c77e59cac83fdaaf3b372c6d2216`) | `crates/chainspec` |
| `op-alloy-consensus` | `optimism-f8498888/op-alloy/crates/consensus` | [ethereum-optimism/optimism](https://github.com/ethereum-optimism/optimism) | `f84988888034b4692715e528a1d9fc69de511eab` | `rust/op-alloy/crates/consensus` |
| `op-alloy-rpc-types` | `optimism-f8498888/op-alloy/crates/rpc-types` | ethereum-optimism/optimism | `f8498888` | `rust/op-alloy/crates/rpc-types` |
| `reth-optimism-chainspec` | `optimism-f8498888/op-reth/crates/chainspec` | ethereum-optimism/optimism | `f8498888` | `rust/op-reth/crates/chainspec` |
| `reth-optimism-primitives` | `optimism-f8498888/op-reth/crates/primitives` | ethereum-optimism/optimism | `f8498888` | `rust/op-reth/crates/primitives` |
| `reth-primitives-traits` | `reth-primitives-traits-0.4.1` | crates.io | `0.4.1` | the published package |

`paradigm-v2.3.0/Cargo.toml` and `optimism-f8498888/Cargo.toml` are the upstream workspace roots
(reth's `Cargo.toml`, and Optimism's `rust/Cargo.toml`), kept so the copied crates resolve their
`workspace = true` entries unchanged.

The MegaETH node repository carries the same six crates under the same paths, next to others it
needs. Their files are byte-identical in both repositories, and so are their lines in the two
`SHA256SUMS` files.

## Differences from upstream

Every difference is listed here. Everything else is byte-identical to upstream.

1. `paradigm-v2.3.0/Cargo.toml`, trimmed workspace root:
   - `members` lists only `crates/chainspec`, and `default-members` is removed;
   - workspace dependencies that upstream gives as `path = "crates/..."` point to
     `git = "https://github.com/paradigmxyz/reth", tag = "v2.3.0"`;
   - `reth-primitives-traits = "=0.4.1"`, `revm = "=43.0.3"`, `revm-bytecode = "=43.0.0"`,
     `revm-database = "=43.0.1"`, `revm-state = "=43.0.1"`, `revm-primitives = "=43.0.0"` and
     `alloy-evm = "=0.39.0"`.
2. `optimism-f8498888/Cargo.toml`, trimmed workspace root:
   - `members` lists only the four Optimism copies, and `default-members` is removed;
   - workspace dependencies that upstream gives as `path = ...` point to
     `git = "https://github.com/ethereum-optimism/optimism", rev = "f84988888034b4692715e528a1d9fc69de511eab"`;
   - `reth-codecs`, `reth-codecs-derive`, `reth-rpc-traits` and `reth-zstd-compressors` require
     `0.4.1` instead of `0.8.1`, and `reth-primitives-traits` requires `=0.4.1`;
   - `revm`, `revm-bytecode`, `revm-database`, `revm-state`, `revm-primitives` and `alloy-evm`
     require the same versions as upstream, written as exact (`=`) requirements.
3. `reth-primitives-traits-0.4.1/Cargo.toml`, three lines: `revm-bytecode` `11.0.0` → `=43.0.0`,
   `revm-primitives` `24.0.0` → `=43.0.0`, `revm-state` `12.0.0` → `=43.0.1`. The published
   `Cargo.toml.orig` is kept as it is.
4. `optimism-f8498888/op-reth/crates/chainspec/res/superchain-configs.tar` is absent. Upstream
   generates it and git ignores it; it is read only with the `superchain-configs` feature, which
   no crate in this workspace enables. `res/superchain-configs.tar.sha256` is kept, as upstream
   tracks it.

No Rust source file differs from upstream.

## Checking the copies

`vendor/check.sh` checks that `vendor/` holds exactly the files listed in `vendor/SHA256SUMS`
with the recorded hashes, and no other file. `README.md`, `SHA256SUMS` and `check.sh` are not
listed. CI runs it in the `lint` job of `.github/workflows/build-and-test.yml`.

To compare a copy with upstream, check out the upstream revision and diff the crate directory,
for example:

```sh
git clone --filter=blob:none --no-checkout https://github.com/paradigmxyz/reth reth-upstream
git -C reth-upstream checkout v2.3.0
diff -ru reth-upstream/crates/chainspec vendor/paradigm-v2.3.0/crates/chainspec
```

Across all copies, the only differences are the ones listed above. For `reth-primitives-traits`,
compare with the published package
(`https://static.crates.io/crates/reth-primitives-traits/reth-primitives-traits-0.4.1.crate`,
a gzipped tar archive).

If a copy has to change, record the change in the list above, regenerate the manifest, and make
the same change in the MegaETH node repository:

```sh
cd vendor && find . -type f ! -path ./README.md ! -path ./SHA256SUMS ! -path ./check.sh \
    | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
```

## Retirement

Delete `vendor/` in full in the change that moves this workspace and the MegaETH node from
Paradigm reth v2.3.0 (reth-core 0.4.1) to a reth release built on revm 43 or later and
alloy-evm 0.39 or later. In the same change, remove:

- the three `vendor/` entries in `[workspace].exclude` and every `[patch]` row that points into
  `vendor/`, and review the `[patch."https://github.com/ethereum-optimism/reth"]` table;
- `./vendor` in the codespell `skip` list of `.github/workflows/build-and-test.yml`;
- the CI step that runs `vendor/check.sh`.

All copies go together; none is kept past that upgrade. No product change is ever made in this
directory.
