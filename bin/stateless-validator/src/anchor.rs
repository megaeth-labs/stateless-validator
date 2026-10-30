//! The validated chain's anchor: how startup sets or keeps it, and how a reorg moves the chain
//! above it.
//!
//! The validated chain is `(anchor, validated]`. The anchor is a block the operator trusts
//! without re-executing it, and every block above it up to `validated` has been validated.
//! Every block in that range is on the canonical chain of the `--rpc-endpoint`s as last observed,
//! and `anchor < validated` whenever both are set.
//!
//! - **Startup** ([`apply_startup_request`]). A data dir with no anchor takes one from
//!   `--start-block`. A data dir with a validated chain resumes it, unless `--start-block` comes
//!   with `--force-anchor`, which replaces it. Either flag alone with a stored chain fails startup.
//!   The anchor `--start-block` names must be on the remote canonical chain, and validation starts
//!   above it with nothing validated.
//! - **Reorg** ([`ValidatorReorgResolver`]). A fork inside the retained canonical chain rewinds
//!   `validated` to the fork point, or to nothing when the fork point is the anchor. A fork below
//!   the retained rows but above the anchor rewinds to the anchor, since the hashes that would
//!   locate it more precisely are gone. A fork below the anchor halts: the validator holds no
//!   hashes below its anchor to find the fork point with, and a new anchor is a trust decision it
//!   cannot make on its own.

use alloy_primitives::BlockHash;
use alloy_rpc_types_eth::BlockId;
use eyre::{Result, eyre};
use stateless_common::RpcClient;
use stateless_core::{
    ChainStore, DivergenceLookups,
    db::BlockMeta,
    find_divergence_point,
    pipeline::{BlockFetcher, DivergenceError, ReorgResolution, ReorgResolver},
};
use stateless_db::ValidatedChain;
use tracing::{info, warn};

use crate::validator_db::ValidatorDB;

/// Decides from the stored chain and `--start-block` / `--force-anchor` which block startup
/// anchors at, or `None` to resume the stored chain.
///
/// `--force-anchor` needs `--start-block`. A stored chain is resumed when neither is given and
/// replaced only when both are, so a `--start-block` left in a deployment's environment cannot
/// silently throw validated progress away on a restart. A data dir with no chain needs
/// `--start-block`; `--force-anchor` is accepted there, as there is nothing to replace.
fn startup_anchor(
    stored: &ValidatedChain,
    start_block: Option<BlockHash>,
    force_anchor: bool,
) -> Result<Option<BlockHash>> {
    match (&stored.anchor, start_block, force_anchor) {
        (_, None, true) => Err(eyre!("--force-anchor requires --start-block")),
        (None, None, false) => Err(eyre!(
            "No trusted starting point found. Specify a trusted block with --start-block \
             <blockhash>"
        )),
        (Some(_), None, false) => Ok(None),
        (Some(anchor), Some(_), false) => Err(eyre!(
            "the data dir already holds a validated chain (anchor {} {}, validated {}); omit \
             --start-block to resume it, or pass --force-anchor with --start-block to replace it \
             and clear its validated progress",
            anchor.block_number,
            anchor.block_hash,
            stored.validated.as_ref().map_or_else(
                || "none".to_string(),
                |v| format!("{} {}", v.block_number, v.block_hash)
            ),
        )),
        (None, Some(hash), _) | (Some(_), Some(hash), true) => Ok(Some(hash)),
    }
}

/// Applies `--start-block` / `--force-anchor` to the validated chain in `validator_db` before the
/// pipeline starts; see [`startup_anchor`] for which combinations are accepted.
///
/// Initializing and resetting both anchor at the block `--start-block` names, which must be on
/// the canonical chain of the `--rpc-endpoint`s, and leave nothing validated above it.
pub(crate) async fn apply_startup_request(
    client: &RpcClient,
    validator_db: &ValidatorDB,
    start_block: Option<BlockHash>,
    force_anchor: bool,
) -> Result<()> {
    let stored = validator_db.validated_chain()?;
    let Some(hash) = startup_anchor(&stored, start_block, force_anchor)? else {
        info!(
            anchor = ?stored.anchor.as_ref().map(|a| (a.block_number, a.block_hash)),
            validated = ?stored.validated.as_ref().map(|v| v.block_number),
            "Resuming the stored validated chain"
        );
        return Ok(());
    };

    info!(start_block = %hash, "Checking --start-block against the canonical chain");
    let anchor = resolve_canonical_anchor(client, hash).await?;
    validator_db.reset_to_anchor(&anchor)?;
    match stored.anchor {
        None => info!(
            block_number = anchor.block_number,
            block_hash = %anchor.block_hash,
            "Anchored at --start-block; validation starts above it"
        ),
        Some(previous) => warn!(
            block_number = anchor.block_number,
            block_hash = %anchor.block_hash,
            previous_anchor = previous.block_number,
            previous_validated = ?stored.validated.as_ref().map(|v| v.block_number),
            "--force-anchor: replaced the validated chain; its validated progress is cleared"
        ),
    }
    Ok(())
}

/// The block `hash` names, provided it is on the canonical chain the `--rpc-endpoint`s serve.
///
/// Transport failures are retried as every RPC call is. A block the endpoints do not have, have
/// only off the canonical chain, or that carries no withdrawals root fails with an error naming
/// the chain head — the highest block that could be an anchor — and, when the block's height is
/// known, the canonical hash at that height.
async fn resolve_canonical_anchor(client: &RpcClient, hash: BlockHash) -> Result<BlockMeta> {
    let header = client.find_header(BlockId::Hash(hash.into()), true).await;
    let canonical = match &header {
        Some(header) => {
            client.find_header(BlockId::Number(header.number.into()), false).await.map(|h| h.hash)
        }
        None => None,
    };
    let reason = match (&header, canonical) {
        (Some(header), Some(canonical)) if canonical == hash => {
            return BlockMeta::try_from_header(header).ok_or_else(|| {
                eyre!("--start-block {hash} (block {}) has no withdrawals root", header.number)
            });
        }
        (None, _) => "the endpoints do not know the block".to_string(),
        (Some(header), Some(canonical)) => format!(
            "it is block {}, but the canonical block at that height is {canonical}",
            header.number
        ),
        (Some(header), None) => {
            format!("it is block {}, above the canonical chain head", header.number)
        }
    };

    let head = client.get_header(BlockId::latest(), false).await;
    Err(eyre!(
        "--start-block {hash} is not on the canonical chain of --rpc-endpoint: {reason}; the \
         chain head, the highest usable anchor, is block {} {}",
        head.number,
        head.hash
    ))
}

/// The validator's [`ReorgResolver`]: the core bisection over the retained canonical chain, with
/// the anchor as the floor when the fork lies below what that chain still holds.
///
/// [`find_divergence_point`] can only compare the rows retention has kept
/// (`--canonical-chain-max-length`). When even the oldest of them is off the remote chain:
/// - and the anchor is still on it, the fork lies between the two, and the chain rewinds to the
///   anchor: every block above it is validated again, and the anchor is kept.
/// - and the anchor is off it too, the fork lies below the anchor. The validator holds no hashes
///   there to locate it with, so it halts, naming the remote head an operator can re-anchor at with
///   `--start-block <hash> --force-anchor`.
pub(crate) struct ValidatorReorgResolver;

impl<F, S> ReorgResolver<F, S> for ValidatorReorgResolver
where
    F: BlockFetcher,
    S: ChainStore + DivergenceLookups,
{
    async fn resolve(&self, fetcher: &F, store: &S, persisted_tip: u64) -> Result<ReorgResolution> {
        let (earliest, earliest_hash, remote_hash) =
            match find_divergence_point(fetcher, store, persisted_tip).await {
                Ok(floor) => return Ok(ReorgResolution::Floor(floor)),
                Err(DivergenceError::CatastrophicReorg {
                    block_number,
                    local_hash,
                    remote_hash,
                }) => (block_number, local_hash, remote_hash),
                Err(e) => return Ok(e.into()),
            };

        let anchor = match store.get_anchor() {
            Ok(Some(anchor)) => anchor,
            Ok(None) => {
                return Ok(ReorgResolution::Fatal(format!(
                    "reorg below block {earliest}, and the validated chain has no anchor"
                )));
            }
            Err(e) => return Ok(ReorgResolution::Retry(e.to_string())),
        };
        let remote_anchor_hash = if anchor.block_number == earliest {
            remote_hash
        } else {
            match fetcher.block_hash(anchor.block_number).await {
                Ok(hash) => hash,
                Err(e) => return Ok(ReorgResolution::Retry(e.to_string())),
            }
        };

        if remote_anchor_hash == anchor.block_hash {
            warn!(
                earliest_retained = earliest,
                earliest_local_hash = %earliest_hash,
                earliest_remote_hash = %remote_hash,
                anchor = anchor.block_number,
                revalidating = persisted_tip.saturating_sub(anchor.block_number),
                "Reorg below the retained canonical chain but above the anchor: validating \
                 again from the anchor"
            );
            return Ok(ReorgResolution::Floor(anchor.block_number));
        }

        let head = match fetcher.latest_block_meta().await {
            Ok(head) => format!("block {} {}", head.block_number, head.block_hash),
            Err(e) => format!("unknown ({e})"),
        };
        Ok(ReorgResolution::Fatal(format!(
            "reorg below the anchor: anchor block {} {} is no longer on the canonical chain of \
             --rpc-endpoint (canonical hash at that height: {remote_anchor_hash}), and the \
             validator keeps no block hashes below its anchor to locate the fork with. Restart \
             with --start-block <hash> --force-anchor on a trusted block of the current chain; \
             its head, the highest usable anchor, is {head}",
            anchor.block_number, anchor.block_hash,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy_primitives::B256;
    use alloy_rpc_types_eth::Header;
    use jsonrpsee::types::ErrorObjectOwned;
    use stateless_test_utils::mock_rpc::{consistent_header, parse_hex_u64, serve};

    use super::*;
    use crate::test_support::make_block_meta;

    fn hash(byte: u8) -> BlockHash {
        BlockHash::repeat_byte(byte)
    }

    fn stored(anchor: Option<u64>, validated: Option<u64>) -> ValidatedChain {
        ValidatedChain {
            anchor: anchor.map(make_block_meta),
            validated: validated.map(make_block_meta),
        }
    }

    /// Every combination of stored chain and anchor flags, against what the chain-pointer
    /// requirements ask of startup.
    #[test]
    fn startup_anchor_follows_the_stored_chain_and_the_flags() {
        let fresh = stored(None, None);
        let anchored = stored(Some(5), None);
        let validated = stored(Some(5), Some(9));

        for chain in [&fresh, &anchored, &validated] {
            let err = startup_anchor(chain, None, true).unwrap_err().to_string();
            assert!(err.contains("--force-anchor requires --start-block"), "{err}");
        }

        let err = startup_anchor(&fresh, None, false).unwrap_err().to_string();
        assert!(err.contains("--start-block"), "{err}");
        for force in [false, true] {
            assert_eq!(startup_anchor(&fresh, Some(hash(1)), force).unwrap(), Some(hash(1)));
        }

        for chain in [&anchored, &validated] {
            assert_eq!(startup_anchor(chain, None, false).unwrap(), None, "resumes");
            let err = startup_anchor(chain, Some(hash(1)), false).unwrap_err().to_string();
            assert!(err.contains("--force-anchor") && err.contains("resume"), "{err}");
            assert_eq!(startup_anchor(chain, Some(hash(1)), true).unwrap(), Some(hash(1)));
        }

        let err = startup_anchor(&validated, Some(hash(1)), false).unwrap_err().to_string();
        assert!(err.contains("anchor 5") && err.contains("validated 9"), "{err}");
    }

    /// A self-consistent header for `number` with a withdrawals root, distinguished by `salt`
    /// so two headers at one height can name different blocks.
    fn header(number: u64, salt: u8) -> Header {
        let mut header = consistent_header(number);
        header.inner.withdrawals_root = Some(B256::repeat_byte(0xaa));
        header.inner.extra_data = vec![salt].into();
        header.hash = header.inner.hash_slow();
        header
    }

    /// A remote whose canonical chain is `canonical` (by height, highest is the head), and that
    /// also knows the `side` blocks by hash, off that chain.
    async fn remote(
        canonical: Vec<Header>,
        side: Vec<Header>,
    ) -> (jsonrpsee::server::ServerHandle, RpcClient) {
        struct Chain {
            by_number: HashMap<u64, Header>,
            by_hash: HashMap<BlockHash, Header>,
            head: Header,
        }
        let head = canonical.iter().max_by_key(|h| h.number).cloned().unwrap();
        let chain = Chain {
            by_number: canonical.iter().map(|h| (h.number, h.clone())).collect(),
            by_hash: canonical.iter().chain(&side).map(|h| (h.hash, h.clone())).collect(),
            head,
        };
        let (handle, url) = serve(chain, |m| {
            m.register_method("eth_getHeaderByHash", |params, chain, _| {
                let (hash,): (BlockHash,) = params.parse().unwrap();
                Ok::<_, ErrorObjectOwned>(chain.by_hash.get(&hash).cloned())
            })
            .unwrap();
            m.register_method("eth_getHeaderByNumber", |params, chain, _| {
                let (tag,): (String,) = params.parse().unwrap();
                Ok::<_, ErrorObjectOwned>(match tag.as_str() {
                    "latest" => Some(chain.head.clone()),
                    number => chain.by_number.get(&parse_hex_u64(number)).cloned(),
                })
            })
            .unwrap();
        })
        .await;
        (handle, RpcClient::new(&[&url], &[&url]).unwrap())
    }

    /// A block on the remote canonical chain becomes the anchor, roots included.
    #[tokio::test]
    async fn a_canonical_start_block_resolves_to_its_meta() {
        let chain: Vec<Header> = (1..=4).map(|n| header(n, 0)).collect();
        let (handle, client) = remote(chain.clone(), vec![]).await;

        let anchor = resolve_canonical_anchor(&client, chain[1].hash).await.unwrap();
        assert_eq!(anchor, BlockMeta::try_from_header(&chain[1]).unwrap());
        handle.stop().unwrap();
    }

    /// A start block the remote does not hold on its canonical chain is refused, and the error
    /// names the head (the highest usable anchor) and, when the block's height is known, the
    /// canonical hash there.
    #[tokio::test]
    async fn a_start_block_off_the_canonical_chain_is_refused_with_the_head() {
        let chain: Vec<Header> = (1..=4).map(|n| header(n, 0)).collect();
        let (sibling, above_head) = (header(3, 1), header(6, 1));
        let (handle, client) =
            remote(chain.clone(), vec![sibling.clone(), above_head.clone()]).await;
        let head = format!("block 4 {}", chain[3].hash);

        let err = resolve_canonical_anchor(&client, sibling.hash).await.unwrap_err().to_string();
        assert!(err.contains(&head), "{err}");
        assert!(err.contains(&format!("canonical block at that height is {}", chain[2].hash)));

        let err = resolve_canonical_anchor(&client, above_head.hash).await.unwrap_err().to_string();
        assert!(err.contains(&head) && err.contains("above the canonical chain head"), "{err}");

        let err = resolve_canonical_anchor(&client, hash(0xee)).await.unwrap_err().to_string();
        assert!(err.contains(&head) && err.contains("do not know the block"), "{err}");
        handle.stop().unwrap();
    }

    /// A reset re-anchors at the block and clears the validated progress; a stored chain with
    /// `--start-block` alone is refused and left as it was.
    #[tokio::test]
    async fn a_forced_reset_replaces_the_stored_chain() {
        let chain: Vec<Header> = (1..=4).map(|n| header(n, 0)).collect();
        let (handle, client) = remote(chain.clone(), vec![]).await;
        let dir = tempfile::tempdir().unwrap();
        let db = ValidatorDB::new(dir.path().join("test.redb")).unwrap();

        apply_startup_request(&client, &db, Some(chain[0].hash), false).await.unwrap();
        let first = BlockMeta::try_from_header(&chain[0]).unwrap();
        db.advance_chain(&[make_block_meta(2), make_block_meta(3)]).unwrap();
        let before = db.validated_chain().unwrap();
        assert_eq!(before.anchor, Some(first));

        assert!(apply_startup_request(&client, &db, Some(chain[1].hash), false).await.is_err());
        assert_eq!(db.validated_chain().unwrap(), before);
        apply_startup_request(&client, &db, None, false).await.unwrap();
        assert_eq!(db.validated_chain().unwrap(), before, "a resume changes nothing");

        apply_startup_request(&client, &db, Some(chain[1].hash), true).await.unwrap();
        let reset = BlockMeta::try_from_header(&chain[1]).unwrap();
        assert_eq!(
            db.validated_chain().unwrap(),
            ValidatedChain { anchor: Some(reset), validated: None }
        );
        handle.stop().unwrap();
    }

    /// An in-memory remote for the resolver: canonical hashes by height.
    struct Remote(HashMap<u64, BlockHash>);

    impl BlockFetcher for Remote {
        type Output = ();
        async fn fetch(&self, _: u64) -> Result<()> {
            unimplemented!("not used")
        }
        async fn latest_block_number(&self) -> Result<u64> {
            Ok(*self.0.keys().max().unwrap())
        }
        async fn block_hash(&self, n: u64) -> Result<BlockHash> {
            self.0.get(&n).copied().ok_or_else(|| eyre!("block {n} not found"))
        }
        async fn latest_block_meta(&self) -> Result<BlockMeta> {
            let n = self.latest_block_number().await?;
            Ok(BlockMeta { block_hash: self.0[&n], ..make_block_meta(n) })
        }
    }

    /// A validator DB anchored at `anchor` with `anchor+1..=tip` validated, retaining `retain`
    /// canonical rows, plus a remote that agrees with it up to `fork` and differs above.
    fn reorged(
        anchor: u64,
        tip: u64,
        retain: u64,
        fork: u64,
    ) -> (tempfile::TempDir, ValidatorDB, Remote) {
        let dir = tempfile::tempdir().unwrap();
        let db = ValidatorDB::with_max_chain_length(dir.path().join("test.redb"), retain).unwrap();
        db.reset_to_anchor(&make_block_meta(anchor)).unwrap();
        db.advance_chain(&((anchor + 1)..=tip).map(make_block_meta).collect::<Vec<_>>()).unwrap();
        let remote = (0..=tip + 2)
            .map(|n| {
                let local = make_block_meta(n).block_hash;
                (n, if n <= fork { local } else { BlockHash::repeat_byte(0xf0) })
            })
            .collect();
        (dir, db, Remote(remote))
    }

    async fn resolve(db: &ValidatorDB, remote: &Remote, tip: u64) -> ReorgResolution {
        ValidatorReorgResolver.resolve(remote, db, tip).await.unwrap()
    }

    /// A fork inside the retained rows rewinds to the fork point, which may be the anchor.
    #[tokio::test]
    async fn a_fork_in_the_retained_chain_rewinds_to_the_fork_point() {
        for fork in [10, 14] {
            let (_dir, db, remote) = reorged(10, 20, 100, fork);
            assert!(
                matches!(resolve(&db, &remote, 20).await, ReorgResolution::Floor(f) if f == fork)
            );
        }
    }

    /// A fork below the retained rows but above the anchor rewinds to the anchor, and the
    /// rollback then leaves the anchor with nothing validated.
    #[tokio::test]
    async fn a_fork_below_the_retained_chain_rewinds_to_the_anchor() {
        let (_dir, db, remote) = reorged(10, 30, 5, 15);
        assert_eq!(DivergenceLookups::get_earliest(&db).unwrap().unwrap().0, 26);

        let ReorgResolution::Floor(floor) = resolve(&db, &remote, 30).await else {
            panic!("the anchor is still canonical, so the chain rewinds to it");
        };
        assert_eq!(floor, 10);
        db.rollback_chain(floor).unwrap();
        assert_eq!(
            db.validated_chain().unwrap(),
            ValidatedChain { anchor: Some(make_block_meta(10)), validated: None }
        );
    }

    /// A fork below the anchor halts with the head to re-anchor at, whether or not the anchor's
    /// row is still retained.
    #[tokio::test]
    async fn a_fork_below_the_anchor_halts_naming_the_head() {
        for retain in [100, 5] {
            let (_dir, db, remote) = reorged(10, 30, retain, 7);
            let ReorgResolution::Fatal(msg) = resolve(&db, &remote, 30).await else {
                panic!("a fork below the anchor cannot be located");
            };
            assert!(msg.contains("--force-anchor"), "{msg}");
            assert!(msg.contains(&format!("block 32 {}", BlockHash::repeat_byte(0xf0))), "{msg}");
            assert_eq!(db.get_anchor().unwrap(), Some(make_block_meta(10)), "nothing is moved");
        }
    }
}
