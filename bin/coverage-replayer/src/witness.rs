//! Where `backfill` gets its witnesses: straight from the R2 bucket when the `--r2-*` flags
//! configure one, with the `--witness-endpoint` RPC chain behind it; from that chain alone
//! otherwise.
//!
//! The bucket object is the payload the witness RPC returns base64-encoded,
//! `zstd(bincode-legacy((SaltWitness, MptWitness)))`, so both paths light-decode to the same
//! witness and which one served a block cannot change what its replay covers. Any R2 failure
//! hands the block to the RPC chain at once, which retries until it succeeds: R2 can slow a scan
//! down, never stop it. Only the S3 target is offered, since a scan runs from a host holding a
//! bucket-scoped key and the custom domain's edge cache would buy it nothing.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use alloy_primitives::B256;
use clap::Args;
use eyre::Result;
use stateless_common::{
    R2CountFlag, R2Flag, R2Flags, R2Metrics, R2WitnessError, R2WitnessTransport, RedactedSecret,
    RpcClient, RpcClientConfig, decode_on_blocking_pool, decode_witness_payload_light, r2_band,
    r2_witness::{DEFAULT_CONNECT_TIMEOUT, FetchTimeouts},
    validate_r2_flags,
};
use stateless_core::{LightWitness, withdrawals::MptWitness};
use tracing::{debug, info, warn};

/// GET attempts per block (first try + retries) on retryable failures: few, because the RPC
/// chain is the next stop.
const MAX_ATTEMPTS: usize = 3;

/// The `--r2-*` flags: the S3 target's credential quad.
#[derive(Args, Debug, Clone, Default)]
pub struct R2Args {
    /// R2 S3 endpoint origin, e.g. `https://<account>.r2.cloudflarestorage.com` (no bucket
    /// path). With the rest of the quad it turns on the R2 witness route: every witness fetch
    /// tries the bucket first and falls back to the `--witness-endpoint` chain.
    #[clap(long, env = "COVERAGE_REPLAYER_R2_ENDPOINT")]
    pub r2_endpoint: Option<String>,
    /// R2 bucket holding the witnesses (e.g. `witness-mainnet`).
    #[clap(long, env = "COVERAGE_REPLAYER_R2_BUCKET")]
    pub r2_bucket: Option<String>,
    /// R2 access key id (Object Read).
    #[clap(long, env = "COVERAGE_REPLAYER_R2_ACCESS_KEY_ID")]
    pub r2_access_key_id: Option<String>,
    /// R2 secret access key. Prefer the env var over the flag.
    #[clap(long, env = "COVERAGE_REPLAYER_R2_SECRET_ACCESS_KEY", hide_env_values = true)]
    pub r2_secret_access_key: Option<RedactedSecret>,
}

impl R2Args {
    /// Builds the R2 transport these flags configure, or `None` when they configure none.
    ///
    /// The shared rules judge them, so a half-configured quad or a blank env line fails the run
    /// by name instead of quietly sending every witness over RPC.
    pub fn transport(&self) -> Result<Option<R2WitnessTransport>> {
        let config = validate_r2_flags(&self.flags())?;
        let defaults = RpcClientConfig::default();
        let timeouts = FetchTimeouts {
            per_attempt: defaults.per_attempt_timeout,
            connect: DEFAULT_CONNECT_TIMEOUT,
        };
        let transport = R2WitnessTransport::from_config(
            config,
            timeouts,
            defaults.rpc_retry,
            Arc::new(NoMetrics),
        )?;
        match &transport {
            Some(t) => info!(
                origin = %t.origin(),
                bucket = %self.r2_bucket.as_deref().unwrap_or("-"),
                "witness source: R2 first, the --witness-endpoint chain as fallback"
            ),
            None => {
                info!("witness source: the --witness-endpoint chain (no --r2-* target configured)")
            }
        }
        Ok(transport)
    }

    /// These flags in the shared rules' terms. The custom-domain members stay unset: this binary
    /// does not offer that target.
    fn flags(&self) -> R2Flags<'_> {
        let unset = |name| R2Flag::new(name, None);
        R2Flags {
            endpoint: R2Flag::new("--r2-endpoint", self.r2_endpoint.as_deref()),
            bucket: R2Flag::new("--r2-bucket", self.r2_bucket.as_deref()),
            access_key_id: R2Flag::new("--r2-access-key-id", self.r2_access_key_id.as_deref()),
            secret_access_key: R2Flag::new(
                "--r2-secret-access-key",
                self.r2_secret_access_key.as_ref().map(AsRef::as_ref),
            ),
            custom_domain: unset("--r2-custom-domain"),
            access_client_id: unset("--r2-access-client-id"),
            access_client_secret: unset("--r2-access-client-secret"),
            connections: unset("--r2-connections"),
            max_concurrent_requests: R2CountFlag::new("--r2-max-concurrent-requests", None),
            tuning: &[],
        }
    }
}

/// This binary exports no metrics; [`WitnessSource::log_summary`] says which path served.
struct NoMetrics;

impl R2Metrics for NoMetrics {
    fn on_target(&self, _: &'static str) {}
    fn on_connections(&self, _: usize) {}
    fn on_negotiated_version(&self, _: &'static str) {}
}

/// Light witnesses for the fetch tasks: from R2 first when a transport is given, else (and after
/// any R2 failure) from the RPC witness chain. Counts which path served each block.
pub struct WitnessSource {
    rpc: Arc<RpcClient>,
    r2: Option<R2WitnessTransport>,
    /// The chain tip the run started under. It bands an R2 miss: near the tip an absent object
    /// is the uploader catching up, deeper it is a hole worth a warning.
    tip: u64,
    from_r2: AtomicU64,
    from_rpc: AtomicU64,
}

impl WitnessSource {
    pub fn new(rpc: Arc<RpcClient>, r2: Option<R2WitnessTransport>, tip: u64) -> Self {
        Self { rpc, r2, tip, from_r2: AtomicU64::new(0), from_rpc: AtomicU64::new(0) }
    }

    /// The light witness of block `(number, hash)`. Never fails: an R2 failure is logged and
    /// the block goes to the RPC chain, which retries until it succeeds.
    pub async fn get(&self, number: u64, hash: B256) -> (LightWitness, MptWitness) {
        if let Some(r2) = &self.r2 {
            match from_bucket(r2, number, hash).await {
                Ok(witness) => {
                    self.from_r2.fetch_add(1, Ordering::Relaxed);
                    return witness;
                }
                Err(e) if e.is_frontier_miss(r2_band(self.tip, number)) => {
                    debug!(number, %hash, "witness not in R2 yet; fetching it over RPC");
                }
                Err(e) => warn!(
                    number,
                    %hash,
                    kind = e.kind(),
                    error = %e,
                    "R2 witness fetch failed; fetching it over RPC"
                ),
            }
        }
        self.from_rpc.fetch_add(1, Ordering::Relaxed);
        self.rpc.get_witness_light(number, hash).await
    }

    /// Logs how many witnesses each path served. Spooled blocks are not counted: a resumed run
    /// fetches no witness for them.
    pub fn log_summary(&self) {
        info!(
            r2 = self.from_r2.load(Ordering::Relaxed),
            rpc = self.from_rpc.load(Ordering::Relaxed),
            "witnesses fetched"
        );
    }
}

/// One bounded R2 attempt for `(number, hash)`: the GETs share one per-attempt budget, like the
/// validator's fast path, so a stalling endpoint costs a block one timeout before RPC takes over.
async fn from_bucket(
    r2: &R2WitnessTransport,
    number: u64,
    hash: B256,
) -> Result<(LightWitness, MptWitness), R2WitnessError> {
    let deadline = Instant::now() + RpcClientConfig::default().per_attempt_timeout;
    let fetched =
        r2.fetcher().get_block_object(number, hash, MAX_ATTEMPTS, Some(deadline), || {}).await?;
    // Outside the deadline: our own CPU on bytes in hand, and abandoning it would only fetch and
    // decode the same witness again over RPC.
    decode_on_blocking_pool(fetched.bytes, number, hash, None, |bytes| {
        decode_witness_payload_light(bytes)
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use stateless_common::{encode_witness_payload, encode_witness_response};
    use stateless_test_utils::{fixtures::TestFixtures, mock_r2::mock_r2, mock_rpc::serve};

    use super::*;

    /// A `Parser` wrapper, so tests exercise the real clap wiring of the flattened flags.
    #[derive(clap::Parser)]
    struct TestCli {
        #[clap(flatten)]
        r2: R2Args,
    }

    fn parse(argv: &[&str]) -> R2Args {
        <TestCli as clap::Parser>::try_parse_from(
            std::iter::once("backfill").chain(argv.iter().copied()),
        )
        .expect("flags parse")
        .r2
    }

    fn quad(endpoint: &str) -> R2Args {
        R2Args {
            r2_endpoint: Some(endpoint.to_string()),
            r2_bucket: Some("witness-test".to_string()),
            r2_access_key_id: Some("ak".to_string()),
            r2_secret_access_key: Some("sk".into()),
        }
    }

    /// The fixture witness as the bucket stores it, as the witness RPC returns it, and as both
    /// light-decode.
    fn fixture_witness() -> (Vec<u8>, String, (LightWitness, MptWitness)) {
        let (salt, mpt): (_, MptWitness) = TestFixtures::mainnet_shared().first_paired_witness();
        let (_, payload) = encode_witness_payload(&salt, &mpt).expect("fixture witness encodes");
        let wire = encode_witness_response(&salt, &mpt).expect("fixture witness encodes");
        let decoded = decode_witness_payload_light(&payload).expect("payload light-decodes");
        (payload, wire, decoded)
    }

    /// A witness RPC endpoint serving `wire` for every request, and the count of requests. The
    /// first element is the server handle: dropping it stops the server.
    async fn witness_rpc(wire: String) -> (impl Sized, Arc<RpcClient>, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let (handle, url) = serve((hits.clone(), wire), |module| {
            module
                .register_method("mega_getBlockWitness", |_, (hits, wire), _| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    wire.clone()
                })
                .unwrap();
        })
        .await;
        let rpc = RpcClient::new_with_config(
            &["http://rpc.invalid"],
            &[&url],
            RpcClientConfig::default(),
            None,
        )
        .unwrap();
        (handle, Arc::new(rpc), hits)
    }

    /// The presence of a target is the whole switch, and the shared rules guard it: no flag at
    /// all is the RPC-only run, while an incomplete quad or a blank value fails by name rather
    /// than silently sending every witness over RPC.
    #[test]
    fn the_flags_select_r2_or_fail_by_name() {
        assert!(parse(&[]).transport().unwrap().is_none(), "no --r2-* flag: RPC only");
        assert!(quad("https://acc.r2.cloudflarestorage.com").transport().unwrap().is_some());

        let half = parse(&["--r2-endpoint", "https://acc.r2.cloudflarestorage.com"]);
        let err = half.transport().expect_err("an incomplete quad must fail").to_string();
        for missing in ["--r2-bucket", "--r2-access-key-id", "--r2-secret-access-key"] {
            assert!(err.contains(missing), "names {missing}: {err}");
        }

        let blank = R2Args {
            r2_secret_access_key: Some("".into()),
            ..quad("https://acc.r2.cloudflarestorage.com")
        };
        let err = blank.transport().expect_err("a blank value must fail").to_string();
        assert!(err.contains("--r2-secret-access-key") && err.contains("empty"), "{err}");
    }

    /// The secret must not reach `Debug` output, which a logged argument struct would print.
    #[test]
    fn the_secret_is_redacted_in_debug_output() {
        let args = quad("https://acc.r2.cloudflarestorage.com");
        assert!(!format!("{args:?}").contains("\"sk\""), "{args:?}");
    }

    /// A bucket hit serves the witness without touching the RPC chain, and decodes to exactly
    /// what the RPC path would have returned.
    #[tokio::test]
    async fn a_bucket_hit_skips_the_rpc_chain() {
        let (payload, wire, expected) = fixture_witness();
        let (endpoint, r2_hits) = mock_r2(vec![(200, payload)]).await;
        let (_server, rpc, rpc_hits) = witness_rpc(wire).await;
        let source = WitnessSource::new(rpc, quad(&endpoint).transport().unwrap(), 0);

        assert_eq!(source.get(1, B256::ZERO).await, expected);
        assert_eq!(r2_hits.load(Ordering::SeqCst), 1);
        assert_eq!(rpc_hits.load(Ordering::SeqCst), 0, "a bucket hit must not reach RPC");
        assert_eq!(source.from_r2.load(Ordering::Relaxed), 1);
        assert_eq!(source.from_rpc.load(Ordering::Relaxed), 0);
    }

    /// Every R2 failure, an absent object or a corrupt one alike, hands the block to the RPC
    /// chain, which serves the same witness.
    #[tokio::test]
    async fn an_r2_failure_falls_back_to_rpc() {
        let (_, wire, expected) = fixture_witness();
        for (status, body) in [(404, "missing"), (200, "not a zstd witness")] {
            let (endpoint, _) = mock_r2(vec![(status, body)]).await;
            let (_server, rpc, rpc_hits) = witness_rpc(wire.clone()).await;
            let source = WitnessSource::new(rpc, quad(&endpoint).transport().unwrap(), 10_000);

            assert_eq!(source.get(1, B256::ZERO).await, expected, "R2 answered {status}");
            assert_eq!(rpc_hits.load(Ordering::SeqCst), 1, "R2 answered {status}");
            assert_eq!(source.from_r2.load(Ordering::Relaxed), 0);
            assert_eq!(source.from_rpc.load(Ordering::Relaxed), 1);
        }
    }

    /// Without a transport the RPC chain serves everything.
    #[tokio::test]
    async fn without_r2_the_rpc_chain_serves() {
        let (_, wire, expected) = fixture_witness();
        let (_server, rpc, rpc_hits) = witness_rpc(wire).await;
        let source = WitnessSource::new(rpc, None, 0);

        assert_eq!(source.get(1, B256::ZERO).await, expected);
        assert_eq!(rpc_hits.load(Ordering::SeqCst), 1);
    }
}
