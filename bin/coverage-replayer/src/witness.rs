//! Where `backfill` gets its witnesses: straight from the R2 bucket when the `--r2-*` flags
//! configure one, with the `--witness-endpoint` RPC chain behind it; from that chain alone
//! otherwise.
//!
//! The bucket object is the payload the witness RPC returns base64-encoded,
//! `zstd(bincode-legacy((SaltWitness, MptWitness)))`, so both paths light-decode to the same
//! witness and which one served a block cannot change what its replay covers. Any R2 failure
//! hands the block to the RPC chain at once, which retries until it succeeds: R2 can slow a scan
//! down, never stop it, and `--r2-timeout-ms` bounds by how much. Only the S3 target is offered,
//! since a scan runs from a host holding a bucket-scoped key and the custom domain's edge cache
//! would buy it nothing.
//!
//! A quarantined block's retry tries R2 first too. The RPC chain is a second path to the same
//! bytes rather than a second copy (the witness gateway reads this bucket), so a witness that
//! decodes but replays wrong would come back the same over RPC.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use clap::Args;
use eyre::Result;
use stateless_common::{
    BackoffPolicy, R2CountFlag, R2Flag, R2Flags, R2Metrics, R2TuningFlag, R2WitnessError,
    R2WitnessTransport, RedactedSecret, RpcClient, decode_on_blocking_pool,
    decode_witness_payload_light, r2_band,
    r2_witness::{DEFAULT_CONNECT_TIMEOUT, FetchTimeouts},
    validate_r2_flags,
};
use stateless_core::{LightWitness, withdrawals::MptWitness};
use tracing::{debug, info, warn};

/// GET attempts per block (first try + retries) on retryable failures: few, because the RPC
/// chain is the next stop.
const MAX_ATTEMPTS: usize = 3;

/// `--r2-timeout-ms` when unset. Witness objects run to tens of KB, so a healthy fetch takes well
/// under a second, and a stalling endpoint costs each block this long before RPC takes over.
const DEFAULT_R2_TIMEOUT_MS: u64 = 5_000;

/// How many R2 failures are logged as warnings before the rest drop to one in [`WARN_EVERY`]:
/// a bucket missing a whole range would otherwise warn once per block. The summary counts all.
const WARN_FIRST: u64 = 10;
const WARN_EVERY: u64 = 1_000;

/// The `--r2-*` flags: the S3 target's credential quad, and the budget for trying it.
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
    /// What one block may spend on R2, in milliseconds (default 5000): the wait for a
    /// connection plus every GET and retry. Past it the block goes to the `--witness-endpoint`
    /// chain, so this is the most a stalling R2 endpoint costs each block. Rejected when no R2
    /// target is configured.
    #[clap(
        long,
        env = "COVERAGE_REPLAYER_R2_TIMEOUT_MS",
        value_parser = clap::value_parser!(u64).range(100..)
    )]
    pub r2_timeout_ms: Option<u64>,
}

impl R2Args {
    /// Builds the R2 source these flags configure, or `None` when they configure none.
    ///
    /// The shared rules judge the flags, so a half-configured quad, a blank env line or a
    /// timeout with nothing to time fails the run by name instead of quietly sending every
    /// witness over RPC. `retry` paces the GET retries, as it paces the RPC client's.
    pub fn source(&self, retry: BackoffPolicy) -> Result<Option<R2Source>> {
        let tuning = [R2TuningFlag::new("--r2-timeout-ms", self.r2_timeout_ms.is_some())];
        let config = validate_r2_flags(&self.flags(&tuning))?;
        let budget = Duration::from_millis(self.r2_timeout_ms.unwrap_or(DEFAULT_R2_TIMEOUT_MS));
        // Each GET may take the whole budget; the deadline clamps the later ones to what is left.
        let timeouts = FetchTimeouts { per_attempt: budget, connect: DEFAULT_CONNECT_TIMEOUT };
        let transport =
            R2WitnessTransport::from_config(config, timeouts, retry, Arc::new(NoMetrics))?;
        let Some(transport) = transport else {
            info!("witness source: the --witness-endpoint chain (no --r2-* target configured)");
            return Ok(None);
        };
        info!(
            origin = %transport.origin(),
            bucket = %self.r2_bucket.as_deref().unwrap_or("-"),
            timeout = ?budget,
            "witness source: R2 first, the --witness-endpoint chain as fallback"
        );
        Ok(Some(R2Source { transport, budget }))
    }

    /// These flags in the shared rules' terms. The custom-domain members stay unset: this binary
    /// does not offer that target.
    fn flags<'a>(&'a self, tuning: &'a [R2TuningFlag<'a>]) -> R2Flags<'a> {
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
            tuning,
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

/// The bucket a run reads first, and what one block may spend on it.
pub struct R2Source {
    transport: R2WitnessTransport,
    budget: Duration,
}

impl R2Source {
    /// One bounded R2 attempt for `(number, hash)`. Every GET and retry shares the budget, like
    /// the validator's fast path, so a stalling endpoint costs the block one budget, not one per
    /// attempt.
    async fn fetch(
        &self,
        number: u64,
        hash: B256,
    ) -> Result<(LightWitness, MptWitness), R2WitnessError> {
        let deadline = Instant::now() + self.budget;
        let fetched = self
            .transport
            .fetcher()
            .get_block_object(number, hash, MAX_ATTEMPTS, Some(deadline), || {})
            .await?;
        // Outside the deadline: our own CPU on bytes in hand, and abandoning it would only fetch
        // and decode the same witness again over RPC.
        decode_on_blocking_pool(fetched.bytes, number, hash, None, |bytes| {
            decode_witness_payload_light(bytes)
        })
        .await
    }
}

/// Light witnesses for the fetch tasks: from R2 first when a source is given, else (and after
/// any R2 failure) from the RPC witness chain. Counts the fetches each path served.
pub struct WitnessSource {
    rpc: Arc<RpcClient>,
    r2: Option<R2Source>,
    /// The chain tip the run started under. It bands an R2 miss: near the tip an absent object
    /// is the uploader catching up, deeper it is a hole worth a warning.
    tip: u64,
    from_r2: AtomicU64,
    from_rpc: AtomicU64,
    /// R2 failures outside the frontier band; each one's witness is in `from_rpc` too.
    r2_failures: AtomicU64,
}

impl WitnessSource {
    pub fn new(rpc: Arc<RpcClient>, r2: Option<R2Source>, tip: u64) -> Self {
        Self {
            rpc,
            r2,
            tip,
            from_r2: AtomicU64::new(0),
            from_rpc: AtomicU64::new(0),
            r2_failures: AtomicU64::new(0),
        }
    }

    /// The light witness of block `(number, hash)`. Never fails: an R2 failure is logged and
    /// the block goes to the RPC chain, which retries until it succeeds.
    pub async fn get(&self, number: u64, hash: B256) -> (LightWitness, MptWitness) {
        if let Some(r2) = &self.r2 {
            match r2.fetch(number, hash).await {
                Ok(witness) => {
                    self.from_r2.fetch_add(1, Ordering::Relaxed);
                    return witness;
                }
                Err(e) if e.is_frontier_miss(r2_band(self.tip, number)) => {
                    debug!(number, %hash, "witness not in R2 yet; fetching it over RPC");
                }
                Err(e) => self.note_failure(number, hash, &e),
            }
        }
        self.from_rpc.fetch_add(1, Ordering::Relaxed);
        self.rpc.get_witness_light(number, hash).await
    }

    /// Counts an R2 failure, warning about the first [`WARN_FIRST`] and one in [`WARN_EVERY`]
    /// after that.
    fn note_failure(&self, number: u64, hash: B256, e: &R2WitnessError) {
        let failures = self.r2_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures > WARN_FIRST && !failures.is_multiple_of(WARN_EVERY) {
            debug!(number, %hash, kind = e.kind(), error = %e, "R2 witness fetch failed; fetching it over RPC");
            return;
        }
        warn!(
            number,
            %hash,
            kind = e.kind(),
            error = %e,
            failures,
            "R2 witness fetch failed; fetching it over RPC"
        );
        if failures == WARN_FIRST {
            warn!(
                "further R2 failures are logged one in {WARN_EVERY}; the run's witness summary \
                 counts them all"
            );
        }
    }

    /// Logs how many witness fetches each path served and how many R2 failures sent one to RPC.
    /// These count fetches, not blocks: a block whose fetch is retried counts again, and a block
    /// a resumed run finds spooled is not fetched at all.
    pub fn log_summary(&self) {
        info!(
            r2 = self.from_r2.load(Ordering::Relaxed),
            rpc = self.from_rpc.load(Ordering::Relaxed),
            r2_failures = self.r2_failures.load(Ordering::Relaxed),
            "witnesses fetched"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use clap::CommandFactory;
    use stateless_common::{RpcClientConfig, encode_witness_payload, encode_witness_response};
    use stateless_test_utils::{
        fixtures::TestFixtures,
        mock_r2::{mock_r2, mock_r2_held},
        mock_rpc::serve,
    };

    use super::*;

    /// A `Parser` wrapper, so tests can read the real clap wiring of the flattened flags.
    #[derive(clap::Parser)]
    struct TestCli {
        #[clap(flatten)]
        r2: R2Args,
    }

    /// Millisecond-scale retry pacing, so the retry paths run fast.
    fn retry() -> BackoffPolicy {
        BackoffPolicy::new(Duration::from_millis(5), Duration::from_millis(20))
    }

    /// A complete S3 quad against `endpoint`. Built directly rather than parsed: clap would read
    /// the `COVERAGE_REPLAYER_R2_*` variables of whatever shell runs the tests.
    fn quad(endpoint: &str) -> R2Args {
        R2Args {
            r2_endpoint: Some(endpoint.to_string()),
            r2_bucket: Some("witness-test".to_string()),
            r2_access_key_id: Some("ak".to_string()),
            r2_secret_access_key: Some("sk".into()),
            ..R2Args::default()
        }
    }

    fn source(args: &R2Args) -> Option<R2Source> {
        args.source(retry()).expect("the flags are valid")
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

    fn counts(source: &WitnessSource) -> [u64; 3] {
        [&source.from_r2, &source.from_rpc, &source.r2_failures].map(|c| c.load(Ordering::Relaxed))
    }

    /// The presence of a target is the whole switch, and the shared rules guard it: no flag at
    /// all is the RPC-only run, while an incomplete quad, a blank value or a timeout with no
    /// target fails by name rather than silently sending every witness over RPC.
    #[test]
    fn the_flags_select_r2_or_fail_by_name() {
        assert!(source(&R2Args::default()).is_none(), "no --r2-* flag: RPC only");
        assert!(source(&quad("https://acc.r2.cloudflarestorage.com")).is_some());

        let half = R2Args {
            r2_endpoint: Some("https://acc.r2.cloudflarestorage.com".to_string()),
            ..R2Args::default()
        };
        let err = half.source(retry()).err().expect("an incomplete quad must fail").to_string();
        for missing in ["--r2-bucket", "--r2-access-key-id", "--r2-secret-access-key"] {
            assert!(err.contains(missing), "names {missing}: {err}");
        }

        let blank = R2Args {
            r2_secret_access_key: Some("".into()),
            ..quad("https://acc.r2.cloudflarestorage.com")
        };
        let err = blank.source(retry()).err().expect("a blank value must fail").to_string();
        assert!(err.contains("--r2-secret-access-key") && err.contains("empty"), "{err}");

        let orphan = R2Args { r2_timeout_ms: Some(1_000), ..R2Args::default() };
        let err = orphan.source(retry()).err().expect("a timeout with no target").to_string();
        assert!(err.contains("--r2-timeout-ms"), "{err}");
    }

    /// Each flag reads the env var the deployments set, and the secret's value stays out of
    /// `--help`. Read off the clap command, so no test touches the process environment.
    #[test]
    fn each_flag_reads_its_env_var() {
        let command = TestCli::command();
        for (id, var) in [
            ("r2_endpoint", "COVERAGE_REPLAYER_R2_ENDPOINT"),
            ("r2_bucket", "COVERAGE_REPLAYER_R2_BUCKET"),
            ("r2_access_key_id", "COVERAGE_REPLAYER_R2_ACCESS_KEY_ID"),
            ("r2_secret_access_key", "COVERAGE_REPLAYER_R2_SECRET_ACCESS_KEY"),
            ("r2_timeout_ms", "COVERAGE_REPLAYER_R2_TIMEOUT_MS"),
        ] {
            let arg = command.get_arguments().find(|a| a.get_id() == id).expect(id);
            assert_eq!(arg.get_env().and_then(|v| v.to_str()), Some(var), "{id}");
        }
        let secret =
            command.get_arguments().find(|a| a.get_id() == "r2_secret_access_key").unwrap();
        assert!(secret.is_hide_env_values_set());
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
        let witnesses = WitnessSource::new(rpc, source(&quad(&endpoint)), 0);

        assert_eq!(witnesses.get(1, B256::ZERO).await, expected);
        assert_eq!(r2_hits.load(Ordering::SeqCst), 1);
        assert_eq!(rpc_hits.load(Ordering::SeqCst), 0, "a bucket hit must not reach RPC");
        assert_eq!(counts(&witnesses), [1, 0, 0]);
    }

    /// Every R2 failure, an absent object or a corrupt one alike, hands the block to the RPC
    /// chain, which serves the same witness. Only a miss near the tip is not a failure.
    #[tokio::test]
    async fn an_r2_failure_falls_back_to_rpc() {
        let (_, wire, expected) = fixture_witness();
        for (status, body, tip, failures) in
            [(404, "missing", 10_000, 1), (200, "not a zstd witness", 10_000, 1), (404, "", 0, 0)]
        {
            let (endpoint, _) = mock_r2(vec![(status, body)]).await;
            let (_server, rpc, rpc_hits) = witness_rpc(wire.clone()).await;
            let witnesses = WitnessSource::new(rpc, source(&quad(&endpoint)), tip);

            assert_eq!(witnesses.get(1, B256::ZERO).await, expected, "R2 answered {status}");
            assert_eq!(rpc_hits.load(Ordering::SeqCst), 1, "R2 answered {status}");
            assert_eq!(counts(&witnesses), [0, 1, failures], "R2 answered {status}, tip {tip}");
        }
    }

    /// An endpoint that accepts the connection and then stalls costs the block one
    /// `--r2-timeout-ms`, after which RPC serves it.
    #[tokio::test]
    async fn a_stalling_bucket_costs_one_budget() {
        let (_, wire, expected) = fixture_witness();
        let (endpoint, _) = mock_r2_held(200, Duration::from_secs(30)).await;
        let (_server, rpc, _) = witness_rpc(wire).await;
        let args = R2Args { r2_timeout_ms: Some(200), ..quad(&endpoint) };
        let witnesses = WitnessSource::new(rpc, source(&args), 10_000);

        let started = Instant::now();
        assert_eq!(witnesses.get(1, B256::ZERO).await, expected);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(200), "gave up early: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "outlived its budget: {elapsed:?}");
        assert_eq!(counts(&witnesses), [0, 1, 1]);
    }

    /// Without a source the RPC chain serves everything.
    #[tokio::test]
    async fn without_r2_the_rpc_chain_serves() {
        let (_, wire, expected) = fixture_witness();
        let (_server, rpc, rpc_hits) = witness_rpc(wire).await;
        let witnesses = WitnessSource::new(rpc, None, 0);

        assert_eq!(witnesses.get(1, B256::ZERO).await, expected);
        assert_eq!(rpc_hits.load(Ordering::SeqCst), 1);
        assert_eq!(counts(&witnesses), [0, 1, 0]);
    }
}
