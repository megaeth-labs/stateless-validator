pub mod logging;
pub mod metrics;
pub use metrics::{RpcMethod, RpcMetrics};
pub mod rpc_client;
pub use rpc_client::{
    CodeFetchError, RpcClient, RpcClientConfig, RpcDeadlineExceeded, SetValidatedBlocksResponse,
    WitnessRequestKeys,
};
/// Exponential-backoff policy used by [`RpcClient`]'s round-level retry loop: `initial` is the
/// first sleep duration; each round doubles it up to `max`.
///
/// The same pair paces the R2 GET loop, so the type is defined in `stateless-r2` (which must
/// stay free of upward dependencies) and re-exported here under the name this crate's API
/// uses; the retry loop steps it through
/// [`RetryPacing::schedule`](stateless_r2::fetch::RetryPacing::schedule).
pub use stateless_r2::fetch::RetryPacing as BackoffPolicy;
pub mod witness_encoding;
pub use witness_encoding::{
    WITNESS_RESPONSE_VERSION_PREFIX, WITNESS_ZSTD_LEVEL, WitnessDecodingError,
    WitnessEncodingError, decode_witness_payload, decode_witness_payload_light,
    decode_witness_response, decode_witness_response_light, encode_witness_payload,
    encode_witness_response,
};
pub mod r2_args;
pub use r2_args::{R2CountFlag, R2Flag, R2Flags, R2Target, R2TuningFlag, validate_r2_flags};
pub mod r2_witness;
pub use r2_witness::{R2WitnessError, R2WitnessTransport, decode_on_blocking_pool};
pub mod secret;
pub use secret::RedactedSecret;
pub mod witness_size;
pub use witness_size::WitnessSizeBreakdown;

/// Default port for Prometheus metrics HTTP endpoint.
pub const DEFAULT_METRICS_PORT: u16 = 9090;
