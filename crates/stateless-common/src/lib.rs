pub mod logging;
pub mod metrics;
pub use metrics::{RpcMethod, RpcMetrics};
pub mod rpc_client;
pub use rpc_client::{
    BackoffPolicy, CodeFetchError, RpcClient, RpcClientConfig, RpcDeadlineExceeded,
    SetValidatedBlocksResponse, WitnessRequestKeys,
};
pub mod witness_encoding;
pub use witness_encoding::{
    WITNESS_RESPONSE_VERSION_PREFIX, WITNESS_ZSTD_LEVEL, WitnessDecodingError,
    WitnessEncodingError, decode_witness_payload, decode_witness_payload_light,
    decode_witness_response, decode_witness_response_light, encode_witness_payload,
    encode_witness_response,
};
pub mod r2_args;
pub use r2_args::{R2Flag, R2Flags, R2Target, R2TuningFlag, validate_r2_flags};
pub mod secret;
pub use secret::RedactedSecret;
pub mod witness_size;
pub use witness_size::WitnessSizeBreakdown;

/// Default port for Prometheus metrics HTTP endpoint.
pub const DEFAULT_METRICS_PORT: u16 = 9090;
