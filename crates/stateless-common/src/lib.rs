pub mod db;
pub mod logging;
pub mod metrics;
pub use metrics::{RpcClientConfig, RpcMethod, RpcMetrics};
pub mod rpc_client;
pub use rpc_client::{RpcClient, SetValidatedBlocksResponse, WitnessRequestKeys};

/// Default port for Prometheus metrics HTTP endpoint.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Parses a hex string into a [`alloy_primitives::BlockHash`].
///
/// Accepts hex strings with or without "0x" prefix. Must be exactly 32 bytes when decoded.
pub fn parse_block_hash(hex_str: &str) -> eyre::Result<alloy_primitives::BlockHash> {
    let hash_bytes = alloy_primitives::hex::decode(hex_str)?;
    eyre::ensure!(hash_bytes.len() == 32, "Block hash must be 32 bytes, got {}", hash_bytes.len());
    Ok(alloy_primitives::BlockHash::from_slice(&hash_bytes))
}
