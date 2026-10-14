//! Shared jsonrpsee mock-upstream scaffolding.
//!
//! Every crate that talks to an upstream node fakes one in its tests; before this module
//! each hand-rolled the same server bootstrap and header shapes. Specialized mocks
//! (scripted witness sources, counting endpoints) stay with the tests that script them —
//! what lives here is only the scaffold they all share.

use alloy_primitives::BlockHash;
use alloy_rpc_types_eth::Header;
use jsonrpsee::{
    RpcModule,
    server::{ServerBuilder, ServerConfig, ServerHandle},
};

/// Starts a jsonrpsee server on an ephemeral loopback port with methods registered via
/// `register`, returning the handle (dropping it stops the server) and the http URL.
pub async fn serve<Ctx: Send + Sync + 'static>(
    ctx: Ctx,
    register: impl FnOnce(&mut RpcModule<Ctx>),
) -> (ServerHandle, String) {
    serve_with_config(ServerConfig::default(), ctx, register).await
}

/// [`serve`] with an explicit [`ServerConfig`] — for mocks whose fixture responses outgrow
/// jsonrpsee's default response-size cap.
pub async fn serve_with_config<Ctx: Send + Sync + 'static>(
    config: ServerConfig,
    ctx: Ctx,
    register: impl FnOnce(&mut RpcModule<Ctx>),
) -> (ServerHandle, String) {
    let mut module = RpcModule::new(ctx);
    register(&mut module);
    let server = ServerBuilder::default().set_config(config).build("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", server.local_addr().unwrap());
    (server.start(module), url)
}

/// Minimal RPC [`Header`] for `number` carrying the given `hash`; every other field is
/// default. For mocks that must serve prescribed hashes (e.g. divergence chains, where two
/// chains differ only by hash) — only `verify_hash = false` fetch paths accept it, since
/// the hash is not the header's real one.
pub fn header_stub(number: u64, hash: BlockHash) -> Header {
    Header {
        hash,
        inner: alloy_consensus::Header { number, ..Default::default() },
        ..Default::default()
    }
}

/// Minimal self-consistent RPC [`Header`] for `number`: `hash` is the inner header's real
/// `hash_slow()`, so `verify_hash = true` fetch paths accept it too.
pub fn consistent_header(number: u64) -> Header {
    let inner = alloy_consensus::Header { number, ..Default::default() };
    Header { hash: inner.hash_slow(), inner, ..Default::default() }
}

/// Parses a `0x`-prefixed (or bare) hex string as `u64` — the wire shape of numeric
/// JSON-RPC block-number params.
pub fn parse_hex_u64(s: &str) -> u64 {
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).unwrap()
}
