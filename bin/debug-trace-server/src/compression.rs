//! Response compression configuration: the negotiated gzip/zstd [`CompressionLayer`].
//!
//! Opt-in per request via `Accept-Encoding`; clients that do not send the header keep
//! receiving identity bodies. Where the layer sits relative to the size and timing
//! middleware — and why that order is load-bearing — is owned by [`crate::middleware`].

use tower_http::{
    CompressionLevel,
    compression::{
        CompressionLayer,
        predicate::{And, DefaultPredicate, Predicate, SizeAbove},
    },
};

/// Bodies below this size are served identity even for opted-in clients:
/// compressing them costs a fresh per-response encoder allocation and downgrades
/// `Content-Length` to chunked framing for a saving of a few dozen wire bytes.
pub(crate) const MIN_COMPRESS_SIZE: u16 = 4096;

/// The concrete layer type [`layer`] returns (named so the middleware-stack signature
/// in [`crate::middleware`] can spell it).
pub(crate) type ResponseCompressionLayer = CompressionLayer<And<SizeAbove, DefaultPredicate>>;

/// Returns the response-compression layer for the HTTP middleware stack.
///
/// `enabled = false` turns every negotiable encoding off and the layer degrades to a
/// pass-through (the `--response-compression-disabled` ops kill switch). The level is
/// pinned to the fastest setting: trace responses are large, highly repetitive JSON,
/// where the fast level already collapses most of the redundancy while keeping
/// per-response CPU small next to the trace itself.
pub(crate) fn layer(enabled: bool) -> ResponseCompressionLayer {
    // no_br/no_deflate are load-bearing, not defaults restated: the layer starts with
    // every *compiled* encoding enabled, and tower-http features are additive across
    // the workspace graph — without the explicit opt-out, any dependency enabling
    // compression-br/compression-deflate would silently widen what this server
    // negotiates and punch through the kill switch.
    //
    // size gate first: it short-circuits the content-type checks for the small
    // responses it exists to reject
    CompressionLayer::new()
        .quality(CompressionLevel::Fastest)
        .gzip(enabled)
        .zstd(enabled)
        .no_br()
        .no_deflate()
        .compress_when(SizeAbove::new(MIN_COMPRESS_SIZE).and(DefaultPredicate::new()))
}
