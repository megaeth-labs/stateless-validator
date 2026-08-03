//! Builds the negotiated gzip/zstd response [`CompressionLayer`].
//!
//! Opt-in per request via `Accept-Encoding`; ordering constraints against the size and
//! timing middleware live on [`crate::http_middleware`], the single place the stack is
//! composed (and what the tests below exercise).

use tower_http::{
    CompressionLevel,
    compression::{
        CompressionLayer,
        predicate::{And, DefaultPredicate, Predicate, SizeAbove},
    },
};

/// Bodies at or below this size are served identity even for opted-in clients:
/// compressing them costs a fresh per-response encoder allocation and downgrades
/// `Content-Length` to chunked framing for a saving of a few dozen wire bytes.
const MIN_COMPRESS_SIZE: u16 = 4096;

/// The concrete layer type [`layer`] returns (named so the middleware-stack signature
/// in `main.rs` can spell it).
pub type ResponseCompressionLayer = CompressionLayer<And<DefaultPredicate, SizeAbove>>;

/// Returns the response-compression layer for the HTTP middleware stack.
///
/// `enabled = false` turns every negotiable encoding off and the layer degrades to a
/// pass-through (the `--response-compression-disabled` ops kill switch). The level is
/// pinned to the fastest setting: trace responses are large, highly repetitive JSON,
/// where the fast level already collapses most of the redundancy while keeping
/// per-response CPU small next to the trace itself.
pub fn layer(enabled: bool) -> ResponseCompressionLayer {
    CompressionLayer::new()
        .quality(CompressionLevel::Fastest)
        .gzip(enabled)
        .zstd(enabled)
        .compress_when(DefaultPredicate::new().and(SizeAbove::new(MIN_COMPRESS_SIZE)))
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::Future,
        io::Read,
        pin::Pin,
        sync::LazyLock,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use http::{
        HeaderMap, Request as HttpRequest, Response as HttpResponse,
        header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE},
    };
    use http_body_util::{BodyExt, Full};
    use tower::{Service, ServiceExt};

    use super::MIN_COMPRESS_SIZE;
    use crate::{response_size::RESPONSE_SIZE_HEADER_NAME, timing::TIMING_HEADER_NAME};

    /// Compressible payload comfortably above [`MIN_COMPRESS_SIZE`].
    static BODY: LazyLock<Bytes> =
        LazyLock::new(|| Bytes::from(r#"{"type":"CALL","gas":"0x0","calls":[]},"#.repeat(256)));

    /// Mock RPC service answering with a fixed `application/json` body, like jsonrpsee.
    #[derive(Clone)]
    struct MockService {
        body: Bytes,
    }

    impl Service<HttpRequest<Full<Bytes>>> for MockService {
        type Response = HttpResponse<Full<Bytes>>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: HttpRequest<Full<Bytes>>) -> Self::Future {
            let body = self.body.clone();
            Box::pin(async move {
                Ok(HttpResponse::builder()
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(body))
                    .unwrap())
            })
        }
    }

    /// Runs one request through the real production middleware stack
    /// ([`crate::http_middleware`]) and returns the response headers and raw body.
    async fn run(enabled: bool, accept_encoding: Option<&str>, body: Bytes) -> (HeaderMap, Bytes) {
        let svc = crate::http_middleware(enabled).service(MockService { body });
        let mut req = HttpRequest::builder().uri("/");
        if let Some(enc) = accept_encoding {
            req = req.header(ACCEPT_ENCODING, enc);
        }
        let resp = svc.oneshot(req.body(Full::new(Bytes::new())).unwrap()).await.unwrap();
        let (parts, body) = resp.into_parts();
        (parts.headers, body.collect().await.unwrap().to_bytes())
    }

    #[tokio::test]
    async fn no_accept_encoding_stays_identity() {
        let (headers, body) = run(true, None, BODY.clone()).await;
        assert!(headers.get(CONTENT_ENCODING).is_none());
        assert_eq!(body, *BODY);
    }

    #[tokio::test]
    async fn gzip_negotiated_and_round_trips() {
        let (headers, compressed) = run(true, Some("gzip"), BODY.clone()).await;
        assert_eq!(headers.get(CONTENT_ENCODING).unwrap(), "gzip");
        // the size and timing headers survive compression, and x-response-size still
        // reports the uncompressed payload size — the stack-ordering invariant
        let size: u64 =
            headers.get(RESPONSE_SIZE_HEADER_NAME).unwrap().to_str().unwrap().parse().unwrap();
        assert_eq!(size, BODY.len() as u64);
        assert!(headers.get(TIMING_HEADER_NAME).is_some());

        assert!(compressed.len() < BODY.len());
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&compressed[..]).read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, *BODY);
    }

    #[tokio::test]
    async fn zstd_negotiated_and_round_trips() {
        let (headers, compressed) = run(true, Some("zstd"), BODY.clone()).await;
        assert_eq!(headers.get(CONTENT_ENCODING).unwrap(), "zstd");

        assert!(compressed.len() < BODY.len());
        let decoded = zstd::stream::decode_all(&compressed[..]).unwrap();
        assert_eq!(decoded, *BODY);
    }

    #[tokio::test]
    async fn small_response_stays_identity() {
        let small = Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"result":null}"#);
        assert!(small.len() <= MIN_COMPRESS_SIZE as usize);
        let (headers, body) = run(true, Some("gzip, zstd"), small.clone()).await;
        assert!(headers.get(CONTENT_ENCODING).is_none());
        assert_eq!(body, small);
    }

    #[tokio::test]
    async fn kill_switch_disables_negotiation() {
        let (headers, body) = run(false, Some("gzip, zstd"), BODY.clone()).await;
        assert!(headers.get(CONTENT_ENCODING).is_none());
        assert_eq!(body, *BODY);
    }
}
