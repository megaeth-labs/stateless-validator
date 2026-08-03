//! Composes the HTTP middleware stack — the one place its order is defined.
//!
//! Compression must stay outermost: `ResponseSizeLayer` reads the body's exact
//! `size_hint` (gone once the body is a compressed stream), and the timing layer's
//! future resolves before the body streams — so this order keeps `x-response-size` at
//! the uncompressed payload size and `x-execution-time-ns` free of compression CPU.
//! The tests below pin exactly that by driving requests through this stack, not a
//! replica.

use tower::{
    ServiceBuilder,
    layer::util::{Identity, Stack},
};

use crate::{compression, response_size, timing};

/// The middleware stack [`http_middleware`] composes, innermost layer first.
pub(crate) type HttpMiddleware = ServiceBuilder<
    Stack<
        timing::TimingHeaderLayer,
        Stack<
            response_size::ResponseSizeLayer,
            Stack<compression::ResponseCompressionLayer, Identity>,
        >,
    >,
>;

/// Builds the server's HTTP middleware stack; see the module doc for why the order is
/// load-bearing.
pub(crate) fn http_middleware(compression_enabled: bool) -> HttpMiddleware {
    ServiceBuilder::new()
        .layer(compression::layer(compression_enabled))
        .layer(response_size::ResponseSizeLayer)
        .layer(timing::TimingHeaderLayer)
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
        header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE, VARY},
    };
    use http_body_util::{BodyExt, Full};
    use tower::{Service, ServiceExt};

    use super::http_middleware;
    use crate::{
        compression::MIN_COMPRESS_SIZE, response_size::RESPONSE_SIZE_HEADER_NAME,
        timing::TIMING_HEADER_NAME,
    };

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

    /// Runs one request through the production middleware stack and returns the
    /// response headers and raw body.
    async fn run(enabled: bool, accept_encoding: Option<&str>, body: Bytes) -> (HeaderMap, Bytes) {
        let svc = http_middleware(enabled).service(MockService { body });
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
        // caches (and a fronting CDN) must key on the negotiated encoding
        assert_eq!(headers.get(VARY).unwrap(), "accept-encoding");
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
        let decoded = zstd::decode_all(&compressed[..]).unwrap();
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
