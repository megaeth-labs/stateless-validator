//! Response compression HTTP middleware configuration.
//!
//! Builds the [`CompressionLayer`] that negotiates gzip/zstd response encoding with
//! clients via the standard `Accept-Encoding` header. Clients that do not send the
//! header keep receiving identity bodies, so enabling the layer changes nothing for
//! consumers that have not opted in.
//!
//! The layer must sit *outside* [`crate::response_size::ResponseSizeLayer`] in the
//! middleware stack: `x-response-size` reads the body's exact `size_hint`, which the
//! compressed (streamed) body no longer has, so compressing outermost keeps that header
//! reporting the uncompressed payload size. Compression itself runs while hyper streams
//! the body — after the timing middleware's future has resolved — so
//! `x-execution-time-ns` excludes compression CPU by construction.

use tower_http::{CompressionLevel, compression::CompressionLayer};

/// Returns the response-compression layer for the HTTP middleware stack.
///
/// `enabled = false` turns every negotiable encoding off and the layer degrades to a
/// pass-through (the `--response-compression-disabled` ops kill switch).
///
/// The level is pinned to the fastest setting: trace responses are large and highly
/// repetitive JSON, where the fast level already collapses most of the redundancy while
/// keeping per-response CPU cost small next to the trace itself.
pub fn layer(enabled: bool) -> CompressionLayer {
    CompressionLayer::new().quality(CompressionLevel::Fastest).gzip(enabled).zstd(enabled)
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::Future,
        io::Read,
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use http::{
        Request as HttpRequest, Response as HttpResponse,
        header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE},
    };
    use http_body_util::{BodyExt, Full};
    use tower::{Service, ServiceBuilder, ServiceExt};

    use super::*;
    use crate::response_size::{RESPONSE_SIZE_HEADER_NAME, ResponseSizeLayer};

    /// A JSON body comfortably above the compressor's minimum-size threshold.
    const BODY: &str = r#"{"jsonrpc":"2.0","id":1,"result":[{"type":"CALL","from":"0x0000000000000000000000000000000000000000","to":"0x0000000000000000000000000000000000000000","gas":"0x0","gasUsed":"0x0","input":"0x","output":"0x","calls":[]},{"type":"CALL","from":"0x0000000000000000000000000000000000000000","to":"0x0000000000000000000000000000000000000000","gas":"0x0","gasUsed":"0x0","input":"0x","output":"0x","calls":[]}]}"#;

    /// Mock RPC service: always answers with an `application/json` body, like jsonrpsee.
    #[derive(Clone)]
    struct MockService;

    impl Service<HttpRequest<Full<Bytes>>> for MockService {
        type Response = HttpResponse<Full<Bytes>>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: HttpRequest<Full<Bytes>>) -> Self::Future {
            Box::pin(async {
                Ok(HttpResponse::builder()
                    .header(CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from_static(BODY.as_bytes())))
                    .unwrap())
            })
        }
    }

    /// Runs one request through the production middleware order
    /// (compression outermost, then response-size) and returns the response.
    async fn run(
        enabled: bool,
        accept_encoding: Option<&str>,
    ) -> HttpResponse<impl http_body::Body<Data = Bytes, Error = impl std::fmt::Debug>> {
        let svc = ServiceBuilder::new()
            .layer(layer(enabled))
            .layer(ResponseSizeLayer)
            .service(MockService);
        let mut req = HttpRequest::builder().uri("/");
        if let Some(enc) = accept_encoding {
            req = req.header(ACCEPT_ENCODING, enc);
        }
        svc.oneshot(req.body(Full::new(Bytes::new())).unwrap()).await.unwrap()
    }

    async fn body_bytes(
        resp: HttpResponse<impl http_body::Body<Data = Bytes, Error = impl std::fmt::Debug>>,
    ) -> Vec<u8> {
        resp.into_body().collect().await.unwrap().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn no_accept_encoding_stays_identity() {
        let resp = run(true, None).await;
        assert!(resp.headers().get(CONTENT_ENCODING).is_none());
        assert_eq!(body_bytes(resp).await, BODY.as_bytes());
    }

    #[tokio::test]
    async fn gzip_negotiated_and_round_trips() {
        let resp = run(true, Some("gzip")).await;
        assert_eq!(resp.headers().get(CONTENT_ENCODING).unwrap(), "gzip");
        // x-response-size still reports the uncompressed payload size
        let size: u64 = resp
            .headers()
            .get(RESPONSE_SIZE_HEADER_NAME)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(size, BODY.len() as u64);

        let compressed = body_bytes(resp).await;
        assert!(compressed.len() < BODY.len());
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&compressed[..]).read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, BODY.as_bytes());
    }

    #[tokio::test]
    async fn zstd_negotiated_and_round_trips() {
        let resp = run(true, Some("zstd")).await;
        assert_eq!(resp.headers().get(CONTENT_ENCODING).unwrap(), "zstd");

        let compressed = body_bytes(resp).await;
        assert!(compressed.len() < BODY.len());
        let decoded = zstd::stream::decode_all(&compressed[..]).unwrap();
        assert_eq!(decoded, BODY.as_bytes());
    }

    #[tokio::test]
    async fn kill_switch_disables_negotiation() {
        let resp = run(false, Some("gzip, zstd")).await;
        assert!(resp.headers().get(CONTENT_ENCODING).is_none());
        assert_eq!(body_bytes(resp).await, BODY.as_bytes());
    }
}
