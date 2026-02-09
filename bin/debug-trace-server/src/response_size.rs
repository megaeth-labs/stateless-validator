//! Response size HTTP middleware.
//!
//! Provides [`ResponseSizeLayer`] which reads the response body size via
//! `http_body::Body::size_hint` and sets the `x-response-size` header (in bytes)
//! on every HTTP response.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{HeaderName, HeaderValue};
use http_body::Body;
use pin_project_lite::pin_project;
use tower::{Layer, Service};

/// Header name for response size in bytes.
pub const RESPONSE_SIZE_HEADER_NAME: &str = "x-response-size";

/// Tower layer that creates [`ResponseSizeService`] instances.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResponseSizeLayer;

impl<S> Layer<S> for ResponseSizeLayer {
    type Service = ResponseSizeService<S>;

    #[inline]
    fn layer(&self, inner: S) -> Self::Service {
        ResponseSizeService { inner }
    }
}

/// HTTP middleware service that measures response body size and sets
/// the `x-response-size` header.
#[derive(Debug, Clone)]
pub struct ResponseSizeService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for ResponseSizeService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send,
    ReqBody: Send + 'static,
    ResBody: Body + Send + 'static,
{
    type Response = http::Response<ResBody>;
    type Error = S::Error;
    type Future = ResponseSizeFuture<S::Future, S::Error, ResBody>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        ResponseSizeFuture::new(self.inner.call(req))
    }
}

pin_project! {
    /// Future that reads the response body size and injects the header.
    pub struct ResponseSizeFuture<F, E, ResBody> {
        #[pin]
        inner: F,
        _error: std::marker::PhantomData<E>,
        _body: std::marker::PhantomData<ResBody>,
    }
}

impl<F, E, ResBody> ResponseSizeFuture<F, E, ResBody> {
    fn new(inner: F) -> Self {
        Self { inner, _error: std::marker::PhantomData, _body: std::marker::PhantomData }
    }
}

impl<F, E, ResBody> Future for ResponseSizeFuture<F, E, ResBody>
where
    F: Future<Output = Result<http::Response<ResBody>, E>>,
    ResBody: Body,
{
    type Output = Result<http::Response<ResBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(mut response)) => {
                let size = response.body().size_hint().exact().unwrap_or(0);
                let mut buf = [0u8; 24];
                if let Some(value_str) = format_u64(size, &mut buf) {
                    let header_name = HeaderName::from_static(RESPONSE_SIZE_HEADER_NAME);
                    if let Ok(header_value) = HeaderValue::from_str(value_str) {
                        response.headers_mut().insert(header_name, header_value);
                    }
                }
                Poll::Ready(Ok(response))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

#[inline]
fn format_u64(value: u64, buf: &mut [u8; 24]) -> Option<&str> {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    write!(cursor, "{}", value).ok()?;
    let len = cursor.position() as usize;
    std::str::from_utf8(&buf[..len]).ok()
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use bytes::Bytes;
    use http::{Request as HttpRequest, Response as HttpResponse};
    use http_body_util::Full;

    use super::*;

    #[derive(Clone)]
    struct MockService {
        body: &'static str,
    }

    impl Service<HttpRequest<Full<Bytes>>> for MockService {
        type Response = HttpResponse<Full<Bytes>>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: HttpRequest<Full<Bytes>>) -> Self::Future {
            let body = self.body;
            Box::pin(async move { Ok(HttpResponse::new(Full::new(Bytes::from(body)))) })
        }
    }

    #[tokio::test]
    async fn test_response_size_header_set() {
        let mock = MockService { body: "hello world" };
        let layer = ResponseSizeLayer;
        let mut service = layer.layer(mock);

        let req = HttpRequest::new(Full::new(Bytes::new()));
        let response = service.call(req).await.unwrap();

        let header = response
            .headers()
            .get(RESPONSE_SIZE_HEADER_NAME)
            .expect("x-response-size header should exist");
        let size: u64 = header.to_str().unwrap().parse().unwrap();
        assert_eq!(size, 11); // "hello world" = 11 bytes
    }

    #[tokio::test]
    async fn test_response_size_empty_body() {
        let mock = MockService { body: "" };
        let layer = ResponseSizeLayer;
        let mut service = layer.layer(mock);

        let req = HttpRequest::new(Full::new(Bytes::new()));
        let response = service.call(req).await.unwrap();

        let header = response
            .headers()
            .get(RESPONSE_SIZE_HEADER_NAME)
            .expect("x-response-size header should exist");
        let size: u64 = header.to_str().unwrap().parse().unwrap();
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn test_response_size_large_body() {
        let large = "x".repeat(1_000_000);
        let large_static: &'static str = Box::leak(large.into_boxed_str());
        let mock = MockService { body: large_static };
        let layer = ResponseSizeLayer;
        let mut service = layer.layer(mock);

        let req = HttpRequest::new(Full::new(Bytes::new()));
        let response = service.call(req).await.unwrap();

        let header = response
            .headers()
            .get(RESPONSE_SIZE_HEADER_NAME)
            .expect("x-response-size header should exist");
        let size: u64 = header.to_str().unwrap().parse().unwrap();
        assert_eq!(size, 1_000_000);
    }

    #[test]
    fn test_format_u64_zero() {
        let mut buf = [0u8; 24];
        assert_eq!(format_u64(0, &mut buf), Some("0"));
    }

    #[test]
    fn test_format_u64_max() {
        let mut buf = [0u8; 24];
        assert_eq!(format_u64(u64::MAX, &mut buf), Some("18446744073709551615"));
    }
}
