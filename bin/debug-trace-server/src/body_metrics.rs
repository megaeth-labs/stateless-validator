//! Body-streaming telemetry HTTP middleware.
//!
//! [`BodyMetricsLayer`] wraps the outgoing response body and accounts for the work that
//! happens while hyper streams it — the phase the `x-execution-time-ns` header and
//! [`CpuTimeMetrics`](crate::metrics::CpuTimeMetrics) are finalized too early to see.
//! Compression runs inside `poll_frame`, so sitting outermost (around the compression
//! layer) this is the only place its CPU and the true wire bytes are observable; both
//! are recorded per response into [`BodyMetrics`], labeled by negotiated encoding.
//!
//! Recording happens at end-of-stream or on drop, so a client that aborts mid-transfer
//! still accounts the CPU it burned.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Buf;
use http::header::CONTENT_ENCODING;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::{metrics::BodyMetrics, timing::thread_cpu_time};

/// Tower layer that creates [`BodyMetricsService`] instances.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BodyMetricsLayer;

impl<S> Layer<S> for BodyMetricsLayer {
    type Service = BodyMetricsService<S>;

    #[inline]
    fn layer(&self, inner: S) -> Self::Service {
        BodyMetricsService { inner }
    }
}

/// HTTP middleware service that wraps response bodies in [`MeasuredBody`].
#[derive(Debug, Clone)]
pub(crate) struct BodyMetricsService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for BodyMetricsService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send,
    ReqBody: Send + 'static,
    ResBody: Body + Send + 'static,
{
    type Response = http::Response<MeasuredBody<ResBody>>;
    type Error = S::Error;
    type Future = BodyMetricsFuture<S::Future, S::Error, ResBody>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        BodyMetricsFuture { inner: self.inner.call(req), _marker: std::marker::PhantomData }
    }
}

pin_project! {
    /// Future that wraps the response body once the inner service resolves.
    pub(crate) struct BodyMetricsFuture<F, E, ResBody> {
        #[pin]
        inner: F,
        _marker: std::marker::PhantomData<(E, ResBody)>,
    }
}

impl<F, E, ResBody> Future for BodyMetricsFuture<F, E, ResBody>
where
    F: Future<Output = Result<http::Response<ResBody>, E>>,
    ResBody: Body,
{
    type Output = Result<http::Response<MeasuredBody<ResBody>>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx).map_ok(|resp| {
            let encoding = encoding_label(&resp);
            resp.map(|body| MeasuredBody::new(body, encoding))
        })
    }
}

/// Static label for the response's negotiated `Content-Encoding`.
fn encoding_label<B>(resp: &http::Response<B>) -> &'static str {
    match resp.headers().get(CONTENT_ENCODING).and_then(|v| v.to_str().ok()) {
        Some("gzip") => "gzip",
        Some("zstd") => "zstd",
        Some("br") => "br",
        Some("deflate") => "deflate",
        _ => "identity",
    }
}

/// Accumulates per-body cost and records it exactly once — at end-of-stream, on a body
/// error, or on drop (client abort), whichever comes first.
struct Recorder {
    metrics: BodyMetrics,
    cpu: Duration,
    bytes: u64,
    done: bool,
}

impl Recorder {
    fn finish(&mut self) {
        if !self.done {
            self.done = true;
            self.metrics.record(self.cpu.as_secs_f64(), self.bytes);
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.finish();
    }
}

pin_project! {
    /// Response body that meters the thread CPU spent producing frames and the bytes
    /// that leave on the wire, delegating everything else to the inner body (including
    /// `size_hint`, so identity responses keep their `Content-Length`).
    pub(crate) struct MeasuredBody<B> {
        #[pin]
        inner: B,
        recorder: Recorder,
    }
}

impl<B> MeasuredBody<B> {
    fn new(inner: B, encoding: &'static str) -> Self {
        Self {
            inner,
            recorder: Recorder {
                metrics: BodyMetrics::create(encoding),
                cpu: Duration::ZERO,
                bytes: 0,
                done: false,
            },
        }
    }
}

impl<B> Body for MeasuredBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let start = thread_cpu_time();
        let res = this.inner.poll_frame(cx);
        this.recorder.cpu += thread_cpu_time().saturating_sub(start);
        match &res {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.recorder.bytes += data.remaining() as u64;
                }
            }
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => this.recorder.finish(),
            Poll::Pending => {}
        }
        res
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};

    use super::*;

    /// The wrapper must be transparent: identical bytes out, exact `size_hint`
    /// preserved (that is what keeps `Content-Length` on identity responses).
    #[tokio::test]
    async fn measured_body_is_transparent() {
        let payload = Bytes::from_static(b"0123456789");
        let body = MeasuredBody::new(Full::new(payload.clone()), "identity");
        assert_eq!(body.size_hint().exact(), Some(payload.len() as u64));
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected, payload);
    }
}
