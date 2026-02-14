//! Timing HTTP middleware for measuring CPU execution time.
//!
//! Provides [`TimingHeaderLayer`] which measures CPU time (excluding sleep/IO wait)
//! and sets the `x-execution-time-ns` header on every HTTP response.
//!
//! Uses `CLOCK_THREAD_CPUTIME_ID` via `libc::clock_gettime` to measure only the
//! actual CPU time consumed by the current thread, similar to mega-reth's approach.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use http::{HeaderName, HeaderValue};
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::metrics::CpuTimeMetrics;

/// Header name for execution time in nanoseconds.
pub const TIMING_HEADER_NAME: &str = "x-execution-time-ns";

/// Tower layer that creates [`TimingHeaderService`] instances.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimingHeaderLayer;

impl<S> Layer<S> for TimingHeaderLayer {
    type Service = TimingHeaderService<S>;

    #[inline]
    fn layer(&self, inner: S) -> Self::Service {
        TimingHeaderService { inner }
    }
}

/// HTTP middleware service that measures CPU time and sets
/// the `x-execution-time-ns` header.
#[derive(Debug, Clone)]
pub struct TimingHeaderService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for TimingHeaderService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = http::Response<ResBody>;
    type Error = S::Error;
    type Future = TimedResponseFuture<S::Future, S::Error, ResBody>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        TimedResponseFuture::new(self.inner.call(req))
    }
}

pin_project! {
    /// Future that measures CPU time and injects the timing header into the response.
    ///
    /// Accumulates CPU time across all poll cycles using `CLOCK_THREAD_CPUTIME_ID`,
    /// which excludes time spent sleeping or waiting for I/O.
    pub struct TimedResponseFuture<F, E, ResBody> {
        #[pin]
        inner: F,
        cpu_time: Duration,
        _error: std::marker::PhantomData<E>,
        _body: std::marker::PhantomData<ResBody>,
    }
}

impl<F, E, ResBody> TimedResponseFuture<F, E, ResBody> {
    fn new(inner: F) -> Self {
        Self {
            inner,
            cpu_time: Duration::ZERO,
            _error: std::marker::PhantomData,
            _body: std::marker::PhantomData,
        }
    }
}

impl<F, E, ResBody> Future for TimedResponseFuture<F, E, ResBody>
where
    F: Future<Output = Result<http::Response<ResBody>, E>>,
{
    type Output = Result<http::Response<ResBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let start = thread_cpu_time();
        let res = this.inner.poll(cx);
        let end = thread_cpu_time();
        *this.cpu_time += end.saturating_sub(start);

        match res {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(mut response)) => {
                let cpu_ns = this.cpu_time.as_nanos() as u64;
                let mut buf = [0u8; 24];
                if let Some(value_str) = format_u64(cpu_ns, &mut buf) {
                    let header_name = HeaderName::from_static(TIMING_HEADER_NAME);
                    if let Ok(header_value) = HeaderValue::from_str(value_str) {
                        response.headers_mut().insert(header_name, header_value);
                    }
                }
                // Record as Prometheus metric
                CpuTimeMetrics::create().record(Duration::from_nanos(cpu_ns).as_secs_f64());
                Poll::Ready(Ok(response))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

/// Measures the CPU time consumed by the current thread.
///
/// Uses `clock_gettime` with `CLOCK_THREAD_CPUTIME_ID` to get thread-specific
/// CPU time, which excludes time spent sleeping or waiting for I/O.
/// Returns [`Duration::ZERO`] if the system call fails.
fn thread_cpu_time() -> Duration {
    use libc::{clock_gettime, timespec, CLOCK_THREAD_CPUTIME_ID};
    unsafe {
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        if clock_gettime(CLOCK_THREAD_CPUTIME_ID, std::ptr::addr_of_mut!(ts)) != 0 {
            return Duration::ZERO;
        }
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
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
