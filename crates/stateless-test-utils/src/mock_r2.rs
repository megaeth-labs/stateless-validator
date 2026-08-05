//! Minimal scripted HTTP server standing in for an R2 (S3 API) endpoint in tests.
//!
//! Shared by every R2 witness *reader* test — `stateless-r2`'s fetcher tests and the
//! binaries' adapter tests — so the response scripting stays identical across them.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serves one scripted HTTP/1.1 response per connection on a local port and counts requests.
/// The last response repeats if more connections arrive than were scripted. Bodies are
/// anything `Into<Vec<u8>>` so failure tests pass `&str` and happy-path tests raw bytes.
///
/// Returns the endpoint origin (`http://127.0.0.1:<port>`) and the request counter.
pub async fn mock_r2(responses: Vec<(u16, impl Into<Vec<u8>>)>) -> (String, Arc<AtomicUsize>) {
    let responses: Vec<(u16, Vec<u8>)> =
        responses.into_iter().map(|(status, body)| (status, body.into())).collect();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let (status, body) = &responses[n.min(responses.len() - 1)];
            // Drain the request head before replying.
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            // The reason phrase is never interpreted; `location` matters only to
            // redirects-not-followed tests.
            let head = format!(
                "HTTP/1.1 {status} X\r\nconnection: close\r\n\
                 location: http://example.invalid/elsewhere\r\n\
                 content-length: {}\r\n\r\n",
                body.len(),
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
        }
    });
    (endpoint, hits)
}
