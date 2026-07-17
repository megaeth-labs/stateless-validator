//! R2 endpoint parsing shared by both witness uploaders.

use reqwest::Url;

/// Parses an R2 endpoint into its origin (`scheme://host[:port]`, no trailing slash) and the
/// request host (`host[:port]`) used for `SigV4` canonical headers.
///
/// Returns empty strings when the endpoint is unusable: not a valid URL, no host, or anything
/// beyond a bare origin (path/query/fragment). A path would be sent on the wire but never signed
/// (the signer builds `/{bucket}/{key}` itself), failing every request with 403
/// `SignatureDoesNotMatch` — so e.g. a pasted R2 dashboard bucket URL is rejected at startup.
pub fn parse_endpoint(endpoint: &str) -> (String, String) {
    let empty = || (String::new(), String::new());
    let trimmed = endpoint.trim_end_matches('/');
    let Ok(url) = Url::parse(trimmed) else { return empty() };
    let Some(host_str) = url.host_str() else { return empty() };

    // Accept only a bare origin. `Url` normalizes a hostname-only URL to a "/" path, so treat "/"
    // (and the empty path) as "no path"; any other path, query, or fragment is rejected.
    let has_path = !matches!(url.path(), "" | "/");
    if has_path || url.query().is_some() || url.fragment().is_some() {
        return empty();
    }

    let host = match url.port() {
        Some(port) => format!("{host_str}:{port}"),
        None => host_str.to_string(),
    };
    // Reconstruct the origin from the parsed components rather than echoing the input, so no path
    // can leak into it even if the trimming above ever misses a shape.
    let origin = format!("{}://{host}", url.scheme());
    (origin, host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_endpoint_strips_trailing_slash_and_extracts_host() {
        let (endpoint, host) = parse_endpoint("https://acc.r2.cloudflarestorage.com/");
        assert_eq!(endpoint, "https://acc.r2.cloudflarestorage.com");
        assert_eq!(host, "acc.r2.cloudflarestorage.com");
    }

    #[test]
    fn parse_endpoint_keeps_non_default_port() {
        let (endpoint, host) = parse_endpoint("http://localhost:9000");
        assert_eq!(endpoint, "http://localhost:9000");
        assert_eq!(host, "localhost:9000");
    }

    #[test]
    fn parse_endpoint_rejects_invalid_url() {
        let (endpoint, host) = parse_endpoint("not a url");
        assert!(endpoint.is_empty());
        assert!(host.is_empty());
    }

    #[test]
    fn parse_endpoint_rejects_endpoint_with_path() {
        let (endpoint, host) =
            parse_endpoint("https://acc.r2.cloudflarestorage.com/witness-testnet");
        assert!(endpoint.is_empty(), "an endpoint with a path must be rejected");
        assert!(host.is_empty(), "an endpoint with a path must be rejected");

        // A trailing-slash-only path is still just the origin and must be accepted.
        let (endpoint, host) = parse_endpoint("https://acc.r2.cloudflarestorage.com/");
        assert_eq!(endpoint, "https://acc.r2.cloudflarestorage.com");
        assert_eq!(host, "acc.r2.cloudflarestorage.com");
    }

    #[test]
    fn parse_endpoint_rejects_query_and_fragment() {
        assert_eq!(
            parse_endpoint("https://acc.r2.cloudflarestorage.com/?x=1"),
            (String::new(), String::new())
        );
        assert_eq!(
            parse_endpoint("https://acc.r2.cloudflarestorage.com/#frag"),
            (String::new(), String::new())
        );
    }
}
