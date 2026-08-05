//! CLI/env secret wrapper shared by the binaries' argument structs.

/// A CLI/env secret that renders as `[redacted]` in `Debug` output, so it cannot leak when
/// an argument struct (which derives `Debug`) is logged.
#[derive(Clone)]
pub struct RedactedSecret(String);

impl std::str::FromStr for RedactedSecret {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl std::fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl AsRef<str> for RedactedSecret {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::RedactedSecret;

    /// Argument structs derive `Debug`; the secret must never appear in that output, bare or
    /// wrapped.
    #[test]
    fn debug_output_redacts_the_secret() {
        let secret: RedactedSecret = "super-secret-key".parse().unwrap();
        assert_eq!(format!("{secret:?}"), "[redacted]");
        assert_eq!(format!("{:?}", Some(&secret)), "Some([redacted])");
        assert_eq!(secret.as_ref(), "super-secret-key");
    }
}
