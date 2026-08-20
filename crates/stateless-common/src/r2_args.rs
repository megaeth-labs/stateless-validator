//! Validation of the `--r2-*` argument set, shared by the binaries' argument structs.
//!
//! These rules decide which R2 target the witness fetcher is built with, and both binaries
//! enforce the same ones. They live here rather than in each binary because, written twice,
//! they diverged three ways inside a single change: one side named every missing member of an
//! incomplete credential quad while the other reported them one at a time, one side swept
//! empty values twice, and the shared tuning flags were gated on one binary and silently
//! ignored on the other.
//!
//! Enforced after parsing rather than through clap attributes because this workspace builds
//! clap without its `error-context` feature, so a clap rejection names no argument — useless
//! to an operator whose configuration is an env file. Every error raised here names the flag,
//! in the spelling the calling binary uses for it.

use eyre::{Result, bail};

/// One `--r2-*` flag carrying a value: the spelling this binary gives it, and what it parsed.
#[derive(Clone, Copy)]
pub struct R2Flag<'a> {
    /// The flag as an operator writes it, e.g. `--r2-endpoint`.
    pub name: &'a str,
    /// The parsed value. `Some("")` is the failed-env-injection shape, not a value.
    pub value: Option<&'a str>,
}

impl<'a> R2Flag<'a> {
    /// Names a flag and its parsed value.
    pub const fn new(name: &'a str, value: Option<&'a str>) -> Self {
        Self { name, value }
    }

    const fn is_set(&self) -> bool {
        self.value.is_some()
    }
}

/// A flag whose value type belongs to the binary, so only its presence reaches these rules.
#[derive(Clone, Copy)]
pub struct R2TuningFlag<'a> {
    /// The flag as an operator writes it, e.g. `--r2-connect-timeout-ms`.
    pub name: &'a str,
    /// Whether the operator set it explicitly (a defaulted value is not "set").
    pub set: bool,
}

impl<'a> R2TuningFlag<'a> {
    /// Names a tuning flag and whether it was explicitly set.
    pub const fn new(name: &'a str, set: bool) -> Self {
        Self { name, set }
    }
}

/// A flag whose numeric *value* the rules need, not just its presence.
#[derive(Clone, Copy)]
pub struct R2CountFlag<'a> {
    /// The flag as an operator writes it, e.g. `--r2-max-concurrent-requests`.
    pub name: &'a str,
    /// The parsed count, `None` when the operator left it alone.
    pub value: Option<usize>,
}

impl<'a> R2CountFlag<'a> {
    /// Names a count flag and its parsed value.
    pub const fn new(name: &'a str, value: Option<usize>) -> Self {
        Self { name, value }
    }
}

/// One binary's `--r2-*` flags, as parsed.
pub struct R2Flags<'a> {
    /// Bare S3 endpoint origin; selects the signed target.
    pub endpoint: R2Flag<'a>,
    /// Bucket for the signed target.
    pub bucket: R2Flag<'a>,
    /// Access key id for the signed target.
    pub access_key_id: R2Flag<'a>,
    /// Secret access key for the signed target.
    pub secret_access_key: R2Flag<'a>,
    /// Cloudflare custom domain; selects the unsigned target.
    pub custom_domain: R2Flag<'a>,
    /// Cloudflare Access service-token client id (custom domain only).
    pub access_client_id: R2Flag<'a>,
    /// Cloudflare Access service-token client secret (custom domain only).
    pub access_client_secret: R2Flag<'a>,
    /// How many HTTP/2 connections the custom-domain target spreads its GETs over, unparsed
    /// (see [`parse_r2_connections`] for why it arrives as a string).
    pub connections: R2Flag<'a>,
    /// The in-flight GET cap these connections divide, whatever the binary calls it.
    pub max_concurrent_requests: R2CountFlag<'a>,
    /// Flags that only mean something once a target is configured.
    pub tuning: &'a [R2TuningFlag<'a>],
}

/// Which target a validated flag set selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum R2Target {
    /// No R2 flags configured; the caller decides whether that is fatal for its mode.
    None,
    /// SigV4-signed GETs against the bare S3 endpoint.
    S3,
    /// Unsigned GETs through a Cloudflare custom domain, spread over this many HTTP/2
    /// connections. Carried on the verdict rather than left for the caller to parse again:
    /// the count is validated here, and a caller that re-derived it would be a second place
    /// the same rule lives.
    CustomDomain { connections: usize },
}

/// Validates one binary's `--r2-*` flags and reports which target they select.
///
/// Rejects, each by flag name: a present-but-empty value, both targets at once, S3 flags left
/// behind by the documented migration to a custom domain, an incomplete S3 credential quad, a
/// half-configured Cloudflare Access pair or one attached to no custom domain, a connection
/// count that is zero, unparseable, attached to a target that cannot spread over connections,
/// or larger than the cap it divides, and tuning flags set with no target to tune.
///
/// Emptiness is swept first so a blank env line is diagnosed as itself, rather than read as a
/// configured target or as a leftover from one — without that ordering, a blank
/// `..._R2_CUSTOM_DOMAIN=` beside a working S3 configuration gets told to unset the S3
/// configuration.
pub fn validate_r2_flags(flags: &R2Flags<'_>) -> Result<R2Target> {
    let s3_credentials = [flags.bucket, flags.access_key_id, flags.secret_access_key];
    let all_values = [
        flags.endpoint,
        flags.bucket,
        flags.access_key_id,
        flags.secret_access_key,
        flags.custom_domain,
        flags.access_client_id,
        flags.access_client_secret,
        flags.connections,
    ];

    for flag in all_values {
        if flag.value.is_some_and(str::is_empty) {
            bail!(
                "{} is set but empty (empty env var injection?): unset it or give it a value",
                flag.name
            );
        }
    }

    // Past the sweep, presence is the only predicate: anything still set was meant.
    let target = match (flags.custom_domain.is_set(), flags.endpoint.is_set()) {
        (true, true) => bail!(
            "{} and {} are mutually exclusive R2 targets: configure exactly one",
            flags.endpoint.name,
            flags.custom_domain.name
        ),
        (true, false) => {
            // The domain replaces the S3 target, so anything left of it is dead configuration;
            // reading past it in silence would hide which credentials are actually in use.
            let leftovers = names_of(&s3_credentials, R2Flag::is_set);
            if !leftovers.is_empty() {
                bail!(
                    "{} replaces the S3 target: unset the leftover {} (ignoring them silently \
                     would hide which credentials are actually in use)",
                    flags.custom_domain.name,
                    leftovers.join(", ")
                );
            }
            R2Target::CustomDomain { connections: 1 }
        }
        (false, true) => {
            let missing = names_of(&s3_credentials, |f| !f.is_set());
            if !missing.is_empty() {
                bail!(
                    "{} needs the whole S3 credential set; missing: {}",
                    flags.endpoint.name,
                    missing.join(", ")
                );
            }
            R2Target::S3
        }
        (false, false) => {
            // A partial quad with no endpoint builds nothing, so say what is missing rather
            // than starting with the R2 route quietly disabled.
            let present = names_of(&s3_credentials, R2Flag::is_set);
            if !present.is_empty() {
                bail!("{} is required alongside {}", flags.endpoint.name, present.join(", "));
            }
            R2Target::None
        }
    };

    validate_access_pair(flags, target)?;
    let connections = validate_connections(flags, target)?;

    // The connection count joins the tuning flags here rather than being reported on its own,
    // so an operator who orphaned several of them is told about all of them at once.
    let orphan_tuning: Vec<&str> = flags
        .tuning
        .iter()
        .filter(|flag| flag.set)
        .map(|flag| flag.name)
        .chain(flags.connections.value.map(|_| flags.connections.name))
        .collect();
    if target == R2Target::None && !orphan_tuning.is_empty() {
        bail!(
            "{} only applies once an R2 target is configured: set one, or unset the flag",
            orphan_tuning.join(", ")
        );
    }

    Ok(match target {
        R2Target::CustomDomain { .. } => R2Target::CustomDomain { connections },
        settled => settled,
    })
}

/// Parses the connection count, defaulting to a single connection when it is not set.
///
/// It travels as a string rather than as a `usize` in the argument struct so that a blank line
/// — what a templated env file renders for an unset variable — is diagnosed here, by name, at
/// the point the R2 flags are actually read. Parsed by clap it would abort startup with clap's
/// unnamed "invalid value for one of the arguments" (this workspace builds clap without
/// `error-context`), and it would abort it even on a binary that never reads the R2 flags in
/// the mode it was started in.
fn parse_r2_connections(flag: R2Flag<'_>) -> Result<usize> {
    let Some(raw) = flag.value else { return Ok(1) };
    let Ok(count) = raw.parse::<usize>() else {
        bail!("{} must be a whole number of connections, got {raw:?}", flag.name);
    };
    if count == 0 {
        bail!("{} must be at least 1", flag.name);
    }
    Ok(count)
}

/// The connection count is a custom-domain concept, must name at least one connection, and
/// cannot name more connections than the in-flight cap can fill.
///
/// Rejected rather than clamped on the S3 target: there, one client already opens a socket per
/// concurrent request, so a count set there is a belief about the deployment that is not true,
/// and honouring it silently would leave the operator expecting a spread they did not get.
/// Rejected rather than clamped against the cap for the same reason — and because clamping
/// would quietly hand back fewer connections than the published gauge reports.
fn validate_connections(flags: &R2Flags<'_>, target: R2Target) -> Result<usize> {
    let count = parse_r2_connections(flags.connections)?;
    if flags.connections.value.is_none() {
        return Ok(count);
    }
    if target == R2Target::S3 {
        bail!(
            "{} applies only to {}: the S3 target already opens a connection per in-flight GET",
            flags.connections.name,
            flags.custom_domain.name
        );
    }
    // The cap is split across the connections, so more connections than permits leaves some of
    // them permanently idle — and the split rounds up, which past this point would be the one
    // way the fetcher-wide total could exceed the cap by more than a rounding residue.
    if let Some(max) = flags.max_concurrent_requests.value &&
        count > max
    {
        bail!(
            "{} ({count}) exceeds {} ({max}): the cap is split across the connections, so more \
             connections than permits leaves some of them idle",
            flags.connections.name,
            flags.max_concurrent_requests.name
        );
    }
    Ok(count)
}

/// The Cloudflare Access pair is all-or-nothing and belongs to the custom-domain target only.
///
/// Checked here rather than by clap's `requires_all` so the error names the missing half. It
/// also protects the callers' `Option::zip`: one half alone would zip to `None`, which is a
/// legitimate configuration (an IP-allowlisted domain), so a half-set pair would otherwise
/// build a working but silently *unauthenticated* client — and on the custom-domain target the
/// edge answers unauthenticated GETs with a non-retryable 403.
fn validate_access_pair(flags: &R2Flags<'_>, target: R2Target) -> Result<()> {
    let (id, secret) = (flags.access_client_id, flags.access_client_secret);
    match (id.is_set(), secret.is_set()) {
        (false, false) => return Ok(()),
        (true, false) => {
            bail!("{} is set without {}: configure both or neither", id.name, secret.name)
        }
        (false, true) => {
            bail!("{} is set without {}: configure both or neither", secret.name, id.name)
        }
        (true, true) => {}
    }
    if !matches!(target, R2Target::CustomDomain { .. }) {
        bail!(
            "{} and {} apply only to {}: configure that target, or unset the pair",
            id.name,
            secret.name,
            flags.custom_domain.name
        );
    }
    Ok(())
}

fn names_of<'a>(flags: &[R2Flag<'a>], keep: impl Fn(&R2Flag<'a>) -> bool) -> Vec<&'a str> {
    flags.iter().filter(|f| keep(f)).map(|f| f.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flags one test cares about; everything it does not name is absent.
    #[derive(Default)]
    struct Cfg<'a> {
        endpoint: Option<&'a str>,
        bucket: Option<&'a str>,
        key_id: Option<&'a str>,
        secret: Option<&'a str>,
        domain: Option<&'a str>,
        access_id: Option<&'a str>,
        access_secret: Option<&'a str>,
        connections: Option<&'a str>,
        max_concurrent: Option<usize>,
        tuning: &'a [R2TuningFlag<'a>],
    }

    impl<'a> Cfg<'a> {
        /// The validator's flag spellings, so the messages read as an operator sees them.
        fn flags(&'a self) -> R2Flags<'a> {
            R2Flags {
                endpoint: R2Flag::new("--r2-endpoint", self.endpoint),
                bucket: R2Flag::new("--r2-bucket", self.bucket),
                access_key_id: R2Flag::new("--r2-access-key-id", self.key_id),
                secret_access_key: R2Flag::new("--r2-secret-access-key", self.secret),
                custom_domain: R2Flag::new("--r2-custom-domain", self.domain),
                access_client_id: R2Flag::new("--r2-access-client-id", self.access_id),
                access_client_secret: R2Flag::new("--r2-access-client-secret", self.access_secret),
                connections: R2Flag::new("--r2-connections", self.connections),
                max_concurrent_requests: R2CountFlag::new(
                    "--r2-max-concurrent-requests",
                    self.max_concurrent,
                ),
                tuning: self.tuning,
            }
        }

        fn validate(&'a self) -> Result<R2Target> {
            validate_r2_flags(&self.flags())
        }

        fn err(&'a self) -> String {
            self.validate().unwrap_err().to_string()
        }
    }

    /// Every way a connection count can be wrong is named. Zero builds a fetcher that can
    /// carry nothing; the S3 target cannot spread over connections at all; more connections
    /// than permits leaves some of them idle. Named rather than clamped or ignored, because
    /// either silence leaves the operator believing in a spread they did not get.
    #[test]
    fn connections_must_be_positive_belong_to_the_custom_domain_and_fit_the_cap() {
        let zero = Cfg { domain: DOMAIN, connections: Some("0"), ..Cfg::default() }.err();
        assert!(zero.contains("--r2-connections") && zero.contains("at least 1"), "{zero}");

        let junk = Cfg { domain: DOMAIN, connections: Some("eight"), ..Cfg::default() }.err();
        assert!(junk.contains("--r2-connections") && junk.contains("whole number"), "{junk}");

        let on_s3 = Cfg { connections: Some("4"), ..s3() }.err();
        assert!(
            on_s3.contains("--r2-connections") && on_s3.contains("--r2-custom-domain"),
            "{on_s3}"
        );

        let orphan = Cfg { connections: Some("4"), ..Cfg::default() }.err();
        assert!(orphan.contains("--r2-connections"), "{orphan}");

        let over_cap = Cfg {
            domain: DOMAIN,
            connections: Some("8"),
            max_concurrent: Some(4),
            ..Cfg::default()
        }
        .err();
        assert!(
            over_cap.contains("--r2-connections") &&
                over_cap.contains("--r2-max-concurrent-requests"),
            "more connections than permits must name both flags: {over_cap}"
        );

        assert!(
            Cfg {
                domain: DOMAIN,
                connections: Some("8"),
                max_concurrent: Some(48),
                ..Cfg::default()
            }
            .validate()
            .is_ok()
        );
    }

    /// A blank line is what a templated env file renders for an unset variable, so it must be
    /// diagnosed as itself rather than as a bad number — and, on a binary that reads the R2
    /// flags in only one mode, must not reach clap at all.
    #[test]
    fn a_blank_connection_count_is_named_as_an_empty_value() {
        let blank = Cfg { domain: DOMAIN, connections: Some(""), ..Cfg::default() }.err();
        assert!(blank.contains("--r2-connections") && blank.contains("empty"), "{blank}");
        assert_eq!(parse_r2_connections(R2Flag::new("--r2-connections", None)).unwrap(), 1);
        assert_eq!(parse_r2_connections(R2Flag::new("--r2-connections", Some("8"))).unwrap(), 8);
    }

    /// A complete, valid S3 configuration.
    fn s3<'a>() -> Cfg<'a> {
        Cfg {
            endpoint: Some("https://acc.r2.cloudflarestorage.com"),
            bucket: Some("b"),
            key_id: Some("k"),
            secret: Some("s"),
            ..Cfg::default()
        }
    }

    const DOMAIN: Option<&str> = Some("https://w.example.com");

    #[test]
    fn selects_the_configured_target() {
        assert_eq!(s3().validate().unwrap(), R2Target::S3);
        assert_eq!(
            Cfg { domain: DOMAIN, ..Cfg::default() }.validate().unwrap(),
            R2Target::CustomDomain { connections: 1 }
        );
        assert_eq!(Cfg::default().validate().unwrap(), R2Target::None);
    }

    /// Emptiness is diagnosed before target selection can read a blank line as a configured
    /// target or as a leftover from one.
    #[test]
    fn empty_values_are_named_before_target_selection() {
        let err = Cfg { domain: Some(""), ..s3() }.err();
        assert!(err.contains("--r2-custom-domain") && err.contains("set but empty"), "{err}");
        // Regression guard: this once reached the leftover branch and told the operator to
        // unset their entire working S3 configuration.
        assert!(!err.contains("--r2-endpoint"), "must not blame the working S3 config: {err}");
    }

    #[test]
    fn both_targets_are_rejected_naming_both() {
        let err = Cfg { domain: DOMAIN, ..s3() }.err();
        assert!(err.contains("--r2-endpoint") && err.contains("--r2-custom-domain"), "{err}");
    }

    #[test]
    fn s3_flags_left_beside_a_custom_domain_are_named() {
        let err = Cfg { domain: DOMAIN, bucket: Some("b"), ..Cfg::default() }.err();
        assert!(err.contains("--r2-bucket"), "{err}");
        assert!(!err.contains("--r2-access-key-id"), "only the flags actually set: {err}");
    }

    /// The S3 target is all-or-nothing, and every missing member is named in one message — the
    /// trace server did this while the validator reported them one flag at a time.
    #[test]
    fn an_incomplete_s3_quad_names_every_missing_member() {
        let err = Cfg { endpoint: s3().endpoint, ..Cfg::default() }.err();
        for missing in ["--r2-bucket", "--r2-access-key-id", "--r2-secret-access-key"] {
            assert!(err.contains(missing), "{missing} must be named: {err}");
        }

        // Credentials with no endpoint select nothing, so say so rather than ignoring them.
        let err = Cfg { bucket: Some("b"), ..Cfg::default() }.err();
        assert!(err.contains("--r2-endpoint") && err.contains("--r2-bucket"), "{err}");
    }

    /// A half-set Access pair is the shape that would otherwise `zip` to `None` and build a
    /// working but unauthenticated client.
    #[test]
    fn a_half_set_access_pair_is_named() {
        let err = Cfg { domain: DOMAIN, access_id: Some("tok"), ..Cfg::default() }.err();
        assert!(err.contains("--r2-access-client-id"), "{err}");
        assert!(err.contains("--r2-access-client-secret"), "{err}");

        let err = Cfg { domain: DOMAIN, access_secret: Some("sec"), ..Cfg::default() }.err();
        assert!(err.contains("--r2-access-client-id"), "{err}");

        // Both halves, but pointed at no custom domain.
        let err = Cfg { access_id: Some("tok"), access_secret: Some("sec"), ..s3() }.err();
        assert!(err.contains("--r2-custom-domain"), "{err}");

        let whole = Cfg {
            domain: DOMAIN,
            access_id: Some("tok"),
            access_secret: Some("sec"),
            ..Cfg::default()
        };
        assert_eq!(whole.validate().unwrap(), R2Target::CustomDomain { connections: 1 });
    }

    /// A tuning flag with no target to tune is named rather than silently ignored — it was
    /// gated by clap on the trace server and accepted-and-dropped on the validator.
    #[test]
    fn tuning_flags_need_a_target() {
        let set: &[R2TuningFlag<'_>] = &[R2TuningFlag::new("--r2-connect-timeout-ms", true)];
        let err = Cfg { tuning: set, ..Cfg::default() }.err();
        assert!(err.contains("--r2-connect-timeout-ms"), "{err}");

        // Fine with a target, and fine when left at its default.
        assert!(Cfg { domain: DOMAIN, tuning: set, ..Cfg::default() }.validate().is_ok());
        let unset: &[R2TuningFlag<'_>] = &[R2TuningFlag::new("--r2-connect-timeout-ms", false)];
        assert!(Cfg { tuning: unset, ..Cfg::default() }.validate().is_ok());
    }
}
