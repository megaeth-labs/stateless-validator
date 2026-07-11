//! Shared Cloudflare R2 (S3-compatible) witness primitives.
//!
//! Both witness producers — mega-reth's standalone witness generator (`bin/stateless/witness`) and
//! its replayer uploader (`bin/replayer/src/uploader`) — archive block witnesses to the same
//! Cloudflare R2 bucket using R2's S3-compatible API, and this repo's validator reads them back
//! (`bin/stateless-validator/src/r2_witness.rs`). The request signing, object-key layout, and
//! response handling must be byte-for-byte identical across all of them, or the validator can no
//! longer locate or authenticate against the uploaded objects. This crate is the single home for
//! those primitives so the writers and the reader cannot drift:
//!
//! - [`sigv4`] — a minimal AWS Signature Version 4 signer for buffered `PUT`/`GET`/`DELETE`
//!   requests;
//! - [`keys`] — the `block/`, `attr/`, `num/` object-key scheme and its block-range bucketing;
//! - [`endpoint`] — parsing an R2 endpoint into the origin and `SigV4` canonical host;
//! - [`client`] — a signed `PUT` helper that classifies the response into a small retry-friendly
//!   error set ([`client::R2Error`]).
//!
//! ## Object retention
//!
//! Objects are written with **no per-object expiry**, so retention must be enforced by an R2
//! **bucket lifecycle rule**. The [`keys`] layout buckets objects under the `block/`, `attr/`, and
//! `num/` prefixes (and `{range_start}_{range_end}` sub-folders) precisely so a lifecycle rule can
//! target contiguous block ranges by prefix. If no lifecycle rule is configured, the bucket grows
//! without bound.

pub mod client;
pub mod endpoint;
pub mod keys;
pub mod sigv4;
