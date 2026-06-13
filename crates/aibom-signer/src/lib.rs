//! Sigstore signing boundary for Reeve AIBOM bundles.
//!
//! Source-checked references:
//! - Sigstore bundle format v0.3 media type:
//!   https://github.com/sigstore/protobuf-specs
//! - Sigstore public-good services:
//!   https://docs.sigstore.dev
//! - sigstore-rs status and support matrix:
//!   https://github.com/sigstore/sigstore-rs
//! - Rekor transparency log:
//!   https://docs.sigstore.dev/logging/overview/
//! - Sigstore TUF trust root:
//!   https://docs.sigstore.dev/system_config/installation/

pub mod bundle;
pub mod online;
pub mod statement;
pub mod verify;

pub use bundle::{
    SigstoreBundle, fixture_bundle, fixture_bundle_for_statement,
    fixture_sensitive_data_report_bundle, write_fixture_bundle, write_fixture_bundle_for_statement,
};
pub use online::{OnlineSigstoreSigner, SigstoreEndpoints};
pub use statement::{
    ArtifactPair, SensitiveDataReportArtifact, build_sensitive_data_report_statement,
    build_statement,
};
pub use verify::{Allowlist, CryptoFailure, verify_crypto};
