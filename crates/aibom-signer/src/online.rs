//! Online Sigstore signer.
//!
//! Network endpoints used by keyless signing:
//! - OIDC: `oauth2.sigstore.dev`, `accounts.google.com`, or
//!   `token.actions.githubusercontent.com`
//! - Fulcio: `https://fulcio.sigstore.dev`
//! - Rekor: `https://rekor.sigstore.dev`
//! - TUF root metadata: Sigstore public-good TUF mirror.

use crate::statement::ArtifactPair;
use anyhow::{Context, Result, anyhow};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;

#[derive(Debug, Clone)]
pub struct SigstoreEndpoints {
    pub oidc_issuer: String,
    pub fulcio_url: String,
    pub rekor_url: String,
    pub tuf_url: String,
}

impl Default for SigstoreEndpoints {
    fn default() -> Self {
        Self {
            oidc_issuer: "oauth2.sigstore.dev".to_string(),
            fulcio_url: "https://fulcio.sigstore.dev".to_string(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            tuf_url: "https://tuf-repo-cdn.sigstore.dev".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OnlineSigstoreSigner {
    pub cosign_bin: PathBuf,
    pub endpoints: SigstoreEndpoints,
}

impl Default for OnlineSigstoreSigner {
    fn default() -> Self {
        Self {
            cosign_bin: PathBuf::from("cosign"),
            endpoints: SigstoreEndpoints::default(),
        }
    }
}

impl OnlineSigstoreSigner {
    /// Build a signer whose `cosign_bin` is taken from the `REEVE_COSIGN_BIN`
    /// environment variable, falling back to the bare binary name `cosign`
    /// (resolved via `PATH`). Used by the CLI and scanner so release and test
    /// environments can point at a specific cosign build without code changes.
    pub fn from_env() -> Self {
        let cosign_bin = std::env::var_os("REEVE_COSIGN_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("cosign"));
        Self {
            cosign_bin,
            endpoints: SigstoreEndpoints::default(),
        }
    }

    pub fn sign_pair_to_bundle(&self, pair: &ArtifactPair<'_>, bundle_path: &Path) -> Result<()> {
        let statement = crate::statement::build_statement(pair);
        self.sign_statement_to_bundle(&statement, pair.aibom_bytes, bundle_path)
    }

    pub fn sign_statement_to_bundle(
        &self,
        statement: &serde_json::Value,
        subject_bytes: &[u8],
        bundle_path: &Path,
    ) -> Result<()> {
        let statement_file = NamedTempFile::new()?;
        std::fs::write(statement_file.path(), serde_json::to_vec(statement)?)?;
        let subject_file = NamedTempFile::new()?;
        std::fs::write(subject_file.path(), subject_bytes)?;
        let status = Command::new(&self.cosign_bin)
            .args(cosign_attest_statement_args(
                statement_file.path(),
                bundle_path,
                subject_file.path(),
            ))
            .status()
            .with_context(|| format!("spawn {}", self.cosign_bin.display()))?;
        if !status.success() {
            return Err(anyhow!("cosign attest-blob failed with status {status}"));
        }
        Ok(())
    }
}

fn cosign_attest_statement_args(
    statement_path: &Path,
    bundle_path: &Path,
    subject_path: &Path,
) -> Vec<OsString> {
    vec![
        "attest-blob".into(),
        "--yes".into(),
        "--new-bundle-format=true".into(),
        "--statement".into(),
        statement_path.as_os_str().to_os_string(),
        "--bundle".into(),
        bundle_path.as_os_str().to_os_string(),
        subject_path.as_os_str().to_os_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosign_args_sign_the_full_statement() {
        let args = cosign_attest_statement_args(
            Path::new("statement.json"),
            Path::new("bundle.json"),
            Path::new("subject.aibom.json"),
        );
        let rendered: Vec<_> = args.iter().map(|arg| arg.to_string_lossy()).collect();

        assert!(rendered.contains(&"--statement".into()));
        assert!(rendered.contains(&"--new-bundle-format=true".into()));
        assert!(!rendered.contains(&"--predicate".into()));
        assert!(!rendered.contains(&"--type".into()));
        assert_eq!(
            rendered.last().map(|arg| arg.as_ref()),
            Some("subject.aibom.json")
        );
    }
}
