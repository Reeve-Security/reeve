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

/// Resolve the `cosign` binary to a single, fixed absolute path, hardened
/// against PATH-hijack.
///
/// cosign is the trust root: it signs scan output and verifies signed surface
/// configs. Resolving it from a bare name on PATH lets a local attacker who
/// can place a malicious `cosign` earlier on PATH (or in a writable PATH dir)
/// intercept every signing and verification. This resolver removes that risk.
///
/// Behaviour:
/// - `explicit` is `Some(v)` (the `REEVE_COSIGN_BIN` value): the value must be
///   an absolute path to an existing regular file, else an error is returned.
/// - `explicit` is `None`: `cosign` is resolved from `PATH` exactly once to the
///   first existing regular file named `cosign`, returning its absolute path.
///   If none is found an error is returned.
/// - Unix only: if the directory holding the chosen binary is world-writable
///   without the sticky bit, resolution is refused. This check is skipped on
///   non-unix platforms.
pub fn resolve_cosign_binary(explicit: Option<OsString>) -> Result<PathBuf> {
    match explicit {
        Some(value) => {
            let candidate = PathBuf::from(&value);
            if !candidate.is_absolute() {
                return Err(anyhow!(
                    "REEVE_COSIGN_BIN must be an absolute path (got '{}')",
                    candidate.display()
                ));
            }
            if !candidate.is_file() {
                return Err(anyhow!(
                    "REEVE_COSIGN_BIN '{}' does not exist or is not a regular file",
                    candidate.display()
                ));
            }
            refuse_world_writable_parent(&candidate)?;
            Ok(candidate)
        }
        None => {
            let path = std::env::var_os("PATH").ok_or_else(|| {
                anyhow!("cosign not found on PATH; set REEVE_COSIGN_BIN to an absolute path")
            })?;
            for dir in std::env::split_paths(&path) {
                if dir.as_os_str().is_empty() {
                    continue;
                }
                let candidate = dir.join("cosign");
                if !candidate.is_file() {
                    continue;
                }
                let absolute = if candidate.is_absolute() {
                    candidate
                } else {
                    match candidate.canonicalize() {
                        Ok(resolved) => resolved,
                        Err(_) => continue,
                    }
                };
                refuse_world_writable_parent(&absolute)?;
                return Ok(absolute);
            }
            Err(anyhow!(
                "cosign not found on PATH; set REEVE_COSIGN_BIN to an absolute path"
            ))
        }
    }
}

/// Refuse to resolve a cosign binary whose containing directory is
/// world-writable without the sticky bit, since any local user could swap the
/// binary out from under us. Unix only; a no-op elsewhere.
#[cfg(unix)]
fn refuse_world_writable_parent(binary: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(parent) = binary.parent() else {
        return Ok(());
    };
    let metadata = std::fs::metadata(parent).with_context(|| {
        format!(
            "inspect permissions of cosign directory {}",
            parent.display()
        )
    })?;
    let mode = metadata.permissions().mode();
    let world_writable = mode & 0o002 != 0;
    let sticky = mode & 0o1000 != 0;
    if world_writable && !sticky {
        return Err(anyhow!(
            "refusing to resolve cosign from world-writable directory {}; \
             move cosign to a non-world-writable location or set REEVE_COSIGN_BIN",
            parent.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_world_writable_parent(_binary: &Path) -> Result<()> {
    Ok(())
}

#[derive(Debug, Clone)]
pub struct OnlineSigstoreSigner {
    pub cosign_bin: PathBuf,
    pub endpoints: SigstoreEndpoints,
}

impl OnlineSigstoreSigner {
    /// Build a signer whose `cosign_bin` is resolved from the `REEVE_COSIGN_BIN`
    /// environment variable (which must be an absolute path) or, when unset,
    /// pinned to a single absolute path discovered on `PATH`. Resolution is
    /// hardened against PATH-hijack: see `resolve_cosign_binary`. Used by the
    /// CLI and scanner so release and test environments can point at a specific
    /// cosign build without code changes.
    pub fn from_env() -> Result<Self> {
        let cosign_bin = resolve_cosign_binary(std::env::var_os("REEVE_COSIGN_BIN"))?;
        Ok(Self {
            cosign_bin,
            endpoints: SigstoreEndpoints::default(),
        })
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

    #[test]
    fn explicit_relative_path_is_rejected() {
        for relative in ["cosign", "./cosign", "bin/cosign"] {
            let err = resolve_cosign_binary(Some(OsString::from(relative)))
                .expect_err("relative REEVE_COSIGN_BIN must be rejected");
            let message = err.to_string();
            assert!(
                message.contains("must be an absolute path"),
                "unexpected error for '{relative}': {message}"
            );
        }
    }

    #[test]
    fn explicit_bare_name_is_rejected() {
        let err = resolve_cosign_binary(Some(OsString::from("cosign")))
            .expect_err("bare REEVE_COSIGN_BIN must be rejected");
        assert!(err.to_string().contains("must be an absolute path"));
    }

    #[test]
    fn explicit_absolute_missing_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("cosign");
        let err = resolve_cosign_binary(Some(missing.into_os_string()))
            .expect_err("missing absolute REEVE_COSIGN_BIN must be rejected");
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn explicit_absolute_existing_file_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let cosign = dir.path().join("cosign");
        write_fake_cosign(&cosign);
        let resolved =
            resolve_cosign_binary(Some(cosign.clone().into_os_string())).expect("resolves");
        assert_eq!(resolved, cosign);
    }

    #[test]
    fn unset_resolves_first_cosign_on_path() {
        let dir = tempfile::tempdir().unwrap();
        let cosign = dir.path().join("cosign");
        write_fake_cosign(&cosign);

        let resolved =
            with_path(dir.path(), || resolve_cosign_binary(None)).expect("cosign on PATH resolves");
        // The resolved path must be absolute and point at our fake binary.
        assert!(resolved.is_absolute(), "resolved path must be absolute");
        assert_eq!(resolved.file_name().unwrap(), "cosign");
        assert!(resolved.is_file());
    }

    #[test]
    fn unset_with_no_cosign_on_path_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = with_path(dir.path(), || resolve_cosign_binary(None))
            .expect_err("missing cosign on PATH must error");
        assert!(err.to_string().contains("cosign not found on PATH"));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_world_writable_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cosign = dir.path().join("cosign");
        write_fake_cosign(&cosign);
        // World-writable, no sticky bit.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = resolve_cosign_binary(Some(cosign.into_os_string()))
            .expect_err("world-writable cosign directory must be refused");
        assert!(
            err.to_string().contains("world-writable"),
            "unexpected error: {err}"
        );
    }

    fn write_fake_cosign(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// Run `body` with `PATH` set to exactly `dir`, restoring the prior value
    /// afterwards. Serialized via a mutex because process env is global.
    fn with_path<T>(dir: &Path, body: impl FnOnce() -> T) -> T {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var_os("PATH");
        // SAFETY: env mutation is serialized by LOCK and restored below.
        unsafe {
            std::env::set_var("PATH", dir.as_os_str());
        }
        let result = body();
        unsafe {
            match previous {
                Some(value) => std::env::set_var("PATH", value),
                None => std::env::remove_var("PATH"),
            }
        }
        result
    }
}
