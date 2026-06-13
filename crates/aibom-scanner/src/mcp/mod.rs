pub mod capabilities;
pub mod client;
pub mod discovery;
pub mod extension_deps;
pub mod fingerprint;
pub mod output;
pub mod profile;

use aibom_core::{
    BehaviorProfile, Capabilities, ProfileOptions, ProtocolAdapter, ProviderIdentity, Target,
    ToolProvider,
};
use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;

pub use output::{
    ProviderGroup, ScanArtifacts, ScanOptions, group_registrations, scan_target,
    scan_target_with_options,
};

pub(crate) fn insert_supported_fs_path_qualifier(
    qualifiers: &mut serde_json::Map<String, serde_json::Value>,
    path: &str,
) {
    if is_supported_fs_path(path) {
        qualifiers.insert(
            "path".to_string(),
            serde_json::Value::String(redact_home_identity(path)),
        );
    }
}

const HOME_MARKER: &str = "<redacted-home>";

/// Replaces the path segment that follows a home-root component (`Users` or
/// `home`) with `<redacted-home>` so serialized AIBOM/CDX output never carries
/// an OS username. The absolute path shape is retained per ADR-0008; matching
/// is component-based so prefixed home roots (for example WSL `/mnt/c/Users/x`
/// or a relocated `/var/home/x`) are redacted too. Cursor's
/// `.cursor/projects/<encoded>` and Claude Code's `.claude/projects/<encoded>`
/// directories flatten an absolute path into one dash-joined segment
/// (`Users-alice-projects-demo`, Windows `C--Users-alice-AppData-Roaming`);
/// the segment right after those parents is rewritten by
/// [`redact_encoded_project_segment`]. See ADR-0045 (#468 extends to
/// `.claude/projects` and drive-letter prefixes).
pub(crate) fn redact_home_identity(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut redact_next_segment = false;
    let mut prev_segment: Option<String> = None;
    let mut prev_prev_segment: Option<String> = None;
    for piece in path.split_inclusive(['/', '\\']) {
        let separator_len = usize::from(piece.ends_with(['/', '\\']));
        let (name, separator) = piece.split_at(piece.len() - separator_len);
        if name.is_empty() {
            out.push_str(piece);
            continue;
        }
        if redact_next_segment {
            out.push_str(HOME_MARKER);
            out.push_str(separator);
            redact_next_segment = false;
            prev_prev_segment = prev_segment.take();
            prev_segment = Some(HOME_MARKER.to_string());
            continue;
        }
        let in_encoded_projects = matches!(
            prev_prev_segment.as_deref(),
            Some(".cursor") | Some(".claude")
        ) && prev_segment.as_deref() == Some("projects");
        if in_encoded_projects {
            let rewritten = redact_encoded_project_segment(name);
            out.push_str(&rewritten);
            out.push_str(separator);
            prev_prev_segment = prev_segment.take();
            prev_segment = Some(rewritten);
            continue;
        }
        redact_next_segment = is_home_root_segment(name);
        out.push_str(piece);
        prev_prev_segment = prev_segment.take();
        prev_segment = Some(name.to_string());
    }
    out
}

/// Rewrites a dash-encoded project directory name so the username token after
/// the home-root token is redacted: `Users-alice-projects-demo` →
/// `Users-<redacted-home>-projects-demo`; Windows drive-prefixed
/// `C--Users-alice-AppData-Roaming` → `C--Users-<redacted-home>-AppData-Roaming`.
/// Applied only to the segment directly under `.cursor/projects` or
/// `.claude/projects`; idempotent on already-redacted names (#468).
fn redact_encoded_project_segment(segment: &str) -> String {
    // Optional encoding prefixes: POSIX root `-Users-alice-...` (leading dash)
    // or Windows drive `C--Users-alice-...`.
    let (prefix, body) = if let Some((drive, rest)) = segment.split_once("--") {
        if drive.len() == 1 && drive.chars().all(|c| c.is_ascii_alphabetic()) {
            (format!("{drive}--"), rest)
        } else {
            (String::new(), segment)
        }
    } else if let Some(rest) = segment.strip_prefix('-') {
        ("-".to_string(), rest)
    } else {
        (String::new(), segment)
    };
    let Some((root, rest)) = body.split_once('-') else {
        return segment.to_string();
    };
    if !is_home_root_segment(root) {
        return segment.to_string();
    }
    if rest.starts_with(HOME_MARKER) {
        return segment.to_string();
    }
    let redacted_body = match rest.split_once('-') {
        Some((_username, tail)) => format!("{root}-{HOME_MARKER}-{tail}"),
        None => format!("{root}-{HOME_MARKER}"),
    };
    format!("{prefix}{redacted_body}")
}

fn is_home_root_segment(segment: &str) -> bool {
    segment.eq_ignore_ascii_case("users") || segment == "home"
}

pub(crate) fn is_supported_fs_path(path: &str) -> bool {
    is_posix_path(path) || is_windows_path(path)
}

pub(crate) fn is_windows_path(path: &str) -> bool {
    is_windows_drive_path(path) || is_windows_unc_path(path)
}

fn is_posix_path(path: &str) -> bool {
    path.starts_with('/')
}

fn is_windows_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn is_windows_unc_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(r"\\").or_else(|| path.strip_prefix("//")) else {
        return false;
    };
    let mut parts = rest.split(['\\', '/']).filter(|part| !part.is_empty());
    parts.next().is_some() && parts.next().is_some()
}

#[derive(Debug, Clone, Default)]
pub struct McpAdapter;

impl McpAdapter {
    pub fn new() -> Self {
        Self
    }

    pub async fn introspect_with_options(
        &self,
        provider: &ToolProvider,
        opts: capabilities::IntrospectionOptions,
    ) -> Result<Capabilities> {
        capabilities::introspect_with_options(provider, opts).await
    }
}

#[async_trait]
impl ProtocolAdapter for McpAdapter {
    fn name(&self) -> &'static str {
        "mcp"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    async fn discover(&self, target: &Target) -> Result<Vec<ToolProvider>> {
        discovery::discover_all(&target.root)
    }

    async fn fingerprint(&self, provider: &ToolProvider) -> Result<ProviderIdentity> {
        fingerprint::fingerprint(provider)
    }

    async fn introspect(&self, provider: &ToolProvider) -> Result<Capabilities> {
        capabilities::introspect(provider).await
    }

    async fn profile(
        &self,
        provider: &ToolProvider,
        opts: &ProfileOptions,
    ) -> Result<BehaviorProfile> {
        profile::profile(provider, opts).await
    }
}

pub async fn scan_root(
    root: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> Result<ScanArtifacts> {
    let target = Target::filesystem(root.as_ref().to_path_buf());
    output::scan_target(&target, output_dir.as_ref()).await
}
