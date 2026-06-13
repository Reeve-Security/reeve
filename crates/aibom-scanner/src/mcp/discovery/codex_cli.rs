//! Codex CLI / desktop App config parser.
//!
//! Source checked against OpenAI Codex config reference:
//! https://developers.openai.com/codex/config-reference
//!
//! `~/.codex/config.toml` carries three independent inventories in one file:
//! - `[mcp_servers.*]` MCP server registrations (handled by the shared MCP
//!   config parser),
//! - `[marketplaces.*]` desktop App plugin marketplaces, and
//! - `[plugins."<name>@<marketplace>"]` installed App plugins.
//!
//! The same file also contains `[projects."/abs/path"]` tables describing every
//! project directory on disk. Those are an identity/layout leak and are never
//! emitted here.

use super::{
    CODEX_APP_GRANT_STATE_PROVIDER_NAME, ConfigFormat, ConfigSurface, DEFAULT_SKIP_DIRS,
    ParserKind, SurfaceSpec, WorkspaceSearch, parse_value,
};
use aibom_core::{DiscoverySource, ExtensionMetadata, ToolProvider, Transport, UnknownConfig};
use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

pub struct CodexCli;
pub struct CodexGlobalState;

/// Surface label for inventoried Codex desktop App plugins.
pub const CODEX_APP_PLUGIN_SURFACE: &str = "codex-app-plugin";
pub const CODEX_APP_FULL_ACCESS_PROVIDER_NAME: &str = "codex-app-full-access-state";

/// Stable marker emitted in place of any absolute filesystem path so that a
/// `/Users/<name>/...` or `C:\Users\<name>\...` provenance string never leaks.
pub const REDACTED_ABS_PATH: &str = "<redacted-abs-path>";

impl ConfigSurface for CodexCli {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "codex-cli",
            paths: &[".codex/config.toml"],
            glob_paths: &[],
            workspace_search: Some(WorkspaceSearch {
                filename: "config.toml",
                parent_dir: Some(".codex"),
                max_depth: 5,
                skip_dirs: DEFAULT_SKIP_DIRS,
            }),
            workspace_searches: &[],
            package_root_search: None,
            parser: ParserKind::CodexConfig,
            format: ConfigFormat::Toml,
            roots: &[&["mcp_servers"]],
            fixture_names: &[
                "codex_1.toml",
                "codex_2.toml",
                "codex_app_approvals_mac.toml",
                "codex_app_approvals_win.toml",
                "codex_app_plugins_mac.toml",
                "codex_app_plugins_win.toml",
            ],
        }
    }
}

impl ConfigSurface for CodexGlobalState {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "codex-app",
            paths: &[".codex/.codex-global-state.json"],
            glob_paths: &[],
            workspace_search: None,
            workspace_searches: &[],
            package_root_search: None,
            parser: ParserKind::CodexGlobalState,
            format: ConfigFormat::Json,
            roots: &[],
            fixture_names: &[
                "codex_global_state_full_access_mac.json",
                "codex_global_state_full_access_win.json",
            ],
        }
    }
}

/// Parse a Codex `config.toml` into providers: the shared MCP parser handles
/// `[mcp_servers]` and the saved-approval state provider, then App-plugin
/// inventory from `[marketplaces]` + `[plugins]` is appended.
pub fn parse_codex_config(
    spec: SurfaceSpec,
    source_path: &Path,
    value: &Value,
) -> Vec<ToolProvider> {
    let mut providers = parse_value(spec.name, source_path, value, spec.roots);
    if let Some(provider) = app_approval_provider(source_path, value) {
        providers.push(provider);
    }
    providers.extend(parse_app_plugins(source_path, value));
    providers
}

/// Read a Codex config from disk and parse it. Used by the discovery driver.
pub fn discover_codex_config(spec: SurfaceSpec, path: &Path) -> Result<Vec<ToolProvider>> {
    let value = super::read_config(path, spec.format)
        .with_context(|| format!("parse {} config {}", spec.name, path.display()))?;
    Ok(parse_codex_config(spec, path, &value))
}

pub fn discover_codex_global_state(spec: SurfaceSpec, path: &Path) -> Result<Vec<ToolProvider>> {
    let value = super::read_config(path, spec.format)
        .with_context(|| format!("parse {} global state {}", spec.name, path.display()))?;
    Ok(codex_global_state_provider(path, &value)
        .into_iter()
        .collect())
}

fn codex_global_state_provider(source_path: &Path, value: &Value) -> Option<ToolProvider> {
    if !has_codex_global_full_access_grants(value) {
        return None;
    }
    Some(ToolProvider {
        surface: "codex-app".to_string(),
        name: CODEX_APP_FULL_ACCESS_PROVIDER_NAME.to_string(),
        transport: Transport::Unknown(UnknownConfig {
            reason: "Codex App plaintext global state contains full-access grant fields; Reeve reads only narrow grant fields and never emits prompt history".to_string(),
        }),
        source_path: Some(source_path.to_path_buf()),
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    })
}

fn has_codex_global_full_access_grants(value: &Value) -> bool {
    string_field_value(value.get("agent-mode")).is_some_and(is_full_access_mode)
        || string_field_value(value.pointer("/sandboxPolicy/type")).is_some_and(is_full_access_mode)
        || string_field_value(value.get("approvalPolicy")).is_some_and(|policy| policy == "never")
        || value
            .get("skip-full-access-confirm")
            .and_then(Value::as_bool)
            == Some(true)
        || value
            .get("active-workspace-roots")
            .and_then(Value::as_array)
            .is_some_and(|roots| {
                roots
                    .iter()
                    .any(|root| root.as_str().is_some_and(crate::mcp::is_supported_fs_path))
            })
}

fn string_field_value(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn is_full_access_mode(value: &str) -> bool {
    matches!(
        value
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>()
            .as_str(),
        "fullaccess" | "dangerfullaccess" | "dangerousfullaccess" | "dangerouslyfullaccess"
    )
}

#[derive(Debug, Clone)]
struct Marketplace {
    source_type: Option<String>,
    source: Option<String>,
}

/// Build one extension-shaped provider per `[plugins."name@marketplace"]`
/// table, enriched with the referenced marketplace provenance.
fn parse_app_plugins(source_path: &Path, value: &Value) -> Vec<ToolProvider> {
    let Some(plugins) = value
        .get("plugins")
        .and_then(Value::as_object)
        .filter(|plugins| !plugins.is_empty())
    else {
        return Vec::new();
    };
    let marketplaces = parse_marketplaces(value);

    let mut providers = Vec::new();
    for (plugin_key, config) in plugins {
        let Some(config) = config.as_object() else {
            continue;
        };
        let (plugin_name, marketplace_id) = split_plugin_key(plugin_key);
        let enabled = config
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let marketplace = marketplace_id.and_then(|id| marketplaces.get(id));

        let mut qualifiers = Vec::new();
        qualifiers.push(format!("plugin_name={plugin_name}"));
        if let Some(marketplace_id) = marketplace_id {
            qualifiers.push(format!("marketplace_id={marketplace_id}"));
        }
        if let Some(source_type) = marketplace.and_then(|mk| mk.source_type.as_deref()) {
            qualifiers.push(format!("source_type={source_type}"));
        }
        if let Some(source) = marketplace.and_then(|mk| mk.source.as_deref()) {
            qualifiers.push(format!("source={}", redact_source(source)));
        }

        let metadata = ExtensionMetadata {
            id: plugin_key.clone(),
            name: Some(plugin_name.to_string()),
            version: marketplace_id.map(str::to_string),
            install_root: None,
            signature_status: None,
            enabled: Some(enabled),
        };

        providers.push(ToolProvider {
            surface: CODEX_APP_PLUGIN_SURFACE.to_string(),
            name: plugin_name.to_string(),
            transport: Transport::Unknown(UnknownConfig {
                reason: format!(
                    "Codex desktop App plugin ({}); marketplace provenance only, no MCP transport",
                    qualifiers.join("; ")
                ),
            }),
            source_path: Some(source_path.to_path_buf()),
            discovery_source: DiscoverySource::BuiltIn,
            extension: Some(metadata),
            declared_tools: Vec::new(),
        });
    }
    providers.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.surface.cmp(&right.surface))
    });
    providers
}

fn parse_marketplaces(value: &Value) -> BTreeMap<String, Marketplace> {
    let Some(marketplaces) = value.get("marketplaces").and_then(Value::as_object) else {
        return BTreeMap::new();
    };
    marketplaces
        .iter()
        .filter_map(|(id, config)| {
            let object = config.as_object()?;
            Some((
                id.clone(),
                Marketplace {
                    source_type: string_field(object, "source_type"),
                    source: string_field(object, "source"),
                },
            ))
        })
        .collect()
}

fn app_approval_provider(source_path: &Path, value: &Value) -> Option<ToolProvider> {
    if !has_app_approval_modes(value) {
        return None;
    }
    Some(ToolProvider {
        surface: "codex-app".to_string(),
        name: CODEX_APP_GRANT_STATE_PROVIDER_NAME.to_string(),
        transport: Transport::Unknown(UnknownConfig {
            reason: "Codex desktop App saved tool approvals from plaintext config; Reeve emits grants only, with redacted references".to_string(),
        }),
        source_path: Some(source_path.to_path_buf()),
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    })
}

fn has_app_approval_modes(value: &Value) -> bool {
    value.pointer("/apps").is_some_and(contains_approval_mode)
}

fn contains_approval_mode(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (key == "approval_mode" && value.as_str() == Some("approve"))
                || contains_approval_mode(value)
        }),
        Value::Array(values) => values.iter().any(contains_approval_mode),
        _ => false,
    }
}

/// Split a `"name@marketplace"` plugin table key into its components. A key
/// without an `@` is treated as a bare plugin name with no marketplace.
fn split_plugin_key(key: &str) -> (&str, Option<&str>) {
    match key.rsplit_once('@') {
        Some((name, marketplace)) if !name.is_empty() && !marketplace.is_empty() => {
            (name, Some(marketplace))
        }
        _ => (key, None),
    }
}

/// Redact a marketplace `source` value. Absolute filesystem paths (POSIX or
/// Windows) are replaced with [`REDACTED_ABS_PATH`]; `http(s)` URLs and other
/// non-path identifiers are emitted as-is.
fn redact_source(source: &str) -> String {
    if is_url(source) {
        return source.to_string();
    }
    if is_absolute_path(source) {
        return REDACTED_ABS_PATH.to_string();
    }
    source.to_string()
}

fn is_url(source: &str) -> bool {
    let lowered = source.to_ascii_lowercase();
    lowered.starts_with("http://") || lowered.starts_with("https://")
}

fn is_absolute_path(source: &str) -> bool {
    // POSIX absolute path.
    if source.starts_with('/') {
        return true;
    }
    // Windows drive-letter path, e.g. `C:\...` or `C:/...`.
    let mut chars = source.chars();
    if let (Some(drive), Some(colon)) = (chars.next(), chars.next())
        && drive.is_ascii_alphabetic()
        && colon == ':'
    {
        return matches!(chars.next(), Some('\\') | Some('/'));
    }
    // Windows UNC path.
    source.starts_with("\\\\")
}

fn string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_string)
}

/// True for providers emitted from the Codex App-plugin inventory.
pub fn is_app_plugin_provider(provider: &ToolProvider) -> bool {
    provider.surface == CODEX_APP_PLUGIN_SURFACE
}
