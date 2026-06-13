//! Claude Cowork / Store MCPB extension inventory parser.
//!
//! This reads local MCPB install state and reports opaque Cowork app state
//! stores by presence only. It never decrypts approval blobs or parses
//! IndexedDB/LevelDB values.

use super::{ConfigFormat, ConfigSurface, PackageRootSearch, ParserKind, SurfaceSpec};
use aibom_core::{
    DiscoverySource, ExtensionMetadata, HttpConfig, StdioConfig, ToolProvider, Transport,
    UnknownConfig, WsConfig,
};
use anyhow::Result;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

pub struct ClaudeCowork;

pub const APPROVAL_CACHE_PROVIDER_NAME: &str = "Claude Cowork approval cache";
pub const COWORK_GRANT_STATE_PROVIDER_NAME: &str = "Claude Cowork session approval state";
pub const CLAUDE_CODE_DESKTOP_GRANT_STATE_PROVIDER_NAME: &str =
    "Claude Code desktop session approval state";
pub const COWORK_SESSION_METADATA_PROVIDER_NAME: &str = "Claude Cowork session metadata state";
pub const CLAUDE_CODE_DESKTOP_SESSION_METADATA_PROVIDER_NAME: &str =
    "Claude Code desktop session metadata state";
pub const INDEXEDDB_CONNECTOR_STORE_PROVIDER_NAME: &str = "Claude Cowork IndexedDB connector store";
pub const LOCAL_STORAGE_CONNECTOR_STORE_PROVIDER_NAME: &str =
    "Claude Cowork localStorage connector store";
pub const APPROVAL_CACHE_CAPABILITY_ID: &str = "mcp:cowork:approval-cache:encrypted";
pub const REMOTE_CONNECTOR_STORE_CAPABILITY_ID: &str =
    "mcp:cowork:remote-connector-store:candidate";
pub const REMOTE_CONNECTOR_CAPABILITY_ID: &str = "mcp:cowork:remote-connector:registered";
pub const COWORK_SCHEDULED_TASK_CAPABILITY_ID: &str = "mcp:cowork-session:scheduled-task";
pub const CLAUDE_CODE_DESKTOP_SCHEDULED_TASK_CAPABILITY_ID: &str =
    "mcp:claude-code-desktop-session:scheduled-task";

const ALLOWLIST_CACHE_KEY: &str = "dxt:allowlistCache";

impl ConfigSurface for ClaudeCowork {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "claude-cowork",
            paths: &[
                "Library/Application Support/Claude/extensions-installations.json",
                "Library/Application Support/Claude/config.json",
                "AppData/Roaming/Claude/extensions-installations.json",
                "AppData/Roaming/Claude/config.json",
            ],
            glob_paths: &[
                "Library/Application Support/Claude/local-agent-mode-sessions/*/*/local_*.json",
                "AppData/Roaming/Claude/local-agent-mode-sessions/*/*/local_*.json",
            ],
            workspace_search: None,
            workspace_searches: &[],
            package_root_search: Some(PackageRootSearch {
                base: "AppData/Local/Packages",
                package_glob: "Claude_*",
                primary_paths: &[
                    "LocalCache/Roaming/Claude/extensions-installations.json",
                    "LocalCache/Roaming/Claude/config.json",
                ],
                primary_glob_paths: &[
                    "LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/local_*.json",
                    "LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_plugins/installed_plugins.json",
                    "LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_settings.json",
                    "LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/rpm/plugin_*/.mcp.json",
                ],
                auxiliary_glob_paths: &[
                    "LocalCache/Roaming/Claude/Claude Extensions/*/manifest.json",
                    "LocalCache/Roaming/Claude/Claude Extensions Settings/*.json",
                    "LocalCache/Roaming/Claude/IndexedDB/**/*",
                    "LocalCache/Roaming/Claude/Local Storage/leveldb/*",
                    "LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_plugins/**/*.mcp.json",
                    "LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/rpm/plugin_*/.claude-plugin/plugin.json",
                ],
            }),
            parser: ParserKind::ClaudeCoworkMcpbExtensions,
            format: ConfigFormat::Json,
            roots: &[],
            fixture_names: &[
                "claude_cowork_extensions_1.json",
                "claude_cowork_extensions_2.json",
                "claude_cowork_config_state_1.json",
                "claude_cowork_installed_plugins_1.json",
                "local_cowork_session_approvals_mac.json",
                "local_cowork_session_approvals_win.json",
                "local_cowork_session_remote_only.json",
            ],
        }
    }
}

pub fn parse_cowork_file(source_path: &Path) -> Result<Vec<ToolProvider>> {
    parse_cowork_file_for_surface("claude-cowork", source_path)
}

pub fn parse_claude_code_desktop_file(source_path: &Path) -> Result<Vec<ToolProvider>> {
    parse_cowork_file_for_surface("claude-code-desktop", source_path)
}

fn parse_cowork_file_for_surface(surface: &str, source_path: &Path) -> Result<Vec<ToolProvider>> {
    match source_path.file_name().and_then(|name| name.to_str()) {
        Some("extensions-installations.json") => parse_extensions_installations(source_path),
        Some("config.json") => parse_config_state(source_path),
        Some("installed_plugins.json") => parse_installed_plugins(source_path),
        Some(name) if is_local_session_descriptor(name) => {
            parse_local_session_descriptor_for_surface(surface, source_path)
        }
        _ if connector_manifest_path(source_path) => parse_connector_manifest(source_path),
        _ => Ok(Vec::new()),
    }
}

fn is_local_session_descriptor(name: &str) -> bool {
    name.starts_with("local_") && name.ends_with(".json")
}

pub fn parse_extensions_installations(source_path: &Path) -> Result<Vec<ToolProvider>> {
    let raw = fs::read_to_string(source_path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let app_root = source_path.parent().unwrap_or_else(|| Path::new(""));
    let manifests = extension_manifests(app_root);
    let settings = extension_settings(app_root);

    let mut candidates = Vec::new();
    collect_candidates(&value, None, &mut candidates);

    let mut seen = BTreeSet::new();
    let mut providers = Vec::new();
    for candidate in candidates {
        let Some(candidate_id) = extension_id(candidate.object, candidate.key.as_deref()) else {
            continue;
        };
        let id = resolve_extension_id(candidate_id, candidate.object, &manifests);
        if !seen.insert(id.clone()) {
            continue;
        }
        let manifest_record = manifests.get(&id);
        let manifest = manifest_record.and_then(|record| record.value.as_object());
        let manifest_root = manifest_record.map(|record| record.install_root.as_path());
        let install_root = install_root(app_root, &id, candidate.object, manifest_root);
        let transport = extension_transport(candidate.object, manifest, install_root.as_deref());
        let declared_tools = declared_tools(candidate.object, manifest);
        let metadata = ExtensionMetadata {
            id: id.clone(),
            name: first_string(candidate.object, &["displayName", "name", "title"]).or_else(|| {
                manifest
                    .and_then(|manifest| first_string(manifest, &["displayName", "name", "title"]))
            }),
            version: first_string(candidate.object, &["version", "packageVersion"]).or_else(|| {
                manifest.and_then(|manifest| first_string(manifest, &["version", "packageVersion"]))
            }),
            install_root,
            signature_status: signature_status(candidate.object)
                .or_else(|| manifest.and_then(signature_status)),
            enabled: settings.get(&id).copied(),
        };
        let name = metadata.name.clone().unwrap_or_else(|| id.clone());
        providers.push(ToolProvider {
            surface: "claude-cowork".to_string(),
            name,
            transport,
            source_path: Some(source_path.to_path_buf()),
            discovery_source: DiscoverySource::BuiltIn,
            extension: Some(metadata),
            declared_tools,
        });
    }
    Ok(providers)
}

pub fn parse_config_state(source_path: &Path) -> Result<Vec<ToolProvider>> {
    let raw = fs::read_to_string(source_path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let app_root = source_path.parent().unwrap_or_else(|| Path::new(""));
    let mut providers = Vec::new();

    if allowlist_cache_value(&value).is_some() {
        providers.push(state_provider(
            "claude-cowork",
            APPROVAL_CACHE_PROVIDER_NAME,
            source_path.to_path_buf(),
            "Claude Cowork approval cache is encrypted Electron safeStorage/DPAPI state; Reeve records presence only",
        ));
    }

    for store in remote_connector_state_stores(app_root) {
        providers.push(state_provider(
            "claude-cowork",
            store.provider_name,
            store.path,
            "Claude Cowork remote connector state is an opaque Electron LevelDB/IndexedDB store; Reeve records presence only",
        ));
    }

    Ok(providers)
}

pub fn parse_installed_plugins(source_path: &Path) -> Result<Vec<ToolProvider>> {
    let raw = fs::read_to_string(source_path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let plugins_root = source_path.parent().unwrap_or_else(|| Path::new(""));
    let session_root = plugins_root.parent().unwrap_or_else(|| Path::new(""));
    let settings = cowork_settings(session_root);

    let mut candidates = Vec::new();
    collect_installed_plugin_candidates(&value, None, &mut candidates);
    let manifest_paths = connector_manifest_paths(plugins_root);
    let restrict_to_installed = !candidates.is_empty();

    let mut providers = Vec::new();
    let mut seen = BTreeSet::new();
    for manifest_path in manifest_paths {
        let raw = match fs::read_to_string(&manifest_path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let value: Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let manifest_candidates = matching_plugin_candidates(&manifest_path, &value, &candidates);
        if restrict_to_installed && manifest_candidates.is_empty() {
            continue;
        }
        let candidate = manifest_candidates.first();
        for provider in
            connector_providers_from_manifest(&manifest_path, &value, candidate.copied(), &settings)
        {
            let key = format!(
                "{}\u{1f}{}\u{1f}{:?}",
                provider
                    .source_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                provider.name,
                provider.transport
            );
            if seen.insert(key) {
                providers.push(provider);
            }
        }
    }

    Ok(providers)
}

pub fn parse_connector_manifest(source_path: &Path) -> Result<Vec<ToolProvider>> {
    let raw = fs::read_to_string(source_path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let settings = session_root_from_connector_path(source_path)
        .as_deref()
        .map(cowork_settings)
        .unwrap_or_default();
    Ok(connector_providers_from_manifest(
        source_path,
        &value,
        None,
        &settings,
    ))
}

pub fn parse_local_session_descriptor(source_path: &Path) -> Result<Vec<ToolProvider>> {
    parse_local_session_descriptor_for_surface("claude-cowork", source_path)
}

fn parse_local_session_descriptor_for_surface(
    surface: &str,
    source_path: &Path,
) -> Result<Vec<ToolProvider>> {
    let raw = fs::read_to_string(source_path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let mut providers = remote_mcp_session_providers(surface, &value, source_path);
    if has_plaintext_session_grants(&value) {
        providers.push(state_provider(
            surface,
            grant_state_provider_name(surface),
            source_path.to_path_buf(),
            session_grant_state_reason(surface),
        ));
    }
    if has_session_metadata(&value) {
        providers.push(state_provider(
            surface,
            session_metadata_provider_name(surface),
            source_path.to_path_buf(),
            session_metadata_state_reason(surface),
        ));
    }
    Ok(providers)
}

pub fn parse_remote_mcp_session_descriptor(source_path: &Path) -> Result<Vec<ToolProvider>> {
    let raw = fs::read_to_string(source_path)?;
    let value: Value = serde_json::from_str(&raw)?;
    Ok(remote_mcp_session_providers(
        "claude-cowork",
        &value,
        source_path,
    ))
}

fn remote_mcp_session_providers(
    surface: &str,
    value: &Value,
    source_path: &Path,
) -> Vec<ToolProvider> {
    let Some(remote_servers) = value
        .get("remoteMcpServersConfig")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    let mut providers = BTreeMap::<String, (String, BTreeSet<String>)>::new();
    for remote_server in remote_servers {
        let Some(object) = remote_server.as_object() else {
            continue;
        };
        let Some(identity) = first_string(object, &["uuid", "id", "serverId"]) else {
            if first_string(object, &["name", "displayName", "serverName", "title"]).is_none() {
                continue;
            }
            let name = remote_session_display_name(object);
            let mut declared = BTreeSet::new();
            collect_tools(object.get("tools"), &mut declared);
            providers.insert(name.clone(), (name, declared));
            continue;
        };

        let display_name = remote_session_display_name(object);
        let entry = providers
            .entry(identity.clone())
            .or_insert_with(|| (display_name.clone(), BTreeSet::new()));
        if entry.0 == identity && display_name != identity {
            entry.0 = display_name;
        }
        collect_tools(object.get("tools"), &mut entry.1);
    }

    providers
        .into_values()
        .map(|(name, declared_tools)| ToolProvider {
            surface: surface.to_string(),
            name,
            transport: Transport::Unknown(UnknownConfig {
                reason: "Claude Cowork session descriptors expose remote MCP names and tools only; transport details are not persisted".to_string(),
            }),
            source_path: Some(source_path.to_path_buf()),
            discovery_source: DiscoverySource::BuiltIn,
            extension: None,
            declared_tools: declared_tools.into_iter().collect(),
        })
        .collect()
}

fn remote_session_display_name(object: &Map<String, Value>) -> String {
    first_string(object, &["name", "displayName", "serverName", "title"])
        .or_else(|| first_string(object, &["uuid", "id", "serverId"]))
        .unwrap_or_else(|| "claude-cowork-remote-mcp".to_string())
}

pub fn is_state_provider(provider: &ToolProvider) -> bool {
    provider.surface == "claude-cowork"
        && matches!(
            provider.name.as_str(),
            APPROVAL_CACHE_PROVIDER_NAME
                | INDEXEDDB_CONNECTOR_STORE_PROVIDER_NAME
                | LOCAL_STORAGE_CONNECTOR_STORE_PROVIDER_NAME
        )
}

pub fn has_plaintext_session_grants(value: &Value) -> bool {
    enabled_mcp_tools_have_grants(value)
        || always_allowed_reasons_have_grants(value)
        || session_permission_updates_have_grants(value)
        || user_selected_folders_have_grants(value)
        || egress_allowed_domains_have_grants(value)
        || org_cli_exec_policies_have_grants(value)
        || permission_mode_has_global_exec_grant(value)
}

fn enabled_mcp_tools_have_grants(value: &Value) -> bool {
    value
        .get("enabledMcpTools")
        .is_some_and(enabled_tool_value_has_grants)
}

fn enabled_tool_value_has_grants(value: &Value) -> bool {
    match value {
        Value::Bool(true) => true,
        Value::Array(values) => values.iter().any(|value| match value {
            Value::String(tool) => !tool.trim().is_empty(),
            other => enabled_tool_value_has_grants(other),
        }),
        Value::Object(object) => object.iter().any(|(_, value)| {
            explicit_approval_marker(value)
                || matches!(value, Value::Array(_) | Value::Object(_))
                    && enabled_tool_value_has_grants(value)
        }),
        _ => explicit_approval_marker(value),
    }
}

fn user_selected_folders_have_grants(value: &Value) -> bool {
    value
        .get("userSelectedFolders")
        .and_then(Value::as_array)
        .is_some_and(|folders| {
            folders.iter().any(|folder| {
                folder
                    .as_str()
                    .is_some_and(|path| crate::mcp::is_supported_fs_path(path.trim()))
            })
        })
}

fn egress_allowed_domains_have_grants(value: &Value) -> bool {
    string_scope_value_has_entries(value.get("egressAllowedDomains"))
}

fn org_cli_exec_policies_have_grants(value: &Value) -> bool {
    exec_policy_value_has_entries(value.get("orgCliExecPolicies"))
}

fn always_allowed_reasons_have_grants(value: &Value) -> bool {
    value
        .get("alwaysAllowedReasons")
        .is_some_and(enabled_tool_value_has_grants)
}

fn session_permission_updates_have_grants(value: &Value) -> bool {
    value
        .get("sessionPermissionUpdates")
        .is_some_and(enabled_tool_value_has_grants)
}

pub fn has_session_metadata(value: &Value) -> bool {
    value
        .get("scheduledTaskId")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.trim().is_empty())
        || value
            .get("sessionType")
            .and_then(Value::as_str)
            .is_some_and(|session_type| !session_type.trim().is_empty())
}

fn string_scope_value_has_entries(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(scope)) => !scope.trim().is_empty(),
        Some(Value::Array(values)) => values
            .iter()
            .any(|value| string_scope_value_has_entries(Some(value))),
        Some(Value::Object(object)) => {
            object
                .get("host")
                .or_else(|| object.get("domain"))
                .or_else(|| object.get("url"))
                .and_then(Value::as_str)
                .is_some_and(|scope| !scope.trim().is_empty())
                || object
                    .iter()
                    .any(|(key, value)| !key.trim().is_empty() && explicit_approval_marker(value))
        }
        _ => false,
    }
}

fn exec_policy_value_has_entries(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(command)) => !command.trim().is_empty(),
        Some(Value::Array(values)) => values
            .iter()
            .any(|value| exec_policy_value_has_entries(Some(value))),
        Some(Value::Object(object)) => {
            !explicitly_denied_object(object)
                && (object
                    .get("command")
                    .or_else(|| object.get("cmd"))
                    .and_then(Value::as_str)
                    .is_some_and(|command| !command.trim().is_empty())
                    || object.iter().any(|(key, value)| {
                        !key.trim().is_empty() && explicit_approval_marker(value)
                    }))
        }
        _ => false,
    }
}

fn explicitly_denied_object(object: &Map<String, Value>) -> bool {
    [
        "enabled",
        "approved",
        "allowed",
        "alwaysAllow",
        "approvalMode",
        "permissionMode",
        "state",
        "value",
    ]
    .iter()
    .any(|key| object.get(*key).is_some_and(explicit_denial_marker))
}

fn explicit_denial_marker(value: &Value) -> bool {
    match value {
        Value::Bool(false) => true,
        Value::Number(number) => number.as_i64() == Some(0),
        Value::String(value) => matches!(
            normalize_mode(value).as_str(),
            "false" | "deny" | "denied" | "disabled" | "off" | "never" | "none" | "default"
        ),
        Value::Object(object) => [
            "enabled",
            "approved",
            "allowed",
            "alwaysAllow",
            "approvalMode",
            "permissionMode",
            "state",
            "value",
        ]
        .iter()
        .any(|key| object.get(*key).is_some_and(explicit_denial_marker)),
        _ => false,
    }
}
fn permission_mode_has_global_exec_grant(value: &Value) -> bool {
    let Some(mode) = value.get("permissionMode").and_then(Value::as_str) else {
        return false;
    };
    matches!(
        normalize_mode(mode).as_str(),
        "bypasspermissions"
            | "dangerouslyskippermissions"
            | "skipprompts"
            | "noprompts"
            | "unrestricted"
            | "alwaysallow"
    )
}

fn explicit_approval_marker(value: &Value) -> bool {
    match value {
        Value::Bool(true) => true,
        Value::Number(number) => number.as_i64().is_some_and(|value| value != 0),
        Value::String(value) => matches!(
            normalize_mode(value).as_str(),
            "true"
                | "allow"
                | "allowed"
                | "approve"
                | "approved"
                | "always"
                | "alwaysallow"
                | "enabled"
                | "on"
        ),
        Value::Object(object) => [
            "enabled",
            "approved",
            "allowed",
            "alwaysAllow",
            "approvalMode",
            "permissionMode",
            "state",
            "value",
        ]
        .iter()
        .any(|key| object.get(*key).is_some_and(explicit_approval_marker)),
        _ => false,
    }
}

fn normalize_mode(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn is_connector_provider(provider: &ToolProvider) -> bool {
    provider.surface == "claude-cowork"
        && provider.extension.is_none()
        && provider
            .source_path
            .as_ref()
            .is_some_and(|path| connector_manifest_path(path))
}

#[derive(Debug, Clone)]
pub struct CoworkConnectorMetadata {
    pub plugin_id: String,
    pub name: String,
    pub transport: String,
    pub url: Option<String>,
    pub connected: Option<bool>,
    pub store: String,
    pub enabled: Option<bool>,
    pub source_path: PathBuf,
    pub settings_path: Option<PathBuf>,
}

pub fn connector_metadata(provider: &ToolProvider) -> Option<CoworkConnectorMetadata> {
    if !is_connector_provider(provider) {
        return None;
    }
    let source_path = provider.source_path.as_ref()?.clone();
    let raw = fs::read_to_string(&source_path).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    let (mcp_key, object) = connector_config_object_for_provider(&value, &provider.name)?;
    let fallback_id = mcp_key
        .map(str::to_string)
        .or_else(|| plugin_root_name(&source_path))
        .unwrap_or_else(|| provider.name.clone());
    let plugin_id = connector_id(object, Some(&fallback_id));
    let name = connector_name(
        object,
        Some(&plugin_id),
        Some(mcp_key.unwrap_or(&provider.name)),
    );
    let (transport, url, connected) = connector_transport_summary(&provider.transport, object);
    let session_root = session_root_from_connector_path(&source_path);
    let settings_path = session_root
        .as_ref()
        .map(|root| root.join("cowork_settings.json"));
    let settings = session_root
        .as_deref()
        .map(cowork_settings)
        .unwrap_or_default();
    let enabled = connector_enabled(&settings, &[&plugin_id, &name, &provider.name]);
    Some(CoworkConnectorMetadata {
        plugin_id,
        name,
        transport,
        url,
        connected,
        store: connector_store_from_path(&source_path)
            .unwrap_or("cowork_plugins")
            .to_string(),
        enabled,
        source_path,
        settings_path,
    })
}

pub fn grant_state_provider_name(surface: &str) -> &'static str {
    match surface {
        "claude-code-desktop" => CLAUDE_CODE_DESKTOP_GRANT_STATE_PROVIDER_NAME,
        _ => COWORK_GRANT_STATE_PROVIDER_NAME,
    }
}

pub fn session_metadata_provider_name(surface: &str) -> &'static str {
    match surface {
        "claude-code-desktop" => CLAUDE_CODE_DESKTOP_SESSION_METADATA_PROVIDER_NAME,
        _ => COWORK_SESSION_METADATA_PROVIDER_NAME,
    }
}

fn session_grant_state_reason(surface: &str) -> &'static str {
    match surface {
        "claude-code-desktop" => {
            "Claude Code desktop session stores plaintext saved approval state"
        }
        _ => "Claude Cowork local-agent-mode session stores plaintext saved approval state",
    }
}

fn session_metadata_state_reason(surface: &str) -> &'static str {
    match surface {
        "claude-code-desktop" => "Claude Code desktop session stores plaintext session metadata",
        _ => "Claude Cowork local-agent-mode session stores plaintext session metadata",
    }
}

fn state_provider(surface: &str, name: &str, source_path: PathBuf, reason: &str) -> ToolProvider {
    ToolProvider {
        surface: surface.to_string(),
        name: name.to_string(),
        transport: Transport::Unknown(UnknownConfig {
            reason: reason.to_string(),
        }),
        source_path: Some(source_path),
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    }
}

fn allowlist_cache_value(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(object) => object
            .get(ALLOWLIST_CACHE_KEY)
            .or_else(|| object.values().find_map(allowlist_cache_value)),
        Value::Array(items) => items.iter().find_map(allowlist_cache_value),
        _ => None,
    }
}

struct RemoteConnectorStateStore {
    provider_name: &'static str,
    path: PathBuf,
}

fn remote_connector_state_stores(app_root: &Path) -> Vec<RemoteConnectorStateStore> {
    let mut stores = Vec::new();
    let indexeddb_root = app_root.join("IndexedDB");
    if let Ok(entries) = fs::read_dir(indexeddb_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".leveldb"))
                && leveldb_has_files(&path)
            {
                stores.push(RemoteConnectorStateStore {
                    provider_name: INDEXEDDB_CONNECTOR_STORE_PROVIDER_NAME,
                    path,
                });
            }
        }
    }

    let local_storage = app_root.join("Local Storage").join("leveldb");
    if local_storage.is_dir() && leveldb_has_files(&local_storage) {
        stores.push(RemoteConnectorStateStore {
            provider_name: LOCAL_STORAGE_CONNECTOR_STORE_PROVIDER_NAME,
            path: local_storage,
        });
    }
    stores
}

fn leveldb_has_files(path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if !path.is_file() {
            return false;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        name == "CURRENT"
            || name.starts_with("MANIFEST-")
            || matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("ldb" | "log")
            )
    })
}

#[derive(Debug, Clone)]
struct CoworkPluginCandidate {
    id: String,
    name: Option<String>,
    enabled: Option<bool>,
}

fn collect_installed_plugin_candidates(
    value: &Value,
    key: Option<String>,
    out: &mut Vec<CoworkPluginCandidate>,
) {
    match value {
        Value::Object(object) => {
            if let Some(candidate) = installed_plugin_candidate(object, key.as_deref()) {
                out.push(candidate);
                return;
            }
            for (child_key, child) in object {
                collect_installed_plugin_candidates(child, Some(child_key.clone()), out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_installed_plugin_candidates(item, None, out);
            }
        }
        Value::String(id) if key.is_none() && !generic_plugin_key(id) => {
            out.push(CoworkPluginCandidate {
                id: id.clone(),
                name: None,
                enabled: None,
            });
        }
        Value::Bool(enabled) => {
            if let Some(key) = key.filter(|key| !generic_plugin_key(key)) {
                out.push(CoworkPluginCandidate {
                    id: key,
                    name: None,
                    enabled: Some(*enabled),
                });
            }
        }
        _ => {}
    }
}

fn installed_plugin_candidate(
    object: &Map<String, Value>,
    key: Option<&str>,
) -> Option<CoworkPluginCandidate> {
    let explicit_id = first_string(
        object,
        &[
            "id",
            "pluginId",
            "connectorId",
            "identifier",
            "slug",
            "name",
        ],
    );
    let fallback_id = key
        .filter(|key| !generic_plugin_key(key) && object_has_plugin_shape(object))
        .map(str::to_string);
    let id = explicit_id.or(fallback_id)?;
    let name = first_string(object, &["displayName", "title", "name"]);
    let enabled = object
        .get("enabled")
        .or_else(|| object.get("isEnabled"))
        .and_then(Value::as_bool);
    Some(CoworkPluginCandidate { id, name, enabled })
}

fn object_has_plugin_shape(object: &Map<String, Value>) -> bool {
    object.keys().any(|key| {
        matches!(
            key.as_str(),
            "displayName"
                | "title"
                | "name"
                | "version"
                | "manifest"
                | "manifestPath"
                | "path"
                | "directory"
                | "enabled"
                | "isEnabled"
                | "mcp"
                | "server"
                | "url"
        )
    })
}

fn generic_plugin_key(key: &str) -> bool {
    matches!(
        key,
        "extensions"
            | "extraKnownMarketplaces"
            | "installed"
            | "installedPlugins"
            | "installed_plugins"
            | "items"
            | "marketplaces"
            | "metadata"
            | "plugins"
            | "schemaVersion"
            | "settings"
            | "version"
    )
}

fn connector_manifest_paths(plugins_root: &Path) -> Vec<PathBuf> {
    if !plugins_root.is_dir() {
        return Vec::new();
    }
    let mut paths: Vec<PathBuf> = WalkDir::new(plugins_root)
        .max_depth(7)
        .into_iter()
        .filter_entry(keep_connector_entry)
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| connector_manifest_path(path))
        .collect();
    paths.sort();
    paths
}

fn keep_connector_entry(entry: &DirEntry) -> bool {
    !entry
        .file_name()
        .to_str()
        .is_some_and(|name| matches!(name, "node_modules" | ".git" | "target"))
}

fn connector_manifest_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == ".mcp.json" || name.ends_with(".mcp.json"))
        && plugin_root_path(path).is_some()
}

fn matching_plugin_candidates<'a>(
    manifest_path: &Path,
    value: &Value,
    candidates: &'a [CoworkPluginCandidate],
) -> Vec<&'a CoworkPluginCandidate> {
    let mut manifest_tokens = BTreeSet::new();
    if let Some(name) = plugin_root_name(manifest_path) {
        insert_token(&mut manifest_tokens, &name);
    }
    if let Some(object) = value.as_object() {
        for key in [
            "id",
            "pluginId",
            "connectorId",
            "identifier",
            "slug",
            "name",
            "displayName",
            "title",
            "serverName",
            "serverIdentifier",
        ] {
            if let Some(value) = object.get(key).and_then(Value::as_str) {
                insert_token(&mut manifest_tokens, value);
            }
        }
        for map_key in ["mcpServers", "servers"] {
            if let Some(map) = object.get(map_key).and_then(Value::as_object) {
                for (name, config) in map {
                    insert_token(&mut manifest_tokens, name);
                    if let Some(config) = config.as_object()
                        && let Some(display_name) =
                            first_string(config, &["displayName", "name", "title"])
                    {
                        insert_token(&mut manifest_tokens, &display_name);
                    }
                }
            }
        }
    }

    candidates
        .iter()
        .filter(|candidate| {
            candidate_tokens(candidate)
                .into_iter()
                .any(|token| manifest_tokens.contains(&token))
        })
        .collect()
}

fn insert_token(tokens: &mut BTreeSet<String>, value: &str) {
    let token = normalized_token(value);
    if !token.is_empty() {
        tokens.insert(token);
    }
}

fn candidate_tokens(candidate: &CoworkPluginCandidate) -> Vec<String> {
    let mut tokens = Vec::new();
    for value in [Some(candidate.id.as_str()), candidate.name.as_deref()]
        .into_iter()
        .flatten()
    {
        let token = normalized_token(value);
        if !token.is_empty() {
            tokens.push(token);
        }
    }
    tokens
}

fn connector_providers_from_manifest(
    source_path: &Path,
    value: &Value,
    candidate: Option<&CoworkPluginCandidate>,
    settings: &BTreeMap<String, bool>,
) -> Vec<ToolProvider> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let mut providers = Vec::new();
    for map_key in ["mcpServers", "servers"] {
        if let Some(map) = object.get(map_key).and_then(Value::as_object) {
            for (name, config) in map {
                if let Some(config) = config.as_object()
                    && let Some(provider) = connector_provider_from_object(
                        source_path,
                        config,
                        candidate,
                        Some(name),
                        settings,
                    )
                {
                    providers.push(provider);
                }
            }
            if !providers.is_empty() {
                return providers;
            }
        }
    }
    connector_provider_from_object(source_path, object, candidate, None, settings)
        .into_iter()
        .collect()
}

fn connector_provider_from_object(
    source_path: &Path,
    object: &Map<String, Value>,
    candidate: Option<&CoworkPluginCandidate>,
    mcp_key: Option<&str>,
    settings: &BTreeMap<String, bool>,
) -> Option<ToolProvider> {
    let plugin_root_name = plugin_root_name(source_path);
    let fallback_id = candidate
        .map(|candidate| candidate.id.as_str())
        .or(mcp_key)
        .or(plugin_root_name.as_deref());
    let id = connector_id(object, fallback_id);
    let name = connector_name(
        object,
        candidate.and_then(|candidate| candidate.name.as_deref()),
        Some(mcp_key.unwrap_or(&id)),
    );
    let transport = connector_transport(object, source_path);
    let _enabled = connector_enabled(settings, &[&id, &name])
        .or_else(|| candidate.and_then(|candidate| candidate.enabled));
    Some(ToolProvider {
        surface: "claude-cowork".to_string(),
        name,
        transport,
        source_path: Some(source_path.to_path_buf()),
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: declared_tools(object, None),
    })
}

fn connector_id(object: &Map<String, Value>, fallback: Option<&str>) -> String {
    first_string(
        object,
        &[
            "id",
            "pluginId",
            "connectorId",
            "identifier",
            "slug",
            "name",
            "serverName",
            "serverIdentifier",
        ],
    )
    .or_else(|| fallback.map(str::to_string))
    .unwrap_or_else(|| "cowork-connector".to_string())
}

fn connector_name(
    object: &Map<String, Value>,
    candidate_name: Option<&str>,
    fallback: Option<&str>,
) -> String {
    first_string(
        object,
        &[
            "displayName",
            "title",
            "name",
            "serverName",
            "serverIdentifier",
        ],
    )
    .or_else(|| candidate_name.map(str::to_string))
    .or_else(|| fallback.map(str::to_string))
    .unwrap_or_else(|| "Cowork connector".to_string())
}

fn connector_transport(object: &Map<String, Value>, source_path: &Path) -> Transport {
    let server = server_object(object).unwrap_or(object);
    if let Some(url) = first_non_empty_string(server, &["url", "sseUrl", "serverUrl", "endpoint"]) {
        if url.starts_with("ws://") || url.starts_with("wss://") {
            return Transport::WebSocket(WsConfig { url });
        }
        return Transport::HttpSse(HttpConfig {
            url,
            headers: string_map(server.get("headers")),
            tls_leaf_sha256: None,
        });
    }

    if let Some(command) = first_non_empty_string(server, &["command", "cmd", "path"]) {
        let install_root = plugin_root_path(source_path);
        return Transport::Stdio(StdioConfig {
            command: substitute_dirname(&command, install_root.as_deref()),
            args: string_array(server.get("args"))
                .into_iter()
                .map(|arg| substitute_dirname(&arg, install_root.as_deref()))
                .collect(),
            env: string_map(server.get("env")),
        });
    }

    Transport::Unknown(UnknownConfig {
        reason: "Cowork connector .mcp.json did not include a string command/url".to_string(),
    })
}

fn connector_config_object_for_provider<'a>(
    value: &'a Value,
    provider_name: &str,
) -> Option<(Option<&'a str>, &'a Map<String, Value>)> {
    let object = value.as_object()?;
    for map_key in ["mcpServers", "servers"] {
        if let Some(map) = object.get(map_key).and_then(Value::as_object) {
            for (name, config) in map {
                let Some(config) = config.as_object() else {
                    continue;
                };
                if name == provider_name
                    || connector_name(config, None, Some(name)) == provider_name
                {
                    return Some((Some(name.as_str()), config));
                }
            }
        }
    }
    Some((None, object))
}

fn connector_transport_summary(
    transport: &Transport,
    object: &Map<String, Value>,
) -> (String, Option<String>, Option<bool>) {
    let server = server_object(object).unwrap_or(object);
    if let Some(url) = first_non_empty_string(server, &["url", "sseUrl", "serverUrl", "endpoint"]) {
        if url.starts_with("ws://") || url.starts_with("wss://") {
            return ("websocket".to_string(), Some(url), Some(true));
        }
        return ("http".to_string(), Some(url), Some(true));
    }
    if let Some(kind) = first_string(server, &["type", "transport"]) {
        let normalized = normalized_token(&kind);
        if matches!(normalized.as_str(), "http" | "https" | "sse") {
            return ("http".to_string(), None, Some(false));
        }
        if matches!(normalized.as_str(), "websocket" | "ws" | "wss") {
            return ("websocket".to_string(), None, Some(false));
        }
        if matches!(normalized.as_str(), "stdio") {
            return ("stdio".to_string(), None, None);
        }
    }
    match transport {
        Transport::HttpSse(http) => ("http".to_string(), Some(http.url.clone()), Some(true)),
        Transport::WebSocket(ws) => ("websocket".to_string(), Some(ws.url.clone()), Some(true)),
        Transport::Stdio(_) => ("stdio".to_string(), None, None),
        Transport::Unknown(_) => ("unknown".to_string(), None, None),
    }
}

fn cowork_settings(session_root: &Path) -> BTreeMap<String, bool> {
    let path = session_root.join("cowork_settings.json");
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return BTreeMap::new();
    };
    let mut settings = BTreeMap::new();
    if let Some(enabled) = value.get("enabledPlugins") {
        collect_plugin_setting(enabled, Some(true), &mut settings);
    }
    if let Some(disabled) = value.get("disabledPlugins") {
        collect_plugin_setting(disabled, Some(false), &mut settings);
    }
    if let Some(extra_known) = value.get("extraKnownMarketplaces") {
        collect_plugin_setting(extra_known, None, &mut settings);
    }
    settings
}

fn collect_plugin_setting(
    value: &Value,
    default_enabled: Option<bool>,
    settings: &mut BTreeMap<String, bool>,
) {
    match value {
        Value::String(id) => {
            if let Some(enabled) = default_enabled {
                insert_plugin_setting(settings, id, enabled);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_plugin_setting(item, default_enabled, settings);
            }
        }
        Value::Object(object) => {
            if let Some(id) = first_string(
                object,
                &[
                    "id",
                    "pluginId",
                    "connectorId",
                    "identifier",
                    "slug",
                    "name",
                ],
            ) {
                let enabled = object
                    .get("enabled")
                    .or_else(|| object.get("isEnabled"))
                    .and_then(Value::as_bool)
                    .or(default_enabled);
                if let Some(enabled) = enabled {
                    insert_plugin_setting(settings, &id, enabled);
                }
                return;
            }
            for (key, child) in object {
                match child {
                    Value::Bool(enabled) => insert_plugin_setting(settings, key, *enabled),
                    Value::Object(child_object) => {
                        if let Some(enabled) = child_object
                            .get("enabled")
                            .or_else(|| child_object.get("isEnabled"))
                            .and_then(Value::as_bool)
                            .or(default_enabled)
                        {
                            insert_plugin_setting(settings, key, enabled);
                        }
                        collect_plugin_setting(child, default_enabled, settings);
                    }
                    _ => collect_plugin_setting(child, default_enabled, settings),
                }
            }
        }
        _ => {}
    }
}

fn insert_plugin_setting(settings: &mut BTreeMap<String, bool>, id: &str, enabled: bool) {
    let key = normalized_token(id);
    if !key.is_empty() {
        settings.insert(key, enabled);
    }
}

fn connector_enabled(settings: &BTreeMap<String, bool>, values: &[&str]) -> Option<bool> {
    values.iter().find_map(|value| {
        let key = normalized_token(value);
        settings.get(&key).copied()
    })
}

fn connector_manifests_root_from_path(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| {
            ancestor
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| matches!(name, "cowork_plugins" | "rpm"))
        })
        .map(Path::to_path_buf)
}

fn session_root_from_connector_path(path: &Path) -> Option<PathBuf> {
    connector_manifests_root_from_path(path).and_then(|root| root.parent().map(Path::to_path_buf))
}

fn plugin_root_path(path: &Path) -> Option<PathBuf> {
    let manifests_root = connector_manifests_root_from_path(path)?;
    let rel = path.strip_prefix(&manifests_root).ok()?;
    let first = rel.components().next()?;
    let plugin_root = manifests_root.join(first.as_os_str());
    if manifests_root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "rpm")
        && !plugin_root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("plugin_"))
    {
        return None;
    }
    Some(plugin_root)
}

fn plugin_root_name(path: &Path) -> Option<String> {
    plugin_root_path(path)?
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.ends_with(".json"))
        .map(str::to_string)
}

fn connector_store_from_path(path: &Path) -> Option<&'static str> {
    connector_manifests_root_from_path(path)?
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| match name {
            "cowork_plugins" => Some("cowork_plugins"),
            "rpm" => Some("rpm"),
            _ => None,
        })
}

fn normalized_token(value: &str) -> String {
    value
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
        .collect()
}

struct Candidate<'a> {
    key: Option<String>,
    object: &'a Map<String, Value>,
}

fn collect_candidates<'a>(value: &'a Value, key: Option<String>, out: &mut Vec<Candidate<'a>>) {
    match value {
        Value::Object(object) => {
            if is_extension_candidate(object, key.as_deref()) {
                out.push(Candidate { key, object });
                return;
            }
            for (child_key, child) in object {
                collect_candidates(child, Some(child_key.clone()), out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_candidates(item, None, out);
            }
        }
        _ => {}
    }
}

fn is_extension_candidate(object: &Map<String, Value>, key: Option<&str>) -> bool {
    extension_id(object, key).is_some()
        && (object.get("server").is_some()
            || object.get("mcpServer").is_some()
            || object.get("tools").is_some())
}

fn extension_id(object: &Map<String, Value>, key: Option<&str>) -> Option<String> {
    first_string(
        object,
        &["id", "identifier", "extensionId", "packageId", "bundleId"],
    )
    .or_else(|| {
        key.filter(|key| !matches!(*key, "extensions" | "installations" | "items"))
            .map(str::to_string)
    })
}

fn resolve_extension_id(
    candidate_id: String,
    object: &Map<String, Value>,
    manifests: &BTreeMap<String, ExtensionManifest>,
) -> String {
    if manifests.contains_key(&candidate_id) || !generic_extension_id(&candidate_id) {
        return candidate_id;
    }

    let candidate_name = first_string(object, &["displayName", "name", "title"]);
    if let Some(candidate_name) = candidate_name.as_deref() {
        for (id, manifest) in manifests {
            let Some(manifest_object) = manifest.value.as_object() else {
                continue;
            };
            if first_string(manifest_object, &["displayName", "name", "title"]).as_deref()
                == Some(candidate_name)
            {
                return id.clone();
            }
        }
    }

    if manifests.len() == 1 {
        return manifests.keys().next().cloned().unwrap_or(candidate_id);
    }

    candidate_id
}

fn generic_extension_id(id: &str) -> bool {
    matches!(id, "manifest" | "mcpb:manifest" | "extension" | "package")
}

struct ExtensionManifest {
    value: Value,
    install_root: PathBuf,
}

fn extension_manifests(app_root: &Path) -> BTreeMap<String, ExtensionManifest> {
    let mut manifests = BTreeMap::new();
    let root = app_root.join("Claude Extensions");
    let Ok(entries) = fs::read_dir(root) else {
        return manifests;
    };
    for entry in entries.flatten() {
        let install_root = entry.path();
        let path = install_root.join("manifest.json");
        if !path.is_file() {
            continue;
        }
        let Some(id) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(raw) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str(&raw) else {
            continue;
        };
        manifests.insert(
            id,
            ExtensionManifest {
                value,
                install_root,
            },
        );
    }
    manifests
}

fn extension_settings(app_root: &Path) -> BTreeMap<String, bool> {
    let mut settings = BTreeMap::new();
    let root = app_root.join("Claude Extensions Settings");
    let Ok(entries) = fs::read_dir(root) else {
        return settings;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(id) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if let Some(enabled) = value.get("isEnabled").and_then(Value::as_bool) {
            settings.insert(id, enabled);
        }
    }
    settings
}

fn install_root(
    app_root: &Path,
    id: &str,
    object: &Map<String, Value>,
    manifest_root: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(root) = manifest_root {
        return Some(root.to_path_buf());
    }
    first_string(
        object,
        &["installPath", "installRoot", "path", "directory", "root"],
    )
    .map(|path| resolve_install_path(app_root, &path))
    .or_else(|| Some(app_root.join("Claude Extensions").join(id)))
}

fn resolve_install_path(app_root: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        app_root.join(path)
    }
}

fn extension_transport(
    object: &Map<String, Value>,
    manifest: Option<&Map<String, Value>>,
    install_root: Option<&Path>,
) -> Transport {
    let server = server_object(object).or_else(|| manifest.and_then(server_object));
    let Some(server) = server else {
        return Transport::Unknown(UnknownConfig {
            reason: "MCPB extension did not include server launch metadata".to_string(),
        });
    };
    if let Some(url) = first_string(server, &["url", "sseUrl", "serverUrl", "endpoint"]) {
        if url.starts_with("ws://") || url.starts_with("wss://") {
            return Transport::WebSocket(WsConfig { url });
        }
        return Transport::HttpSse(HttpConfig {
            url,
            headers: BTreeMap::new(),
            tls_leaf_sha256: None,
        });
    }

    let command = first_string(server, &["command", "cmd", "path"])
        .map(|command| substitute_dirname(&command, install_root))
        .or_else(|| {
            first_string(server, &["type"]).and_then(|kind| {
                (kind == "node"
                    && (server.get("args").is_some()
                        || first_string(server, &["entryPoint", "entry_point", "main"]).is_some()))
                .then(|| "node".to_string())
            })
        });
    let Some(command) = command else {
        return Transport::Unknown(UnknownConfig {
            reason: "MCPB extension server did not include a string command/url".to_string(),
        });
    };

    let mut args: Vec<String> = string_array(server.get("args"))
        .into_iter()
        .map(|arg| substitute_dirname(&arg, install_root))
        .collect();
    if args.is_empty()
        && let Some(entry_point) = first_string(server, &["entryPoint", "entry_point", "main"])
    {
        args.push(entry_point_arg(&entry_point, install_root));
    }
    Transport::Stdio(StdioConfig {
        command,
        args,
        env: BTreeMap::new(),
    })
}

fn server_object(object: &Map<String, Value>) -> Option<&Map<String, Value>> {
    object
        .get("server")
        .or_else(|| object.get("mcpServer"))
        .and_then(Value::as_object)
}

fn declared_tools(
    object: &Map<String, Value>,
    manifest: Option<&Map<String, Value>>,
) -> Vec<String> {
    let mut tools = BTreeSet::new();
    collect_tools(object.get("tools"), &mut tools);
    if let Some(server) = server_object(object) {
        collect_tools(server.get("tools"), &mut tools);
    }
    if let Some(manifest) = manifest {
        collect_tools(manifest.get("tools"), &mut tools);
        if let Some(server) = server_object(manifest) {
            collect_tools(server.get("tools"), &mut tools);
        }
    }
    tools.into_iter().collect()
}

fn collect_tools(value: Option<&Value>, tools: &mut BTreeSet<String>) {
    let Some(Value::Array(items)) = value else {
        return;
    };
    for item in items {
        match item {
            Value::String(name) => {
                tools.insert(name.clone());
            }
            Value::Object(object) => {
                if let Some(name) = first_string(object, &["name", "id"]) {
                    tools.insert(name);
                }
            }
            _ => {}
        }
    }
}

fn signature_status(object: &Map<String, Value>) -> Option<String> {
    object
        .get("signatureInfo")
        .and_then(Value::as_object)
        .and_then(|signature| first_string(signature, &["status"]))
        .or_else(|| first_string(object, &["signatureStatus", "signature"]))
}

fn substitute_dirname(value: &str, install_root: Option<&Path>) -> String {
    let Some(install_root) = install_root else {
        return value.to_string();
    };
    value.replace("${__dirname}", &install_root.display().to_string())
}

fn entry_point_arg(entry_point: &str, install_root: Option<&Path>) -> String {
    let substituted = substitute_dirname(entry_point, install_root);
    if Path::new(&substituted).is_absolute() {
        return substituted;
    }
    install_root
        .map(|root| root.join(&substituted).display().to_string())
        .unwrap_or(substituted)
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

fn first_non_empty_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}
