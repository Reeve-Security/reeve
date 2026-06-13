use crate::mcp::{
    McpAdapter, capabilities, discovery,
    extension_deps::{self, NpmDependency},
    fingerprint::normalize_id,
    is_supported_fs_path, redact_home_identity,
};
use crate::sensitive_data::{
    SensitiveDataScanOptions, write_sensitive_data_report, write_sensitive_data_sarif_report,
};
use aibom_core::{
    AIBOM_SCHEMA_URL, AIBOM_SCHEMA_URL_V2, AIBOM_SCHEMA_URL_V3, AIBOM_SCHEMA_VERSION,
    AIBOM_SCHEMA_VERSION_V2, AIBOM_SCHEMA_VERSION_V3, Capability, CapabilitySource,
    DiscoverySource, EvidenceRecord, ProfileOptions, ProtocolAdapter, ProviderIdentity, Target,
    ToolProvider, Transport, canonicalize_json, sha256_hex,
};
use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ScanArtifacts {
    pub scan_id: String,
    pub cdx_path: PathBuf,
    pub aibom_path: PathBuf,
    pub cdx_bytes: Vec<u8>,
    pub aibom_bytes: Vec<u8>,
    pub sensitive_report_path: Option<PathBuf>,
    pub sensitive_report_bytes: Option<Vec<u8>>,
    pub sensitive_sarif_path: Option<PathBuf>,
    pub sensitive_sarif_bytes: Option<Vec<u8>>,
}

pub async fn scan_target(target: &Target, output_dir: &Path) -> Result<ScanArtifacts> {
    scan_target_with_options(target, output_dir, &ScanOptions::default()).await
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub profile: bool,
    pub introspect_execute: bool,
    pub profile_timeout_per_tool_seconds: u64,
    pub profile_timeout_total_seconds: u64,
    pub custom_surfaces: Vec<discovery::CustomSurfaceSpec>,
    pub include_conversation_metadata: bool,
    pub scan_conversation_secrets: bool,
    pub conversation_suppressions_file: Option<PathBuf>,
    pub conversation_rules_file: Option<PathBuf>,
    pub sensitive_data_sarif: bool,
}

pub async fn scan_target_with_options(
    target: &Target,
    output_dir: &Path,
    opts: &ScanOptions,
) -> Result<ScanArtifacts> {
    if opts.conversation_rules_file.is_some() && !opts.scan_conversation_secrets {
        bail!("--conversation-rules-file requires --scan-conversation-secrets");
    }
    fs::create_dir_all(output_dir)?;
    let adapter = McpAdapter::new();
    let providers = if opts.custom_surfaces.is_empty() {
        adapter.discover(target).await?
    } else {
        discovery::discover_all_with_custom(&target.root, &opts.custom_surfaces)?
    };
    let empty_discovery = providers.is_empty();

    let scan_id = format!("scan-{}", unix_nanos());
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut components = Vec::new();
    let mut cdx_components = Vec::new();
    let mut evidence = Vec::new();
    let mut bom_ref_counts = BTreeMap::new();
    let mut used_bom_refs = BTreeSet::new();
    let mut npm_dependency_components: BTreeMap<String, NpmDependencyComponent> = BTreeMap::new();
    let mut cdx_dependency_edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    let groups = group_registrations(&adapter, &providers).await?;
    let mut emit_v2 =
        empty_discovery || !opts.custom_surfaces.is_empty() || groups_have_grants(&groups)?;
    let mut emit_v3 = false;

    for (index, group) in groups.iter().enumerate() {
        let canonical = &group.occurrences[0];
        let mut declared_caps = Vec::new();
        for (surface_idx, occurrence) in group.occurrences.iter().enumerate() {
            let evidence_id = if surface_idx == 0 {
                format!("ev-{index:03}-tools")
            } else {
                format!("ev-{index:03}-tools-{surface_idx}")
            };
            let (evidence_kind, evidence_reference) = capability_evidence_reference(
                occurrence,
                capabilities::IntrospectionOptions {
                    execute_stdio: opts.introspect_execute,
                },
            );
            evidence.push(json!({
                "id": evidence_id,
                "kind": evidence_kind,
                "reference": evidence_reference
            }));
            let capabilities = adapter
                .introspect_with_options(
                    occurrence,
                    capabilities::IntrospectionOptions {
                        execute_stdio: opts.introspect_execute,
                    },
                )
                .await?;
            let mut occurrence_declared = capabilities.declared;
            occurrence_declared
                .extend(registration_declared_capabilities(occurrence, &evidence_id));
            if discovery::claude_cowork::is_state_provider(occurrence) {
                let fallback_id = format!("mcp:{}", normalize_id(&occurrence.name));
                occurrence_declared.retain(|cap| cap.id != fallback_id);
            }
            if discovery::is_grant_state_provider(occurrence) {
                let fallback_id = format!("mcp:{}", normalize_id(&occurrence.name));
                occurrence_declared.retain(|cap| cap.id != fallback_id);
            }
            let rewrite_fallback =
                declared_capabilities_are_fallback(occurrence, &occurrence_declared);
            declared_caps.extend(occurrence_declared.into_iter().map(|mut cap| {
                if rewrite_fallback {
                    cap.id = format!("mcp:{}", normalize_id(&group.identity.name));
                }
                cap.evidence = vec![evidence_id.clone()];
                cap
            }));
            declared_caps.extend(filesystem_root_capabilities(
                occurrence,
                &group.identity.name,
                &evidence_id,
            ));
        }

        let declared: Vec<Value> = merge_capabilities(declared_caps)
            .into_iter()
            .map(|cap| capability_value(cap.id, cap.qualifiers, "declared", cap.evidence))
            .collect();
        let mut observed = Vec::new();
        if opts.profile {
            let profile = adapter
                .profile(
                    canonical,
                    &ProfileOptions {
                        scan_id: scan_id.clone(),
                        evidence_prefix: format!("ev-{index:03}-sandbox"),
                        timeout_per_tool_seconds: opts.profile_timeout_per_tool_seconds,
                        timeout_total_seconds: opts.profile_timeout_total_seconds,
                    },
                )
                .await?;
            evidence.extend(profile.evidence.into_iter().map(evidence_value));
            observed = profile
                .observed
                .into_iter()
                .map(|cap| capability_value(cap.id, cap.qualifiers, "observed", cap.evidence))
                .collect();
        }
        let (granted_caps, grant_evidence) = granted_capabilities_for_group(index, group)?;
        evidence.extend(grant_evidence.into_iter().map(evidence_value));
        let granted: Vec<Value> = merge_capabilities(granted_caps)
            .into_iter()
            .map(|cap| capability_value(cap.id, cap.qualifiers, "granted", cap.evidence))
            .collect();
        if capabilities_require_v3(&declared)
            || capabilities_require_v3(&observed)
            || capabilities_require_v3(&granted)
        {
            emit_v3 = true;
        }
        let bom_ref = reserve_bom_ref(
            unique_bom_ref(
                &group.identity.bom_ref,
                canonical,
                index,
                &mut bom_ref_counts,
            ),
            &mut used_bom_refs,
            &format!("component-{index}"),
        );
        let npm_dependencies = npm_dependencies_for_group(group)?;
        if !npm_dependencies.is_empty() {
            emit_v2 = true;
            let edge = cdx_dependency_edges.entry(bom_ref.clone()).or_default();
            for dependency in npm_dependencies {
                let component = npm_dependency_components
                    .entry(dependency.purl.clone())
                    .or_insert_with(|| {
                        let bom_ref = reserve_bom_ref(
                            dependency.purl.clone(),
                            &mut used_bom_refs,
                            "npm-dependency",
                        );
                        NpmDependencyComponent {
                            bom_ref,
                            dependency,
                        }
                    });
                edge.insert(component.bom_ref.clone());
            }
        }
        if emit_v2 {
            let source = if group
                .occurrences
                .iter()
                .any(|occurrence| occurrence.discovery_source == DiscoverySource::UserDefined)
            {
                "user-defined"
            } else {
                "built-in"
            };
            components.push(json!({
                "bom-ref": bom_ref,
                "source": source,
                "capabilities": {
                    "declared": declared,
                    "observed": observed,
                    "granted": granted
                }
            }));
        } else {
            components.push(json!({
                "bom-ref": bom_ref,
                "capabilities": {
                    "declared": declared,
                    "observed": observed
                }
            }));
        }

        let mut cdx_component = json!({
            "type": "application",
            "bom-ref": bom_ref,
            "name": group.identity.name,
            "externalReferences": []
        });
        if let Some(version) = group.identity.version.clone() {
            cdx_component["version"] = json!(version);
        }
        if let Some(purl) = group.identity.purl.clone() {
            cdx_component["purl"] = json!(purl);
        }
        if let Some(hash) = group.identity.entry_point_sha256.clone() {
            cdx_component["hashes"] = json!([{"alg":"SHA-256","content":hash}]);
        }
        cdx_components.push(cdx_component);
    }

    for component in npm_dependency_components.values() {
        components.push(npm_dependency_aibom_component(component));
        cdx_components.push(npm_dependency_cdx_component(component));
    }

    let aibom_filename = format!("{scan_id}.aibom.json");
    let cdx_filename = format!("{scan_id}.cdx.json");
    if emit_v2 || emit_v3 {
        upgrade_components_to_v2_shape(&mut components);
    }
    let schema_url = if emit_v2 {
        if emit_v3 {
            AIBOM_SCHEMA_URL_V3
        } else {
            AIBOM_SCHEMA_URL_V2
        }
    } else if emit_v3 {
        AIBOM_SCHEMA_URL_V3
    } else {
        AIBOM_SCHEMA_URL
    };
    let schema_version = if emit_v2 {
        if emit_v3 {
            AIBOM_SCHEMA_VERSION_V3
        } else {
            AIBOM_SCHEMA_VERSION_V2
        }
    } else if emit_v3 {
        AIBOM_SCHEMA_VERSION_V3
    } else {
        AIBOM_SCHEMA_VERSION
    };
    let aibom_value = json!({
        "$schema": schema_url,
        "aibom": {
            "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
            "components": components,
            "evidence": evidence,
            "scan": {
                "adapter": {"name":"mcp","version": env!("CARGO_PKG_VERSION")},
                "scanId": scan_id,
                "scanner": {"name":"reeve","version": env!("CARGO_PKG_VERSION")},
                "target": {"description": redact_home_identity(&target.description), "kind": "filesystem"},
                "timestamp": timestamp
            },
            "schemaVersion": schema_version
        }
    });
    let aibom_bytes = canonicalize_json(&aibom_value)?;
    let aibom_hash = sha256_hex(&aibom_bytes);

    for component in &mut cdx_components {
        let refs = component
            .pointer_mut("/externalReferences")
            .and_then(Value::as_array_mut)
            .context("missing externalReferences")?;
        refs.push(json!({
            "type": "bom",
            "url": aibom_filename,
            "hashes": [{"alg":"SHA-256","content": aibom_hash}]
        }));
    }

    let mut cdx_value = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", pseudo_uuid(&scan_id)),
        "version": 1,
        "metadata": {"timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)},
        "components": cdx_components
    });
    if !cdx_dependency_edges.is_empty() {
        cdx_value["dependencies"] = json!(cdx_dependency_values(&cdx_dependency_edges));
    }
    let cdx_bytes = canonicalize_json(&cdx_value)?;

    let aibom_path = output_dir.join(&aibom_filename);
    let cdx_path = output_dir.join(&cdx_filename);
    fs::write(&aibom_path, &aibom_bytes)?;
    fs::write(&cdx_path, &cdx_bytes)?;
    let (
        sensitive_report_path,
        sensitive_report_bytes,
        sensitive_sarif_path,
        sensitive_sarif_bytes,
    ) = if opts.include_conversation_metadata || opts.scan_conversation_secrets {
        let report_path = write_sensitive_data_report(
            target,
            output_dir,
            &scan_id,
            &timestamp,
            &SensitiveDataScanOptions {
                scan_conversation_secrets: opts.scan_conversation_secrets,
                suppressions_file: opts.conversation_suppressions_file.clone(),
                conversation_rules_file: opts.conversation_rules_file.clone(),
            },
        )?;
        let report_bytes = fs::read(&report_path)?;
        let (sarif_path, sarif_bytes) = if opts.sensitive_data_sarif {
            let sarif_path = write_sensitive_data_sarif_report(&report_path, output_dir, &scan_id)?;
            let sarif_bytes = fs::read(&sarif_path)?;
            (Some(sarif_path), Some(sarif_bytes))
        } else {
            (None, None)
        };
        (
            Some(report_path),
            Some(report_bytes),
            sarif_path,
            sarif_bytes,
        )
    } else {
        (None, None, None, None)
    };

    Ok(ScanArtifacts {
        scan_id,
        cdx_path,
        aibom_path,
        cdx_bytes,
        aibom_bytes,
        sensitive_report_path,
        sensitive_report_bytes,
        sensitive_sarif_path,
        sensitive_sarif_bytes,
    })
}

fn npm_dependencies_for_group(group: &ProviderGroup) -> Result<Vec<NpmDependency>> {
    let mut dependencies = BTreeMap::new();
    for occurrence in &group.occurrences {
        if occurrence.extension.is_none() {
            continue;
        }
        for dependency in extension_deps::collect_npm_dependencies(occurrence)? {
            dependencies
                .entry(dependency.purl.clone())
                .or_insert(dependency);
        }
    }
    Ok(dependencies.into_values().collect())
}

struct NpmDependencyComponent {
    bom_ref: String,
    dependency: NpmDependency,
}

fn npm_dependency_aibom_component(component: &NpmDependencyComponent) -> Value {
    json!({
        "bom-ref": component.bom_ref,
        "source": "built-in",
        "capabilities": {
            "declared": [],
            "observed": [],
            "granted": []
        }
    })
}

fn npm_dependency_cdx_component(component: &NpmDependencyComponent) -> Value {
    let dependency = &component.dependency;
    let mut component = json!({
        "type": "library",
        "bom-ref": component.bom_ref,
        "name": dependency.name,
        "purl": dependency.purl,
        "externalReferences": [],
        "properties": [
            {"name": "aibom:dependencyScope", "value": "ai-harness-extension"},
            {"name": "aibom:packageManager", "value": "npm"},
            {"name": "aibom:dependencyManifestScope", "value": dependency.scope},
            {"name": "aibom:dependencySource", "value": dependency.source.as_str()},
            {"name": "aibom:dependencyManifest", "value": redact_home_identity(&dependency.source_path.display().to_string())}
        ]
    });
    if let Some(version) = dependency.version.as_ref() {
        component["version"] = json!(version);
    }
    component
}

fn reserve_bom_ref(preferred: String, used: &mut BTreeSet<String>, suffix_hint: &str) -> String {
    if used.insert(preferred.clone()) {
        return preferred;
    }
    for index in 1.. {
        let candidate = format!("{preferred}#aibom-{suffix_hint}-{index}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("unbounded bom-ref suffix loop")
}

fn cdx_dependency_values(edges: &BTreeMap<String, BTreeSet<String>>) -> Vec<Value> {
    edges
        .iter()
        .map(|(parent, dependencies)| {
            let depends_on: Vec<_> = dependencies.iter().cloned().collect();
            json!({
                "ref": parent,
                "dependsOn": depends_on
            })
        })
        .collect()
}

fn capabilities_require_v3(capabilities: &[Value]) -> bool {
    capabilities.iter().any(|capability| {
        matches!(
            capability
                .pointer("/qualifiers/path")
                .and_then(Value::as_str),
            Some(path) if super::is_windows_path(path)
        )
    })
}

fn upgrade_components_to_v2_shape(components: &mut [Value]) {
    for component in components {
        let Some(component) = component.as_object_mut() else {
            continue;
        };
        component
            .entry("source")
            .or_insert_with(|| json!("built-in"));
        if let Some(capabilities) = component
            .get_mut("capabilities")
            .and_then(Value::as_object_mut)
        {
            capabilities.entry("granted").or_insert_with(|| json!([]));
        }
    }
}

fn capability_evidence_reference(
    provider: &ToolProvider,
    introspection: capabilities::IntrospectionOptions,
) -> (&'static str, String) {
    if capabilities::executes_stdio(provider, introspection) {
        return (
            "mcp-tools-list",
            format!("mcp://{}/{}/tools/list", provider.surface, provider.name),
        );
    }
    (
        "mcp-registration",
        registration_evidence_reference(provider),
    )
}

fn registration_evidence_reference(provider: &ToolProvider) -> String {
    if provider.surface == "codex-app"
        && provider.name == discovery::CODEX_APP_GRANT_STATE_PROVIDER_NAME
    {
        return "codex-app://config#approval-state".to_string();
    }
    if provider.surface == "claude-cowork"
        && provider.name == discovery::claude_cowork::COWORK_GRANT_STATE_PROVIDER_NAME
    {
        return "claude-cowork://local-agent-mode-session#approval-state".to_string();
    }
    if let Some(path) = provider.source_path.as_ref() {
        let redacted = redact_home_identity(&path.display().to_string());
        if let Some(extension) = provider.extension.as_ref() {
            return format!("{redacted}#extension[{}]", extension.id);
        }
        return redacted;
    }
    format!("mcp://{}/{}/registration", provider.surface, provider.name)
}

fn registration_declared_capabilities(
    provider: &ToolProvider,
    evidence_id: &str,
) -> Vec<Capability> {
    let mut capabilities = extension_declared_capabilities(provider, evidence_id);
    if let Some(capability) = cowork_state_declared_capability(provider, evidence_id) {
        capabilities.push(capability);
    }
    if let Some(capability) = session_metadata_declared_capability(provider, evidence_id) {
        capabilities.push(capability);
    }
    if let Some(capability) = cowork_connector_declared_capability(provider, evidence_id) {
        capabilities.push(capability);
    }
    let Transport::Stdio(stdio) = &provider.transport else {
        return capabilities;
    };
    let Some(package_index) = stdio
        .args
        .iter()
        .position(|arg| arg.contains("@modelcontextprotocol/server-filesystem"))
    else {
        return capabilities;
    };

    for path in stdio.args.iter().skip(package_index + 1) {
        if !super::is_supported_fs_path(path) {
            continue;
        }
        capabilities.push(registration_fs_capability("fs:read", path, evidence_id));
        capabilities.push(registration_fs_capability("fs:write", path, evidence_id));
    }
    capabilities
}

fn session_metadata_declared_capability(
    provider: &ToolProvider,
    evidence_id: &str,
) -> Option<Capability> {
    let capability_id = match (provider.surface.as_str(), provider.name.as_str()) {
        ("claude-cowork", discovery::claude_cowork::COWORK_SESSION_METADATA_PROVIDER_NAME) => {
            discovery::claude_cowork::COWORK_SCHEDULED_TASK_CAPABILITY_ID
        }
        (
            "claude-code-desktop",
            discovery::claude_cowork::CLAUDE_CODE_DESKTOP_SESSION_METADATA_PROVIDER_NAME,
        ) => discovery::claude_cowork::CLAUDE_CODE_DESKTOP_SCHEDULED_TASK_CAPABILITY_ID,
        _ => return None,
    };
    let source_path = provider.source_path.as_ref()?;
    let value = read_json_grant_config(source_path).ok()?;
    let scheduled_task_id = value
        .get("scheduledTaskId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let session_type = value
        .get("sessionType")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if scheduled_task_id.is_none() && session_type.is_none() {
        return None;
    }

    let mut qualifiers = Map::new();
    qualifiers.insert("surface".to_string(), json!(provider.surface));
    qualifiers.insert("stateKind".to_string(), json!("session-metadata"));
    if let Some(scheduled_task_id) = scheduled_task_id {
        qualifiers.insert("scheduledTaskId".to_string(), json!(scheduled_task_id));
    }
    if let Some(session_type) = session_type {
        qualifiers.insert("sessionType".to_string(), json!(session_type));
    }
    Some(Capability {
        id: capability_id.to_string(),
        qualifiers,
        source: CapabilitySource::Declared,
        evidence: vec![evidence_id.to_string()],
    })
}

fn cowork_state_declared_capability(
    provider: &ToolProvider,
    evidence_id: &str,
) -> Option<Capability> {
    if provider.surface != "claude-cowork" {
        return None;
    }

    let (id, state_kind, store, store_format, encrypted) = match provider.name.as_str() {
        discovery::claude_cowork::APPROVAL_CACHE_PROVIDER_NAME => (
            discovery::claude_cowork::APPROVAL_CACHE_CAPABILITY_ID,
            "approval-cache",
            "dxt:allowlistCache",
            "electron-safeStorage-dpapi",
            Some(true),
        ),
        discovery::claude_cowork::INDEXEDDB_CONNECTOR_STORE_PROVIDER_NAME => (
            discovery::claude_cowork::REMOTE_CONNECTOR_STORE_CAPABILITY_ID,
            "remote-connector-store",
            "IndexedDB",
            "indexeddb-leveldb",
            None,
        ),
        discovery::claude_cowork::LOCAL_STORAGE_CONNECTOR_STORE_PROVIDER_NAME => (
            discovery::claude_cowork::REMOTE_CONNECTOR_STORE_CAPABILITY_ID,
            "remote-connector-store",
            "Local Storage/leveldb",
            "local-storage-leveldb",
            None,
        ),
        _ => return None,
    };

    let mut qualifiers = Map::new();
    qualifiers.insert("surface".to_string(), json!("claude-cowork"));
    qualifiers.insert("stateKind".to_string(), json!(state_kind));
    qualifiers.insert("store".to_string(), json!(store));
    qualifiers.insert("storeFormat".to_string(), json!(store_format));
    qualifiers.insert("support".to_string(), json!("presence-only"));
    if let Some(encrypted) = encrypted {
        qualifiers.insert("encrypted".to_string(), json!(encrypted));
    }
    if let Some(path) = provider.source_path.as_ref() {
        qualifiers.insert(
            "storePath".to_string(),
            json!(redact_home_identity(&path.display().to_string())),
        );
    }

    Some(Capability {
        id: id.to_string(),
        qualifiers,
        source: CapabilitySource::Declared,
        evidence: vec![evidence_id.to_string()],
    })
}

fn cowork_connector_declared_capability(
    provider: &ToolProvider,
    evidence_id: &str,
) -> Option<Capability> {
    let metadata = discovery::claude_cowork::connector_metadata(provider)?;
    let mut qualifiers = Map::new();
    qualifiers.insert("surface".to_string(), json!("claude-cowork"));
    qualifiers.insert("stateKind".to_string(), json!("remote-connector"));
    qualifiers.insert("connectorId".to_string(), json!(metadata.plugin_id));
    qualifiers.insert("name".to_string(), json!(metadata.name));
    qualifiers.insert("transport".to_string(), json!(metadata.transport));
    qualifiers.insert("support".to_string(), json!("inventory"));
    qualifiers.insert("store".to_string(), json!(metadata.store));
    qualifiers.insert(
        "manifestPath".to_string(),
        json!(redact_home_identity(
            &metadata.source_path.display().to_string()
        )),
    );
    if let Some(url) = metadata.url {
        qualifiers.insert("url".to_string(), json!(url));
    }
    if let Some(connected) = metadata.connected {
        qualifiers.insert("connected".to_string(), json!(connected));
    }
    if let Some(enabled) = metadata.enabled {
        qualifiers.insert("enabled".to_string(), json!(enabled));
    }
    if let Some(settings_path) = metadata.settings_path {
        qualifiers.insert(
            "settingsPath".to_string(),
            json!(redact_home_identity(&settings_path.display().to_string())),
        );
    }

    Some(Capability {
        id: discovery::claude_cowork::REMOTE_CONNECTOR_CAPABILITY_ID.to_string(),
        qualifiers,
        source: CapabilitySource::Declared,
        evidence: vec![evidence_id.to_string()],
    })
}

fn extension_declared_capabilities(provider: &ToolProvider, evidence_id: &str) -> Vec<Capability> {
    let Some(extension) = provider.extension.as_ref() else {
        return Vec::new();
    };
    let mut qualifiers = Map::new();
    qualifiers.insert("surface".to_string(), json!(provider.surface.as_str()));
    qualifiers.insert("extensionId".to_string(), json!(extension.id.as_str()));
    if let Some(name) = extension.name.as_ref() {
        qualifiers.insert("name".to_string(), json!(name));
    }
    if let Some(version) = extension.version.as_ref() {
        qualifiers.insert("version".to_string(), json!(version));
    }
    if let Some(path) = extension.install_root.as_ref() {
        qualifiers.insert(
            "installRoot".to_string(),
            json!(redact_home_identity(&path.display().to_string())),
        );
    }
    if let Some(status) = extension.signature_status.as_ref() {
        qualifiers.insert("signatureStatus".to_string(), json!(status));
    }
    if let Some(enabled) = extension.enabled {
        qualifiers.insert("enabled".to_string(), json!(enabled));
    }

    let mut capabilities = vec![Capability {
        id: "mcp:extension:installed".to_string(),
        qualifiers: qualifiers.clone(),
        source: CapabilitySource::Declared,
        evidence: vec![evidence_id.to_string()],
    }];
    if extension
        .signature_status
        .as_deref()
        .is_some_and(|status| status.eq_ignore_ascii_case("unsigned"))
    {
        capabilities.push(Capability {
            id: "mcp:extension:unsigned".to_string(),
            qualifiers: qualifiers.clone(),
            source: CapabilitySource::Declared,
            evidence: vec![evidence_id.to_string()],
        });
    }
    if extension.enabled == Some(false) {
        capabilities.push(Capability {
            id: "mcp:extension:disabled".to_string(),
            qualifiers,
            source: CapabilitySource::Declared,
            evidence: vec![evidence_id.to_string()],
        });
    }
    capabilities
}

fn registration_fs_capability(id: &str, path: &str, evidence_id: &str) -> Capability {
    let qualifiers = path_qualifiers(path);
    Capability {
        id: id.to_string(),
        qualifiers,
        source: CapabilitySource::Declared,
        evidence: vec![evidence_id.to_string()],
    }
}

/// A set of MCP registrations that resolve to the same identity and transport.
/// First-occurrence ordering is preserved from `discover_all`'s output so the
/// canonical entry (used for introspection and CDX naming) is stable.
pub struct ProviderGroup {
    pub identity: ProviderIdentity,
    pub occurrences: Vec<ToolProvider>,
}

pub async fn group_registrations(
    adapter: &McpAdapter,
    providers: &[ToolProvider],
) -> Result<Vec<ProviderGroup>> {
    let mut groups: Vec<ProviderGroup> = Vec::new();
    let mut indexes_by_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for provider in providers {
        let identity = adapter.fingerprint(provider).await?;
        let key = dedupe_key(&identity, provider);
        let candidates: Vec<usize> = indexes_by_key
            .get(&key)
            .into_iter()
            .flatten()
            .copied()
            .filter(|idx| can_merge_provider(&groups[*idx], provider))
            .collect();
        let existing = match candidates.as_slice() {
            [idx] => Some(*idx),
            _ => None,
        };
        match existing {
            Some(idx) => groups[idx].occurrences.push(provider.clone()),
            None => {
                let idx = groups.len();
                indexes_by_key.entry(key).or_default().push(idx);
                groups.push(ProviderGroup {
                    identity,
                    occurrences: vec![provider.clone()],
                });
            }
        }
    }
    Ok(groups)
}

fn groups_have_grants(groups: &[ProviderGroup]) -> Result<bool> {
    for group in groups {
        for occurrence in &group.occurrences {
            if occurrence.surface == "claude-code"
                && occurrence.source_path.as_ref().is_some_and(|path| {
                    read_json_grant_config(path)
                        .ok()
                        .is_some_and(|value| !claude_code_grant_specs(&value).is_empty())
                })
            {
                return Ok(true);
            }
            if occurrence.surface == "claude-desktop"
                && occurrence.source_path.as_ref().is_some_and(|path| {
                    read_json_grant_config(path).ok().is_some_and(|value| {
                        !claude_desktop_trusted_folder_grant_specs(&value).is_empty()
                    })
                })
            {
                return Ok(true);
            }
            if occurrence.surface == "codex-cli"
                && occurrence.source_path.as_ref().is_some_and(|path| {
                    read_toml_grant_config(path)
                        .ok()
                        .is_some_and(|value| !codex_project_grant_specs(&value).is_empty())
                })
            {
                return Ok(true);
            }
            if occurrence.surface == "codex-app"
                && occurrence.name == discovery::CODEX_APP_GRANT_STATE_PROVIDER_NAME
                && occurrence.source_path.as_ref().is_some_and(|path| {
                    read_toml_grant_config(path)
                        .ok()
                        .is_some_and(|value| !codex_app_grant_specs(&value).is_empty())
                })
            {
                return Ok(true);
            }
            if occurrence.surface == "codex-app"
                && occurrence.name == discovery::codex_cli::CODEX_APP_FULL_ACCESS_PROVIDER_NAME
                && occurrence.source_path.as_ref().is_some_and(|path| {
                    read_json_grant_config(path)
                        .ok()
                        .is_some_and(|value| !codex_app_full_access_grant_specs(&value).is_empty())
                })
            {
                return Ok(true);
            }
            if occurrence.surface == "claude-cowork"
                && occurrence.name == discovery::claude_cowork::COWORK_GRANT_STATE_PROVIDER_NAME
                && occurrence.source_path.as_ref().is_some_and(|path| {
                    read_json_grant_config(path).ok().is_some_and(|value| {
                        !session_grant_specs(&value, "claude-cowork").is_empty()
                    })
                })
            {
                return Ok(true);
            }
            if occurrence.surface == "claude-code-desktop"
                && occurrence.name
                    == discovery::claude_cowork::CLAUDE_CODE_DESKTOP_GRANT_STATE_PROVIDER_NAME
                && occurrence.source_path.as_ref().is_some_and(|path| {
                    read_json_grant_config(path).ok().is_some_and(|value| {
                        !session_grant_specs(&value, "claude-code-desktop").is_empty()
                    })
                })
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn granted_capabilities_for_group(
    group_index: usize,
    group: &ProviderGroup,
) -> Result<(Vec<Capability>, Vec<EvidenceRecord>)> {
    let mut capabilities = Vec::new();
    let mut evidence = Vec::new();
    let mut grant_index = 0usize;
    for occurrence in &group.occurrences {
        let Some(source_path) = occurrence.source_path.as_ref() else {
            continue;
        };
        match occurrence.surface.as_str() {
            "claude-code" => {
                let value = read_json_grant_config(source_path)
                    .with_context(|| format!("parse approval state {}", source_path.display()))?;
                for spec in claude_code_grant_specs(&value) {
                    let evidence_id = format!("ev-{group_index:03}-grant-{grant_index}");
                    evidence.push(EvidenceRecord {
                        id: evidence_id.clone(),
                        kind: "granted-permission".to_string(),
                        // Redact the full formatted reference: spec.reference fragments can
                        // embed raw absolute paths (e.g. codex projects["/Users/x/..."] keys).
                        reference: redact_home_identity(&format!(
                            "file://{}#{}",
                            source_path.display(),
                            spec.reference
                        )),
                    });
                    capabilities.extend(spec.capabilities.into_iter().map(|(id, qualifiers)| {
                        Capability {
                            id,
                            qualifiers,
                            source: CapabilitySource::Granted,
                            evidence: vec![evidence_id.clone()],
                        }
                    }));
                    grant_index += 1;
                }
            }
            "claude-desktop"
                if occurrence.name == discovery::CLAUDE_DESKTOP_GRANT_STATE_PROVIDER_NAME =>
            {
                let value = read_json_grant_config(source_path)
                    .with_context(|| format!("parse approval state {}", source_path.display()))?;
                for spec in claude_desktop_trusted_folder_grant_specs(&value) {
                    let evidence_id = format!("ev-{group_index:03}-grant-{grant_index}");
                    evidence.push(EvidenceRecord {
                        id: evidence_id.clone(),
                        kind: "granted-permission".to_string(),
                        // Redact the full formatted reference: spec.reference fragments can
                        // embed raw absolute paths (e.g. codex projects["/Users/x/..."] keys).
                        reference: redact_home_identity(&format!(
                            "file://{}#{}",
                            source_path.display(),
                            spec.reference
                        )),
                    });
                    capabilities.extend(spec.capabilities.into_iter().map(|(id, qualifiers)| {
                        Capability {
                            id,
                            qualifiers,
                            source: CapabilitySource::Granted,
                            evidence: vec![evidence_id.clone()],
                        }
                    }));
                    grant_index += 1;
                }
            }
            "codex-cli" => {
                let value = read_toml_grant_config(source_path)
                    .with_context(|| format!("parse approval state {}", source_path.display()))?;
                for spec in codex_project_grant_specs(&value) {
                    let evidence_id = format!("ev-{group_index:03}-grant-{grant_index}");
                    evidence.push(EvidenceRecord {
                        id: evidence_id.clone(),
                        kind: "granted-permission".to_string(),
                        // Redact the full formatted reference: spec.reference fragments can
                        // embed raw absolute paths (e.g. codex projects["/Users/x/..."] keys).
                        reference: redact_home_identity(&format!(
                            "file://{}#{}",
                            source_path.display(),
                            spec.reference
                        )),
                    });
                    capabilities.extend(spec.capabilities.into_iter().map(|(id, qualifiers)| {
                        Capability {
                            id,
                            qualifiers,
                            source: CapabilitySource::Granted,
                            evidence: vec![evidence_id.clone()],
                        }
                    }));
                    grant_index += 1;
                }
            }
            "codex-app" if occurrence.name == discovery::CODEX_APP_GRANT_STATE_PROVIDER_NAME => {
                let value = read_toml_grant_config(source_path)
                    .with_context(|| format!("parse approval state {}", source_path.display()))?;
                for spec in codex_app_grant_specs(&value) {
                    let evidence_id = format!("ev-{group_index:03}-grant-{grant_index}");
                    evidence.push(EvidenceRecord {
                        id: evidence_id.clone(),
                        kind: "granted-permission".to_string(),
                        reference: format!("codex-app://config#{}", spec.reference),
                    });
                    capabilities.extend(spec.capabilities.into_iter().map(|(id, qualifiers)| {
                        Capability {
                            id,
                            qualifiers,
                            source: CapabilitySource::Granted,
                            evidence: vec![evidence_id.clone()],
                        }
                    }));
                    grant_index += 1;
                }
            }
            "codex-app"
                if occurrence.name == discovery::codex_cli::CODEX_APP_FULL_ACCESS_PROVIDER_NAME =>
            {
                let value = read_json_grant_config(source_path).with_context(|| {
                    format!("parse Codex App global state {}", source_path.display())
                })?;
                for spec in codex_app_full_access_grant_specs(&value) {
                    let evidence_id = format!("ev-{group_index:03}-grant-{grant_index}");
                    evidence.push(EvidenceRecord {
                        id: evidence_id.clone(),
                        kind: "granted-permission".to_string(),
                        reference: format!("codex-app://global-state#{}", spec.reference),
                    });
                    capabilities.extend(spec.capabilities.into_iter().map(|(id, qualifiers)| {
                        Capability {
                            id,
                            qualifiers,
                            source: CapabilitySource::Granted,
                            evidence: vec![evidence_id.clone()],
                        }
                    }));
                    grant_index += 1;
                }
            }
            "claude-cowork"
                if occurrence.name
                    == discovery::claude_cowork::COWORK_GRANT_STATE_PROVIDER_NAME =>
            {
                let value = read_json_grant_config(source_path)
                    .with_context(|| format!("parse approval state {}", source_path.display()))?;
                for spec in session_grant_specs(&value, "claude-cowork") {
                    let evidence_id = format!("ev-{group_index:03}-grant-{grant_index}");
                    evidence.push(EvidenceRecord {
                        id: evidence_id.clone(),
                        kind: "granted-permission".to_string(),
                        reference: format!(
                            "claude-cowork://local-agent-mode-session#{}",
                            spec.reference
                        ),
                    });
                    capabilities.extend(spec.capabilities.into_iter().map(|(id, qualifiers)| {
                        Capability {
                            id,
                            qualifiers,
                            source: CapabilitySource::Granted,
                            evidence: vec![evidence_id.clone()],
                        }
                    }));
                    grant_index += 1;
                }
            }
            "claude-code-desktop"
                if occurrence.name
                    == discovery::claude_cowork::CLAUDE_CODE_DESKTOP_GRANT_STATE_PROVIDER_NAME =>
            {
                let value = read_json_grant_config(source_path)
                    .with_context(|| format!("parse approval state {}", source_path.display()))?;
                for spec in session_grant_specs(&value, "claude-code-desktop") {
                    let evidence_id = format!("ev-{group_index:03}-grant-{grant_index}");
                    evidence.push(EvidenceRecord {
                        id: evidence_id.clone(),
                        kind: "granted-permission".to_string(),
                        reference: format!("claude-code-desktop://session#{}", spec.reference),
                    });
                    capabilities.extend(spec.capabilities.into_iter().map(|(id, qualifiers)| {
                        Capability {
                            id,
                            qualifiers,
                            source: CapabilitySource::Granted,
                            evidence: vec![evidence_id.clone()],
                        }
                    }));
                    grant_index += 1;
                }
            }
            _ => {}
        }
    }
    Ok((capabilities, evidence))
}

fn read_json_grant_config(path: &Path) -> Result<Value> {
    discovery::read_config(path, discovery::ConfigFormat::Json)
}

fn read_toml_grant_config(path: &Path) -> Result<Value> {
    discovery::read_config(path, discovery::ConfigFormat::Toml)
}

fn claude_code_allow_rules(value: &Value) -> Vec<(usize, &str)> {
    value
        .pointer("/permissions/allow")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(index, rule)| rule.as_str().map(|rule| (index, rule)))
        .collect()
}

struct GrantSpec {
    reference: String,
    capabilities: Vec<(String, Map<String, Value>)>,
}

fn claude_code_grant_specs(value: &Value) -> Vec<GrantSpec> {
    let mut grants = Vec::new();
    for (rule_index, rule) in claude_code_allow_rules(value) {
        let Some((id, qualifiers)) = capability_parts_from_claude_code_rule(rule) else {
            continue;
        };
        grants.push(GrantSpec {
            reference: format!("permissions.allow[{rule_index}]"),
            capabilities: vec![(id, qualifiers)],
        });
    }
    if accept_edits_is_granted(value.get("acceptEdits")) {
        grants.push(GrantSpec {
            reference: "acceptEdits".to_string(),
            capabilities: vec![("fs:write".to_string(), Map::new())],
        });
    }
    grants
}

fn codex_project_grant_specs(value: &Value) -> Vec<GrantSpec> {
    let mut grants = Vec::new();
    if let Some(projects) = value.pointer("/projects").and_then(Value::as_object) {
        for (project_path, project) in projects {
            if project
                .get("approval_policy")
                .and_then(Value::as_str)
                .is_some_and(|policy| policy == "never")
            {
                let mut qualifiers = Map::new();
                qualifiers.insert("cmd".to_string(), json!("*"));
                qualifiers.insert("argCount".to_string(), json!(0));
                grants.push(GrantSpec {
                    reference: format!("projects[{}].approval_policy", json!(project_path)),
                    capabilities: vec![("exec:subprocess".to_string(), qualifiers)],
                });
            }
            if let Some(sandbox_mode) = project.get("sandbox_mode").and_then(Value::as_str) {
                grants.extend(codex_sandbox_grants(project_path, sandbox_mode));
            }
        }
    }
    grants
}

fn codex_app_grant_specs(value: &Value) -> Vec<GrantSpec> {
    let mut grants = Vec::new();
    if let Some(apps) = value.pointer("/apps").and_then(Value::as_object) {
        for (app_id, app) in apps {
            let Some(tools) = app.pointer("/tools").and_then(Value::as_object) else {
                continue;
            };
            for (tool_name, tool) in tools {
                if tool
                    .get("approval_mode")
                    .and_then(Value::as_str)
                    .is_some_and(|mode| mode == "approve")
                {
                    let mut qualifiers = Map::new();
                    qualifiers.insert("approvalMode".to_string(), json!("approve"));
                    grants.push(GrantSpec {
                        reference: format!(
                            "apps[{}].tools.{}.approval_mode",
                            json!(app_id),
                            tool_name
                        ),
                        capabilities: vec![(
                            format!("mcp:codex-app-tool:{}", normalize_id(tool_name)),
                            qualifiers,
                        )],
                    });
                }
            }
        }
    }
    grants
}

fn codex_app_full_access_grant_specs(value: &Value) -> Vec<GrantSpec> {
    let mut grants = Vec::new();
    let agent_mode = value.get("agent-mode").and_then(Value::as_str);
    let sandbox_type = value.pointer("/sandboxPolicy/type").and_then(Value::as_str);
    let approval_policy = value.get("approvalPolicy").and_then(Value::as_str);
    let skip_confirm = value
        .get("skip-full-access-confirm")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if agent_mode.is_some_and(codex_full_access_mode)
        || sandbox_type.is_some_and(codex_full_access_mode)
        || skip_confirm
    {
        let mut qualifiers = Map::new();
        if let Some(agent_mode) = agent_mode {
            qualifiers.insert("agentMode".to_string(), json!(agent_mode));
        }
        if let Some(sandbox_type) = sandbox_type {
            qualifiers.insert("sandboxPolicyType".to_string(), json!(sandbox_type));
        }
        if let Some(approval_policy) = approval_policy {
            qualifiers.insert("approvalPolicy".to_string(), json!(approval_policy));
        }
        qualifiers.insert("skipFullAccessConfirm".to_string(), json!(skip_confirm));
        grants.push(GrantSpec {
            reference: "full-access".to_string(),
            capabilities: vec![("mcp:codex-app:full-access".to_string(), qualifiers)],
        });
    }

    if approval_policy == Some("never") {
        let mut qualifiers = Map::new();
        qualifiers.insert("cmd".to_string(), json!("*"));
        qualifiers.insert("argCount".to_string(), json!(0));
        grants.push(GrantSpec {
            reference: "approvalPolicy".to_string(),
            capabilities: vec![("exec:subprocess".to_string(), qualifiers)],
        });
    }

    if agent_mode.is_some_and(codex_full_access_mode)
        || sandbox_type.is_some_and(codex_full_access_mode)
    {
        for (index, root) in codex_active_workspace_roots(value).into_iter().enumerate() {
            grants.push(GrantSpec {
                reference: format!("active-workspace-roots[{index}]"),
                capabilities: vec![
                    ("fs:read".to_string(), path_qualifiers(&root)),
                    ("fs:write".to_string(), path_qualifiers(&root)),
                ],
            });
        }
    }

    grants
}

fn codex_full_access_mode(value: &str) -> bool {
    matches!(
        normalize_approval_value(value).as_str(),
        "fullaccess" | "dangerfullaccess" | "dangerousfullaccess" | "dangerouslyfullaccess"
    )
}

fn codex_active_workspace_roots(value: &Value) -> Vec<String> {
    let roots = value
        .get("active-workspace-roots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|root| root.as_str().map(str::trim))
        .filter(|root| super::is_supported_fs_path(root))
        .map(str::to_string)
        .collect::<Vec<_>>();
    if roots.is_empty() {
        vec!["/".to_string()]
    } else {
        roots
    }
}

fn session_grant_specs(value: &Value, surface: &str) -> Vec<GrantSpec> {
    let mut grants = Vec::new();
    grants.extend(session_enabled_mcp_tool_grants(value, surface));
    grants.extend(session_always_allowed_reason_grants(value, surface));
    grants.extend(session_permission_update_grants(value, surface));
    grants.extend(cowork_selected_folder_grants(value));
    grants.extend(cowork_egress_grants(value));
    grants.extend(cowork_exec_policy_grants(value));
    grants.extend(cowork_permission_mode_grants(value));
    grants
}

fn session_enabled_mcp_tool_grants(value: &Value, surface: &str) -> Vec<GrantSpec> {
    let mut entries = Vec::new();
    if let Some(value) = value.get("enabledMcpTools") {
        collect_enabled_mcp_tool_entries("enabledMcpTools", value, &mut entries);
    }
    tool_grants_from_entries(entries, surface)
}

fn session_always_allowed_reason_grants(value: &Value, surface: &str) -> Vec<GrantSpec> {
    let mut entries = Vec::new();
    if let Some(value) = value.get("alwaysAllowedReasons") {
        collect_enabled_mcp_tool_entries("alwaysAllowedReasons", value, &mut entries);
    }
    tool_grants_from_entries(entries, surface)
}

fn session_permission_update_grants(value: &Value, surface: &str) -> Vec<GrantSpec> {
    let mut entries = Vec::new();
    if let Some(value) = value.get("sessionPermissionUpdates") {
        collect_enabled_mcp_tool_entries("sessionPermissionUpdates", value, &mut entries);
    }
    tool_grants_from_entries(entries, surface)
}

fn tool_grants_from_entries(entries: Vec<(String, String)>, surface: &str) -> Vec<GrantSpec> {
    entries
        .into_iter()
        .map(|(reference, tool_name)| {
            // Some approvals name a filesystem path as the "tool" (for example
            // a directory grant). Redact the home segment BEFORE slugifying:
            // normalize_id strips separators, fusing the username into one
            // token that cannot be redacted afterwards (#468).
            let tool_name = if is_supported_fs_path(&tool_name) {
                redact_home_identity(&tool_name)
            } else {
                tool_name
            };
            let mut qualifiers = Map::new();
            qualifiers.insert("toolName".to_string(), json!(tool_name));
            GrantSpec {
                // The reference embeds the raw tool key (for example
                // enabledMcpTools["/Users/x/.ssh"]) — redact it too (#468).
                reference: redact_home_identity(&reference),
                capabilities: vec![(
                    format!(
                        "{}:{}",
                        session_tool_capability_prefix(surface),
                        normalize_id(&tool_name)
                    ),
                    qualifiers,
                )],
            }
        })
        .collect()
}

fn session_tool_capability_prefix(surface: &str) -> &'static str {
    match surface {
        "claude-code-desktop" => "mcp:claude-code-desktop-tool",
        _ => "mcp:cowork-tool",
    }
}

fn collect_enabled_mcp_tool_entries(
    reference: &str,
    value: &Value,
    entries: &mut Vec<(String, String)>,
) {
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                match value {
                    Value::String(tool_name) if !tool_name.trim().is_empty() => {
                        entries.push((
                            format!("{reference}[{index}]"),
                            tool_name.trim().to_string(),
                        ));
                    }
                    _ => collect_enabled_mcp_tool_entries(
                        &format!("{reference}[{index}]"),
                        value,
                        entries,
                    ),
                }
            }
        }
        Value::Object(object) => {
            if let Some(tool_name) = session_tool_name_from_object(object)
                && object.values().any(approval_marker)
            {
                entries.push((reference.to_string(), tool_name));
                return;
            }
            for (key, value) in object {
                let child_reference = format!("{reference}[{}]", json!(key));
                if approval_marker(value) {
                    entries.push((child_reference, key.clone()));
                } else if matches!(value, Value::Array(_) | Value::Object(_)) {
                    collect_enabled_mcp_tool_entries(&child_reference, value, entries);
                }
            }
        }
        _ => {}
    }
}

fn session_tool_name_from_object(object: &Map<String, Value>) -> Option<String> {
    [
        "toolName",
        "tool",
        "name",
        "toolUseName",
        "serverToolName",
        "mcpToolName",
    ]
    .iter()
    .find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn cowork_selected_folder_grants(value: &Value) -> Vec<GrantSpec> {
    value
        .get("userSelectedFolders")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(index, folder)| {
            let path = absolute_fs_specifier(folder.as_str())?;
            Some(GrantSpec {
                reference: format!("userSelectedFolders[{index}]"),
                capabilities: vec![
                    ("fs:read".to_string(), path_qualifiers(path)),
                    ("fs:write".to_string(), path_qualifiers(path)),
                ],
            })
        })
        .collect()
}

fn cowork_egress_grants(value: &Value) -> Vec<GrantSpec> {
    let mut entries = Vec::new();
    if let Some(value) = value.get("egressAllowedDomains") {
        collect_cowork_egress_entries("egressAllowedDomains", value, &mut entries);
    }

    entries
        .into_iter()
        .filter_map(|(reference, scope)| {
            let qualifiers = net_egress_qualifiers(&scope)?;
            Some(GrantSpec {
                reference,
                capabilities: vec![("net:egress".to_string(), qualifiers)],
            })
        })
        .collect()
}

fn collect_cowork_egress_entries(
    reference: &str,
    value: &Value,
    entries: &mut Vec<(String, String)>,
) {
    match value {
        Value::String(scope) if !scope.trim().is_empty() => {
            entries.push((reference.to_string(), scope.trim().to_string()));
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_cowork_egress_entries(&format!("{reference}[{index}]"), value, entries);
            }
        }
        Value::Object(object) => {
            let direct_scope = object
                .get("host")
                .or_else(|| object.get("domain"))
                .or_else(|| object.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|scope| !scope.is_empty());
            if let Some(scope) = direct_scope {
                entries.push((
                    reference.to_string(),
                    egress_scope_from_object(scope, object),
                ));
                return;
            }
            for (key, value) in object {
                if approval_marker(value) && !key.trim().is_empty() {
                    entries.push((
                        format!("{reference}[{}]", json!(key)),
                        key.trim().to_string(),
                    ));
                }
            }
        }
        _ => {}
    }
}

fn egress_scope_from_object(scope: &str, object: &Map<String, Value>) -> String {
    let mut scope = scope.to_string();
    if !scope.contains("://")
        && let Some(scheme) = object
            .get("scheme")
            .and_then(Value::as_str)
            .filter(|scheme| matches!(*scheme, "http" | "https" | "tcp" | "udp" | "tls"))
    {
        scope = format!("{scheme}://{scope}");
    }
    let authority = scope
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(scope.as_str())
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if !authority.contains(':')
        && let Some(port) = object
            .get("port")
            .and_then(Value::as_u64)
            .filter(|port| (1..=65535).contains(port))
    {
        scope.push(':');
        scope.push_str(&port.to_string());
    }
    scope
}

fn cowork_exec_policy_grants(value: &Value) -> Vec<GrantSpec> {
    let mut entries = Vec::new();
    if let Some(value) = value.get("orgCliExecPolicies") {
        collect_cowork_exec_entries("orgCliExecPolicies", value, &mut entries);
    }

    entries
        .into_iter()
        .filter_map(|(reference, command)| {
            let qualifiers = exec_command_qualifiers(&command)?;
            Some(GrantSpec {
                reference,
                capabilities: vec![("exec:subprocess".to_string(), qualifiers)],
            })
        })
        .collect()
}

fn collect_cowork_exec_entries(
    reference: &str,
    value: &Value,
    entries: &mut Vec<(String, String)>,
) {
    match value {
        Value::String(command) if !command.trim().is_empty() => {
            entries.push((reference.to_string(), command.trim().to_string()));
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_cowork_exec_entries(&format!("{reference}[{index}]"), value, entries);
            }
        }
        Value::Object(object) => {
            if explicitly_denied_object(object) {
                return;
            }
            if let Some(command) = object
                .get("command")
                .or_else(|| object.get("cmd"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|command| !command.is_empty())
            {
                entries.push((reference.to_string(), command.to_string()));
                return;
            }
            for (key, value) in object {
                if approval_marker(value) && !key.trim().is_empty() {
                    entries.push((
                        format!("{reference}[{}]", json!(key)),
                        key.trim().to_string(),
                    ));
                }
            }
        }
        _ => {}
    }
}

fn cowork_permission_mode_grants(value: &Value) -> Vec<GrantSpec> {
    let Some(mode) = value.get("permissionMode").and_then(Value::as_str) else {
        return Vec::new();
    };
    if !permission_mode_is_global_exec_grant(mode) {
        return Vec::new();
    }
    let mut qualifiers = Map::new();
    qualifiers.insert("cmd".to_string(), json!("*"));
    qualifiers.insert("argCount".to_string(), json!(0));
    vec![GrantSpec {
        reference: "permissionMode".to_string(),
        capabilities: vec![("exec:subprocess".to_string(), qualifiers)],
    }]
}

fn net_egress_qualifiers(scope: &str) -> Option<Map<String, Value>> {
    let scope = scope.trim();
    if scope.is_empty() {
        return None;
    }
    let mut qualifiers = Map::new();
    let (scheme, rest) = match scope.split_once("://") {
        Some(("http", rest)) => (Some("http"), rest),
        Some(("https", rest)) => (Some("https"), rest),
        Some(("tcp", rest)) => (Some("tcp"), rest),
        Some(("udp", rest)) => (Some("udp"), rest),
        Some(("tls", rest)) => (Some("tls"), rest),
        _ => (None, scope),
    };
    if let Some(scheme) = scheme {
        qualifiers.insert("scheme".to_string(), json!(scheme));
    }

    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .trim()
        .trim_matches('/');
    if authority.is_empty() {
        return None;
    }
    let (host, port) = host_port(authority);
    qualifiers.insert("host".to_string(), json!(host));
    if let Some(port) = port {
        qualifiers.insert("port".to_string(), json!(port));
    }
    Some(qualifiers)
}

fn host_port(authority: &str) -> (&str, Option<u16>) {
    let Some((host, port)) = authority.rsplit_once(':') else {
        return (authority, None);
    };
    if host.contains(':') {
        return (authority, None);
    }
    match port.parse::<u16>() {
        Ok(port) if port > 0 => (host, Some(port)),
        _ => (authority, None),
    }
}

fn exec_command_qualifiers(command: &str) -> Option<Map<String, Value>> {
    let command = command.trim();
    if command.is_empty() {
        return None;
    }
    let mut qualifiers = Map::new();
    let cmd = if command == "*" {
        "*"
    } else {
        first_shell_word(command)?
    };
    qualifiers.insert("cmd".to_string(), json!(redact_home_identity(cmd)));
    qualifiers.insert(
        "argCount".to_string(),
        json!(command.split_whitespace().count().saturating_sub(1)),
    );
    Some(qualifiers)
}

fn approval_marker(value: &Value) -> bool {
    match value {
        Value::Bool(true) => true,
        Value::Number(number) => number.as_i64().is_some_and(|value| value != 0),
        Value::String(value) => matches!(
            normalize_approval_value(value).as_str(),
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
        .any(|key| object.get(*key).is_some_and(approval_marker)),
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
    .any(|key| object.get(*key).is_some_and(denial_marker))
}

fn denial_marker(value: &Value) -> bool {
    match value {
        Value::Bool(false) => true,
        Value::Number(number) => number.as_i64() == Some(0),
        Value::String(value) => matches!(
            normalize_approval_value(value).as_str(),
            "false" | "deny" | "denied" | "disabled" | "off" | "never" | "none" | "default"
        ),
        _ => false,
    }
}

fn permission_mode_is_global_exec_grant(mode: &str) -> bool {
    matches!(
        normalize_approval_value(mode).as_str(),
        "bypasspermissions"
            | "dangerouslyskippermissions"
            | "skipprompts"
            | "noprompts"
            | "unrestricted"
            | "alwaysallow"
    )
}

fn normalize_approval_value(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn claude_desktop_trusted_folder_grant_specs(value: &Value) -> Vec<GrantSpec> {
    let mut grants = Vec::new();
    if let Some(folders) = value
        .pointer("/preferences/localAgentModeTrustedFolders")
        .and_then(Value::as_array)
    {
        for (index, folder) in folders.iter().enumerate() {
            let Some(path) = absolute_fs_specifier(folder.as_str()) else {
                continue;
            };
            grants.push(GrantSpec {
                reference: format!("preferences.localAgentModeTrustedFolders[{index}]"),
                capabilities: vec![
                    ("fs:read".to_string(), path_qualifiers(path)),
                    ("fs:write".to_string(), path_qualifiers(path)),
                ],
            });
        }
    }
    grants
}

fn codex_sandbox_grants(project_path: &str, sandbox_mode: &str) -> Vec<GrantSpec> {
    let Some(path) = absolute_posix_specifier(Some(project_path)) else {
        return Vec::new();
    };
    match sandbox_mode {
        "read-only" => vec![GrantSpec {
            reference: format!("projects[{}].sandbox_mode", json!(project_path)),
            capabilities: vec![("fs:read".to_string(), path_qualifiers(path))],
        }],
        "workspace-write" => vec![GrantSpec {
            reference: format!("projects[{}].sandbox_mode", json!(project_path)),
            capabilities: vec![
                ("fs:read".to_string(), path_qualifiers(path)),
                ("fs:write".to_string(), path_qualifiers(path)),
            ],
        }],
        "danger-full-access" => {
            let mut exec_qualifiers = Map::new();
            exec_qualifiers.insert("cmd".to_string(), json!("*"));
            exec_qualifiers.insert("argCount".to_string(), json!(0));
            vec![GrantSpec {
                reference: format!("projects[{}].sandbox_mode", json!(project_path)),
                capabilities: vec![
                    ("fs:read".to_string(), path_qualifiers("/")),
                    ("fs:write".to_string(), path_qualifiers("/")),
                    ("exec:subprocess".to_string(), exec_qualifiers),
                ],
            }]
        }
        _ => Vec::new(),
    }
}

fn path_qualifiers(path: &str) -> Map<String, Value> {
    let mut qualifiers = Map::new();
    qualifiers.insert("path".to_string(), json!(redact_home_identity(path)));
    qualifiers
}

fn filesystem_root_capabilities(
    provider: &ToolProvider,
    _identity_name: &str,
    evidence_id: &str,
) -> Vec<Capability> {
    let Transport::Stdio(stdio) = &provider.transport else {
        return Vec::new();
    };
    filesystem_roots_from_stdio(&stdio.command, &stdio.args)
        .into_iter()
        .flat_map(|path| {
            ["fs:read", "fs:write"]
                .into_iter()
                .map(move |id| Capability {
                    id: id.to_string(),
                    qualifiers: path_qualifiers(path),
                    source: CapabilitySource::Declared,
                    evidence: vec![evidence_id.to_string()],
                })
        })
        .collect()
}

fn filesystem_roots_from_stdio<'a>(command: &str, args: &'a [String]) -> Vec<&'a str> {
    if command.contains("server-filesystem") {
        return args
            .iter()
            .map(String::as_str)
            .filter(|arg| looks_like_filesystem_root(arg))
            .collect();
    }
    let Some(package_index) = args.iter().position(|arg| is_filesystem_package_arg(arg)) else {
        return Vec::new();
    };
    args[package_index + 1..]
        .iter()
        .map(String::as_str)
        .filter(|arg| looks_like_filesystem_root(arg))
        .collect()
}

fn is_filesystem_package_arg(arg: &str) -> bool {
    arg == "@modelcontextprotocol/server-filesystem"
        || arg.starts_with("@modelcontextprotocol/server-filesystem@")
}

fn looks_like_filesystem_root(arg: &str) -> bool {
    let trimmed = arg.trim();
    trimmed == "~"
        || trimmed.starts_with('/')
        || trimmed.starts_with("%USERPROFILE%")
        || (trimmed.len() >= 3
            && trimmed.as_bytes()[1] == b':'
            && matches!(trimmed.as_bytes()[2], b'\\' | b'/')
            && trimmed.as_bytes()[0].is_ascii_alphabetic())
}

fn capability_parts_from_claude_code_rule(rule: &str) -> Option<(String, Map<String, Value>)> {
    let (tool, specifier) = split_permission_rule(rule);
    if tool.is_empty() {
        return None;
    }
    let tool_lower = tool.to_ascii_lowercase();
    let mut qualifiers = Map::new();
    let id = match tool_lower.as_str() {
        "read" | "ls" | "glob" | "grep" => {
            if let Some(path) = absolute_posix_specifier(specifier) {
                qualifiers = path_qualifiers(path);
            }
            "fs:read".to_string()
        }
        "write" | "edit" | "multiedit" | "notebookedit" => {
            if let Some(path) = absolute_posix_specifier(specifier) {
                qualifiers = path_qualifiers(path);
            }
            "fs:write".to_string()
        }
        "bash" => {
            if let Some(command) = specifier.and_then(first_shell_word) {
                let arg_count = specifier
                    .map(|spec| spec.split_whitespace().count().saturating_sub(1))
                    .unwrap_or(0);
                qualifiers.insert("cmd".to_string(), json!(redact_home_identity(command)));
                qualifiers.insert("argCount".to_string(), json!(arg_count));
            }
            "exec:subprocess".to_string()
        }
        "webfetch" => {
            if let Some(host) = specifier.and_then(web_host) {
                qualifiers.insert("host".to_string(), json!(host));
                qualifiers.insert("scheme".to_string(), json!("https"));
            }
            "net:egress".to_string()
        }
        "websearch" => "net:egress".to_string(),
        other => format!("mcp:{}", normalize_id(other)),
    };
    Some((id, qualifiers))
}

fn accept_edits_is_granted(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(true)) => true,
        Some(Value::String(value)) => matches!(
            normalize_approval_value(value).as_str(),
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
        Some(Value::Object(object)) => [
            "enabled",
            "approved",
            "allowed",
            "alwaysAllow",
            "approvalMode",
            "state",
            "value",
        ]
        .iter()
        .any(|key| accept_edits_is_granted(object.get(*key))),
        _ => false,
    }
}

fn split_permission_rule(rule: &str) -> (&str, Option<&str>) {
    let rule = rule.trim();
    let Some(open) = rule.find('(') else {
        return (rule, None);
    };
    if !rule.ends_with(')') {
        return (rule, None);
    }
    let tool = rule[..open].trim();
    let specifier = rule[open + 1..rule.len() - 1].trim();
    if specifier.is_empty() {
        (tool, None)
    } else {
        (tool, Some(specifier))
    }
}

fn absolute_posix_specifier(specifier: Option<&str>) -> Option<&str> {
    let value = specifier?.trim();
    value.starts_with('/').then_some(value)
}

fn absolute_fs_specifier(specifier: Option<&str>) -> Option<&str> {
    let value = specifier?.trim();
    super::is_supported_fs_path(value).then_some(value)
}

fn first_shell_word(specifier: &str) -> Option<&str> {
    specifier.split_whitespace().next()
}

fn web_host(specifier: &str) -> Option<&str> {
    let value = specifier.trim();
    let value = value
        .strip_prefix("domain:")
        .or_else(|| value.strip_prefix("host:"))
        .unwrap_or(value);
    let value = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(value);
    value.split('/').next().filter(|host| !host.is_empty())
}

fn can_merge_provider(group: &ProviderGroup, provider: &ToolProvider) -> bool {
    !matches!(provider.transport, Transport::Unknown(_))
        && group.occurrences.iter().all(|occurrence| {
            occurrence.surface != provider.surface
                || mirrored_claude_desktop_windows_config(occurrence, provider)
        })
}

fn mirrored_claude_desktop_windows_config(a: &ToolProvider, b: &ToolProvider) -> bool {
    if a.surface != "claude-desktop" || b.surface != "claude-desktop" {
        return false;
    }
    let Some(path_a) = a.source_path.as_deref() else {
        return false;
    };
    let Some(path_b) = b.source_path.as_deref() else {
        return false;
    };
    same_windows_appdata_root(path_a, path_b)
        && ((is_windows_claude_classic_config(path_a) && is_windows_claude_store_config(path_b))
            || (is_windows_claude_store_config(path_a) && is_windows_claude_classic_config(path_b)))
}

fn is_windows_claude_classic_config(path: &Path) -> bool {
    normalize_source_path(path).ends_with("AppData/Roaming/Claude/claude_desktop_config.json")
}

fn is_windows_claude_store_config(path: &Path) -> bool {
    let path = normalize_source_path(path);
    let suffix = "/LocalCache/Roaming/Claude/claude_desktop_config.json";
    (path.contains("/AppData/Local/Packages/Claude_")
        || path.starts_with("AppData/Local/Packages/Claude_"))
        && path.ends_with(suffix)
}

fn normalize_source_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn same_windows_appdata_root(path_a: &Path, path_b: &Path) -> bool {
    let path_a = normalize_source_path(path_a);
    let path_b = normalize_source_path(path_b);
    windows_appdata_root(&path_a) == windows_appdata_root(&path_b)
}

fn windows_appdata_root(path: &str) -> Option<&str> {
    path.find("AppData/").map(|index| &path[..index])
}

/// Dedupe key: package identity plus launch identity. Hosted transports dedupe
/// by endpoint regardless of local alias. Relative stdio launches include their
/// source path because they resolve in client/config context. Unknown transports
/// also include source path because they lack launch data.
fn dedupe_key(identity: &ProviderIdentity, provider: &ToolProvider) -> String {
    match &provider.transport {
        Transport::HttpSse(_) | Transport::WebSocket(_) => {
            serde_json::to_string(&provider.transport)
                .unwrap_or_else(|_| format!("hosted:{}", identity.bom_ref))
        }
        Transport::Stdio(stdio) => {
            let mut transport_repr = serde_json::to_string(&provider.transport).unwrap_or_default();
            if has_relative_launch_path(&stdio.command, &stdio.args) {
                transport_repr.push('\u{1f}');
                transport_repr.push_str(
                    &provider
                        .source_path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default(),
                );
            }
            format!("{}\u{1f}{}", identity.bom_ref, transport_repr)
        }
        Transport::Unknown(_) => format!(
            "{}\u{1f}unknown:{}:{}:{}",
            identity.bom_ref,
            provider.surface,
            provider.name,
            provider
                .source_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        ),
    }
}

fn has_relative_launch_path(command: &str, args: &[String]) -> bool {
    if is_relative_path_like(command) {
        return true;
    }
    match command {
        "npx" | "uvx" => false,
        "pnpm" if args.first().is_some_and(|arg| arg == "dlx") => false,
        "pipx" if args.first().is_some_and(|arg| arg == "run") => false,
        "node" => args
            .first()
            .is_some_and(|arg| !Path::new(arg).is_absolute()),
        "python" | "python3" => args
            .first()
            .is_some_and(|arg| arg == "-m" || !Path::new(arg).is_absolute()),
        "bash" | "sh" | "zsh" | "fish" => args.iter().any(|arg| is_relative_path_like(arg)),
        _ => args.iter().any(|arg| is_relative_path_like(arg)),
    }
}

fn is_relative_path_like(value: &str) -> bool {
    if value.is_empty() || value.starts_with('-') || Path::new(value).is_absolute() {
        return false;
    }
    value == "."
        || value == ".."
        || value.starts_with("./")
        || value.starts_with("../")
        || value.contains('/')
        || value.contains('\\')
}

fn declared_capabilities_are_fallback(provider: &ToolProvider, caps: &[Capability]) -> bool {
    if !fallback_transport(provider) || caps.len() != 1 || !caps[0].qualifiers.is_empty() {
        return false;
    }
    caps[0].id == format!("mcp:{}", normalize_id(&provider.name))
}

fn fallback_transport(provider: &ToolProvider) -> bool {
    match &provider.transport {
        Transport::Stdio(stdio) => !safe_to_spawn_locally(&stdio.command, &stdio.args),
        Transport::HttpSse(_) | Transport::WebSocket(_) | Transport::Unknown(_) => true,
    }
}

fn safe_to_spawn_locally(command: &str, args: &[String]) -> bool {
    let command_path = Path::new(command);
    if command_path.is_absolute() && command_path.is_file() {
        return true;
    }
    if matches!(command, "python" | "python3" | "node") {
        return args
            .first()
            .is_some_and(|arg| Path::new(arg).is_absolute() && Path::new(arg).is_file());
    }
    false
}

fn merge_capabilities(caps: Vec<Capability>) -> Vec<Capability> {
    let mut merged: Vec<Capability> = Vec::new();
    for cap in caps {
        if let Some(existing) = merged
            .iter_mut()
            .find(|existing| existing.id == cap.id && existing.qualifiers == cap.qualifiers)
        {
            for evidence in cap.evidence {
                if !existing.evidence.contains(&evidence) {
                    existing.evidence.push(evidence);
                }
            }
            existing.evidence.sort();
        } else {
            merged.push(cap);
        }
    }
    merged.sort_by(|a, b| {
        a.id.cmp(&b.id).then(
            serde_json::to_string(&a.qualifiers)
                .unwrap_or_default()
                .cmp(&serde_json::to_string(&b.qualifiers).unwrap_or_default()),
        )
    });
    merged
}

fn unique_bom_ref(
    base: &str,
    provider: &aibom_core::ToolProvider,
    index: usize,
    seen: &mut BTreeMap<String, usize>,
) -> String {
    let count = seen.entry(base.to_string()).or_insert(0);
    if *count == 0 {
        *count += 1;
        return base.to_string();
    }
    *count += 1;
    format!(
        "{}#instance-{}-{}-{}",
        base,
        normalize_fragment(&provider.surface),
        normalize_fragment(&provider.name),
        index
    )
}

fn normalize_fragment(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            out.push(ch);
        } else if matches!(ch, '-' | '_' | '.' | ':' | '/') {
            out.push('-');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out.trim_matches('-').to_string()
    }
}

fn capability_value(
    id: String,
    qualifiers: Map<String, Value>,
    source: &str,
    evidence: Vec<String>,
) -> Value {
    json!({
        "evidence": evidence,
        "id": id,
        "qualifiers": qualifiers,
        "source": source
    })
}

fn evidence_value(record: EvidenceRecord) -> Value {
    json!({
        "id": record.id,
        "kind": record.kind,
        "reference": record.reference
    })
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn pseudo_uuid(scan_id: &str) -> String {
    let digest = sha256_hex(scan_id.as_bytes());
    format!(
        "{}-{}-{}-{}-{}",
        &digest[0..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::{
        capability_evidence_reference, cowork_state_declared_capability, exec_command_qualifiers,
        extension_declared_capabilities, filesystem_root_capabilities, redact_home_identity,
        registration_evidence_reference, registration_fs_capability, tool_grants_from_entries,
    };
    use crate::mcp::capabilities::IntrospectionOptions;
    use crate::mcp::discovery::claude_cowork::APPROVAL_CACHE_PROVIDER_NAME;
    use aibom_core::{
        DiscoverySource, ExtensionMetadata, HttpConfig, StdioConfig, ToolProvider, Transport,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn registration_evidence_is_used_when_introspection_is_disabled() {
        let provider = http_provider();
        let (kind, reference) = capability_evidence_reference(
            &provider,
            IntrospectionOptions {
                execute_stdio: false,
            },
        );

        assert_eq!(kind, "mcp-registration");
        assert_eq!(reference, "mcp://test/http/registration");
    }

    #[test]
    fn tools_list_evidence_is_used_when_stdio_execution_will_run() {
        let provider = safe_stdio_provider();
        let (kind, reference) = capability_evidence_reference(
            &provider,
            IntrospectionOptions {
                execute_stdio: true,
            },
        );

        assert_eq!(kind, "mcp-tools-list");
        assert_eq!(reference, "mcp://test/stdio/tools/list");
    }

    #[test]
    fn registration_evidence_is_used_for_unsafe_stdio_even_with_opt_in() {
        let provider = unsafe_stdio_provider();
        let (kind, reference) = capability_evidence_reference(
            &provider,
            IntrospectionOptions {
                execute_stdio: true,
            },
        );

        assert_eq!(kind, "mcp-registration");
        assert_eq!(reference, "mcp://test/unsafe/registration");
    }

    #[test]
    fn filesystem_server_stdio_args_emit_root_capabilities() {
        let provider = ToolProvider {
            surface: "claude-desktop".into(),
            name: "filesystem".into(),
            transport: Transport::Stdio(StdioConfig {
                command: "npx".into(),
                args: vec![
                    "-y".into(),
                    "@modelcontextprotocol/server-filesystem".into(),
                    r"C:\Users\alice".into(),
                ],
                env: BTreeMap::new(),
            }),
            source_path: None,
            discovery_source: DiscoverySource::BuiltIn,
            extension: None,
            declared_tools: Vec::new(),
        };

        let caps = filesystem_root_capabilities(
            &provider,
            "@modelcontextprotocol/server-filesystem",
            "ev-001",
        );

        assert_eq!(caps.len(), 2);
        assert!(caps.iter().any(|cap| cap.id == "fs:read"));
        assert!(caps.iter().any(|cap| cap.id == "fs:write"));
        assert!(caps.iter().all(|cap| {
            cap.qualifiers.get("path").and_then(|value| value.as_str())
                == Some(r"C:\Users\<redacted-home>")
        }));
    }

    #[test]
    fn grant_paths_redact_home_identity_but_keep_absolute_scope() {
        assert_eq!(
            redact_home_identity("/Users/alice/LegalDocs"),
            "/Users/<redacted-home>/LegalDocs"
        );
        assert_eq!(
            redact_home_identity("/home/alice/projects/**"),
            "/home/<redacted-home>/projects/**"
        );
        assert_eq!(
            redact_home_identity(r"C:\Users\alice\LegalDocs"),
            r"C:\Users\<redacted-home>\LegalDocs"
        );
        assert_eq!(
            redact_home_identity("D:/Users/alice/LegalDocs"),
            "D:/Users/<redacted-home>/LegalDocs"
        );
        assert_eq!(
            redact_home_identity(r"\\fileserver\team\MatterRoom"),
            r"\\fileserver\team\MatterRoom"
        );
        assert_eq!(redact_home_identity("/workspaces/acme"), "/workspaces/acme");
        // Interior home roots (prefixed mounts, temp harness homes) are
        // component-matched too. See ADR-0045.
        assert_eq!(
            redact_home_identity("/mnt/c/Users/alice/LegalDocs"),
            "/mnt/c/Users/<redacted-home>/LegalDocs"
        );
        assert_eq!(
            redact_home_identity("/var/home/alice/projects"),
            "/var/home/<redacted-home>/projects"
        );
        assert_eq!(
            redact_home_identity("/Users/<redacted-home>/LegalDocs"),
            "/Users/<redacted-home>/LegalDocs"
        );
        assert_eq!(redact_home_identity("/Users/"), "/Users/");
    }

    // launch-proof: #463
    #[test]
    fn grant_reference_fragments_redact_embedded_project_paths() {
        // Codex CLI fragments embed raw project paths as TOML table keys;
        // redacting the full formatted reference covers them (ADR-0045).
        assert_eq!(
            redact_home_identity(
                "file:///Users/alice/.codex/config.toml#projects[\"/Users/alice/projects/demo\"].approval_policy"
            ),
            "file:///Users/<redacted-home>/.codex/config.toml#projects[\"/Users/<redacted-home>/projects/demo\"].approval_policy"
        );
        // Idempotent on a fully redacted reference.
        let redacted = "file:///Users/<redacted-home>/.codex/config.toml#projects[\"/Users/<redacted-home>/projects/demo\"].sandbox_mode";
        assert_eq!(redact_home_identity(redacted), redacted);
    }

    // launch-proof: #463
    #[test]
    fn cursor_encoded_project_segments_redact_username_token() {
        // Cursor flattens an absolute project path into one dash-joined
        // directory under .cursor/projects; the username token is redacted.
        assert_eq!(
            redact_home_identity(
                "/Users/alice/.cursor/projects/Users-alice-projects-demo/mcps/x/SERVER_METADATA.json"
            ),
            "/Users/<redacted-home>/.cursor/projects/Users-<redacted-home>-projects-demo/mcps/x/SERVER_METADATA.json"
        );
        assert_eq!(
            redact_home_identity(
                "/home/alice/.cursor/projects/home-alice-work/mcps/y/SERVER_METADATA.json"
            ),
            "/home/<redacted-home>/.cursor/projects/home-<redacted-home>-work/mcps/y/SERVER_METADATA.json"
        );
        // Idempotent on already-redacted encoded segments.
        let redacted = "/Users/<redacted-home>/.cursor/projects/Users-<redacted-home>-projects-demo/mcps/x/SERVER_METADATA.json";
        assert_eq!(redact_home_identity(redacted), redacted);
        // Dash-joined names OUTSIDE .cursor/projects are untouched.
        assert_eq!(
            redact_home_identity("/opt/data/Users-alice-projects-x/file.json"),
            "/opt/data/Users-alice-projects-x/file.json"
        );
    }

    // launch-proof: #468
    #[test]
    fn claude_projects_encoded_segments_redact_username_token() {
        // Claude Code flattens absolute paths into dash-joined directories
        // under .claude/projects; Windows adds a drive prefix (`C--`).
        assert_eq!(
            redact_home_identity(
                "~/AppData/x/<segment-1>/.claude/projects/C--Users-alice-AppData-Roaming/file.jsonl"
            ),
            "~/AppData/x/<segment-1>/.claude/projects/C--Users-<redacted-home>-AppData-Roaming/file.jsonl"
        );
        assert_eq!(
            redact_home_identity(
                "/Users/alice/.claude/projects/-Users-alice-projects-demo/s.jsonl"
            ),
            "/Users/<redacted-home>/.claude/projects/-Users-<redacted-home>-projects-demo/s.jsonl"
        );
        // Idempotent.
        let redacted = "/x/.claude/projects/C--Users-<redacted-home>-AppData-Roaming/file.jsonl";
        assert_eq!(redact_home_identity(redacted), redacted);
        // Drive-prefixed dash names outside .claude/.cursor projects untouched.
        assert_eq!(
            redact_home_identity("/opt/data/C--Users-alice-x/file.json"),
            "/opt/data/C--Users-alice-x/file.json"
        );
    }

    // launch-proof: #468
    #[test]
    fn path_valued_tool_grants_redact_home_before_slugifying() {
        let specs = tool_grants_from_entries(
            vec![
                (
                    "enabledMcpTools[0]".to_string(),
                    r"C:\Users\alice\.ssh".to_string(),
                ),
                ("enabledMcpTools[1]".to_string(), "web_search".to_string()),
            ],
            "claude-code-desktop",
        );
        let (id0, q0) = &specs[0].capabilities[0];
        assert!(
            !id0.contains("alice"),
            "slugified id must not fuse the username: {id0}"
        );
        assert!(id0.starts_with("mcp:claude-code-desktop-tool:"));
        assert_eq!(
            q0.get("toolName").and_then(|v| v.as_str()),
            Some(r"C:\Users\<redacted-home>\.ssh")
        );
        // Non-path tool names keep the standard slug (no redaction applied).
        let (id1, q1) = &specs[1].capabilities[0];
        assert_eq!(id1, "mcp:claude-code-desktop-tool:web-search");
        assert_eq!(
            q1.get("toolName").and_then(|v| v.as_str()),
            Some("web_search")
        );
    }

    // launch-proof: #463
    #[test]
    fn registration_evidence_reference_redacts_home_identity() {
        let mut provider = http_provider();
        provider.source_path = Some(PathBuf::from("/Users/alice/.cursor/mcp.json"));
        let reference = registration_evidence_reference(&provider);
        assert_eq!(reference, "/Users/<redacted-home>/.cursor/mcp.json");

        provider.extension = Some(extension_metadata());
        let reference = registration_evidence_reference(&provider);
        assert_eq!(
            reference,
            "/Users/<redacted-home>/.cursor/mcp.json#extension[ext-1]"
        );
    }

    // launch-proof: #463
    #[test]
    fn registration_fs_capability_redacts_home_identity() {
        let cap = registration_fs_capability("fs:read", "/home/alice/repo", "ev-000");
        assert_eq!(
            cap.qualifiers.get("path").and_then(|value| value.as_str()),
            Some("/home/<redacted-home>/repo")
        );
    }

    // launch-proof: #463
    #[test]
    fn exec_command_qualifiers_redact_home_identity() {
        let qualifiers = exec_command_qualifiers("/Users/alice/bin/deploy.sh --prod").unwrap();
        assert_eq!(
            qualifiers.get("cmd").and_then(|value| value.as_str()),
            Some("/Users/<redacted-home>/bin/deploy.sh")
        );
    }

    // launch-proof: #463
    #[test]
    fn extension_install_root_qualifier_redacts_home_identity() {
        let mut provider = http_provider();
        provider.extension = Some(extension_metadata());
        let caps = extension_declared_capabilities(&provider, "ev-000");
        assert!(!caps.is_empty());
        assert!(caps.iter().all(|cap| {
            cap.qualifiers
                .get("installRoot")
                .and_then(|value| value.as_str())
                == Some("/Users/<redacted-home>/.vscode/extensions/ext-1")
        }));
    }

    // launch-proof: #463
    #[test]
    fn cowork_store_path_qualifier_redacts_home_identity() {
        let mut provider = http_provider();
        provider.surface = "claude-cowork".into();
        provider.name = APPROVAL_CACHE_PROVIDER_NAME.into();
        provider.source_path = Some(PathBuf::from(
            "/Users/alice/Library/Application Support/Claude/dxt-allowlist-cache",
        ));
        let cap = cowork_state_declared_capability(&provider, "ev-000").unwrap();
        assert_eq!(
            cap.qualifiers
                .get("storePath")
                .and_then(|value| value.as_str()),
            Some("/Users/<redacted-home>/Library/Application Support/Claude/dxt-allowlist-cache")
        );
    }

    fn extension_metadata() -> ExtensionMetadata {
        ExtensionMetadata {
            id: "ext-1".into(),
            name: Some("Ext One".into()),
            version: Some("1.0.0".into()),
            install_root: Some(PathBuf::from("/Users/alice/.vscode/extensions/ext-1")),
            signature_status: Some("signed".into()),
            enabled: Some(true),
        }
    }

    fn http_provider() -> ToolProvider {
        ToolProvider {
            surface: "test".into(),
            name: "http".into(),
            transport: Transport::HttpSse(HttpConfig {
                url: "https://example.com/sse".into(),
                headers: BTreeMap::new(),
                tls_leaf_sha256: None,
            }),
            source_path: None,
            discovery_source: DiscoverySource::BuiltIn,
            extension: None,
            declared_tools: Vec::new(),
        }
    }

    fn safe_stdio_provider() -> ToolProvider {
        ToolProvider {
            surface: "test".into(),
            name: "stdio".into(),
            transport: Transport::Stdio(StdioConfig {
                command: std::env::current_exe().unwrap().display().to_string(),
                args: Vec::new(),
                env: BTreeMap::new(),
            }),
            source_path: None,
            discovery_source: DiscoverySource::BuiltIn,
            extension: None,
            declared_tools: Vec::new(),
        }
    }

    fn unsafe_stdio_provider() -> ToolProvider {
        ToolProvider {
            surface: "test".into(),
            name: "unsafe".into(),
            transport: Transport::Stdio(StdioConfig {
                command: "npx".into(),
                args: vec!["-y".into(), "demo-server".into()],
                env: BTreeMap::new(),
            }),
            source_path: None,
            discovery_source: DiscoverySource::BuiltIn,
            extension: None,
            declared_tools: Vec::new(),
        }
    }
}
