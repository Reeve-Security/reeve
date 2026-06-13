//! Cross-surface dedupe: when the same MCP server is registered through
//! multiple config surfaces (Claude Desktop, Cursor, Claude Code, ...), the
//! scanner must emit one component for that identity rather than one per
//! surface, while still recording per-surface evidence.
//!
//! Acceptance for issue #3: covers at least three duplicated registration
//! surfaces plus a non-duplicated server to guard against over-collapse.

use aibom_core::Target;
use aibom_core::{
    DiscoverySource, HttpConfig, StdioConfig, ToolProvider, Transport, UnknownConfig,
};
use aibom_scanner::McpAdapter;
use aibom_scanner::mcp::discovery::discover_all;
use aibom_scanner::mcp::group_registrations;
use aibom_scanner::scan_target;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const FILESYSTEM_NPX: &str = r#"{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2.3.1","/Users/alice/project"]}"#;
const FILESYSTEM_NPX_WINDOWS: &str = r#"{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2.3.1","C:\\Users\\reeveadmin"]}"#;

#[tokio::test]
async fn scan_dedupes_filesystem_across_three_surfaces() {
    let root = make_dir("reeve-dedupe-scan");
    let out = make_dir("reeve-dedupe-out");

    write_file(
        &root.join("Library/Application Support/Claude/claude_desktop_config.json"),
        &mcp_servers_json(&[("filesystem", FILESYSTEM_NPX)]),
    );
    write_file(
        &root.join(".cursor/mcp.json"),
        &mcp_servers_json(&[("filesystem", FILESYSTEM_NPX)]),
    );
    write_file(
        &root.join(".mcp.json"),
        &mcp_servers_json(&[
            ("filesystem", FILESYSTEM_NPX),
            (
                "unique-grep",
                r#"{"command":"npx","args":["-y","@example/grep@0.1.0"]}"#,
            ),
        ]),
    );

    let target = Target::filesystem(root.clone());
    let artifacts = scan_target(&target, &out).await.unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(&artifacts.aibom_path).unwrap()).unwrap();

    let components = aibom
        .pointer("/aibom/components")
        .and_then(Value::as_array)
        .expect("components array");
    assert_eq!(
        components.len(),
        2,
        "expected one component for the duplicated filesystem server plus one for unique-grep, got {components:#?}"
    );

    let evidence_records = aibom
        .pointer("/aibom/evidence")
        .and_then(Value::as_array)
        .expect("evidence array");
    let registration_refs: Vec<&str> = evidence_records
        .iter()
        .filter(|record| {
            record
                .pointer("/kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "mcp-registration")
        })
        .filter_map(|record| record.pointer("/reference").and_then(Value::as_str))
        .collect();
    assert_eq!(
        registration_refs.len(),
        4,
        "expected one config-registration evidence record per discovered occurrence"
    );
    assert!(registration_refs.iter().any(|reference| {
        reference.ends_with("Library/Application Support/Claude/claude_desktop_config.json")
    }));
    assert!(
        registration_refs
            .iter()
            .any(|reference| reference.ends_with(".cursor/mcp.json"))
    );
    assert!(
        registration_refs
            .iter()
            .any(|reference| reference.ends_with(".mcp.json"))
    );

    // Capability evidence must point at every surface that was inventoried so
    // downstream policy/audit consumers can reconstruct the surface fan-out.
    let filesystem_component = components
        .iter()
        .find(|component| {
            component
                .pointer("/capabilities/declared")
                .and_then(Value::as_array)
                .map(|caps| {
                    caps.iter().any(|cap| {
                        cap.pointer("/evidence")
                            .and_then(Value::as_array)
                            .map(|ev| ev.len() >= 3)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        })
        .expect("filesystem component with multi-surface evidence");
    let declared = filesystem_component
        .pointer("/capabilities/declared")
        .and_then(Value::as_array)
        .unwrap();
    assert!(
        !declared.is_empty(),
        "deduped component must still carry declared capabilities"
    );
    for cap in declared {
        let evidence_ids: Vec<&str> = cap
            .pointer("/evidence")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            evidence_ids.len(),
            3,
            "every declared capability on a 3-surface dedupe must reference all 3 queried evidence ids: {evidence_ids:?}"
        );
        let unique: BTreeSet<&str> = evidence_ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            evidence_ids.len(),
            "evidence ids on a capability must be unique"
        );
    }

    // bom-refs across components must be unique (CDX requirement).
    let cdx: Value = serde_json::from_slice(&fs::read(&artifacts.cdx_path).unwrap()).unwrap();
    let cdx_components = cdx
        .pointer("/components")
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(cdx_components.len(), 2);
    let bom_refs: BTreeSet<&str> = cdx_components
        .iter()
        .filter_map(|component| component.pointer("/bom-ref").and_then(Value::as_str))
        .collect();
    assert_eq!(bom_refs.len(), cdx_components.len());

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&out);
}

#[tokio::test]
async fn scan_emits_v0_3_for_windows_filesystem_root() {
    let root = make_dir("reeve-v03-windows-root");
    let out = make_dir("reeve-v03-windows-out");

    write_file(
        &root.join(".mcp.json"),
        &mcp_servers_json(&[("filesystem", FILESYSTEM_NPX_WINDOWS)]),
    );

    let target = Target::filesystem(root);
    let artifacts = scan_target(&target, &out).await.unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(&artifacts.aibom_path).unwrap()).unwrap();

    assert_eq!(aibom["aibom"]["schemaVersion"], "0.3.0");
    assert_eq!(
        aibom["$schema"],
        "https://aibom.example/schemas/aibom-v0.3.0.json"
    );

    let declared = aibom
        .pointer("/aibom/components/0/capabilities/declared")
        .and_then(Value::as_array)
        .unwrap();
    assert!(declared.iter().any(|cap| {
        cap["id"] == "fs:read" && cap["qualifiers"]["path"] == "C:\\Users\\<redacted-home>"
    }));
    assert!(declared.iter().any(|cap| {
        cap["id"] == "fs:write" && cap["qualifiers"]["path"] == "C:\\Users\\<redacted-home>"
    }));
}

#[tokio::test]
async fn group_registrations_collapses_two_surfaces_with_same_identity_and_transport() {
    // Same package, same launch parameters, different surfaces: one group.
    let provider_a = stdio(
        "claude-desktop",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
    );
    let provider_b = stdio(
        "cursor",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
    );
    // Different package on a third surface: its own group.
    let provider_c = stdio("claude-code", "shell", "python3", &["-m", "acme_shell_mcp"]);

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[provider_a, provider_b, provider_c])
        .await
        .unwrap();

    assert_eq!(
        groups.len(),
        2,
        "expected one group for the duplicated filesystem registration and one for shell"
    );

    let filesystem = groups
        .iter()
        .find(|g| g.identity.bom_ref.contains("server-filesystem"))
        .expect("filesystem group");
    let surfaces: Vec<&str> = filesystem
        .occurrences
        .iter()
        .map(|provider| provider.surface.as_str())
        .collect();
    assert_eq!(surfaces, vec!["claude-desktop", "cursor"]);

    let shell = groups
        .iter()
        .find(|g| {
            g.identity.bom_ref.contains("acme_shell_mcp")
                || g.identity.name.contains("acme_shell_mcp")
        })
        .expect("shell group");
    assert_eq!(shell.occurrences.len(), 1);
}

#[tokio::test]
async fn group_registrations_keeps_distinct_when_transport_differs() {
    // Same surface name+alias across surfaces, but one is stdio and one is
    // http: different launch identity, must stay separate.
    let stdio_provider = stdio(
        "claude-desktop",
        "linear",
        "npx",
        &["-y", "@linear/mcp-server@0.1.0"],
    );
    let http_provider = ToolProvider {
        surface: "cursor".to_string(),
        name: "linear".to_string(),
        transport: Transport::HttpSse(aibom_core::HttpConfig {
            url: "http://127.0.0.1:3923/sse".to_string(),
            headers: Default::default(),
            tls_leaf_sha256: None,
        }),
        source_path: None,
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    };

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[stdio_provider, http_provider])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        2,
        "stdio and http registrations are not the same launch identity"
    );
}

#[tokio::test]
async fn group_registrations_keeps_same_surface_files_distinct() {
    let provider_a = stdio_with_source(
        "claude-code",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
        "/tmp/project-a/.mcp.json",
    );
    let provider_b = stdio_with_source(
        "claude-code",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
        "/tmp/project-b/.mcp.json",
    );

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[provider_a, provider_b])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        2,
        "same-surface registrations from different config files must not dedupe"
    );
}

#[tokio::test]
async fn group_registrations_dedupes_windows_claude_mirror_paths() {
    let provider_a = stdio_with_source(
        "claude-desktop",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
        "/tmp/host/AppData/Roaming/Claude/claude_desktop_config.json",
    );
    let provider_b = stdio_with_source(
        "claude-desktop",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
        "/tmp/host/AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/claude_desktop_config.json",
    );

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[provider_a, provider_b])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        1,
        "mirrored Windows Claude Desktop config paths should dedupe"
    );
    assert_eq!(groups[0].occurrences.len(), 2);
}

#[tokio::test]
async fn group_registrations_keeps_windows_claude_mirror_paths_distinct_across_roots() {
    let provider_a = stdio_with_source(
        "claude-desktop",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
        "/tmp/alice/AppData/Roaming/Claude/claude_desktop_config.json",
    );
    let provider_b = stdio_with_source(
        "claude-desktop",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
        "/tmp/bob/AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/claude_desktop_config.json",
    );

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[provider_a, provider_b])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        2,
        "mirrored path shapes from different roots must stay distinct"
    );
}

#[tokio::test]
async fn group_registrations_keeps_relative_stdio_sources_distinct() {
    let provider_a = stdio_with_source(
        "claude-desktop",
        "local-server",
        "node",
        &["./server.js"],
        "/tmp/project-a/claude_desktop_config.json",
    );
    let provider_b = stdio_with_source(
        "cursor",
        "local-server",
        "node",
        &["./server.js"],
        "/tmp/project-b/.cursor/mcp.json",
    );

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[provider_a, provider_b])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        2,
        "relative stdio launches resolve per config context and must not dedupe"
    );
}

#[tokio::test]
async fn group_registrations_keeps_slash_relative_stdio_sources_distinct() {
    let provider_a = stdio_with_source(
        "claude-desktop",
        "local-server",
        "bash",
        &["scripts/mcp.sh"],
        "/tmp/project-a/claude_desktop_config.json",
    );
    let provider_b = stdio_with_source(
        "cursor",
        "local-server",
        "bash",
        &["scripts/mcp.sh"],
        "/tmp/project-b/.cursor/mcp.json",
    );

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[provider_a, provider_b])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        2,
        "slash-containing relative stdio launches resolve per config context"
    );
}

#[tokio::test]
async fn group_registrations_keeps_module_and_shell_wrapper_sources_distinct() {
    let module_a = stdio_with_source(
        "claude-desktop",
        "project-server",
        "python3",
        &["-m", "project_mcp"],
        "/tmp/project-a/claude_desktop_config.json",
    );
    let module_b = stdio_with_source(
        "cursor",
        "project-server",
        "python3",
        &["-m", "project_mcp"],
        "/tmp/project-b/.cursor/mcp.json",
    );
    let shell_a = stdio_with_source(
        "continue",
        "wrapped-server",
        "bash",
        &["-lc", "./scripts/mcp.sh"],
        "/tmp/project-a/config.yaml",
    );
    let shell_b = stdio_with_source(
        "vscode",
        "wrapped-server",
        "bash",
        &["-lc", "./scripts/mcp.sh"],
        "/tmp/project-b/mcp.json",
    );

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[module_a, module_b, shell_a, shell_b])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        4,
        "module and shell-wrapper launches are config-relative without installed-package proof"
    );
}

#[tokio::test]
async fn group_registrations_dedupes_hosted_transports_by_endpoint() {
    let provider_a = http("claude-desktop", "linear", "https://mcp.example.com/sse");
    let provider_b = http("cursor", "corp-linear", "https://mcp.example.com/sse");

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[provider_a, provider_b])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        1,
        "same hosted endpoint should dedupe even when aliases differ"
    );
    assert_eq!(groups[0].occurrences.len(), 2);
}

#[tokio::test]
async fn scan_dedupes_hosted_aliases_without_unioning_fallback_capabilities() {
    let root = make_dir("reeve-hosted-alias-scan");
    let out = make_dir("reeve-hosted-alias-out");
    let hosted = r#"{"url":"https://mcp.example.com/sse"}"#;

    write_file(
        &root.join("Library/Application Support/Claude/claude_desktop_config.json"),
        &mcp_servers_json(&[("linear", hosted)]),
    );
    write_file(
        &root.join(".cursor/mcp.json"),
        &mcp_servers_json(&[("corp-linear", hosted)]),
    );

    let target = Target::filesystem(root.clone());
    let artifacts = scan_target(&target, &out).await.unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(&artifacts.aibom_path).unwrap()).unwrap();
    let components = aibom
        .pointer("/aibom/components")
        .and_then(Value::as_array)
        .expect("components array");
    assert_eq!(components.len(), 1);

    let declared = components[0]
        .pointer("/capabilities/declared")
        .and_then(Value::as_array)
        .expect("declared capabilities");
    assert_eq!(
        declared.len(),
        1,
        "fallback capabilities from local aliases must not be unioned"
    );
    assert_eq!(
        declared[0].pointer("/id").and_then(Value::as_str),
        Some("mcp:linear")
    );
    let evidence_ids: Vec<&str> = declared[0]
        .pointer("/evidence")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(evidence_ids.len(), 2);

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&out);
}

#[tokio::test]
async fn group_registrations_does_not_pick_an_arbitrary_ambiguous_cross_surface_match() {
    let provider_a = stdio_with_source(
        "claude-code",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
        "/tmp/project-a/.mcp.json",
    );
    let provider_b = stdio_with_source(
        "claude-code",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
        "/tmp/project-b/.mcp.json",
    );
    let provider_c = stdio_with_source(
        "cursor",
        "filesystem",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem@2.3.1"],
        "/tmp/project-c/.cursor/mcp.json",
    );

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[provider_a, provider_b, provider_c])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        3,
        "ambiguous cross-surface matches must stay separate instead of picking the first candidate"
    );
}

#[tokio::test]
async fn group_registrations_keeps_metadata_only_sources_distinct() {
    let provider_a = metadata_only(
        "cursor",
        "filesystem",
        "/tmp/project-a/.cursor/projects/a/mcps/filesystem/SERVER_METADATA.json",
    );
    let provider_b = metadata_only(
        "cursor",
        "filesystem",
        "/tmp/project-b/.cursor/projects/b/mcps/filesystem/SERVER_METADATA.json",
    );

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &[provider_a, provider_b])
        .await
        .unwrap();
    assert_eq!(
        groups.len(),
        2,
        "metadata-only records lack command/url proof and must not cross-file dedupe"
    );
}

#[tokio::test]
async fn discover_all_then_group_registrations_dedupes_across_surfaces() {
    // End-to-end: real on-disk configs feed discovery, and grouping collapses
    // the duplicates discovery emits.
    let root = make_dir("reeve-dedupe-discover");
    write_file(
        &root.join("Library/Application Support/Claude/claude_desktop_config.json"),
        &mcp_servers_json(&[("filesystem", FILESYSTEM_NPX)]),
    );
    write_file(
        &root.join(".cursor/mcp.json"),
        &mcp_servers_json(&[("filesystem", FILESYSTEM_NPX)]),
    );
    write_file(
        &root.join(".mcp.json"),
        &mcp_servers_json(&[("filesystem", FILESYSTEM_NPX)]),
    );

    let providers = discover_all(&root).unwrap();
    let surfaces: BTreeSet<&str> = providers
        .iter()
        .map(|provider| provider.surface.as_str())
        .collect();
    assert!(
        surfaces.contains("claude-desktop")
            && surfaces.contains("cursor")
            && surfaces.contains("claude-code"),
        "expected all three surfaces to discover the registration: {surfaces:?}"
    );

    let adapter = McpAdapter::new();
    let groups = group_registrations(&adapter, &providers).await.unwrap();
    assert_eq!(
        groups.len(),
        1,
        "three identical registrations must dedupe to one identity"
    );
    assert_eq!(groups[0].occurrences.len(), 3);

    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn scan_dedupes_windows_claude_classic_and_store_mirror_paths() {
    let root = make_dir("reeve-windows-claude-mirror");
    let out = make_dir("reeve-windows-claude-mirror-out");

    write_file(
        &root.join("AppData/Roaming/Claude/claude_desktop_config.json"),
        &mcp_servers_json(&[("filesystem", FILESYSTEM_NPX_WINDOWS)]),
    );
    write_file(
        &root.join(
            "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/claude_desktop_config.json",
        ),
        &mcp_servers_json(&[("filesystem", FILESYSTEM_NPX_WINDOWS)]),
    );

    let target = Target::filesystem(root.clone());
    let artifacts = scan_target(&target, &out).await.unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(&artifacts.aibom_path).unwrap()).unwrap();

    let components = aibom
        .pointer("/aibom/components")
        .and_then(Value::as_array)
        .expect("components array");
    assert_eq!(
        components.len(),
        1,
        "mirrored Windows Claude Desktop registrations should become one component"
    );

    let evidence_records = aibom
        .pointer("/aibom/evidence")
        .and_then(Value::as_array)
        .expect("evidence array");
    let registration_refs: Vec<&str> = evidence_records
        .iter()
        .filter(|record| record["kind"] == "mcp-registration")
        .filter_map(|record| record.pointer("/reference").and_then(Value::as_str))
        .collect();
    assert_eq!(registration_refs.len(), 2);
    assert!(registration_refs.iter().any(|reference| {
        normalized_registration_ref(reference)
            .ends_with("AppData/Roaming/Claude/claude_desktop_config.json")
    }));
    assert!(registration_refs.iter().any(|reference| {
        normalized_registration_ref(reference).ends_with(
            "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/claude_desktop_config.json",
        )
    }));

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&out);
}

fn stdio(surface: &str, name: &str, command: &str, args: &[&str]) -> ToolProvider {
    ToolProvider {
        surface: surface.to_string(),
        name: name.to_string(),
        transport: Transport::Stdio(StdioConfig {
            command: command.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            env: Default::default(),
        }),
        source_path: None,
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    }
}

fn stdio_with_source(
    surface: &str,
    name: &str,
    command: &str,
    args: &[&str],
    source_path: &str,
) -> ToolProvider {
    let mut provider = stdio(surface, name, command, args);
    provider.source_path = Some(PathBuf::from(source_path));
    provider
}

fn metadata_only(surface: &str, name: &str, source_path: &str) -> ToolProvider {
    ToolProvider {
        surface: surface.to_string(),
        name: name.to_string(),
        transport: Transport::Unknown(UnknownConfig {
            reason: "metadata-only MCP registration; command/url not present".to_string(),
        }),
        source_path: Some(PathBuf::from(source_path)),
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    }
}

fn http(surface: &str, name: &str, url: &str) -> ToolProvider {
    ToolProvider {
        surface: surface.to_string(),
        name: name.to_string(),
        transport: Transport::HttpSse(HttpConfig {
            url: url.to_string(),
            headers: Default::default(),
            tls_leaf_sha256: None,
        }),
        source_path: None,
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    }
}

fn mcp_servers_json(servers: &[(&str, &str)]) -> String {
    let body = servers
        .iter()
        .map(|(name, json)| format!("\"{name}\":{json}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"mcpServers\":{{{body}}}}}")
}

fn normalized_registration_ref(reference: &str) -> String {
    reference.replace('\\', "/")
}

fn write_file(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

fn make_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{nanos}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}
