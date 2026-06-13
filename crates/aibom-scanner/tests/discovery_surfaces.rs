use aibom_core::{ToolProvider, Transport};
use aibom_scanner::mcp::discovery::{
    ConfigSurface, antigravity::Antigravity, claude_code::ClaudeCode,
    claude_code_desktop::ClaudeCodeDesktop, claude_cowork, claude_cowork::ClaudeCowork,
    claude_desktop::ClaudeDesktop, codex_cli, codex_cli::CodexCli, continue_dev::ContinueDev,
    cursor::Cursor, discover_all, dry_run_surfaces, factory::Factory, fixture_path, parse_value,
    read_config, registry, vscode_mcp::VsCodeMcp, zed::Zed,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_TARGET_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn parses_two_captured_configs_per_surface() {
    assert_surface::<ClaudeDesktop>(&["claude_desktop_1.json", "claude_desktop_2.json"]);
    assert_surface::<Cursor>(&["cursor_1.json", "cursor_2.json"]);
    assert_surface::<ContinueDev>(&["continue_1.yaml", "continue_2.yaml"]);
    assert_surface::<ClaudeCode>(&["claude_code_1.json", "claude_code_2.json"]);
    assert_surface::<CodexCli>(&["codex_1.toml", "codex_2.toml"]);
    assert_surface::<Factory>(&["factory_1.json", "factory_2.json"]);
    assert_surface::<Zed>(&["zed_1.json", "zed_2.json"]);
    assert_surface::<VsCodeMcp>(&["vscode_1.json", "vscode_2.json"]);
    assert_surface::<Antigravity>(&["antigravity_1.json", "antigravity_2.json"]);
    assert_cowork_fixture("claude_cowork_extensions_1.json");
    assert_cowork_fixture("claude_cowork_extensions_2.json");
    assert_cowork_state_fixture("claude_cowork_config_state_1.json");
    assert_cowork_connector_fixture("claude_cowork_installed_plugins_1.json");
    assert_cowork_session_fixture("local_cowork_session_approvals_mac.json", true);
    assert_cowork_session_fixture("local_cowork_session_remote_only.json", false);
    assert_claude_code_desktop_session_fixture(
        "local_claude_code_desktop_session_approvals_mac.json",
    );
    assert_claude_code_desktop_session_fixture(
        "local_claude_code_desktop_session_approvals_win.json",
    );
    assert_codex_global_state_fixture("codex_global_state_full_access_mac.json");
    assert_codex_global_state_fixture("codex_global_state_full_access_win.json");
}

fn assert_surface<S: ConfigSurface>(names: &[&str]) {
    let spec = S::spec();
    for name in names {
        let path = fixture_path(name);
        let value = read_config(&path, spec.format).unwrap();
        let providers = parse_value(spec.name, &path, &value, spec.roots);
        assert_eq!(providers.len(), 1, "{name}");
        assert_eq!(providers[0].surface, spec.name);
        match &providers[0].transport {
            Transport::Stdio(stdio) => assert!(!stdio.command.is_empty()),
            Transport::HttpSse(http) => assert!(http.url.starts_with("http")),
            Transport::WebSocket(ws) => assert!(ws.url.starts_with("ws")),
            Transport::Unknown(unknown) => assert!(!unknown.reason.is_empty()),
        }
    }
}

fn assert_cowork_fixture(name: &str) {
    let path = fixture_path(name);
    let providers = claude_cowork::parse_extensions_installations(&path).unwrap();
    assert_eq!(providers.len(), 1, "{name}");
    assert_eq!(providers[0].surface, ClaudeCowork::spec().name);
    assert!(
        providers[0].extension.is_some(),
        "Cowork fixture must emit extension metadata"
    );
    assert!(
        !providers[0].declared_tools.is_empty(),
        "Cowork fixture must emit declared tools"
    );
}

fn assert_cowork_state_fixture(name: &str) {
    let path = fixture_path(name);
    let providers = claude_cowork::parse_config_state(&path).unwrap();
    assert_eq!(providers.len(), 1, "{name}");
    assert_eq!(providers[0].surface, ClaudeCowork::spec().name);
    assert_eq!(
        providers[0].name,
        claude_cowork::APPROVAL_CACHE_PROVIDER_NAME
    );
    assert!(providers[0].extension.is_none());
    assert!(matches!(providers[0].transport, Transport::Unknown(_)));
}

fn assert_cowork_connector_fixture(name: &str) {
    let root = temp_target();
    let claude_root = root.join("AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude");
    let session = claude_root.join("local-agent-mode-sessions/account-123/org-456");
    let plugins = session.join("cowork_plugins");
    fs::create_dir_all(plugins.join("slack")).unwrap();
    fs::copy(fixture_path(name), plugins.join("installed_plugins.json")).unwrap();
    fs::write(
        plugins.join("slack/.mcp.json"),
        r#"{"id":"slack","name":"Slack","type":"http","url":"https://mcp.slack.example/sse"}"#,
    )
    .unwrap();
    fs::write(
        session.join("cowork_settings.json"),
        r#"{"enabledPlugins":["slack"],"extraKnownMarketplaces":[]}"#,
    )
    .unwrap();

    let providers =
        claude_cowork::parse_installed_plugins(&plugins.join("installed_plugins.json")).unwrap();
    assert_eq!(providers.len(), 1, "{name}");
    assert_eq!(providers[0].surface, ClaudeCowork::spec().name);
    assert_eq!(providers[0].name, "Slack");
    assert!(providers[0].extension.is_none());
    match &providers[0].transport {
        Transport::HttpSse(http) => assert_eq!(http.url, "https://mcp.slack.example/sse"),
        other => panic!("expected Cowork connector HTTP transport, got {other:?}"),
    }

    let _ = fs::remove_dir_all(root);
}

fn assert_cowork_session_fixture(name: &str, expect_grants: bool) {
    let path = fixture_path(name);
    let providers = claude_cowork::parse_local_session_descriptor(&path).unwrap();
    assert_eq!(
        providers
            .iter()
            .any(|provider| { provider.name == claude_cowork::COWORK_GRANT_STATE_PROVIDER_NAME }),
        expect_grants,
        "{name}"
    );
    assert_eq!(
        providers
            .iter()
            .filter(|provider| provider.surface == ClaudeCowork::spec().name)
            .count(),
        providers.len()
    );
}

fn assert_claude_code_desktop_session_fixture(name: &str) {
    let path = fixture_path(name);
    let providers = claude_cowork::parse_claude_code_desktop_file(&path).unwrap();
    assert!(
        providers.iter().any(|provider| {
            provider.surface == ClaudeCodeDesktop::spec().name
                && provider.name == claude_cowork::CLAUDE_CODE_DESKTOP_GRANT_STATE_PROVIDER_NAME
        }),
        "{name} must emit Claude Code desktop grant state"
    );
    assert!(
        providers.iter().any(|provider| {
            provider.surface == ClaudeCodeDesktop::spec().name
                && provider.name
                    == claude_cowork::CLAUDE_CODE_DESKTOP_SESSION_METADATA_PROVIDER_NAME
        }),
        "{name} must emit Claude Code desktop session metadata"
    );
}

fn assert_codex_global_state_fixture(name: &str) {
    let spec = codex_cli::CodexGlobalState::spec();
    let path = fixture_path(name);
    let providers = codex_cli::discover_codex_global_state(spec, &path).unwrap();
    assert_eq!(providers.len(), 1, "{name}");
    assert_eq!(providers[0].surface, "codex-app");
    assert_eq!(
        providers[0].name,
        codex_cli::CODEX_APP_FULL_ACCESS_PROVIDER_NAME
    );
}

#[test]
fn discovers_cowork_rpm_plugin_bundled_remote_connectors() {
    let root = temp_target();
    let claude_root = root.join(
        "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/local-agent-mode-sessions/account-123/org-456",
    );
    let plugin = claude_root.join("rpm/plugin_marketing");
    fs::create_dir_all(plugin.join(".claude-plugin")).unwrap();
    fs::write(
        plugin.join(".mcp.json"),
        r#"{
  "mcpServers": {
    "ahrefs": {"type": "http", "url": "https://api.ahrefs.com/mcp/mcp"},
    "similarweb": {"type": "http", "url": "https://mcp.similarweb.com"},
    "klaviyo": {"type": "http", "url": "https://mcp.klaviyo.com/mcp"},
    "supermetrics": {"type": "http", "url": "https://mcp.supermetrics.com/mcp"},
    "google calendar": {"type": "http", "url": ""},
    "gmail": {"type": "http", "url": ""}
  },
  "redactionProbe": "REEVE_COWORK_RPM_PROBE_DO_NOT_EMIT"
}"#,
    )
    .unwrap();
    fs::write(
        plugin.join(".claude-plugin/plugin.json"),
        r#"{"name":"Marketing plugin","description":"fixture metadata only"}"#,
    )
    .unwrap();

    let providers = discover_all(&root).unwrap();
    let names: Vec<_> = providers
        .iter()
        .filter(|provider| provider.surface == "claude-cowork")
        .map(|provider| provider.name.as_str())
        .collect();
    for expected in [
        "ahrefs",
        "similarweb",
        "klaviyo",
        "supermetrics",
        "google calendar",
        "gmail",
    ] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }
    let ahrefs = providers
        .iter()
        .find(|provider| provider.name == "ahrefs")
        .unwrap();
    match &ahrefs.transport {
        Transport::HttpSse(http) => assert_eq!(http.url, "https://api.ahrefs.com/mcp/mcp"),
        other => panic!("expected ahrefs HTTP transport, got {other:?}"),
    }
    let gmail = providers
        .iter()
        .find(|provider| provider.name == "gmail")
        .unwrap();
    assert!(matches!(gmail.transport, Transport::Unknown(_)));

    let dry_run = dry_run_surfaces(&root).unwrap();
    let cowork = dry_run
        .iter()
        .find(|surface| surface.surface == "claude-cowork")
        .unwrap();
    assert!(cowork.detected);
    assert!(cowork.entries.iter().any(|entry| {
        entry.source == "package-root-search"
            && entry.path.to_string_lossy().contains(
                "local-agent-mode-sessions/account-123/org-456/rpm/plugin_marketing/.mcp.json",
            )
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn registry_declares_fixture_contracts() {
    for spec in registry() {
        assert!(
            spec.fixture_names.len() >= 2,
            "{} missing fixture contract",
            spec.name
        );
        for fixture in spec.fixture_names {
            assert!(
                fixture_path(fixture).is_file(),
                "{} fixture {} missing",
                spec.name,
                fixture
            );
        }
    }
}

/// Parse a Codex `config.toml` fixture through the full Codex parser
/// (`[mcp_servers]` + App-plugin inventory), mirroring the discovery driver.
fn parse_codex_fixture(name: &str) -> Vec<ToolProvider> {
    let spec = CodexCli::spec();
    let path = fixture_path(name);
    let value = read_config(&path, spec.format).unwrap();
    codex_cli::parse_codex_config(spec, &path, &value)
}

fn app_plugins(providers: &[ToolProvider]) -> Vec<&ToolProvider> {
    providers
        .iter()
        .filter(|provider| codex_cli::is_app_plugin_provider(provider))
        .collect()
}

fn plugin_named<'a>(providers: &'a [ToolProvider], name: &str) -> &'a ToolProvider {
    app_plugins(providers)
        .into_iter()
        .find(|provider| provider.name == name)
        .unwrap_or_else(|| panic!("missing App plugin {name}"))
}

#[test]
fn discovers_codex_app_plugins_macos() {
    let providers = parse_codex_fixture("codex_app_plugins_mac.toml");
    let plugins = app_plugins(&providers);

    let mut names: Vec<&str> = plugins.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["browser", "computer-use", "documents", "spreadsheets"],
        "all four App plugins must be inventoried on the {} surface",
        codex_cli::CODEX_APP_PLUGIN_SURFACE
    );

    for plugin in &plugins {
        assert_eq!(plugin.surface, codex_cli::CODEX_APP_PLUGIN_SURFACE);
        assert!(matches!(plugin.transport, Transport::Unknown(_)));
        assert_eq!(
            plugin.source_path.as_deref(),
            Some(fixture_path("codex_app_plugins_mac.toml").as_path())
        );
    }

    // Disabled plugins are still inventoried, with enabled == Some(false).
    let spreadsheets = plugin_named(&providers, "spreadsheets");
    let spreadsheets_ext = spreadsheets.extension.as_ref().unwrap();
    assert_eq!(spreadsheets_ext.enabled, Some(false));
    assert_eq!(spreadsheets_ext.id, "spreadsheets@openai-primary-runtime");
    assert_eq!(spreadsheets_ext.name.as_deref(), Some("spreadsheets"));
    assert_eq!(
        spreadsheets_ext.version.as_deref(),
        Some("openai-primary-runtime"),
        "marketplace id rides in extension.version"
    );

    for enabled_name in ["browser", "computer-use", "documents"] {
        let ext = plugin_named(&providers, enabled_name)
            .extension
            .as_ref()
            .unwrap();
        assert_eq!(ext.enabled, Some(true), "{enabled_name} should be enabled");
    }

    let documents = plugin_named(&providers, "documents");
    let documents_ext = documents.extension.as_ref().unwrap();
    assert_eq!(documents_ext.id, "documents@openai-primary-runtime");
    assert_eq!(
        documents_ext.version.as_deref(),
        Some("openai-primary-runtime")
    );
    let browser_ext = plugin_named(&providers, "browser")
        .extension
        .as_ref()
        .unwrap();
    assert_eq!(browser_ext.id, "browser@openai-bundled");
    assert_eq!(browser_ext.version.as_deref(), Some("openai-bundled"));

    // The transport reason carries the structured qualifiers.
    match &documents.transport {
        Transport::Unknown(unknown) => {
            assert!(unknown.reason.contains("plugin_name=documents"));
            assert!(
                unknown
                    .reason
                    .contains("marketplace_id=openai-primary-runtime")
            );
        }
        other => panic!("expected Unknown transport, got {other:?}"),
    }

    // mcp_servers providers (if any) coexist untouched. This fixture has none,
    // so only App plugins are present; assert the inventory is exactly the four.
    let non_plugin: Vec<&ToolProvider> = providers
        .iter()
        .filter(|provider| !codex_cli::is_app_plugin_provider(provider))
        .collect();
    for provider in &non_plugin {
        assert_ne!(
            provider.surface,
            codex_cli::CODEX_APP_PLUGIN_SURFACE,
            "non-plugin providers must not claim the plugin surface"
        );
    }
}

#[test]
fn discovers_codex_app_plugins_windows() {
    let providers = parse_codex_fixture("codex_app_plugins_win.toml");
    let mut names: Vec<&str> = app_plugins(&providers)
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["browser", "computer-use", "corp-plugin", "presentations"],
        "Windows fixture must inventory its four App plugins"
    );
    for name in ["browser", "computer-use", "corp-plugin", "presentations"] {
        let plugin = plugin_named(&providers, name);
        assert_eq!(plugin.surface, codex_cli::CODEX_APP_PLUGIN_SURFACE);
        assert_eq!(
            plugin.extension.as_ref().unwrap().enabled,
            Some(true),
            "{name} should be enabled"
        );
    }
}

#[test]
fn codex_app_plugins_redact_absolute_paths() {
    // Forbidden home-directory roots from both fixtures, in every separator
    // form a parser might emit them.
    let forbidden = [
        "/Users/testuser",
        "C:\\Users\\testuser",
        "C:/Users/testuser",
        "\\\\corp-share",
        "testuser", // catch any other path component leaking the username
    ];

    let mut saw_redaction_marker = false;
    for fixture in ["codex_app_plugins_mac.toml", "codex_app_plugins_win.toml"] {
        let providers = parse_codex_fixture(fixture);
        let plugins = app_plugins(&providers);
        assert!(!plugins.is_empty(), "{fixture} produced no App plugins");

        for plugin in &plugins {
            // Serialize the whole provider (name, transport reason, extension
            // fields) to catch a leak in any field. source_path is the fixture
            // file path on the test host, not the simulated user's home, so it
            // cannot mask a fixture-content leak of `testuser`.
            let mut clone = (*plugin).clone();
            clone.source_path = None;
            let json = serde_json::to_string(&clone).unwrap();
            for needle in forbidden {
                assert!(
                    !json.contains(needle),
                    "{fixture}: provider {} leaked `{needle}`:\n{json}",
                    plugin.name
                );
            }
            if json.contains(codex_cli::REDACTED_ABS_PATH) {
                saw_redaction_marker = true;
            }
        }
    }

    assert!(
        saw_redaction_marker,
        "expected the {} marker to appear in place of a redacted absolute marketplace source",
        codex_cli::REDACTED_ABS_PATH
    );
}

#[test]
fn codex_projects_table_is_never_emitted() {
    for fixture in ["codex_app_plugins_mac.toml", "codex_app_plugins_win.toml"] {
        let providers = parse_codex_fixture(fixture);
        for provider in &providers {
            let mut clone = provider.clone();
            clone.source_path = None;
            let json = serde_json::to_string(&clone).unwrap();
            assert!(
                !json.contains("secret-client-work"),
                "{fixture}: provider {} leaked a [projects.*] path:\n{json}",
                provider.name
            );
            assert_ne!(
                provider.name, "secret-client-work",
                "{fixture}: a [projects.*] table was emitted as a provider"
            );
        }
    }
}

#[test]
fn cursor_metadata_file_is_enriched_when_command_or_url_present() {
    let spec = Cursor::spec();

    let stdio_path = fixture_path("cursor_project_enriched_stdio.json");
    let stdio_value = read_config(&stdio_path, spec.format).unwrap();
    let stdio_providers = parse_value(spec.name, &stdio_path, &stdio_value, spec.roots);
    assert_eq!(stdio_providers.len(), 1);
    let stdio = &stdio_providers[0];
    assert_eq!(stdio.name, "project-shell");
    match &stdio.transport {
        Transport::Stdio(cfg) => {
            assert_eq!(cfg.command, "node");
            assert_eq!(
                cfg.args,
                vec!["/opt/cursor/projects/alpha/mcps/project-shell/index.js".to_string()]
            );
            assert_eq!(
                cfg.env.get("NODE_ENV").map(String::as_str),
                Some("production")
            );
        }
        other => panic!("expected Stdio transport from metadata + command, got {other:?}"),
    }

    let http_path = fixture_path("cursor_project_enriched_http.json");
    let http_value = read_config(&http_path, spec.format).unwrap();
    let http_providers = parse_value(spec.name, &http_path, &http_value, spec.roots);
    assert_eq!(http_providers.len(), 1);
    let http = &http_providers[0];
    assert_eq!(http.name, "project-http");
    match &http.transport {
        Transport::HttpSse(cfg) => {
            assert_eq!(cfg.url, "https://mcp.example.com/cursor/project-http/sse");
            assert_eq!(
                cfg.headers.get("Authorization").map(String::as_str),
                Some("Bearer ${CURSOR_TOKEN}")
            );
        }
        other => panic!("expected HttpSse transport from metadata + url, got {other:?}"),
    }

    // Pure metadata-only files (no command/url) still surface as Unknown so
    // policy can flag them; the enrichment must not regress that signal.
    let metadata_only = fixture_path("cursor_project_1.json");
    let metadata_value = read_config(&metadata_only, spec.format).unwrap();
    let metadata_providers = parse_value(spec.name, &metadata_only, &metadata_value, spec.roots);
    assert_eq!(metadata_providers.len(), 1);
    assert_eq!(metadata_providers[0].name, "project-db");
    assert!(matches!(
        metadata_providers[0].transport,
        Transport::Unknown(_)
    ));
}

#[test]
fn discovers_project_and_workspace_configs() {
    let root = temp_target();
    write_fixture(&root, ".cursor/mcp.json", "cursor_1.json");
    write_fixture(
        &root,
        ".cursor/projects/acme/mcps/project-db/SERVER_METADATA.json",
        "cursor_project_1.json",
    );
    write_fixture(
        &root,
        ".cursor/projects/beta/mcps/project-docs/SERVER_METADATA.json",
        "cursor_project_2.json",
    );
    write_raw(
        &root,
        "projects/gamma/.cursor/mcp.json",
        r#"{"mcpServers":{"cursor-project":{"command":"node","args":["cursor-project.js"]}}}"#,
    );
    write_fixture(&root, "projects/alpha/.mcp.json", "claude_workspace_1.json");
    write_fixture(&root, "projects/beta/.mcp.json", "claude_workspace_2.json");
    write_fixture(
        &root,
        "projects/beta/.claude/settings.local.json",
        "claude_code_project_settings_local_1.json",
    );
    write_fixture(
        &root,
        "projects/alpha/.codex/config.toml",
        "codex_project_approval_only_1.toml",
    );
    write_fixture(&root, ".factory/mcp.json", "factory_1.json");
    write_fixture(&root, "projects/alpha/.factory/mcp.json", "factory_2.json");
    write_fixture(
        &root,
        ".gemini/antigravity/mcp_config.json",
        "antigravity_1.json",
    );
    write_fixture(&root, "projects/beta/.vscode/mcp.json", "vscode_2.json");
    write_raw(
        &root,
        "projects/alpha/node_modules/ignored/.mcp.json",
        r#"{"mcpServers":{"ignored":{"command":"npx","args":["ignored-mcp"]}}}"#,
    );
    write_raw(
        &root,
        "projects/alpha/node_modules/ignored/.codex/config.toml",
        r#"[mcp_servers.ignored_codex]
command = "npx"
args = ["ignored-codex"]
"#,
    );
    write_raw(
        &root,
        "projects/beta/node_modules/ignored/.vscode/mcp.json",
        r#"{"servers":{"ignored-vscode":{"command":"npx","args":["ignored-vscode"]}}}"#,
    );

    let providers = discover_all(&root).unwrap();
    let names: Vec<_> = providers
        .iter()
        .map(|provider| provider.name.as_str())
        .collect();
    for expected in [
        "linear",
        "project-db",
        "project-docs",
        "cursor-project",
        "repo-reader",
        "repo-shell",
        "repo-fetch",
        "claude-code-approval-state",
        "codex-cli-approval-state",
        "factory-local",
        "factory-project",
        "antigravity-local",
        "browser",
    ] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }
    assert!(
        !names.contains(&"ignored"),
        "workspace search descended into skipped dirs"
    );
    assert!(
        !names.contains(&"ignored_codex"),
        "Codex workspace search descended into skipped dirs"
    );
    assert!(
        !names.contains(&"ignored-vscode"),
        "VS Code workspace search descended into skipped dirs"
    );
    assert!(
        providers
            .iter()
            .any(|provider| provider.surface == "cursor")
    );
    assert!(
        providers
            .iter()
            .any(|provider| provider.surface == "claude-code")
    );
    assert!(
        providers
            .iter()
            .any(|provider| provider.surface == "factory")
    );
    assert!(
        providers
            .iter()
            .any(|provider| provider.surface == "antigravity")
    );
    assert!(
        providers
            .iter()
            .any(|provider| provider.surface == "codex-cli")
    );
    assert!(
        providers
            .iter()
            .any(|provider| provider.surface == "vscode")
    );

    let dry_run = dry_run_surfaces(&root).unwrap();
    let claude = dry_run
        .iter()
        .find(|surface| surface.surface == "claude-code")
        .unwrap();
    assert!(claude.entries.iter().any(|entry| {
        entry.source == "workspace-search" && entry.path.ends_with(".claude/settings.local.json")
    }));
    let codex = dry_run
        .iter()
        .find(|surface| surface.surface == "codex-cli")
        .unwrap();
    assert!(codex.entries.iter().any(|entry| {
        entry.source == "workspace-search" && entry.path.ends_with(".codex/config.toml")
    }));
    let vscode = dry_run
        .iter()
        .find(|surface| surface.surface == "vscode")
        .unwrap();
    assert!(vscode.entries.iter().any(|entry| {
        entry.source == "workspace-search" && entry.path.ends_with(".vscode/mcp.json")
    }));
    let cursor = dry_run
        .iter()
        .find(|surface| surface.surface == "cursor")
        .unwrap();
    assert!(cursor.entries.iter().any(|entry| {
        entry.source == "workspace-search"
            && entry
                .path
                .ends_with(Path::new("projects/gamma/.cursor/mcp.json"))
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_cursor_global_user_and_project_configs() {
    let root = temp_target();
    write_raw(
        &root,
        ".cursor/mcp.json",
        r#"{"mcpServers":{"cursor-global":{"url":"https://mcp.cursor.example/global/sse"}}}"#,
    );
    write_raw(
        &root,
        "alice/.cursor/mcp.json",
        r#"{"mcpServers":{"cursor-windows-user":{"command":"node","args":["cursor-user.js"]}}}"#,
    );
    write_raw(
        &root,
        "workspaces/app/.cursor/mcp.json",
        r#"{"mcpServers":{"cursor-project":{"command":"node","args":["cursor-project.js"]}}}"#,
    );
    write_raw(
        &root,
        "workspaces/app/node_modules/pkg/.cursor/mcp.json",
        r#"{"mcpServers":{"cursor-ignored":{"command":"node","args":["ignored.js"]}}}"#,
    );

    let providers = discover_all(&root).unwrap();
    let names: Vec<_> = providers
        .iter()
        .filter(|provider| provider.surface == "cursor")
        .map(|provider| provider.name.as_str())
        .collect();
    for expected in ["cursor-global", "cursor-windows-user", "cursor-project"] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }
    assert!(
        !names.contains(&"cursor-ignored"),
        "Cursor workspace search descended into skipped dirs"
    );

    let cursor_sources: Vec<_> = providers
        .iter()
        .filter(|provider| provider.surface == "cursor")
        .filter_map(|provider| provider.source_path.as_ref())
        .collect();
    for expected in [
        ".cursor/mcp.json",
        "alice/.cursor/mcp.json",
        "workspaces/app/.cursor/mcp.json",
    ] {
        assert!(
            cursor_sources
                .iter()
                .any(|path| path.ends_with(Path::new(expected))),
            "missing Cursor source {expected}: {cursor_sources:?}"
        );
    }

    let dry_run = dry_run_surfaces(&root).unwrap();
    let cursor = dry_run
        .iter()
        .find(|surface| surface.surface == "cursor")
        .unwrap();
    assert!(cursor.entries.iter().any(|entry| {
        entry.source == "literal-path" && entry.path.ends_with(Path::new(".cursor/mcp.json"))
    }));
    assert!(cursor.entries.iter().any(|entry| {
        entry.source == "workspace-search"
            && entry
                .path
                .ends_with(Path::new("workspaces/app/.cursor/mcp.json"))
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_literal_configs_below_user_home_roots() {
    let root = temp_target();
    write_fixture(
        &root,
        "admin/Library/Application Support/Claude/claude_desktop_config.json",
        "claude_desktop_1.json",
    );
    write_fixture(&root, "admin/.codex/config.toml", "codex_1.toml");

    let providers = discover_all(&root).unwrap();
    let surface_names: Vec<_> = providers
        .iter()
        .map(|provider| (provider.surface.as_str(), provider.name.as_str()))
        .collect();
    assert!(
        surface_names.contains(&("claude-desktop", "filesystem")),
        "missing Claude Desktop config below user home: {surface_names:?}"
    );
    assert!(
        surface_names.contains(&("codex-cli", "filesystem")),
        "missing Codex config below user home: {surface_names:?}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_windows_user_config_paths() {
    let root = temp_target();
    write_fixture(
        &root,
        "AppData/Roaming/Claude/claude_desktop_config.json",
        "claude_desktop_1.json",
    );
    write_fixture(&root, ".cursor/mcp.json", "cursor_1.json");
    write_raw(
        &root,
        ".continue/config.json",
        r#"{"mcpServers":{"continue-json":{"command":"uvx","args":["continue-json-mcp"]}}}"#,
    );
    write_raw(
        &root,
        ".claude/settings.json",
        r#"{"mcpServers":{"claude-settings":{"command":"npx","args":["-y","claude-settings-mcp"]}}}"#,
    );
    write_fixture(&root, ".codex/config.toml", "codex_1.toml");
    write_fixture(&root, ".factory/mcp.json", "factory_1.json");
    write_fixture(
        &root,
        "AppData/Roaming/Code/User/settings.json",
        "vscode_1.json",
    );

    let providers = discover_all(&root).unwrap();
    let surfaces: Vec<_> = providers
        .iter()
        .map(|provider| provider.surface.as_str())
        .collect();
    for expected in [
        "claude-desktop",
        "cursor",
        "continue",
        "claude-code",
        "codex-cli",
        "factory",
        "vscode",
    ] {
        assert!(
            surfaces.contains(&expected),
            "missing {expected}: {surfaces:?}"
        );
    }
    assert!(
        !surfaces.contains(&"zed"),
        "Zed has no Windows build and should not appear in Windows fixture"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_linux_user_config_paths() {
    let root = temp_target();
    write_raw(
        &root,
        ".config/Cursor/mcp.json",
        r#"{"mcpServers":{"cursor-linux":{"command":"node","args":["cursor-linux.js"]}}}"#,
    );
    write_raw(
        &root,
        ".config/Code/User/mcp.json",
        r#"{"servers":{"vscode-linux-mcp":{"command":"node","args":["vscode-linux-mcp.js"]}}}"#,
    );
    write_raw(
        &root,
        ".config/Code/User/settings.json",
        r#"{"mcp":{"servers":{"vscode-linux-settings":{"url":"https://mcp.vscode.example/linux/sse"}}}}"#,
    );
    // Claude Desktop has no official Linux build (#403): the removed `.config/Claude`
    // path must NOT yield a claude-desktop surface even when the file is present.
    write_raw(
        &root,
        ".config/Claude/claude_desktop_config.json",
        r#"{"mcpServers":{"should-not-appear":{"command":"x"}}}"#,
    );

    let providers = discover_all(&root).unwrap();
    let surface_names: Vec<_> = providers
        .iter()
        .map(|provider| (provider.surface.as_str(), provider.name.as_str()))
        .collect();
    assert!(
        !surface_names
            .iter()
            .any(|(surface, _)| *surface == "claude-desktop"),
        "claude-desktop must not be discovered on Linux (#403, no official Linux app): {surface_names:?}"
    );
    for expected in [
        ("cursor", "cursor-linux"),
        ("vscode", "vscode-linux-mcp"),
        ("vscode", "vscode-linux-settings"),
    ] {
        assert!(
            surface_names.contains(&expected),
            "missing {expected:?}: {surface_names:?}"
        );
    }

    let dry_run = dry_run_surfaces(&root).unwrap();
    let cursor = dry_run
        .iter()
        .find(|surface| surface.surface == "cursor")
        .unwrap();
    assert!(cursor.entries.iter().any(|entry| {
        entry.source == "literal-path" && entry.path.ends_with(Path::new(".config/Cursor/mcp.json"))
    }));
    let vscode = dry_run
        .iter()
        .find(|surface| surface.surface == "vscode")
        .unwrap();
    assert!(vscode.entries.iter().any(|entry| {
        entry.source == "literal-path"
            && entry
                .path
                .ends_with(Path::new(".config/Code/User/mcp.json"))
    }));
    assert!(vscode.entries.iter().any(|entry| {
        entry.source == "literal-path"
            && entry
                .path
                .ends_with(Path::new(".config/Code/User/settings.json"))
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_windows_store_claude_config_paths() {
    let root = temp_target();
    write_fixture(
        &root,
        "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/claude_desktop_config.json",
        "claude_desktop_1.json",
    );

    let providers = discover_all(&root).unwrap();
    assert!(
        providers.iter().any(|provider| {
            provider.surface == "claude-desktop" && provider.name == "filesystem"
        }),
        "missing Store/UWP Claude Desktop config provider: {providers:?}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_windows_classic_and_store_claude_config_paths_together() {
    let root = temp_target();
    write_fixture(
        &root,
        "AppData/Roaming/Claude/claude_desktop_config.json",
        "claude_desktop_1.json",
    );
    write_fixture(
        &root,
        "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/claude_desktop_config.json",
        "claude_desktop_1.json",
    );

    let providers = discover_all(&root).unwrap();
    let claude_providers: Vec<_> = providers
        .iter()
        .filter(|provider| provider.surface == "claude-desktop")
        .collect();
    assert_eq!(
        claude_providers.len(),
        2,
        "expected both Windows config paths"
    );
    assert!(claude_providers.iter().any(|provider| {
        provider.source_path.as_ref().is_some_and(|path| {
            path.ends_with(Path::new(
                "AppData/Roaming/Claude/claude_desktop_config.json",
            ))
        })
    }));
    assert!(claude_providers.iter().any(|provider| {
        provider.source_path.as_ref().is_some_and(|path| {
            path.ends_with(Path::new(
                "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/claude_desktop_config.json",
            ))
        })
    }));

    let dry_run = dry_run_surfaces(&root).unwrap();
    let claude = dry_run
        .iter()
        .find(|surface| surface.surface == "claude-desktop")
        .unwrap();
    assert!(claude.entries.iter().any(|entry| {
        entry.source == "literal-path"
            && entry.path.ends_with(Path::new(
                "AppData/Roaming/Claude/claude_desktop_config.json",
            ))
    }));
    assert!(claude.entries.iter().any(|entry| {
        entry.source == "package-root-search"
            && entry.path
                .ends_with(Path::new(
                    "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/claude_desktop_config.json",
                ))
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_claude_cowork_state_from_macos_user_data_root() {
    let root = temp_target();
    let claude_root = "Library/Application Support/Claude";
    write_raw(
        &root,
        &format!("{claude_root}/config.json"),
        r#"{"dxt:allowlistCache":{"plugins":["slack"]}}"#,
    );
    write_raw(
        &root,
        &format!("{claude_root}/IndexedDB/https_claude.ai_0.indexeddb.leveldb/CURRENT"),
        "MANIFEST-000001\n",
    );
    write_raw(
        &root,
        &format!("{claude_root}/Local Storage/leveldb/CURRENT"),
        "MANIFEST-000001\n",
    );

    let providers = discover_all(&root).unwrap();
    let provider_names: Vec<_> = providers
        .iter()
        .map(|provider| provider.name.as_str())
        .collect();
    for expected in [
        claude_cowork::APPROVAL_CACHE_PROVIDER_NAME,
        claude_cowork::INDEXEDDB_CONNECTOR_STORE_PROVIDER_NAME,
        claude_cowork::LOCAL_STORAGE_CONNECTOR_STORE_PROVIDER_NAME,
    ] {
        assert!(
            provider_names.contains(&expected),
            "missing {expected}: {provider_names:?}"
        );
    }

    let dry_run = dry_run_surfaces(&root).unwrap();
    let cowork = dry_run
        .iter()
        .find(|surface| surface.surface == "claude-cowork")
        .unwrap();
    assert!(cowork.detected);
    assert!(cowork.entries.iter().any(|entry| {
        entry.source == "literal-path"
            && entry
                .path
                .ends_with("Library/Application Support/Claude/config.json")
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_claude_cowork_remote_mcp_from_macos_session_descriptors() {
    let root = temp_target();
    let session_root =
        "Library/Application Support/Claude/local-agent-mode-sessions/account-123/org-456";
    write_raw(
        &root,
        &format!("{session_root}/local_123.json"),
        r#"{
  "emailAddress": "secret@example.com",
  "cwd": "/Users/example/private",
  "userSelectedFolders": ["/Users/example/private"],
  "remoteMcpServersConfig": [
    {
      "name": "EXA.ai",
      "uuid": "e786afac-3991-4dc4-8334-68fdbf06aa9e",
      "tools": [
        {"name": "web_search_exa"},
        {"name": "company_research_exa"}
      ]
    },
    {
      "uuid": "7de6993b-41e7-46dd-9ae0-1f3108a607c6",
      "tools": [
        {"name": "create_file"}
      ]
    }
  ]
}"#,
    );

    let providers = discover_all(&root).unwrap();
    let exa = providers
        .iter()
        .find(|provider| provider.name == "EXA.ai")
        .expect("missing EXA.ai provider");
    assert!(matches!(exa.transport, Transport::Unknown(_)));
    assert_eq!(
        exa.declared_tools,
        vec![
            "company_research_exa".to_string(),
            "web_search_exa".to_string()
        ]
    );

    let uuid_only = providers
        .iter()
        .find(|provider| provider.name == "7de6993b-41e7-46dd-9ae0-1f3108a607c6")
        .expect("missing UUID fallback provider");
    assert_eq!(uuid_only.declared_tools, vec!["create_file".to_string()]);

    let dry_run = dry_run_surfaces(&root).unwrap();
    let cowork = dry_run
        .iter()
        .find(|surface| surface.surface == "claude-cowork")
        .unwrap();
    assert!(cowork.detected);
    assert!(cowork.entries.iter().any(|entry| {
        entry.source == "glob-path"
            && entry.path.ends_with(
                "Library/Application Support/Claude/local-agent-mode-sessions/account-123/org-456/local_123.json"
            )
    }));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn discovers_claude_cowork_mcpb_extensions_from_store_package() {
    let root = temp_target();
    let claude_root = "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude";
    write_raw(
        &root,
        &format!("{claude_root}/claude_desktop_config.json"),
        r#"{"theme":"dark"}"#,
    );
    write_fixture(
        &root,
        &format!("{claude_root}/extensions-installations.json"),
        "claude_cowork_extensions_1.json",
    );
    write_raw(
        &root,
        &format!(
            "{claude_root}/Claude Extensions/ant.dir.gh.wonderwhy-er.desktopcommandermcp/manifest.json"
        ),
        r#"{"name":"Desktop Commander","version":"0.2.8"}"#,
    );
    write_raw(
        &root,
        &format!(
            "{claude_root}/Claude Extensions Settings/ant.dir.gh.wonderwhy-er.desktopcommandermcp.json"
        ),
        r#"{"isEnabled":true}"#,
    );

    let providers = discover_all(&root).unwrap();
    let provider = providers
        .iter()
        .find(|provider| provider.surface == "claude-cowork")
        .expect("missing Claude Cowork extension provider");
    let extension = provider.extension.as_ref().unwrap();
    assert_eq!(extension.id, "ant.dir.gh.wonderwhy-er.desktopcommandermcp");
    assert_eq!(extension.signature_status.as_deref(), Some("unsigned"));
    assert_eq!(extension.enabled, Some(true));
    assert!(provider.declared_tools.contains(&"read_file".to_string()));
    match &provider.transport {
        Transport::Stdio(stdio) => {
            assert_eq!(stdio.command, "node");
            assert!(
                stdio.args[0].ends_with(
                    "Claude Extensions/ant.dir.gh.wonderwhy-er.desktopcommandermcp/dist/index.js"
                ),
                "dirname substitution failed: {:?}",
                stdio.args
            );
        }
        other => panic!("expected stdio transport, got {other:?}"),
    }

    let dry_run = dry_run_surfaces(&root).unwrap();
    let cowork = dry_run
        .iter()
        .find(|surface| surface.surface == "claude-cowork")
        .unwrap();
    assert!(cowork.detected);
    assert!(
        cowork
            .entries
            .iter()
            .any(|entry| entry.source == "package-root-search")
    );
    assert!(
        cowork
            .entries
            .iter()
            .any(|entry| entry.source == "package-root-auxiliary")
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn scope_catalog_marks_windows_appdata_paths() {
    let catalog = aibom_scanner::mcp::discovery::scope_catalog();
    let claude = catalog
        .iter()
        .find(|entry| entry.surface == "claude-desktop")
        .unwrap();
    assert!(claude.os_paths.iter().any(|path| {
        path.os == "windows" && path.path == "AppData/Roaming/Claude/claude_desktop_config.json"
    }));
    assert!(claude.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-search"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/claude_desktop_config.json"
    }));

    let claude_code = catalog
        .iter()
        .find(|entry| entry.surface == "claude-code")
        .unwrap();
    assert!(claude_code.os_paths.iter().any(|path| {
        path.os == "macos"
            && path.source == "glob-path"
            && path.path
                == "Library/Application Support/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json"
    }));
    assert!(claude_code.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-search"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json"
    }));

    let claude_code_desktop = catalog
        .iter()
        .find(|entry| entry.surface == "claude-code-desktop")
        .unwrap();
    assert_eq!(
        claude_code_desktop.parser,
        aibom_scanner::mcp::discovery::ParserKind::ClaudeCodeDesktopSessions
    );
    assert!(claude_code_desktop.os_paths.iter().any(|path| {
        path.os == "macos"
            && path.source == "glob-path"
            && path.path
                == "Library/Application Support/Claude/claude-code-sessions/*/*/local_*.json"
    }));
    assert!(claude_code_desktop.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-search"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/claude-code-sessions/*/*/local_*.json"
    }));

    let cowork = catalog
        .iter()
        .find(|entry| entry.surface == "claude-cowork")
        .unwrap();
    assert_eq!(
        cowork.parser,
        aibom_scanner::mcp::discovery::ParserKind::ClaudeCoworkMcpbExtensions
    );
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "macos"
            && path.source == "literal-path"
            && path.path == "Library/Application Support/Claude/config.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "macos"
            && path.source == "glob-path"
            && path.path
                == "Library/Application Support/Claude/local-agent-mode-sessions/*/*/local_*.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "glob-path"
            && path.path == "AppData/Roaming/Claude/local-agent-mode-sessions/*/*/local_*.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "literal-path"
            && path.path == "AppData/Roaming/Claude/config.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-search"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/extensions-installations.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-search"
            && path.path == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/config.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-search"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/local_*.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-search"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_plugins/installed_plugins.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-search"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_settings.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-auxiliary"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/IndexedDB/**/*"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-auxiliary"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_plugins/**/*.mcp.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-search"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/rpm/plugin_*/.mcp.json"
    }));
    assert!(cowork.os_paths.iter().any(|path| {
        path.os == "windows"
            && path.source == "package-root-auxiliary"
            && path.path
                == "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/rpm/plugin_*/.claude-plugin/plugin.json"
    }));

    let codex_app_global = catalog
        .iter()
        .find(|entry| {
            entry.surface == "codex-app"
                && entry
                    .paths
                    .iter()
                    .any(|path| path.as_ref() == ".codex/.codex-global-state.json")
        })
        .unwrap();
    assert_eq!(
        codex_app_global.parser,
        aibom_scanner::mcp::discovery::ParserKind::CodexGlobalState
    );

    let vscode = catalog
        .iter()
        .find(|entry| entry.surface == "vscode")
        .unwrap();
    assert!(vscode.os_paths.iter().any(|path| {
        path.os == "windows" && path.path == "AppData/Roaming/Code/User/settings.json"
    }));
    assert!(
        vscode.os_paths.iter().any(|path| {
            path.os == "windows" && path.path == "AppData/Roaming/Code/User/mcp.json"
        })
    );
}

fn temp_target() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TEMP_TARGET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "reeve-discovery-test-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

// Admin running on a shared machine: pointing --target at a parent of user
// home directories discovers each immediate child home's configs (one level
// deep). It does NOT recurse the whole disk: a config two levels down is not
// reached by this literal-home expansion. claude-desktop has no workspace
// search, so the literal-home expansion is the only mechanism in play.
#[test]
fn discover_target_parent_of_homes_finds_each_immediate_child() {
    let root = temp_target();
    let rel = "Library/Application Support/Claude/claude_desktop_config.json";
    let write_config = |home: PathBuf, server: &str| {
        let path = home.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            format!(r#"{{"mcpServers":{{"{server}":{{"command":"uvx","args":["x"]}}}}}}"#),
        )
        .unwrap();
    };

    write_config(root.join("alice"), "alice-server");
    write_config(root.join("bob"), "bob-server");
    // Two levels deep: must NOT be discovered by the literal-home expansion.
    write_config(root.join("nested").join("charlie"), "charlie-server");

    let providers = discover_all(&root).unwrap();
    let names: Vec<&str> = providers
        .iter()
        .filter(|provider| provider.surface == "claude-desktop")
        .map(|provider| provider.name.as_str())
        .collect();

    assert!(
        names.contains(&"alice-server"),
        "immediate child home alice not discovered: {names:?}"
    );
    assert!(
        names.contains(&"bob-server"),
        "immediate child home bob not discovered: {names:?}"
    );
    assert!(
        !names.contains(&"charlie-server"),
        "two-levels-deep config must not be discovered (no whole-disk recursion): {names:?}"
    );

    fs::remove_dir_all(&root).ok();
}

#[test]
fn scope_catalog_lists_project_workspace_searches() {
    let catalog = aibom_scanner::mcp::discovery::scope_catalog();
    let claude = catalog
        .iter()
        .find(|entry| entry.surface == "claude-code")
        .unwrap();
    assert_eq!(
        claude.workspace_search.unwrap().filename,
        ".mcp.json",
        "Claude Code must keep project .mcp.json search"
    );
    assert!(
        claude
            .workspace_searches
            .iter()
            .any(|search| search.filename == "settings.local.json"
                && search.parent_dir == Some(".claude")
                && search.max_depth == 5),
        "Claude Code must list bounded settings.local.json search"
    );

    let codex = catalog
        .iter()
        .find(|entry| entry.surface == "codex-cli")
        .unwrap();
    assert!(
        codex
            .workspace_search
            .is_some_and(|search| search.filename == "config.toml"
                && search.parent_dir == Some(".codex")
                && search.max_depth == 5),
        "Codex must list bounded .codex/config.toml search"
    );

    let vscode = catalog
        .iter()
        .find(|entry| entry.surface == "vscode")
        .unwrap();
    assert!(
        vscode
            .workspace_search
            .is_some_and(|search| search.filename == "mcp.json"
                && search.parent_dir == Some(".vscode")
                && search.max_depth == 5),
        "VS Code must list bounded .vscode/mcp.json search"
    );

    let cursor = catalog
        .iter()
        .find(|entry| entry.surface == "cursor")
        .unwrap();
    assert!(
        cursor
            .workspace_searches
            .iter()
            .any(|search| search.filename == "mcp.json"
                && search.parent_dir == Some(".cursor")
                && search.max_depth == 6),
        "Cursor must list bounded project .cursor/mcp.json search"
    );
    assert!(
        cursor
            .workspace_searches
            .iter()
            .any(|search| search.filename == "mcpServers.json"
                && search.parent_dir == Some(".cursor")
                && search.max_depth == 6),
        "Cursor must list bounded project .cursor/mcpServers.json search"
    );
}

fn write_fixture(root: &Path, rel: &str, fixture: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::copy(fixture_path(fixture), path).unwrap();
}

fn write_raw(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}
