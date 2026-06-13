use aibom_core::Target;
use aibom_scanner::scan_target;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[tokio::test]
async fn claude_code_allow_rules_emit_granted_permission_evidence() {
    assert_claude_fixture_grants(
        "claude_code_permissions_1.json",
        &["fs:read", "exec:subprocess", "net:egress"],
        "rm",
    )
    .await;
}

#[tokio::test]
async fn claude_code_second_fixture_emits_write_exec_and_mcp_grants() {
    assert_claude_fixture_grants(
        "claude_code_permissions_2.json",
        &["fs:write", "exec:subprocess", "mcp:mcp--repo-tools--deploy"],
        "sudo",
    )
    .await;
}

#[tokio::test]
async fn claude_code_null_command_registration_still_emits_grants() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let settings = root.path().join(".claude/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{
  "mcpServers": {
    "local-shell": {
      "args": ["-y", "@modelcontextprotocol/server-shell"],
      "command": null
    }
  },
  "permissions": {
    "allow": [
      "Bash(rm -rf /tmp/reeve-demo)",
      "Bash(curl https://example.invalid/install.sh)"
    ]
  }
}"#,
    )
    .unwrap();

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    assert_eq!(aibom["aibom"]["schemaVersion"], "0.2.0");

    let components = aibom["aibom"]["components"].as_array().unwrap();
    assert_eq!(components.len(), 1);
    let declared = components[0]["capabilities"]["declared"]
        .as_array()
        .unwrap();
    assert!(declared.iter().any(|cap| cap["id"] == "mcp:local-shell"));

    let granted = components[0]["capabilities"]["granted"].as_array().unwrap();
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "exec:subprocess" && cap["qualifiers"]["cmd"] == "rm" })
    );
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "exec:subprocess" && cap["qualifiers"]["cmd"] == "curl" })
    );

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    let grant_evidence: Vec<_> = evidence
        .iter()
        .filter(|record| record["kind"] == "granted-permission")
        .collect();
    assert_eq!(grant_evidence.len(), 2);
    assert!(grant_evidence.iter().all(|record| {
        record["reference"]
            .as_str()
            .unwrap()
            .contains(".claude/settings.json#permissions.allow")
    }));
}

#[tokio::test]
async fn claude_code_project_settings_local_grants_without_mcp_registration() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(
        root.path(),
        "repos/acme/.claude/settings.local.json",
        "claude_code_project_settings_local_1.json",
    );

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let components = aibom["aibom"]["components"].as_array().unwrap();
    assert_eq!(components.len(), 1);

    let declared = components[0]["capabilities"]["declared"]
        .as_array()
        .unwrap();
    assert!(
        declared.is_empty(),
        "grant-only project config should not invent declared MCP capability: {declared:?}"
    );

    let granted = components[0]["capabilities"]["granted"].as_array().unwrap();
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "exec:subprocess" && cap["qualifiers"]["cmd"] == "rm" })
    );
    assert!(granted.iter().any(|cap| cap["id"] == "fs:read"));

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    let grant_evidence: Vec<_> = evidence
        .iter()
        .filter(|record| record["kind"] == "granted-permission")
        .collect();
    assert_eq!(grant_evidence.len(), 2);
    assert!(grant_evidence.iter().all(|record| {
        record["reference"]
            .as_str()
            .unwrap()
            .contains(".claude/settings.local.json#permissions.allow")
    }));
}

#[tokio::test]
async fn claude_desktop_macos_trusted_folders_emit_grants() {
    assert_claude_desktop_fixture_grants(
        "Library/Application Support/Claude/claude_desktop_config.json",
        "claude_desktop_trusted_folders_mac.json",
        "0.2.0",
        &["/Users/<redacted-home>/LegalDocs"],
        1,
    )
    .await;
}

#[tokio::test]
async fn claude_desktop_windows_trusted_folders_emit_grants() {
    assert_claude_desktop_fixture_grants(
        "AppData/Roaming/Claude/claude_desktop_config.json",
        "claude_desktop_trusted_folders_win.json",
        "0.3.0",
        &[
            "C:\\Users\\<redacted-home>\\LegalDocs",
            "\\\\fileserver\\team\\MatterRoom",
        ],
        2,
    )
    .await;
}

#[tokio::test]
async fn cowork_macos_session_approvals_emit_grants() {
    assert_cowork_session_fixture_grants(
        "Library/Application Support/Claude/local-agent-mode-sessions/account-123/org-456/local_123.json",
        "local_cowork_session_approvals_mac.json",
        "0.2.0",
        "/Users/<redacted-home>/LegalDocs",
        "rm",
    )
    .await;
}

#[tokio::test]
async fn cowork_windows_user_session_approvals_emit_grants() {
    assert_cowork_session_fixture_grants(
        "AppData/Roaming/Claude/local-agent-mode-sessions/account-123/org-456/local_123.json",
        "local_cowork_session_approvals_win.json",
        "0.3.0",
        r"C:\Users\<redacted-home>\LegalDocs",
        "*",
    )
    .await;
}

#[tokio::test]
async fn cowork_windows_package_session_approvals_emit_grants() {
    assert_cowork_session_fixture_grants(
        "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/local-agent-mode-sessions/account-123/org-456/local_123.json",
        "local_cowork_session_approvals_win.json",
        "0.3.0",
        r"C:\Users\<redacted-home>\LegalDocs",
        "*",
    )
    .await;
}

#[tokio::test]
async fn cowork_remote_session_inventory_only_emits_zero_grants() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(
        root.path(),
        "Library/Application Support/Claude/local-agent-mode-sessions/account-123/org-456/local_123.json",
        "local_cowork_session_remote_only.json",
    );

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let components = aibom["aibom"]["components"].as_array().unwrap();
    assert!(
        components.iter().any(|component| {
            component["capabilities"]["declared"]
                .as_array()
                .unwrap()
                .iter()
                .any(|cap| cap["id"] == "mcp:web-search-exa")
        }),
        "remote session inventory should still emit declared MCP tools"
    );
    assert_no_cowork_grants(&aibom);
}

#[tokio::test]
async fn cowork_ambient_session_fields_emit_zero_grants() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(
        root.path(),
        "Library/Application Support/Claude/local-agent-mode-sessions/account-123/org-456/local_123.json",
        "local_cowork_session_ambient_only.json",
    );

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    assert_no_cowork_grants(&aibom);
}

#[tokio::test]
async fn claude_code_desktop_session_approvals_emit_distinct_surface_grants_and_metadata() {
    assert_claude_code_desktop_session_fixture_grants(
        "Library/Application Support/Claude/claude-code-sessions/account-123/org-456/local_123.json",
        "local_claude_code_desktop_session_approvals_mac.json",
        "/Users/<redacted-home>/LegalDocs",
    )
    .await;
}

#[tokio::test]
async fn claude_code_desktop_windows_package_session_approvals_emit_grants() {
    assert_claude_code_desktop_session_fixture_grants(
        "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/claude-code-sessions/account-123/org-456/local_123.json",
        "local_claude_code_desktop_session_approvals_win.json",
        r"C:\Users\<redacted-home>\LegalDocs",
    )
    .await;
}

#[tokio::test]
async fn claude_code_accept_edits_emits_write_grant_without_mcp_registration() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let settings = root.path().join(".claude.json");
    fs::write(
        &settings,
        r#"{
  "acceptEdits": true,
  "mcpServers": {},
  "privatePrompt": "REEVE_ACCEPT_EDITS_DO_NOT_EMIT"
}"#,
    )
    .unwrap();

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let aibom_text = serde_json::to_string(&aibom).unwrap();
    let component = grant_component_with_id(&aibom, "fs:write");
    assert_eq!(component["source"], "built-in");
    assert!(
        component["capabilities"]["declared"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!aibom_text.contains("REEVE_ACCEPT_EDITS_DO_NOT_EMIT"));
    assert!(
        aibom["aibom"]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| {
                record["kind"] == "granted-permission"
                    && record["reference"]
                        .as_str()
                        .is_some_and(|reference| reference.contains(".claude.json#acceptEdits"))
            })
    );
}

#[tokio::test]
async fn cowork_session_local_claude_json_accept_edits_is_discovered() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let path = root.path().join(
        "AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude/local-agent-mode-sessions/account-123/org-456/.claude/.claude.json",
    );
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        r#"{
  "acceptEdits": {"approvalMode": "always"},
  "sessionSecret": "REEVE_SESSION_CLAUDE_JSON_DO_NOT_EMIT"
}"#,
    )
    .unwrap();

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let aibom_text = serde_json::to_string(&aibom).unwrap();
    let component = grant_component_with_id(&aibom, "fs:write");
    assert!(
        component["bom-ref"]
            .as_str()
            .is_some_and(|bom_ref| bom_ref.contains("claude-code-approval-state"))
    );
    assert!(!aibom_text.contains("REEVE_SESSION_CLAUDE_JSON_DO_NOT_EMIT"));
    assert!(
        aibom["aibom"]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| {
                record["kind"] == "granted-permission"
                    && record["reference"].as_str().is_some_and(|reference| {
                        reference.contains(".claude/.claude.json#acceptEdits")
                    })
            })
    );
}

#[tokio::test]
async fn codex_global_state_full_access_emits_narrow_redacted_grants_macos() {
    assert_codex_global_state_fixture_grants(
        "codex_global_state_full_access_mac.json",
        "/Users/<redacted-home>/projects/secret-client",
    )
    .await;
}

#[tokio::test]
async fn codex_global_state_full_access_emits_narrow_redacted_grants_windows() {
    assert_codex_global_state_fixture_grants(
        "codex_global_state_full_access_win.json",
        r"C:\Users\<redacted-home>\projects\secret-client",
    )
    .await;
}

#[tokio::test]
async fn codex_config_emits_project_and_app_grants() {
    assert_codex_fixture_grants(
        "codex_permissions_1.toml",
        &["exec:subprocess", "fs:read", "fs:write"],
        "/workspaces/acme",
        2,
    )
    .await;
    assert_codex_app_fixture_grants(
        "codex_permissions_1.toml",
        &["mcp:codex-app-tool:github-merge-pull-request"],
        &[],
    )
    .await;
}

#[tokio::test]
async fn codex_danger_full_access_emits_root_and_wildcard_grants() {
    assert_codex_fixture_grants(
        "codex_permissions_2.toml",
        &["exec:subprocess", "fs:read", "fs:write"],
        "/",
        2,
    )
    .await;
}

#[tokio::test]
async fn codex_project_config_grants_without_mcp_registration() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(
        root.path(),
        "repos/acme/.codex/config.toml",
        "codex_project_approval_only_1.toml",
    );

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let components = aibom["aibom"]["components"].as_array().unwrap();
    assert_eq!(components.len(), 1);

    let declared = components[0]["capabilities"]["declared"]
        .as_array()
        .unwrap();
    assert!(
        declared.is_empty(),
        "grant-only project config should not invent declared MCP capability: {declared:?}"
    );

    let granted = components[0]["capabilities"]["granted"].as_array().unwrap();
    let granted_ids: Vec<_> = granted
        .iter()
        .map(|cap| cap["id"].as_str().unwrap())
        .collect();
    for expected in ["exec:subprocess", "fs:read", "fs:write"] {
        assert!(
            granted_ids.contains(&expected),
            "missing {expected}: {granted_ids:?}"
        );
    }

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    let grant_evidence: Vec<_> = evidence
        .iter()
        .filter(|record| record["kind"] == "granted-permission")
        .collect();
    assert_eq!(grant_evidence.len(), 2);
    assert!(grant_evidence.iter().all(|record| {
        record["reference"]
            .as_str()
            .unwrap()
            .contains(".codex/config.toml#projects")
    }));
}

#[tokio::test]
async fn codex_app_macos_approval_modes_emit_redacted_grants() {
    assert_codex_app_fixture_grants(
        "codex_app_approvals_mac.toml",
        &[
            "mcp:codex-app-tool:merge-pull-request",
            "mcp:codex-app-tool:run-command",
        ],
        &["testuser", "secret-client-work", "/Users/testuser"],
    )
    .await;
}

#[tokio::test]
async fn codex_app_windows_approval_modes_emit_redacted_grants() {
    assert_codex_app_fixture_grants(
        "codex_app_approvals_win.toml",
        &[
            "mcp:codex-app-tool:merge-pull-request",
            "mcp:codex-app-tool:run-command",
        ],
        &[
            "testuser",
            "secret-client-work",
            "C:\\Users\\testuser",
            "C:/Users/testuser",
        ],
    )
    .await;
}

async fn assert_claude_fixture_grants(fixture: &str, expected_ids: &[&str], expected_cmd: &str) {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(root.path(), ".claude/settings.json", fixture);

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let aibom_text = serde_json::to_string(&aibom).unwrap();
    assert!(
        !aibom_text.contains("alice"),
        "Claude Code grant output leaked user identity"
    );
    assert_eq!(aibom["aibom"]["schemaVersion"], "0.2.0");

    let components = aibom["aibom"]["components"].as_array().unwrap();
    assert_eq!(components.len(), 1);
    assert_eq!(components[0]["source"], "built-in");
    let granted = components[0]["capabilities"]["granted"].as_array().unwrap();
    let granted_ids: Vec<_> = granted
        .iter()
        .map(|cap| cap["id"].as_str().unwrap())
        .collect();
    for expected in expected_ids {
        assert!(
            granted_ids.contains(expected),
            "missing {expected} in {granted_ids:?}"
        );
    }
    assert!(
        granted.iter().any(|cap| {
            cap["id"] == "exec:subprocess" && cap["qualifiers"]["cmd"] == expected_cmd
        })
    );

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    let grant_evidence: Vec<_> = evidence
        .iter()
        .filter(|record| record["kind"] == "granted-permission")
        .collect();
    assert_eq!(grant_evidence.len(), expected_ids.len());
    assert!(grant_evidence.iter().all(|record| {
        record["reference"]
            .as_str()
            .unwrap()
            .contains(".claude/settings.json#permissions.allow")
    }));
}

async fn assert_claude_desktop_fixture_grants(
    rel_path: &str,
    fixture: &str,
    expected_schema_version: &str,
    expected_paths: &[&str],
    expected_evidence_count: usize,
) {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(root.path(), rel_path, fixture);

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let aibom_text = serde_json::to_string(&aibom).unwrap();
    assert!(
        !aibom_text.contains("testuser"),
        "Claude Desktop trusted-folder grants leaked user identity"
    );
    assert_eq!(aibom["aibom"]["schemaVersion"], expected_schema_version);

    let components = aibom["aibom"]["components"].as_array().unwrap();
    let grant_component = components
        .iter()
        .find(|component| {
            component["bom-ref"]
                .as_str()
                .is_some_and(|bom_ref| bom_ref.contains("claude-desktop-approval-state"))
                && component["capabilities"]["granted"]
                    .as_array()
                    .is_some_and(|granted| !granted.is_empty())
        })
        .expect("Claude Desktop approval component");
    assert_eq!(grant_component["source"], "built-in");
    assert!(
        grant_component["capabilities"]["declared"]
            .as_array()
            .unwrap()
            .is_empty(),
        "trusted-folder approval state must not invent declared capabilities"
    );

    let granted = grant_component["capabilities"]["granted"]
        .as_array()
        .unwrap();
    for expected_path in expected_paths {
        assert!(
            granted.iter().any(|cap| {
                cap["id"] == "fs:read" && cap["qualifiers"]["path"] == *expected_path
            }),
            "missing fs:read grant for {expected_path}: {granted:?}"
        );
        assert!(
            granted.iter().any(|cap| {
                cap["id"] == "fs:write" && cap["qualifiers"]["path"] == *expected_path
            }),
            "missing fs:write grant for {expected_path}: {granted:?}"
        );
    }
    assert!(
        granted
            .iter()
            .all(|cap| cap["qualifiers"]["path"] != "relative/path/ignored")
    );
    assert!(
        granted
            .iter()
            .all(|cap| cap["qualifiers"]["path"] != "relative\\path\\ignored")
    );

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    let grant_evidence: Vec<_> = evidence
        .iter()
        .filter(|record| record["kind"] == "granted-permission")
        .filter(|record| {
            record["reference"].as_str().is_some_and(|reference| {
                reference
                    .contains("claude_desktop_config.json#preferences.localAgentModeTrustedFolders")
            })
        })
        .collect();
    assert_eq!(grant_evidence.len(), expected_evidence_count);
}

async fn assert_cowork_session_fixture_grants(
    rel_path: &str,
    fixture: &str,
    expected_schema_version: &str,
    expected_path: &str,
    expected_exec_cmd: &str,
) {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(root.path(), rel_path, fixture);

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let aibom_text = serde_json::to_string(&aibom).unwrap();
    for forbidden in [
        "secret@example.com",
        "TOP_SECRET_SYSTEM_PROMPT",
        "/Users/example",
        r"C:\Users\example",
    ] {
        assert!(
            !aibom_text.contains(forbidden),
            "Cowork grant output leaked {forbidden}"
        );
    }
    assert_eq!(aibom["aibom"]["schemaVersion"], expected_schema_version);

    let components = aibom["aibom"]["components"].as_array().unwrap();
    let grant_component = components
        .iter()
        .find(|component| {
            component["capabilities"]["granted"]
                .as_array()
                .is_some_and(|granted| {
                    granted.iter().any(|cap| {
                        cap["id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with("mcp:cowork-tool:"))
                    })
                })
        })
        .expect("Cowork approval component");
    assert_eq!(grant_component["source"], "built-in");
    assert!(
        grant_component["capabilities"]["declared"]
            .as_array()
            .unwrap()
            .is_empty(),
        "Cowork approval state must not invent declared capabilities"
    );

    let granted = grant_component["capabilities"]["granted"]
        .as_array()
        .unwrap();
    for expected_id in [
        "fs:read",
        "fs:write",
        "net:egress",
        "exec:subprocess",
        "mcp:cowork-tool:desktop-commander-read-file",
    ] {
        assert!(
            granted.iter().any(|cap| cap["id"] == expected_id),
            "missing {expected_id}: {granted:?}"
        );
    }
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "fs:write" && cap["qualifiers"]["path"] == expected_path })
    );
    assert!(granted.iter().any(|cap| {
        cap["id"] == "exec:subprocess" && cap["qualifiers"]["cmd"] == expected_exec_cmd
    }));
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "net:egress" && cap["qualifiers"]["scheme"] == "https" }),
        "Cowork egress grants should preserve scheme when fixture provides it"
    );
    assert!(
        granted
            .iter()
            .all(|cap| cap["qualifiers"]["toolName"] != "desktop-commander.delete_file"),
        "false enabledMcpTools entry must not become a grant"
    );

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    let grant_evidence: Vec<_> = evidence
        .iter()
        .filter(|record| record["kind"] == "granted-permission")
        .filter(|record| {
            record["reference"].as_str().is_some_and(|reference| {
                reference.starts_with("claude-cowork://local-agent-mode-session#")
            })
        })
        .collect();
    assert!(
        grant_evidence.len() >= 4,
        "expected multiple Cowork grant evidence records: {grant_evidence:?}"
    );
}

fn assert_no_cowork_grants(aibom: &Value) {
    let components = aibom["aibom"]["components"].as_array().unwrap();
    assert!(
        components.iter().all(|component| {
            !component["capabilities"]["granted"]
                .as_array()
                .is_some_and(|granted| {
                    granted.iter().any(|cap| {
                        cap["id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with("mcp:cowork-tool:"))
                    })
                })
        }),
        "Cowork grant-state component should not exist"
    );
    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    assert!(
        evidence.iter().all(|record| {
            record["kind"] != "granted-permission"
                || !record["reference"].as_str().is_some_and(|reference| {
                    reference.starts_with("claude-cowork://local-agent-mode-session#")
                })
        }),
        "Cowork granted-permission evidence should not exist"
    );
}

async fn assert_claude_code_desktop_session_fixture_grants(
    rel_path: &str,
    fixture: &str,
    expected_path: &str,
) {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(root.path(), rel_path, fixture);

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let aibom_text = serde_json::to_string(&aibom).unwrap();
    for forbidden in [
        "desktop-secret@example.com",
        "/Users/example",
        r"C:\Users\example",
    ] {
        assert!(
            !aibom_text.contains(forbidden),
            "Claude Code desktop grant output leaked {forbidden}"
        );
    }

    let grant_component = aibom["aibom"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| {
            component["capabilities"]["granted"]
                .as_array()
                .is_some_and(|granted| {
                    granted.iter().any(|cap| {
                        cap["id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with("mcp:claude-code-desktop-tool:"))
                    })
                })
        })
        .expect("Claude Code desktop grant component");
    assert_eq!(grant_component["source"], "built-in");
    let granted = grant_component["capabilities"]["granted"]
        .as_array()
        .unwrap();
    for expected_id in [
        "mcp:claude-code-desktop-tool:desktop-commander-read-file",
        "mcp:claude-code-desktop-tool:filesystem-write-file",
        "mcp:claude-code-desktop-tool:shell-run",
        "fs:read",
        "fs:write",
    ] {
        assert!(
            granted.iter().any(|cap| cap["id"] == expected_id),
            "missing {expected_id}: {granted:?}"
        );
    }
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "fs:write" && cap["qualifiers"]["path"] == expected_path })
    );

    let metadata_component = aibom["aibom"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| {
            component["capabilities"]["declared"]
                .as_array()
                .is_some_and(|declared| {
                    declared.iter().any(|cap| {
                        cap["id"].as_str().is_some_and(|id| {
                            id == "mcp:claude-code-desktop-session:scheduled-task"
                        })
                    })
                })
        })
        .expect("Claude Code desktop session metadata component");
    let declared = metadata_component["capabilities"]["declared"]
        .as_array()
        .unwrap();
    assert!(declared.iter().any(|cap| {
        cap["id"] == "mcp:claude-code-desktop-session:scheduled-task"
            && cap["qualifiers"]["scheduledTaskId"].as_str().is_some()
            && cap["qualifiers"]["sessionType"].as_str().is_some()
    }));

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    assert!(evidence.iter().any(|record| {
        record["kind"] == "granted-permission"
            && record["reference"]
                .as_str()
                .is_some_and(|reference| reference.starts_with("claude-code-desktop://session#"))
    }));
}

async fn assert_codex_global_state_fixture_grants(fixture: &str, expected_path: &str) {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(root.path(), ".codex/.codex-global-state.json", fixture);

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let aibom_text = serde_json::to_string(&aibom).unwrap();
    for forbidden in [
        "REEVE_PROMPT_HISTORY_DO_NOT_EMIT",
        "/Users/example",
        r"C:\Users\example",
    ] {
        assert!(
            !aibom_text.contains(forbidden),
            "Codex global-state grant output leaked {forbidden}"
        );
    }

    let component = grant_component_with_id(&aibom, "mcp:codex-app:full-access");
    let granted = component["capabilities"]["granted"].as_array().unwrap();
    for expected_id in [
        "mcp:codex-app:full-access",
        "exec:subprocess",
        "fs:read",
        "fs:write",
    ] {
        assert!(
            granted.iter().any(|cap| cap["id"] == expected_id),
            "missing {expected_id}: {granted:?}"
        );
    }
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "exec:subprocess" && cap["qualifiers"]["cmd"] == "*" })
    );
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "fs:write" && cap["qualifiers"]["path"] == expected_path })
    );

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    let grant_evidence: Vec<_> = evidence
        .iter()
        .filter(|record| {
            record["kind"] == "granted-permission"
                && record["reference"]
                    .as_str()
                    .is_some_and(|reference| reference.starts_with("codex-app://global-state#"))
        })
        .collect();
    assert!(
        grant_evidence.len() >= 3,
        "expected Codex global-state grant evidence: {grant_evidence:?}"
    );
}

fn grant_component_with_id<'a>(aibom: &'a Value, id: &str) -> &'a Value {
    aibom["aibom"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| {
            component["capabilities"]["granted"]
                .as_array()
                .is_some_and(|granted| granted.iter().any(|cap| cap["id"] == id))
        })
        .unwrap_or_else(|| panic!("missing granted capability {id}"))
}

async fn assert_codex_app_fixture_grants(
    fixture: &str,
    expected_ids: &[&str],
    forbidden_text: &[&str],
) {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(root.path(), ".codex/config.toml", fixture);

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let aibom_text = serde_json::to_string(&aibom).unwrap();
    assert_eq!(aibom["aibom"]["schemaVersion"], "0.2.0");

    let components = aibom["aibom"]["components"].as_array().unwrap();
    let app_component = components
        .iter()
        .find(|component| {
            component["capabilities"]["granted"]
                .as_array()
                .is_some_and(|granted| {
                    granted.iter().any(|cap| {
                        cap["id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with("mcp:codex-app-tool:"))
                    })
                })
        })
        .expect("Codex App approval component");
    assert_eq!(app_component["source"], "built-in");
    assert!(
        app_component["capabilities"]["declared"]
            .as_array()
            .unwrap()
            .is_empty(),
        "App approval state must not invent declared capabilities"
    );

    let granted = app_component["capabilities"]["granted"].as_array().unwrap();
    let granted_ids: Vec<_> = granted
        .iter()
        .map(|cap| cap["id"].as_str().unwrap())
        .collect();
    for expected in expected_ids {
        assert!(
            granted_ids.contains(expected),
            "missing {expected} in {granted_ids:?}"
        );
    }

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    let grant_evidence: Vec<_> = evidence
        .iter()
        .filter(|record| record["kind"] == "granted-permission")
        .filter(|record| {
            record["reference"]
                .as_str()
                .is_some_and(|reference| reference.starts_with("codex-app://config#apps["))
        })
        .collect();
    assert_eq!(grant_evidence.len(), expected_ids.len());

    for value in forbidden_text {
        assert!(
            !aibom_text.contains(value),
            "Codex App approval output leaked {value}"
        );
    }
}

async fn assert_codex_fixture_grants(
    fixture: &str,
    expected_ids: &[&str],
    expected_path: &str,
    expected_evidence_count: usize,
) {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    write_fixture(root.path(), ".codex/config.toml", fixture);

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    assert_eq!(aibom["aibom"]["schemaVersion"], "0.2.0");

    let components = aibom["aibom"]["components"].as_array().unwrap();
    let component = components
        .iter()
        .find(|component| {
            component["capabilities"]["granted"]
                .as_array()
                .is_some_and(|granted| granted.iter().any(|cap| cap["id"] == "exec:subprocess"))
        })
        .expect("Codex CLI grant component");
    assert_eq!(component["source"], "built-in");
    let granted = component["capabilities"]["granted"].as_array().unwrap();
    let granted_ids: Vec<_> = granted
        .iter()
        .map(|cap| cap["id"].as_str().unwrap())
        .collect();
    for expected in expected_ids {
        assert!(
            granted_ids.contains(expected),
            "missing {expected} in {granted_ids:?}"
        );
    }
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "exec:subprocess" && cap["qualifiers"]["cmd"] == "*" })
    );
    assert!(
        granted
            .iter()
            .any(|cap| { cap["id"] == "fs:write" && cap["qualifiers"]["path"] == expected_path })
    );

    let evidence = aibom["aibom"]["evidence"].as_array().unwrap();
    let grant_evidence: Vec<_> = evidence
        .iter()
        .filter(|record| record["kind"] == "granted-permission")
        .filter(|record| {
            record["reference"]
                .as_str()
                .is_some_and(|reference| reference.contains(".codex/config.toml#projects"))
        })
        .collect();
    assert_eq!(grant_evidence.len(), expected_evidence_count);
    assert!(grant_evidence.iter().all(|record| {
        record["reference"]
            .as_str()
            .unwrap()
            .contains(".codex/config.toml#")
    }));
}

fn write_fixture(root: &Path, rel: &str, fixture: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(fixture),
        path,
    )
    .unwrap();
}
