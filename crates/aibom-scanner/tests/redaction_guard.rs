use aibom_core::Target;
use aibom_scanner::scan_target;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

const FIXTURE_USERNAME: &str = "alice";

// launch-proof: #463
//
// End-to-end guard: a scan rooted in a home directory whose path carries an
// OS username must never serialize that username into the AIBOM or CDX
// output. Covers grant qualifiers, granted-permission evidence references,
// registration evidence references, declared filesystem-root qualifiers, and
// the scan target description in one pass.
#[tokio::test]
async fn serialized_scan_output_never_contains_home_username() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    // Fake home rooted at <tmp>/Users/alice so every discovered config's
    // source path carries a username-like home segment.
    let home = root.path().join("Users").join(FIXTURE_USERNAME);

    let settings = home.join(".claude/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{
  "mcpServers": {
    "files": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/alice/projects"]
    }
  },
  "permissions": {
    "allow": [
      "Read(/Users/alice/docs/**)",
      "Bash(/Users/alice/bin/deploy.sh --prod)"
    ]
  }
}"#,
    )
    .unwrap();

    let desktop_config = home.join("Library/Application Support/Claude/claude_desktop_config.json");
    fs::create_dir_all(desktop_config.parent().unwrap()).unwrap();
    fs::write(
        &desktop_config,
        r#"{
  "mcpServers": {},
  "preferences": {
    "localAgentModeTrustedFolders": ["/Users/alice/LegalDocs"]
  }
}"#,
    )
    .unwrap();

    // Codex CLI: project-table keys embed raw absolute paths that surface in
    // granted-evidence reference fragments (#463 residual pattern 1).
    let codex_config = home.join(".codex/config.toml");
    fs::create_dir_all(codex_config.parent().unwrap()).unwrap();
    fs::write(
        &codex_config,
        r#"[projects."/Users/alice/projects/demo"]
trust_level = "trusted"
approval_policy = "never"
sandbox_mode = "workspace-write"
"#,
    )
    .unwrap();

    // Cowork session with a PATH-VALUED tool approval: the username must not
    // fuse into the slugified capability id or the toolName qualifier (#468).
    let session = home.join(
        "Library/Application Support/Claude/local-agent-mode-sessions/s1/t1/local_session.json",
    );
    fs::create_dir_all(session.parent().unwrap()).unwrap();
    fs::write(
        &session,
        r#"{
  "permissionMode": "default",
  "enabledMcpTools": {
    "/Users/alice/.ssh": true,
    "exa.web_search": true
  }
}"#,
    )
    .unwrap();

    // Cursor: project dirs flatten the absolute project path into one
    // dash-joined segment (#463 residual pattern 2).
    let cursor_metadata = home.join(format!(
        ".cursor/projects/Users-{FIXTURE_USERNAME}-projects-demo/mcps/project-db/SERVER_METADATA.json"
    ));
    fs::create_dir_all(cursor_metadata.parent().unwrap()).unwrap();
    fs::write(
        &cursor_metadata,
        r#"{
  "serverIdentifier": "project-db",
  "serverName": "project-db"
}"#,
    )
    .unwrap();

    let artifacts = scan_target(&Target::filesystem(home.clone()), out.path())
        .await
        .unwrap();

    let aibom_text = String::from_utf8(artifacts.aibom_bytes.clone()).unwrap();
    let cdx_text = String::from_utf8(artifacts.cdx_bytes.clone()).unwrap();
    assert!(
        !aibom_text.contains(FIXTURE_USERNAME),
        "AIBOM output leaked the home username: {aibom_text}"
    );
    assert!(
        !cdx_text.contains(FIXTURE_USERNAME),
        "CDX output leaked the home username: {cdx_text}"
    );
    assert!(
        aibom_text.contains("<redacted-home>"),
        "AIBOM output should carry redacted home segments: {aibom_text}"
    );

    // Spot-check the shapes stayed absolute per ADR-0008.
    let aibom: Value = serde_json::from_slice(&artifacts.aibom_bytes).unwrap();
    let granted_paths: Vec<&str> = aibom["aibom"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|component| {
            component["capabilities"]["granted"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .filter_map(|cap| cap["qualifiers"]["path"].as_str())
        .collect();
    assert!(
        granted_paths.contains(&"/Users/<redacted-home>/LegalDocs"),
        "trusted-folder grant should keep absolute redacted scope: {granted_paths:?}"
    );
    assert!(
        granted_paths.contains(&"/Users/<redacted-home>/docs/**"),
        "allow-rule grant should keep absolute redacted scope: {granted_paths:?}"
    );

    let references: Vec<&str> = aibom["aibom"]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|record| record["reference"].as_str())
        .collect();
    assert!(
        references.iter().any(|reference| {
            reference.starts_with("file://") && reference.contains("/Users/<redacted-home>/")
        }),
        "granted-permission evidence should reference the redacted source path: {references:?}"
    );
    // Positive proof the residual-pattern fixtures were parsed (not skipped):
    // codex fragment carries the redacted project-table key…
    assert!(
        references.iter().any(|reference| {
            reference.contains(".codex/config.toml#projects[")
                && reference.contains("/Users/<redacted-home>/projects/demo")
        }),
        "codex project fragment should be present and redacted: {references:?}"
    );
    // …and the cursor encoded project segment is redacted in place.
    assert!(
        references.iter().any(|reference| {
            reference.contains(".cursor/projects/Users-<redacted-home>-projects-demo/")
        }),
        "cursor encoded project segment should be present and redacted: {references:?}"
    );

    let description = aibom["aibom"]["scan"]["target"]["description"]
        .as_str()
        .unwrap();
    assert!(
        description.ends_with("/Users/<redacted-home>")
            || description.ends_with("\\Users\\<redacted-home>"),
        "target description should redact the home segment: {description}"
    );
}
