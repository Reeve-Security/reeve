//! Regression test for GHSA-44pg-86fc-fc7q.
//!
//! Proves that ambient parent environment (including secrets) is scrubbed
//! before an introspected stdio MCP child is spawned, while a config declared
//! allowlist env var is still passed through.
//!
//! Unix only: the test stdio "server" is a small shell script. The Windows
//! spawn site is covered by mirroring the same env_clear plus minimal env
//! pattern in run_windows_observational_server.
#![cfg(unix)]

use aibom_scanner::mcp::client;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

/// Writes a tiny stdio MCP server that echoes two environment variables back
/// inside the tools/list response so the test can observe what the child saw.
///
/// REEVE_TEST_PLANTED_SECRET is the ambient secret that must be scrubbed.
/// REEVE_TEST_ALLOWED is the config declared allowlist var that must survive.
fn write_env_echo_server() -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("env_echo_server.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
secret="${REEVE_TEST_PLANTED_SECRET:-ABSENT}"
allowed="${REEVE_TEST_ALLOWED:-ABSENT}"
while IFS= read -r line; do
  case "$line" in
    *'"id":1'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{}}'
      ;;
    *'"id":2'*)
      printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"saw_secret_${secret}\"},{\"name\":\"saw_allowed_${allowed}\"}]}}"
      ;;
    *'"id":3'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"resources":[]}}'
      ;;
    *'"id":4'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"prompts":[]}}'
      exit 0
      ;;
  esac
done
"#,
    )
    .unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script, perms).unwrap();
    (dir, script)
}

#[tokio::test]
async fn list_stdio_scrubs_parent_env_but_keeps_allowlist() {
    // Plant a secret in the parent process environment. The spawned child must
    // NOT see it. On the pre fix code (no env_clear) the child inherits this
    // and the test fails.
    unsafe {
        std::env::set_var("REEVE_TEST_PLANTED_SECRET", "leakme");
    }

    let (_dir, script) = write_env_echo_server();

    // Config declared allowlist passed via the env map; this MUST reach the
    // child.
    let mut env = BTreeMap::new();
    env.insert("REEVE_TEST_ALLOWED".to_string(), "passme".to_string());

    let lists = client::list_stdio(&script.display().to_string(), &[], &env, 10)
        .await
        .expect("list_stdio should drive the stdio server");

    let tool_names: Vec<String> = lists
        .tools
        .pointer("/tools")
        .and_then(|v| v.as_array())
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| t.pointer("/name").and_then(|n| n.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // The child reported what it observed in its own environment.
    assert!(
        tool_names.contains(&"saw_secret_ABSENT".to_string()),
        "child must NOT inherit the planted parent secret, saw: {tool_names:?}"
    );
    assert!(
        !tool_names.iter().any(|name| name.contains("leakme")),
        "planted secret value leaked into the child, saw: {tool_names:?}"
    );

    // The legitimately allowlisted env var must still reach the child.
    assert!(
        tool_names.contains(&"saw_allowed_passme".to_string()),
        "config declared allowlist env var must reach the child, saw: {tool_names:?}"
    );

    unsafe {
        std::env::remove_var("REEVE_TEST_PLANTED_SECRET");
    }
}
