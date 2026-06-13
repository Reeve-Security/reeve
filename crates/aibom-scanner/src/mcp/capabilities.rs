use crate::mcp::client;
use crate::mcp::fingerprint::normalize_id;
use aibom_core::{Capabilities, Capability, CapabilitySource, ToolProvider, Transport};
use anyhow::Result;
use serde_json::{Map, Value, json};
use std::path::Path;

#[derive(Debug, Clone, Copy, Default)]
pub struct IntrospectionOptions {
    pub execute_stdio: bool,
}

pub fn executes_stdio(provider: &ToolProvider, opts: IntrospectionOptions) -> bool {
    let Transport::Stdio(stdio) = &provider.transport else {
        return false;
    };

    opts.execute_stdio && safe_to_spawn_locally(&stdio.command, &stdio.args)
}

pub async fn introspect(provider: &ToolProvider) -> Result<Capabilities> {
    introspect_with_options(provider, IntrospectionOptions::default()).await
}

pub async fn introspect_with_options(
    provider: &ToolProvider,
    opts: IntrospectionOptions,
) -> Result<Capabilities> {
    if !provider.declared_tools.is_empty() {
        return Ok(Capabilities {
            declared: derive_from_tool_names(&provider.declared_tools, "ev-tools"),
        });
    }

    let Transport::Stdio(stdio) = &provider.transport else {
        return Ok(Capabilities {
            declared: vec![fallback_capability(&provider.name, "ev-tools")],
        });
    };

    if !executes_stdio(provider, opts) {
        return Ok(Capabilities {
            declared: vec![fallback_capability(&provider.name, "ev-tools")],
        });
    }

    match client::list_stdio(&stdio.command, &stdio.args, &stdio.env, 10).await {
        Ok(lists) => Ok(Capabilities {
            declared: derive_from_lists(&lists.tools, "ev-tools"),
        }),
        Err(_) => Ok(Capabilities {
            declared: vec![fallback_capability(&provider.name, "ev-tools")],
        }),
    }
}

fn derive_from_tool_names(tool_names: &[String], evidence_id: &str) -> Vec<Capability> {
    let tools: Vec<Value> = tool_names
        .iter()
        .map(|name| json!({ "name": name }))
        .collect();
    derive_from_lists(&json!({ "tools": tools }), evidence_id)
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

pub fn derive_from_lists(tools_result: &Value, evidence_id: &str) -> Vec<Capability> {
    let tools = tools_result
        .pointer("/tools")
        .or_else(|| tools_result.pointer("/result/tools"))
        .and_then(Value::as_array);
    let mut caps = Vec::new();
    for tool in tools.into_iter().flatten() {
        let name = tool
            .pointer("/name")
            .and_then(Value::as_str)
            .unwrap_or("tool");
        let description = tool
            .pointer("/description")
            .and_then(Value::as_str)
            .unwrap_or("");
        caps.extend(derive_tool(name, description, tool, evidence_id));
    }
    merge_caps(caps)
}

fn derive_tool(name: &str, description: &str, tool: &Value, evidence_id: &str) -> Vec<Capability> {
    let haystack = format!("{name} {description}").to_ascii_lowercase();
    let mut caps = Vec::new();
    let mut qualifiers = Map::new();

    // fs:read — file read operations
    if haystack.contains("read_file")
        || haystack.contains("read file")
        || haystack.contains("read_path")
        || haystack.contains("load file")
        || haystack.contains("open file")
        || (haystack.contains("read") && schema_has_property(tool, "path"))
        || schema_has_property(tool, "file_path")
    {
        if let Some(path) = schema_const_or_default(tool, "path")
            .or_else(|| schema_const_or_default(tool, "file_path"))
        {
            super::insert_supported_fs_path_qualifier(&mut qualifiers, &path);
        }
        caps.push(mk_cap("fs:read", qualifiers.clone(), evidence_id));
    }

    // fs:write — file write operations
    if haystack.contains("write_file")
        || haystack.contains("write file")
        || haystack.contains("save file")
        || haystack.contains("create file")
        || (haystack.contains("write") && schema_has_property(tool, "path"))
    {
        if let Some(path) = schema_const_or_default(tool, "path") {
            super::insert_supported_fs_path_qualifier(&mut qualifiers, &path);
        }
        caps.push(mk_cap("fs:write", qualifiers.clone(), evidence_id));
    }

    // net:egress — network outbound connections
    if haystack.contains("fetch")
        || haystack.contains("http")
        || haystack.contains("url")
        || haystack.contains("request")
        || haystack.contains("download")
        || haystack.contains("upload")
        || haystack.contains("api")
        || haystack.contains("navigate")
        || haystack.contains("browse")
        || haystack.contains("visit")
        || haystack.contains("connect")
        || haystack.contains("web")
        || haystack.contains("network")
        || schema_has_property(tool, "url")
        || schema_has_property(tool, "host")
        || schema_has_property(tool, "hostname")
        || schema_has_property(tool, "endpoint")
    {
        if let Some(host) = schema_const_or_default(tool, "host")
            .or_else(|| schema_const_or_default(tool, "hostname"))
        {
            qualifiers.insert("host".to_string(), json!(host));
        }
        if let Some(port) = schema_const_or_default(tool, "port") {
            qualifiers.insert(
                "port".to_string(),
                json!(port.parse::<i64>().unwrap_or(443)),
            );
        }
        if let Some(scheme) = schema_const_or_default(tool, "scheme") {
            qualifiers.insert("scheme".to_string(), json!(scheme));
        }
        caps.push(mk_cap("net:egress", qualifiers.clone(), evidence_id));
    }

    // net:listen — network inbound listening
    if haystack.contains("listen")
        || haystack.contains("server")
        || haystack.contains("bind")
        || haystack.contains("accept")
        || haystack.contains("incoming")
        || schema_has_property(tool, "port")
            && (haystack.contains("listen")
                || haystack.contains("server")
                || haystack.contains("start"))
    {
        if let Some(port) = schema_const_or_default(tool, "port") {
            qualifiers.insert("port".to_string(), json!(port.parse::<i64>().unwrap_or(80)));
        }
        caps.push(mk_cap("net:listen", qualifiers.clone(), evidence_id));
    }

    // exec:subprocess — subprocess execution
    if haystack.contains("exec")
        || haystack.contains("shell")
        || haystack.contains("subprocess")
        || haystack.contains("start_process")
        || haystack.contains("kill_process")
        || haystack.contains("run_process")
        || haystack.contains("command")
        || haystack.contains("run cmd")
        || haystack.contains("execute")
        || haystack.contains("spawn")
        || haystack.contains("launch process")
        || haystack.contains("child process")
        || schema_has_property(tool, "command")
        || schema_has_property(tool, "cmd")
        || schema_has_property(tool, "args")
    {
        if let Some(cmd) = schema_const_or_default(tool, "cmd")
            .or_else(|| schema_const_or_default(tool, "command"))
        {
            qualifiers.insert("cmd".to_string(), json!(cmd));
        }
        caps.push(mk_cap("exec:subprocess", qualifiers.clone(), evidence_id));
    }

    // env:read — environment variable access
    if haystack.contains("env")
        || haystack.contains("environment")
        || haystack.contains(" getenv")
        || schema_has_property(tool, "env")
        || schema_has_property(tool, "environment_variable")
    {
        if let Some(name) =
            schema_const_or_default(tool, "env").or_else(|| schema_const_or_default(tool, "name"))
        {
            qualifiers.insert("name".to_string(), json!(name));
        }
        caps.push(mk_cap("env:read", qualifiers.clone(), evidence_id));
    }

    // secret:read — secret / token / credential access
    if haystack.contains("secret")
        || haystack.contains("token")
        || haystack.contains("password")
        || haystack.contains("credential")
        || haystack.contains("api_key")
        || haystack.contains("apikey")
        || haystack.contains("auth")
        || haystack.contains("key") && (haystack.contains("api") || haystack.contains("access"))
        || schema_has_property(tool, "api_key")
        || schema_has_property(tool, "token")
        || schema_has_property(tool, "secret")
    {
        if let Some(ref_key) = schema_const_or_default(tool, "api_key")
            .or_else(|| schema_const_or_default(tool, "token"))
            .or_else(|| schema_const_or_default(tool, "secret"))
        {
            qualifiers.insert("ref".to_string(), json!(format!("env:{}", ref_key)));
        }
        caps.push(mk_cap("secret:read", qualifiers.clone(), evidence_id));
    }

    // ipc:connect — inter-process communication
    if haystack.contains("ipc")
        || haystack.contains("socket")
        || haystack.contains("pipe")
        || haystack.contains("message queue")
        || haystack.contains("dbus")
        || haystack.contains("domain socket")
    {
        caps.push(mk_cap("ipc:connect", qualifiers.clone(), evidence_id));
    }

    // If no core capability was derived, emit the mcp extension stub
    // AND any core capability that was derived alongside it.
    if caps.is_empty() {
        caps.push(fallback_capability(name, evidence_id));
    } else {
        // Also emit the original mcp:* extension so downstream tools
        // can see the raw tool identity even when a core id is derived.
        let ext = fallback_capability(name, evidence_id);
        // Avoid duplicate if the normalized id happens to equal a core id
        if !caps.iter().any(|cap| cap.id == ext.id) {
            caps.push(ext);
        }
    }

    caps
}

fn mk_cap(id: &str, qualifiers: Map<String, Value>, evidence_id: &str) -> Capability {
    Capability {
        id: id.to_string(),
        qualifiers,
        source: CapabilitySource::Declared,
        evidence: vec![evidence_id.to_string()],
    }
}

fn schema_has_property(tool: &Value, property: &str) -> bool {
    tool.pointer("/inputSchema/properties")
        .and_then(Value::as_object)
        .is_some_and(|props| props.contains_key(property))
}

fn schema_const_or_default(tool: &Value, property: &str) -> Option<String> {
    let schema = tool
        .pointer("/inputSchema/properties")?
        .as_object()?
        .get(property)?;
    schema
        .pointer("/const")
        .or_else(|| schema.pointer("/default"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn fallback_capability(name: &str, evidence_id: &str) -> Capability {
    Capability {
        id: format!("mcp:{}", normalize_id(name)),
        qualifiers: Map::new(),
        source: CapabilitySource::Declared,
        evidence: vec![evidence_id.to_string()],
    }
}

fn merge_caps(caps: Vec<Capability>) -> Vec<Capability> {
    let mut merged: Vec<Capability> = Vec::new();
    for cap in caps {
        if let Some(existing) = merged
            .iter_mut()
            .find(|existing| existing.id == cap.id && existing.qualifiers == cap.qualifiers)
        {
            for evidence in cap.evidence {
                if !existing.evidence.contains(&evidence) {
                    existing.evidence.push(evidence);
                    existing.evidence.sort();
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use aibom_core::{DiscoverySource, StdioConfig, Transport};
    use serde_json::json;
    #[cfg(unix)]
    use std::collections::BTreeMap;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use tempfile::TempDir;

    #[test]
    fn maps_core_heuristics_and_fallback() {
        let tools = json!({"tools":[
            {"name":"read_file","inputSchema":{"properties":{"path":{"type":"string"}}}},
            {"name":"fetch_url","description":"http fetch"},
            {"name":"run_shell","description":"execute subprocess"},
            {"name":"semantic_search"}
        ]});
        let caps = derive_from_lists(&tools, "ev-001");
        let ids: Vec<_> = caps.iter().map(|cap| cap.id.as_str()).collect();
        assert!(ids.contains(&"fs:read"));
        assert!(ids.contains(&"net:egress"));
        assert!(ids.contains(&"exec:subprocess"));
        assert!(ids.contains(&"mcp:semantic-search"));
    }

    #[test]
    fn filesystem_posix_default_path_is_preserved() {
        let tools = json!({"tools":[
            {"name":"read_file","inputSchema":{"properties":{"path":{"type":"string","default":"/home/reeve"}}}}
        ]});
        let caps = derive_from_lists(&tools, "ev-001");
        let cap = caps.iter().find(|cap| cap.id == "fs:read").unwrap();
        // Absolute shape is preserved; the home segment is redacted (ADR-0045).
        assert_eq!(
            cap.qualifiers.get("path"),
            Some(&json!("/home/<redacted-home>"))
        );
    }

    #[test]
    fn filesystem_windows_default_path_is_preserved_for_v0_3() {
        let tools = json!({"tools":[
            {"name":"read_file","inputSchema":{"properties":{"path":{"type":"string","default":"C:\\Users\\reeveadmin"}}}},
            {"name":"write_file","inputSchema":{"properties":{"path":{"type":"string","default":"C:\\Users\\reeveadmin"}}}}
        ]});
        let caps = derive_from_lists(&tools, "ev-001");
        let read = caps.iter().find(|cap| cap.id == "fs:read").unwrap();
        let write = caps.iter().find(|cap| cap.id == "fs:write").unwrap();

        // Absolute shape is preserved; the home segment is redacted (ADR-0045).
        assert_eq!(
            read.qualifiers.get("path"),
            Some(&json!("C:\\Users\\<redacted-home>"))
        );
        assert_eq!(
            write.qualifiers.get("path"),
            Some(&json!("C:\\Users\\<redacted-home>"))
        );
    }

    #[test]
    fn playwright_like_tools_derive_net_egress() {
        let tools = json!({"tools":[
            {"name":"browser_navigate","description":"Navigate browser to URL","inputSchema":{"properties":{"url":{"type":"string"}}}},
            {"name":"browser_click","description":"Click element on page"},
            {"name":"browser_screenshot","description":"Take screenshot"},
            {"name":"browser_download","description":"Download file from URL"}
        ]});
        let caps = derive_from_lists(&tools, "ev-001");
        let ids: Vec<_> = caps.iter().map(|cap| cap.id.as_str()).collect();
        assert!(
            ids.contains(&"net:egress"),
            "browser_navigate should derive net:egress, got {:?}",
            ids
        );
        assert!(
            ids.contains(&"mcp:browser-navigate"),
            "should also emit mcp:browser-navigate extension, got {:?}",
            ids
        );
        assert!(
            ids.contains(&"net:egress"),
            "browser_download should derive net:egress, got {:?}",
            ids
        );
    }

    #[test]
    fn secret_tool_derives_secret_read() {
        let tools = json!({"tools":[
            {"name":"get_api_key","description":"Retrieve API key for service","inputSchema":{"properties":{"service":{"type":"string"}}}},
            {"name":"auth_with_token","description":"Authenticate using bearer token","inputSchema":{"properties":{"token":{"type":"string"}}}}
        ]});
        let caps = derive_from_lists(&tools, "ev-001");
        let ids: Vec<_> = caps.iter().map(|cap| cap.id.as_str()).collect();
        assert!(
            ids.contains(&"secret:read"),
            "api_key/token tools should derive secret:read, got {:?}",
            ids
        );
    }

    #[test]
    fn env_tool_derives_env_read() {
        let tools = json!({"tools":[
            {"name":"get_env","description":"Read environment variable","inputSchema":{"properties":{"name":{"type":"string"}}}},
            {"name":"load_dotenv","description":"Load .env file into environment"}
        ]});
        let caps = derive_from_lists(&tools, "ev-001");
        let ids: Vec<_> = caps.iter().map(|cap| cap.id.as_str()).collect();
        assert!(
            ids.contains(&"env:read"),
            "env tools should derive env:read, got {:?}",
            ids
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn default_introspection_does_not_execute_stdio() {
        let (_dir, script, marker) = write_test_server();
        let provider = test_provider(&script, &marker);

        let caps = introspect(&provider).await.unwrap();

        assert!(
            !marker.exists(),
            "default introspection must not spawn the stdio MCP server"
        );
        assert!(
            caps.declared.iter().any(|cap| cap.id == "mcp:fixture"),
            "default introspection should fall back to static MCP identity"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn explicit_introspection_executes_stdio() {
        let (_dir, script, marker) = write_test_server();
        let provider = test_provider(&script, &marker);

        let caps = introspect_with_options(
            &provider,
            IntrospectionOptions {
                execute_stdio: true,
            },
        )
        .await
        .unwrap();

        assert!(
            marker.exists(),
            "explicit introspection should spawn the stdio MCP server"
        );
        assert!(caps.declared.iter().any(|cap| cap.id == "fs:read"));
    }

    #[cfg(unix)]
    fn write_test_server() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("server.sh");
        let marker = dir.path().join("marker");
        fs::write(
            &script,
            r#"#!/bin/sh
touch "$REEVE_INTROSPECTION_MARKER"
while IFS= read -r line; do
  case "$line" in
    *'"id":1'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{}}'
      ;;
    *'"id":2'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file","description":"Read file","inputSchema":{"properties":{"path":{"type":"string"}}}}]}}'
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
        (dir, script, marker)
    }

    #[cfg(unix)]
    fn test_provider(script: &std::path::Path, marker: &std::path::Path) -> ToolProvider {
        let mut env = BTreeMap::new();
        env.insert(
            "REEVE_INTROSPECTION_MARKER".to_string(),
            marker.display().to_string(),
        );
        ToolProvider {
            surface: "test".into(),
            name: "fixture".into(),
            transport: Transport::Stdio(StdioConfig {
                command: script.display().to_string(),
                args: Vec::new(),
                env,
            }),
            source_path: None,
            discovery_source: DiscoverySource::BuiltIn,
            extension: None,
            declared_tools: Vec::new(),
        }
    }
}
