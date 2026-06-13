use aibom_core::Target;
use aibom_scanner::scan_target;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn cowork_mcpb_extension_inventory_reaches_aibom_output() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let claude_root = root
        .path()
        .join("AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude");
    fs::create_dir_all(&claude_root).unwrap();
    fs::write(
        claude_root.join("claude_desktop_config.json"),
        r#"{"theme":"dark"}"#,
    )
    .unwrap();
    fs::write(
        claude_root.join("extensions-installations.json"),
        r#"{
  "extensions": [
    {
      "id": "manifest",
      "name": "Desktop Commander",
      "version": "0.2.8",
      "path": "mcpb:manifest",
      "signatureInfo": {"status": "unsigned"},
      "server": {
        "type": "node",
        "command": "node",
        "args": ["${__dirname}/dist/index.js"]
      },
      "tools": [
        {"name": "read_file"},
        {"name": "write_file"},
        {"name": "start_process"}
      ]
    }
  ]
}"#,
    )
    .unwrap();
    fs::create_dir_all(
        claude_root.join("Claude Extensions/ant.dir.gh.wonderwhy-er.desktopcommandermcp"),
    )
    .unwrap();
    fs::write(
        claude_root
            .join("Claude Extensions/ant.dir.gh.wonderwhy-er.desktopcommandermcp/manifest.json"),
        r#"{"name":"Desktop Commander","version":"0.2.8"}"#,
    )
    .unwrap();
    let extension_root =
        claude_root.join("Claude Extensions/ant.dir.gh.wonderwhy-er.desktopcommandermcp");
    fs::write(
        extension_root.join("package.json"),
        r#"{
  "dependencies": {
    "rxjs": "^6.6.7",
    "rxjs/ajax": "^6.6.7",
    "rxjs/operators": "^6.6.7",
    "rxjs/webSocket": "^6.6.7"
  }
}"#,
    )
    .unwrap();
    fs::create_dir_all(extension_root.join("node_modules/minimatch")).unwrap();
    fs::write(
        extension_root.join("node_modules/minimatch/package.json"),
        r#"{"name":"minimatch","version":"9.0.5"}"#,
    )
    .unwrap();
    fs::create_dir_all(extension_root.join("node_modules/rxjs")).unwrap();
    fs::write(
        extension_root.join("node_modules/rxjs/package.json"),
        r#"{"name":"rxjs","version":"6.6.7"}"#,
    )
    .unwrap();
    fs::create_dir_all(extension_root.join("node_modules/@modelcontextprotocol/sdk")).unwrap();
    fs::write(
        extension_root.join("node_modules/@modelcontextprotocol/sdk/package.json"),
        r#"{"name":"@modelcontextprotocol/sdk","version":"1.12.0"}"#,
    )
    .unwrap();
    fs::create_dir_all(claude_root.join("Claude Extensions Settings")).unwrap();
    fs::write(
        claude_root
            .join("Claude Extensions Settings/ant.dir.gh.wonderwhy-er.desktopcommandermcp.json"),
        r#"{"isEnabled":true}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("node_modules/left-pad")).unwrap();
    fs::write(
        root.path().join("node_modules/left-pad/package.json"),
        r#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom: Value = serde_json::from_slice(&fs::read(artifacts.aibom_path).unwrap()).unwrap();
    let cdx: Value = serde_json::from_slice(&fs::read(artifacts.cdx_path).unwrap()).unwrap();

    assert_eq!(cdx["components"][0]["name"], "Desktop Commander");
    assert_eq!(cdx["components"][0]["version"], "0.2.8");
    let declared = aibom["aibom"]["components"][0]["capabilities"]["declared"]
        .as_array()
        .unwrap();
    for expected in [
        "mcp:extension:installed",
        "mcp:extension:unsigned",
        "fs:read",
        "fs:write",
        "exec:subprocess",
        "mcp:read-file",
        "mcp:write-file",
        "mcp:start-process",
    ] {
        assert!(
            declared.iter().any(|cap| cap["id"] == expected),
            "missing declared capability {expected}: {declared:?}"
        );
    }
    let unsigned = declared
        .iter()
        .find(|cap| cap["id"] == "mcp:extension:unsigned")
        .unwrap();
    assert_eq!(
        unsigned["qualifiers"]["extensionId"],
        "ant.dir.gh.wonderwhy-er.desktopcommandermcp"
    );
    assert_eq!(unsigned["qualifiers"]["signatureStatus"], "unsigned");
    assert_eq!(unsigned["qualifiers"]["surface"], "claude-cowork");

    let cdx_components = cdx["components"].as_array().unwrap();
    let dependency_purls: Vec<_> = cdx_components
        .iter()
        .filter(|component| component["type"] == "library")
        .filter_map(|component| component["purl"].as_str())
        .collect();
    assert!(dependency_purls.contains(&"pkg:npm/minimatch@9.0.5"));
    assert!(dependency_purls.contains(&"pkg:npm/rxjs@6.6.7"));
    assert!(dependency_purls.contains(&"pkg:npm/%40modelcontextprotocol/sdk@1.12.0"));
    assert_eq!(
        dependency_purls
            .iter()
            .filter(|purl| **purl == "pkg:npm/rxjs@6.6.7")
            .count(),
        1
    );
    assert!(!dependency_purls.contains(&"pkg:npm/rxjs"));
    assert!(
        dependency_purls
            .iter()
            .all(|purl| !purl.starts_with("pkg:npm/rxjs/"))
    );
    assert!(!dependency_purls.contains(&"pkg:npm/left-pad@1.3.0"));

    let extension_ref = cdx_components[0]["bom-ref"].as_str().unwrap();
    assert_eq!(
        extension_ref,
        "mcpb:ant-dir-gh-wonderwhy-er-desktopcommandermcp"
    );
    let edge = cdx["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["ref"] == extension_ref)
        .unwrap();
    let depends_on: Vec<_> = edge["dependsOn"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(depends_on.contains(&"pkg:npm/minimatch@9.0.5"));
    assert!(depends_on.contains(&"pkg:npm/rxjs@6.6.7"));
    assert!(depends_on.contains(&"pkg:npm/%40modelcontextprotocol/sdk@1.12.0"));

    let minimatch = cdx_components
        .iter()
        .find(|component| component["purl"] == "pkg:npm/minimatch@9.0.5")
        .unwrap();
    assert_eq!(minimatch["name"], "minimatch");
    assert_eq!(minimatch["version"], "9.0.5");
    assert!(
        minimatch["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|property| {
                property["name"] == "aibom:dependencyScope"
                    && property["value"] == "ai-harness-extension"
            })
    );

    let aibom_refs: Vec<_> = aibom["aibom"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|component| component["bom-ref"].as_str())
        .collect();
    assert!(aibom_refs.contains(&"pkg:npm/minimatch@9.0.5"));
    assert!(aibom_refs.contains(&"pkg:npm/rxjs@6.6.7"));
    assert!(aibom_refs.contains(&"pkg:npm/%40modelcontextprotocol/sdk@1.12.0"));
}

#[tokio::test]
async fn cowork_opaque_state_stores_report_presence_without_secret_values() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let claude_root = root
        .path()
        .join("AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude");
    fs::create_dir_all(&claude_root).unwrap();
    fs::write(
        claude_root.join("config.json"),
        r#"{
  "dxt:allowlistCache": "v10SUPER_SECRET_FIXTURE_BLOB",
  "theme": "dark"
}"#,
    )
    .unwrap();
    let indexeddb = claude_root.join("IndexedDB/https_claude.ai_0.indexeddb.leveldb");
    fs::create_dir_all(&indexeddb).unwrap();
    fs::write(indexeddb.join("CURRENT"), "MANIFEST-000001\n").unwrap();
    fs::write(indexeddb.join("000003.log"), "redacted").unwrap();
    let local_storage = claude_root.join("Local Storage/leveldb");
    fs::create_dir_all(&local_storage).unwrap();
    fs::write(local_storage.join("CURRENT"), "MANIFEST-000001\n").unwrap();

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom_bytes = fs::read(artifacts.aibom_path).unwrap();
    let cdx_bytes = fs::read(artifacts.cdx_path).unwrap();
    let aibom_text = String::from_utf8(aibom_bytes.clone()).unwrap();
    let cdx_text = String::from_utf8(cdx_bytes).unwrap();
    assert!(!aibom_text.contains("v10SUPER_SECRET_FIXTURE_BLOB"));
    assert!(!cdx_text.contains("v10SUPER_SECRET_FIXTURE_BLOB"));

    let aibom: Value = serde_json::from_slice(&aibom_bytes).unwrap();
    let declared: Vec<&Value> = aibom["aibom"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|component| {
            component["capabilities"]["declared"]
                .as_array()
                .unwrap()
                .iter()
        })
        .collect();

    let approval = declared
        .iter()
        .find(|cap| cap["id"] == "mcp:cowork:approval-cache:encrypted")
        .expect("missing encrypted approval-cache presence capability");
    assert_eq!(approval["qualifiers"]["store"], "dxt:allowlistCache");
    assert_eq!(
        approval["qualifiers"]["storeFormat"],
        "electron-safeStorage-dpapi"
    );
    assert_eq!(approval["qualifiers"]["support"], "presence-only");
    assert_eq!(approval["qualifiers"]["encrypted"], true);

    let connector_formats: Vec<_> = declared
        .iter()
        .filter(|cap| cap["id"] == "mcp:cowork:remote-connector-store:candidate")
        .filter_map(|cap| cap["qualifiers"]["storeFormat"].as_str())
        .collect();
    assert!(connector_formats.contains(&"indexeddb-leveldb"));
    assert!(connector_formats.contains(&"local-storage-leveldb"));
}

#[tokio::test]
async fn cowork_named_remote_connectors_resolve_from_real_store_session_layout() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let claude_root = root
        .path()
        .join("AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude");
    let session = claude_root.join("local-agent-mode-sessions/account-123/org-456");
    let plugins = session.join("cowork_plugins");
    for plugin in ["slack", "hubspot", "gmail"] {
        fs::create_dir_all(plugins.join(plugin)).unwrap();
    }
    fs::write(
        plugins.join("installed_plugins.json"),
        r#"{
  "installedPlugins": [
    {"id":"slack","name":"Slack"},
    {"id":"hubspot","name":"HubSpot"},
    {"id":"gmail","name":"Gmail"}
  ]
}"#,
    )
    .unwrap();
    fs::write(
        session.join("cowork_settings.json"),
        r#"{
  "enabledPlugins": ["slack", "hubspot"],
  "extraKnownMarketplaces": [{"id":"gmail","enabled":false}]
}"#,
    )
    .unwrap();
    fs::write(
        plugins.join("slack/.mcp.json"),
        r#"{"id":"slack","name":"Slack","type":"http","url":"https://mcp.slack.example/sse"}"#,
    )
    .unwrap();
    fs::write(
        plugins.join("hubspot/.mcp.json"),
        r#"{"id":"hubspot","name":"HubSpot","type":"http","url":"https://mcp.hubspot.example/sse"}"#,
    )
    .unwrap();
    fs::write(
        plugins.join("gmail/.mcp.json"),
        r#"{"id":"gmail","name":"Gmail","type":"http","url":"https://mcp.gmail.example/sse"}"#,
    )
    .unwrap();
    fs::create_dir_all(root.path().join("node_modules/not-a-connector")).unwrap();
    fs::write(
        root.path()
            .join("node_modules/not-a-connector/package.json"),
        r#"{"name":"not-a-connector","version":"1.0.0"}"#,
    )
    .unwrap();

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom_bytes = fs::read(artifacts.aibom_path).unwrap();
    let cdx_bytes = fs::read(artifacts.cdx_path).unwrap();
    let aibom_text = String::from_utf8(aibom_bytes.clone()).unwrap();
    let cdx_text = String::from_utf8(cdx_bytes.clone()).unwrap();

    for expected in ["Slack", "HubSpot", "Gmail"] {
        assert!(cdx_text.contains(expected), "missing {expected} in CDX");
    }
    for expected in [
        "https://mcp.slack.example/sse",
        "https://mcp.hubspot.example/sse",
        "https://mcp.gmail.example/sse",
    ] {
        assert!(aibom_text.contains(expected), "missing {expected} in AIBOM");
    }
    assert!(aibom_text.contains("cowork_plugins"));
    assert!(!cdx_text.contains("not-a-connector"));

    let aibom: Value = serde_json::from_slice(&aibom_bytes).unwrap();
    let connector_caps: Vec<&Value> = aibom["aibom"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|component| {
            component["capabilities"]["declared"]
                .as_array()
                .unwrap()
                .iter()
        })
        .filter(|cap| cap["id"] == "mcp:cowork:remote-connector:registered")
        .collect();
    assert_eq!(connector_caps.len(), 3, "{connector_caps:?}");

    let slack = connector_caps
        .iter()
        .find(|cap| cap["qualifiers"]["connectorId"] == "slack")
        .unwrap();
    assert_eq!(slack["qualifiers"]["name"], "Slack");
    assert_eq!(slack["qualifiers"]["transport"], "http");
    assert_eq!(slack["qualifiers"]["url"], "https://mcp.slack.example/sse");
    assert_eq!(slack["qualifiers"]["enabled"], true);

    let gmail = connector_caps
        .iter()
        .find(|cap| cap["qualifiers"]["connectorId"] == "gmail")
        .unwrap();
    assert_eq!(gmail["qualifiers"]["enabled"], false);
}

#[tokio::test]
async fn cowork_rpm_plugin_bundled_remote_connectors_reach_aibom_output() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let session = root.path().join(
        "AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/local-agent-mode-sessions/account-123/org-456",
    );
    let plugin = session.join("rpm/plugin_marketing");
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
        r#"{
  "name": "Marketing plugin",
  "privateSessionValue": "REEVE_COWORK_PLUGIN_METADATA_DO_NOT_EMIT"
}"#,
    )
    .unwrap();

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom_bytes = fs::read(artifacts.aibom_path).unwrap();
    let cdx_bytes = fs::read(artifacts.cdx_path).unwrap();
    let aibom_text = String::from_utf8(aibom_bytes.clone()).unwrap();
    let cdx_text = String::from_utf8(cdx_bytes).unwrap();

    for expected in [
        "ahrefs",
        "similarweb",
        "klaviyo",
        "supermetrics",
        "google calendar",
        "gmail",
    ] {
        assert!(cdx_text.contains(expected), "missing {expected} in CDX");
    }
    for expected in [
        "https://api.ahrefs.com/mcp/mcp",
        "https://mcp.similarweb.com",
        "https://mcp.klaviyo.com/mcp",
        "https://mcp.supermetrics.com/mcp",
    ] {
        assert!(aibom_text.contains(expected), "missing {expected} in AIBOM");
    }
    for sensitive in [
        "REEVE_COWORK_RPM_PROBE_DO_NOT_EMIT",
        "REEVE_COWORK_PLUGIN_METADATA_DO_NOT_EMIT",
    ] {
        assert!(
            !aibom_text.contains(sensitive),
            "leaked {sensitive} in AIBOM"
        );
        assert!(!cdx_text.contains(sensitive), "leaked {sensitive} in CDX");
    }

    let aibom: Value = serde_json::from_slice(&aibom_bytes).unwrap();
    let connector_caps: Vec<&Value> = aibom["aibom"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|component| {
            component["capabilities"]["declared"]
                .as_array()
                .unwrap()
                .iter()
        })
        .filter(|cap| cap["id"] == "mcp:cowork:remote-connector:registered")
        .collect();
    assert_eq!(connector_caps.len(), 6, "{connector_caps:?}");

    let ahrefs = connector_caps
        .iter()
        .find(|cap| cap["qualifiers"]["connectorId"] == "ahrefs")
        .unwrap();
    assert_eq!(ahrefs["qualifiers"]["store"], "rpm");
    assert_eq!(ahrefs["qualifiers"]["transport"], "http");
    assert_eq!(ahrefs["qualifiers"]["connected"], true);
    assert_eq!(
        ahrefs["qualifiers"]["url"],
        "https://api.ahrefs.com/mcp/mcp"
    );

    let gmail = connector_caps
        .iter()
        .find(|cap| cap["qualifiers"]["connectorId"] == "gmail")
        .unwrap();
    assert_eq!(gmail["qualifiers"]["store"], "rpm");
    assert_eq!(gmail["qualifiers"]["transport"], "http");
    assert_eq!(gmail["qualifiers"]["connected"], false);
    assert!(gmail["qualifiers"].get("url").is_none());
}

#[tokio::test]
async fn cowork_macos_remote_session_descriptors_do_not_leak_sensitive_fields() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let session = root
        .path()
        .join("Library/Application Support/Claude/local-agent-mode-sessions/account-123/org-456");
    fs::create_dir_all(&session).unwrap();
    fs::write(
        session.join("local_123.json"),
        r#"{
  "emailAddress": "secret@example.com",
  "cwd": "/Users/example/private",
  "systemPrompt": "TOP_SECRET_SYSTEM_PROMPT",
  "userSelectedFolders": ["/Users/example/private"],
  "remoteMcpServersConfig": [
    {
      "name": "EXA.ai",
      "uuid": "e786afac-3991-4dc4-8334-68fdbf06aa9e",
      "tools": [
        {"name": "web_search_exa", "description": "Search the web"},
        {"name": "company_research_exa", "description": "Research a company"}
      ]
    },
    {
      "uuid": "7de6993b-41e7-46dd-9ae0-1f3108a607c6",
      "tools": [
        {"name": "create_file", "description": "Create a file"}
      ]
    }
  ]
}"#,
    )
    .unwrap();

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .unwrap();
    let aibom_bytes = fs::read(artifacts.aibom_path).unwrap();
    let cdx_bytes = fs::read(artifacts.cdx_path).unwrap();
    let aibom_text = String::from_utf8(aibom_bytes.clone()).unwrap();
    let cdx_text = String::from_utf8(cdx_bytes).unwrap();

    for expected in ["EXA.ai", "7de6993b-41e7-46dd-9ae0-1f3108a607c6"] {
        assert!(cdx_text.contains(expected), "missing {expected} in CDX");
    }
    for sensitive in [
        "secret@example.com",
        "/Users/example/private",
        "TOP_SECRET_SYSTEM_PROMPT",
    ] {
        assert!(
            !aibom_text.contains(sensitive),
            "leaked {sensitive} in AIBOM"
        );
        assert!(!cdx_text.contains(sensitive), "leaked {sensitive} in CDX");
    }

    let aibom: Value = serde_json::from_slice(&aibom_bytes).unwrap();
    let declared: Vec<&Value> = aibom["aibom"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|component| {
            component["capabilities"]["declared"]
                .as_array()
                .unwrap()
                .iter()
        })
        .collect();
    for expected in [
        "mcp:web-search-exa",
        "mcp:company-research-exa",
        "mcp:create-file",
    ] {
        assert!(
            declared.iter().any(|cap| cap["id"] == expected),
            "missing declared capability {expected}: {declared:?}"
        );
    }
}
