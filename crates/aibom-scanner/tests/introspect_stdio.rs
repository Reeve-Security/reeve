use aibom_core::{DiscoverySource, StdioConfig, ToolProvider, Transport};
use aibom_scanner::mcp::{McpAdapter, capabilities::IntrospectionOptions};
use std::collections::BTreeMap;
use std::path::PathBuf;

// launch-proof: #325 Introspection (tools/list)
#[tokio::test]
async fn introspects_stdio_test_server() {
    let server = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("test_mcp_server.py");
    let provider = ToolProvider {
        surface: "test".into(),
        name: "fixture".into(),
        transport: Transport::Stdio(StdioConfig {
            command: "python3".into(),
            args: vec![server.display().to_string()],
            env: BTreeMap::new(),
        }),
        source_path: None,
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    };
    let caps = McpAdapter::new()
        .introspect_with_options(
            &provider,
            IntrospectionOptions {
                execute_stdio: true,
            },
        )
        .await
        .unwrap();
    assert!(caps.declared.iter().any(|cap| cap.id == "fs:read"));
}
