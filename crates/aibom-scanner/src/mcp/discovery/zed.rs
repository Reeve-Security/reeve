//! Zed context-server/MCP config parser.
//!
//! Source checked against Zed MCP docs:
//! https://zed.dev/docs/ai/mcp

use super::{ConfigFormat, ConfigSurface, ParserKind, SurfaceSpec};

pub struct Zed;

impl ConfigSurface for Zed {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "zed",
            paths: &[".config/zed/settings.json", ".zed/settings.json"],
            glob_paths: &[],
            workspace_search: None,
            workspace_searches: &[],
            package_root_search: None,
            parser: ParserKind::McpConfig,
            format: ConfigFormat::Json,
            roots: &[&["context_servers"], &["mcpServers"]],
            fixture_names: &["zed_1.json", "zed_2.json"],
        }
    }
}
