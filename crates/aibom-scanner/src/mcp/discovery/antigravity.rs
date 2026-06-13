//! Google Antigravity MCP config parser.
//!
//! Source checked against Google Antigravity MCP docs:
//! https://antigravity.google/docs/mcp

use super::{ConfigFormat, ConfigSurface, ParserKind, SurfaceSpec};

pub struct Antigravity;

impl ConfigSurface for Antigravity {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "antigravity",
            paths: &[".gemini/antigravity/mcp_config.json"],
            glob_paths: &[],
            workspace_search: None,
            workspace_searches: &[],
            package_root_search: None,
            parser: ParserKind::McpConfig,
            format: ConfigFormat::Json,
            roots: &[&["mcpServers"]],
            fixture_names: &["antigravity_1.json", "antigravity_2.json"],
        }
    }
}
