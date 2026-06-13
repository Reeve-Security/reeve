//! Continue MCP config parser.
//!
//! Source checked against Continue MCP customization docs:
//! https://docs.continue.dev/customize/model-context-protocol

use super::{ConfigFormat, ConfigSurface, ParserKind, SurfaceSpec};

pub struct ContinueDev;

impl ConfigSurface for ContinueDev {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "continue",
            paths: &[
                ".continue/config.yaml",
                ".continue/config.yml",
                ".continue/config.json",
            ],
            glob_paths: &[],
            workspace_search: None,
            workspace_searches: &[],
            package_root_search: None,
            parser: ParserKind::McpConfig,
            format: ConfigFormat::JsonOrYaml,
            roots: &[&["mcpServers"], &["mcp_servers"]],
            fixture_names: &["continue_1.yaml", "continue_2.yaml"],
        }
    }
}
