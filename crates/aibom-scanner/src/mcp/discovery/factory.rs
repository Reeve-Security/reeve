//! Factory MCP config parser.
//!
//! Source checked against Factory CLI MCP docs:
//! https://docs.factory.ai/factory-cli/configuration/mcp

use super::{
    ConfigFormat, ConfigSurface, DEFAULT_SKIP_DIRS, ParserKind, SurfaceSpec, WorkspaceSearch,
};

pub struct Factory;

impl ConfigSurface for Factory {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "factory",
            paths: &[".factory/mcp.json"],
            glob_paths: &[],
            workspace_search: Some(WorkspaceSearch {
                filename: "mcp.json",
                parent_dir: Some(".factory"),
                max_depth: 5,
                skip_dirs: DEFAULT_SKIP_DIRS,
            }),
            workspace_searches: &[],
            package_root_search: None,
            parser: ParserKind::McpConfig,
            format: ConfigFormat::Json,
            roots: &[&["mcpServers"], &["servers"]],
            fixture_names: &["factory_1.json", "factory_2.json"],
        }
    }
}
