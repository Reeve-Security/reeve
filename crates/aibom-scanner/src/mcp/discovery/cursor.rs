//! Cursor MCP config parser.
//!
//! Source checked against Cursor MCP docs:
//! https://docs.cursor.com/context/model-context-protocol

use super::{ConfigFormat, ConfigSurface, ParserKind, SurfaceSpec};
use super::{DEFAULT_SKIP_DIRS, WorkspaceSearch};

pub struct Cursor;

impl ConfigSurface for Cursor {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "cursor",
            paths: &[
                ".cursor/mcp.json",
                ".cursor/mcpServers.json",
                ".config/Cursor/mcp.json",
            ],
            glob_paths: &[
                ".cursor/projects/*/mcps/*.json",
                ".cursor/projects/*/mcps/*/SERVER_METADATA.json",
            ],
            workspace_search: None,
            workspace_searches: &[
                WorkspaceSearch {
                    filename: "mcp.json",
                    parent_dir: Some(".cursor"),
                    max_depth: 6,
                    skip_dirs: DEFAULT_SKIP_DIRS,
                },
                WorkspaceSearch {
                    filename: "mcpServers.json",
                    parent_dir: Some(".cursor"),
                    max_depth: 6,
                    skip_dirs: DEFAULT_SKIP_DIRS,
                },
            ],
            package_root_search: None,
            parser: ParserKind::McpConfig,
            format: ConfigFormat::Json,
            roots: &[&["mcpServers"], &["servers"]],
            fixture_names: &["cursor_1.json", "cursor_2.json"],
        }
    }
}
