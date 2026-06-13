//! VS Code MCP config parser.
//!
//! Source checked against VS Code MCP docs:
//! https://code.visualstudio.com/docs/copilot/chat/mcp-servers

use super::{
    ConfigFormat, ConfigSurface, DEFAULT_SKIP_DIRS, ParserKind, SurfaceSpec, WorkspaceSearch,
};

pub struct VsCodeMcp;

impl ConfigSurface for VsCodeMcp {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "vscode",
            paths: &[
                ".vscode/mcp.json",
                ".config/Code/User/mcp.json",
                ".config/Code/User/settings.json",
                "AppData/Roaming/Code/User/mcp.json",
                "AppData/Roaming/Code/User/settings.json",
            ],
            glob_paths: &[],
            workspace_search: Some(WorkspaceSearch {
                filename: "mcp.json",
                parent_dir: Some(".vscode"),
                max_depth: 5,
                skip_dirs: DEFAULT_SKIP_DIRS,
            }),
            workspace_searches: &[],
            package_root_search: None,
            parser: ParserKind::McpConfig,
            format: ConfigFormat::Json,
            roots: &[&["servers"], &["mcp", "servers"], &["mcpServers"]],
            fixture_names: &["vscode_1.json", "vscode_2.json"],
        }
    }
}
