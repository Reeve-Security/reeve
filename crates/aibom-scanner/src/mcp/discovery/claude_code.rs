//! Claude Code MCP config parser.
//!
//! Source checked against Claude Code MCP docs:
//! https://code.claude.com/docs/en/mcp

use super::{
    ConfigFormat, ConfigSurface, DEFAULT_SKIP_DIRS, PackageRootSearch, ParserKind, SurfaceSpec,
    WorkspaceSearch,
};

pub struct ClaudeCode;

impl ConfigSurface for ClaudeCode {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "claude-code",
            paths: &[".mcp.json", ".claude.json", ".claude/settings.json"],
            glob_paths: &[
                "Library/Application Support/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json",
                "AppData/Roaming/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json",
            ],
            workspace_search: Some(WorkspaceSearch {
                filename: ".mcp.json",
                parent_dir: None,
                max_depth: 4,
                skip_dirs: DEFAULT_SKIP_DIRS,
            }),
            workspace_searches: &[WorkspaceSearch {
                filename: "settings.local.json",
                parent_dir: Some(".claude"),
                max_depth: 5,
                skip_dirs: DEFAULT_SKIP_DIRS,
            }],
            package_root_search: Some(PackageRootSearch {
                base: "AppData/Local/Packages",
                package_glob: "Claude_*",
                primary_paths: &[],
                primary_glob_paths: &[
                    "LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json",
                ],
                auxiliary_glob_paths: &[],
            }),
            parser: ParserKind::McpConfig,
            format: ConfigFormat::Json,
            roots: &[&["mcpServers"], &["projects", "default", "mcpServers"]],
            fixture_names: &["claude_code_1.json", "claude_code_2.json"],
        }
    }
}
