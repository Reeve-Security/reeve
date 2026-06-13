//! Claude Desktop/user MCP config parser.
//!
//! Source checked against MCP user quickstart:
//! https://modelcontextprotocol.io/quickstart/user

use super::{ConfigFormat, ConfigSurface, PackageRootSearch, ParserKind, SurfaceSpec};

pub struct ClaudeDesktop;

impl ConfigSurface for ClaudeDesktop {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "claude-desktop",
            // Anthropic ships Claude Desktop for macOS + Windows only; there is no
            // official Linux build, so no Linux (`.config/Claude`) path is scanned.
            paths: &[
                "Library/Application Support/Claude/claude_desktop_config.json",
                "AppData/Roaming/Claude/claude_desktop_config.json",
            ],
            glob_paths: &[],
            workspace_search: None,
            workspace_searches: &[],
            package_root_search: Some(PackageRootSearch {
                base: "AppData/Local/Packages",
                package_glob: "Claude_*",
                primary_paths: &["LocalCache/Roaming/Claude/claude_desktop_config.json"],
                primary_glob_paths: &[],
                auxiliary_glob_paths: &[],
            }),
            parser: ParserKind::McpConfig,
            format: ConfigFormat::Json,
            roots: &[&["mcpServers"]],
            fixture_names: &["claude_desktop_1.json", "claude_desktop_2.json"],
        }
    }
}
