//! Claude Code desktop session-state parser.
//!
//! The Claude desktop app has a Claude Code mode with a session store separate
//! from the Claude Code CLI config files. The local session descriptor schema is
//! close to Cowork's plaintext session descriptor, so this surface reuses the
//! bounded session parser while keeping a distinct surface name.

use super::{ConfigFormat, ConfigSurface, PackageRootSearch, ParserKind, SurfaceSpec};

pub struct ClaudeCodeDesktop;

impl ConfigSurface for ClaudeCodeDesktop {
    fn spec() -> SurfaceSpec {
        SurfaceSpec {
            name: "claude-code-desktop",
            paths: &[],
            glob_paths: &[
                "Library/Application Support/Claude/claude-code-sessions/*/*/local_*.json",
                "AppData/Roaming/Claude/claude-code-sessions/*/*/local_*.json",
            ],
            workspace_search: None,
            workspace_searches: &[],
            package_root_search: Some(PackageRootSearch {
                base: "AppData/Local/Packages",
                package_glob: "Claude_*",
                primary_paths: &[],
                primary_glob_paths: &[
                    "LocalCache/Roaming/Claude/claude-code-sessions/*/*/local_*.json",
                ],
                auxiliary_glob_paths: &[],
            }),
            parser: ParserKind::ClaudeCodeDesktopSessions,
            format: ConfigFormat::Json,
            roots: &[],
            fixture_names: &[
                "local_claude_code_desktop_session_approvals_mac.json",
                "local_claude_code_desktop_session_approvals_win.json",
            ],
        }
    }
}
