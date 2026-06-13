//! MCP config discovery registry.
//!
//! Primary-source references used by child parsers:
//! - Claude Desktop/user MCP: https://modelcontextprotocol.io/quickstart/user
//! - Claude Desktop Extensions/MCPB: https://claude.com/docs/connectors/building/mcpb
//! - MCPB `${__dirname}` contract: https://www.anthropic.com/engineering/desktop-extensions
//! - Claude Cowork app-internal stores: observed local fixtures, not a published contract
//! - Cursor MCP: https://docs.cursor.com/context/model-context-protocol
//! - Continue MCP: https://docs.continue.dev/customize/model-context-protocol
//! - Claude Code MCP: https://code.claude.com/docs/en/mcp
//! - Codex CLI config: https://developers.openai.com/codex/config-reference
//! - Zed MCP/context servers: https://zed.dev/docs/ai/mcp
//! - VS Code MCP: https://code.visualstudio.com/docs/copilot/chat/mcp-servers
//! - Factory MCP: https://docs.factory.ai/factory-cli/configuration/mcp
//! - Google Antigravity MCP: https://antigravity.google/docs/mcp

use aibom_core::{
    DiscoverySource, HttpConfig, StdioConfig, ToolProvider, Transport, UnknownConfig, WsConfig,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

pub mod antigravity;
pub mod claude_code;
pub mod claude_code_desktop;
pub mod claude_cowork;
pub mod claude_desktop;
pub mod codex_cli;
pub mod continue_dev;
pub mod cursor;
pub mod factory;
pub mod vscode_mcp;
pub mod zed;

pub const CLAUDE_CODE_GRANT_STATE_PROVIDER_NAME: &str = "claude-code-approval-state";
pub const CLAUDE_CODE_ACCEPT_EDITS_GRANT_STATE_PROVIDER_NAME: &str = "claude-code-approval-state";
pub const CLAUDE_DESKTOP_GRANT_STATE_PROVIDER_NAME: &str = "claude-desktop-approval-state";
pub const CODEX_CLI_GRANT_STATE_PROVIDER_NAME: &str = "codex-cli-approval-state";
pub const CODEX_APP_GRANT_STATE_PROVIDER_NAME: &str = "codex-app-approval-state";

pub const DEFAULT_SKIP_DIRS: &[&str] = &[
    ".cache",
    ".git",
    ".idea",
    ".next",
    ".venv",
    ".vscode-insiders",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "venv",
];

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SurfaceSpec {
    pub name: &'static str,
    pub paths: &'static [&'static str],
    pub glob_paths: &'static [&'static str],
    pub workspace_search: Option<WorkspaceSearch>,
    pub workspace_searches: &'static [WorkspaceSearch],
    pub package_root_search: Option<PackageRootSearch>,
    pub parser: ParserKind,
    pub format: ConfigFormat,
    pub roots: &'static [&'static [&'static str]],
    pub fixture_names: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct WorkspaceSearch {
    pub filename: &'static str,
    pub parent_dir: Option<&'static str>,
    pub max_depth: usize,
    pub skip_dirs: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct PackageRootSearch {
    pub base: &'static str,
    pub package_glob: &'static str,
    pub primary_paths: &'static [&'static str],
    pub primary_glob_paths: &'static [&'static str],
    pub auxiliary_glob_paths: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ParserKind {
    McpConfig,
    ClaudeCoworkMcpbExtensions,
    ClaudeCodeDesktopSessions,
    CodexConfig,
    CodexGlobalState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigFormat {
    Json,
    JsonOrYaml,
    Toml,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeCatalogEntry {
    pub adapter: Cow<'static, str>,
    pub surface: Cow<'static, str>,
    pub parser: ParserKind,
    pub format: ConfigFormat,
    pub os_paths: Vec<ScopedPath>,
    pub paths: Vec<Cow<'static, str>>,
    pub glob_paths: Vec<Cow<'static, str>>,
    pub workspace_search: Option<WorkspaceSearch>,
    pub workspace_searches: Vec<WorkspaceSearch>,
    pub package_root_search: Option<PackageRootSearch>,
    pub roots: Vec<Vec<Cow<'static, str>>>,
    pub fixture_names: Vec<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopedPath {
    pub os: Cow<'static, str>,
    pub source: Cow<'static, str>,
    pub path: Cow<'static, str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DryRunEntry {
    pub adapter: Cow<'static, str>,
    pub surface: Cow<'static, str>,
    pub path: PathBuf,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DryRunSurface {
    pub adapter: Cow<'static, str>,
    pub surface: Cow<'static, str>,
    pub detected: bool,
    pub entries: Vec<DryRunEntry>,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CustomSurfaceFile {
    pub surfaces: Vec<CustomSurfaceSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CustomSurfaceSpec {
    pub name: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub glob_paths: Vec<String>,
    pub format: ConfigFormat,
    #[serde(default = "default_custom_roots")]
    pub roots: Vec<Vec<String>>,
}

fn default_custom_roots() -> Vec<Vec<String>> {
    vec![vec!["mcpServers".to_string()]]
}

pub trait ConfigSurface {
    fn spec() -> SurfaceSpec;
}

pub fn discover_all(target_root: &Path) -> Result<Vec<ToolProvider>> {
    discover_all_with_custom(target_root, &[])
}

pub fn discover_all_with_custom(
    target_root: &Path,
    custom_surfaces: &[CustomSurfaceSpec],
) -> Result<Vec<ToolProvider>> {
    let mut providers = Vec::new();
    for spec in registry() {
        providers.extend(discover_surface(target_root, spec)?);
    }
    for spec in custom_surfaces {
        providers.extend(discover_custom_surface(target_root, spec)?);
    }
    providers.sort_by(|a, b| {
        a.surface
            .cmp(&b.surface)
            .then(a.name.cmp(&b.name))
            .then(format!("{:?}", a.transport).cmp(&format!("{:?}", b.transport)))
    });
    Ok(providers)
}

pub fn registry() -> Vec<SurfaceSpec> {
    vec![
        claude_desktop::ClaudeDesktop::spec(),
        claude_cowork::ClaudeCowork::spec(),
        claude_code_desktop::ClaudeCodeDesktop::spec(),
        cursor::Cursor::spec(),
        continue_dev::ContinueDev::spec(),
        claude_code::ClaudeCode::spec(),
        codex_cli::CodexCli::spec(),
        codex_cli::CodexGlobalState::spec(),
        factory::Factory::spec(),
        zed::Zed::spec(),
        vscode_mcp::VsCodeMcp::spec(),
        antigravity::Antigravity::spec(),
    ]
}

pub fn scope_catalog() -> Vec<ScopeCatalogEntry> {
    registry()
        .into_iter()
        .map(|spec| ScopeCatalogEntry {
            adapter: Cow::Borrowed("mcp"),
            surface: Cow::Borrowed(spec.name),
            parser: spec.parser,
            format: spec.format,
            os_paths: scoped_paths(spec),
            paths: spec.paths.iter().map(|path| Cow::Borrowed(*path)).collect(),
            glob_paths: spec
                .glob_paths
                .iter()
                .map(|path| Cow::Borrowed(*path))
                .collect(),
            workspace_search: spec.workspace_search,
            workspace_searches: spec.workspace_searches.to_vec(),
            package_root_search: spec.package_root_search,
            roots: spec
                .roots
                .iter()
                .map(|root| root.iter().map(|segment| Cow::Borrowed(*segment)).collect())
                .collect(),
            fixture_names: spec
                .fixture_names
                .iter()
                .map(|fixture| Cow::Borrowed(*fixture))
                .collect(),
        })
        .collect()
}

fn scoped_paths(spec: SurfaceSpec) -> Vec<ScopedPath> {
    let mut paths = Vec::new();
    for path in spec.paths {
        paths.push(ScopedPath {
            os: Cow::Borrowed(os_for_path(path)),
            source: Cow::Borrowed("literal-path"),
            path: Cow::Borrowed(path),
        });
    }
    for path in spec.glob_paths {
        paths.push(ScopedPath {
            os: Cow::Borrowed(os_for_path(path)),
            source: Cow::Borrowed("glob-path"),
            path: Cow::Borrowed(path),
        });
    }
    for search in workspace_searches_for_spec(spec) {
        paths.push(ScopedPath {
            os: Cow::Borrowed("all"),
            source: Cow::Borrowed("workspace-search"),
            path: Cow::Borrowed(search.filename),
        });
    }
    if let Some(search) = spec.package_root_search {
        for rel in search.primary_paths {
            paths.push(ScopedPath {
                os: Cow::Borrowed(os_for_path(search.base)),
                source: Cow::Borrowed("package-root-search"),
                path: Cow::Owned(format!("{}/{}/{}", search.base, search.package_glob, rel)),
            });
        }
        for rel in search.primary_glob_paths {
            paths.push(ScopedPath {
                os: Cow::Borrowed(os_for_path(search.base)),
                source: Cow::Borrowed("package-root-search"),
                path: Cow::Owned(format!("{}/{}/{}", search.base, search.package_glob, rel)),
            });
        }
        for rel in search.auxiliary_glob_paths {
            paths.push(ScopedPath {
                os: Cow::Borrowed(os_for_path(search.base)),
                source: Cow::Borrowed("package-root-auxiliary"),
                path: Cow::Owned(format!("{}/{}/{}", search.base, search.package_glob, rel)),
            });
        }
    }
    paths
}

fn os_for_path(path: &str) -> &'static str {
    if path.starts_with("Library/") {
        "macos"
    } else if path.starts_with("AppData/") {
        "windows"
    } else if path.starts_with(".config/") {
        "linux"
    } else {
        "all"
    }
}

pub fn custom_scope_catalog(custom_surfaces: &[CustomSurfaceSpec]) -> Vec<ScopeCatalogEntry> {
    custom_surfaces
        .iter()
        .map(|spec| {
            let paths: Vec<Cow<'static, str>> =
                spec.paths.iter().cloned().map(Cow::Owned).collect();
            let glob_paths: Vec<Cow<'static, str>> =
                spec.glob_paths.iter().cloned().map(Cow::Owned).collect();
            let roots: Vec<Vec<Cow<'static, str>>> = spec
                .roots
                .iter()
                .map(|root| root.iter().cloned().map(Cow::Owned).collect())
                .collect();
            ScopeCatalogEntry {
                adapter: Cow::Borrowed("mcp"),
                surface: Cow::Owned(spec.name.clone()),
                format: spec.format,
                parser: ParserKind::McpConfig,
                os_paths: paths
                    .iter()
                    .map(|path| ScopedPath {
                        os: Cow::Borrowed("custom"),
                        source: Cow::Borrowed("user-defined"),
                        path: path.clone(),
                    })
                    .collect(),
                paths,
                glob_paths,
                workspace_search: None,
                workspace_searches: Vec::new(),
                package_root_search: None,
                roots,
                fixture_names: Vec::new(),
            }
        })
        .collect()
}

pub fn dry_run_surfaces(target_root: &Path) -> Result<Vec<DryRunSurface>> {
    dry_run_surfaces_with_custom(target_root, &[])
}

pub fn dry_run_surfaces_with_custom(
    target_root: &Path,
    custom_surfaces: &[CustomSurfaceSpec],
) -> Result<Vec<DryRunSurface>> {
    let mut surfaces: Vec<DryRunSurface> = registry()
        .into_iter()
        .map(|spec| dry_run_surface(target_root, spec))
        .collect::<Result<Vec<_>>>()?;
    for spec in custom_surfaces {
        surfaces.push(dry_run_custom_surface(target_root, spec)?);
    }
    Ok(surfaces)
}

pub fn load_custom_surfaces(config_path: &Path) -> Result<Vec<CustomSurfaceSpec>> {
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("read custom surface config {}", config_path.display()))?;
    let config: CustomSurfaceFile = serde_yaml::from_str(&raw)
        .with_context(|| format!("parse custom surface config {}", config_path.display()))?;
    for surface in &config.surfaces {
        validate_custom_surface(surface)?;
    }
    Ok(config.surfaces)
}

fn validate_custom_surface(surface: &CustomSurfaceSpec) -> Result<()> {
    if surface.name.is_empty()
        || !surface
            .name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        bail!("custom surface name must use ascii letters, numbers, dash, underscore, or dot");
    }
    if surface.paths.is_empty() && surface.glob_paths.is_empty() {
        bail!("custom surface must declare at least one path or glob-path");
    }
    for rel in surface.paths.iter().chain(surface.glob_paths.iter()) {
        validate_custom_path(rel)?;
    }
    if surface.roots.is_empty() || surface.roots.iter().any(Vec::is_empty) {
        bail!("custom surface roots must include at least one non-empty parser root");
    }
    Ok(())
}

fn validate_custom_path(rel: &str) -> Result<()> {
    let path = Path::new(rel);
    if path.is_absolute() {
        bail!("custom surface path must be relative: {rel}");
    }
    if rel.is_empty()
        || rel.contains('\0')
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("custom surface path must stay below scan target: {rel}");
    }
    Ok(())
}

fn discover_custom_surface(
    target_root: &Path,
    spec: &CustomSurfaceSpec,
) -> Result<Vec<ToolProvider>> {
    let mut providers = Vec::new();
    for path in custom_config_paths(target_root, spec)? {
        let value = read_config(&path, spec.format)
            .with_context(|| format!("parse user-defined config {}", path.display()))?;
        providers.extend(parse_custom_value(spec, &path, &value));
    }
    Ok(providers)
}

fn parse_custom_value(
    spec: &CustomSurfaceSpec,
    source_path: &Path,
    value: &Value,
) -> Vec<ToolProvider> {
    let roots: Vec<Vec<&str>> = spec
        .roots
        .iter()
        .map(|root| root.iter().map(String::as_str).collect())
        .collect();
    parse_value_with_source(
        &spec.name,
        source_path,
        value,
        &roots,
        DiscoverySource::UserDefined,
    )
}

fn custom_config_paths(target_root: &Path, spec: &CustomSurfaceSpec) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    let target_root = target_root
        .canonicalize()
        .with_context(|| format!("canonicalize scan target {}", target_root.display()))?;
    for rel in &spec.paths {
        let path = target_root.join(rel);
        if path.is_file() && custom_path_stays_under_target(&target_root, &path)? {
            paths.insert(path);
        }
    }
    for pattern in &spec.glob_paths {
        let absolute_pattern = target_root.join(pattern);
        for entry in glob::glob(&absolute_pattern.to_string_lossy())? {
            let Ok(path) = entry else {
                continue;
            };
            if path.is_file() && custom_path_stays_under_target(&target_root, &path)? {
                paths.insert(path);
            }
        }
    }
    Ok(paths.into_iter().collect())
}

fn custom_path_stays_under_target(target_root: &Path, path: &Path) -> Result<bool> {
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("canonicalize custom surface path {}", path.display()))?;
    if !canonical_path.starts_with(target_root) {
        bail!(
            "custom surface path resolves outside scan target: {}",
            path.display()
        );
    }
    Ok(true)
}

pub fn discover_surface(target_root: &Path, spec: SurfaceSpec) -> Result<Vec<ToolProvider>> {
    let mut providers = Vec::new();
    for path in config_paths(target_root, spec)? {
        match spec.parser {
            ParserKind::McpConfig => {
                let value = read_config(&path, spec.format)
                    .with_context(|| format!("parse {} config {}", spec.name, path.display()))?;
                providers.extend(parse_value(spec.name, &path, &value, spec.roots));
            }
            ParserKind::ClaudeCoworkMcpbExtensions => {
                providers.extend(claude_cowork::parse_cowork_file(&path).with_context(|| {
                    format!("parse {} Cowork state {}", spec.name, path.display())
                })?);
            }
            ParserKind::ClaudeCodeDesktopSessions => {
                providers.extend(
                    claude_cowork::parse_claude_code_desktop_file(&path).with_context(|| {
                        format!("parse {} session state {}", spec.name, path.display())
                    })?,
                );
            }
            ParserKind::CodexConfig => {
                providers.extend(codex_cli::discover_codex_config(spec, &path)?);
            }
            ParserKind::CodexGlobalState => {
                providers.extend(codex_cli::discover_codex_global_state(spec, &path)?);
            }
        }
    }
    Ok(providers)
}

fn config_paths(target_root: &Path, spec: SurfaceSpec) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    for rel in spec.paths {
        for path in literal_config_path_candidates(target_root, rel)? {
            paths.insert(path);
        }
    }
    for pattern in spec.glob_paths {
        let pattern = target_root.join(pattern);
        for entry in glob::glob(&pattern.to_string_lossy())? {
            let path = entry?;
            if path.is_file() {
                paths.insert(path);
            }
        }
    }
    for search in workspace_searches_for_spec(spec) {
        for entry in WalkDir::new(target_root)
            .max_depth(search.max_depth)
            .into_iter()
            .filter_entry(|entry| keep_entry(entry, search.skip_dirs))
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file()
                && entry.file_name() == search.filename
                && parent_matches(&entry, search.parent_dir)
            {
                paths.insert(entry.into_path());
            }
        }
    }
    if let Some(search) = spec.package_root_search {
        for package_root in package_roots(target_root, search)? {
            for rel in search.primary_paths {
                let path = package_root.join(rel);
                if path.is_file() {
                    paths.insert(path);
                }
            }
            for rel in search.primary_glob_paths {
                let pattern = package_root.join(rel);
                for entry in glob::glob(&pattern.to_string_lossy())? {
                    let Ok(path) = entry else {
                        continue;
                    };
                    if path.is_file() {
                        paths.insert(path);
                    }
                }
            }
        }
    }
    Ok(paths.into_iter().collect())
}

fn workspace_searches_for_spec(spec: SurfaceSpec) -> impl Iterator<Item = WorkspaceSearch> {
    spec.workspace_search
        .into_iter()
        .chain(spec.workspace_searches.iter().copied())
}

fn package_roots(target_root: &Path, search: PackageRootSearch) -> Result<Vec<PathBuf>> {
    let pattern = target_root.join(search.base).join(search.package_glob);
    let mut roots = BTreeSet::new();
    for entry in glob::glob(&pattern.to_string_lossy())? {
        let Ok(path) = entry else {
            continue;
        };
        if path.is_dir() {
            roots.insert(path);
        }
    }
    Ok(roots.into_iter().collect())
}

fn literal_config_path_candidates(target_root: &Path, rel: &str) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let direct = target_root.join(rel);
    if direct.is_file() {
        paths.push(direct);
    }
    for entry in fs::read_dir(target_root)
        .with_context(|| format!("read scan target {}", target_root.display()))?
        .filter_map(Result::ok)
    {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path().join(rel);
        if path.is_file() {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn dry_run_surface(target_root: &Path, spec: SurfaceSpec) -> Result<DryRunSurface> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for rel in spec.paths {
        for path in literal_config_path_candidates(target_root, rel)? {
            if !seen.insert(path.clone()) {
                continue;
            }
            entries.push(DryRunEntry {
                adapter: Cow::Borrowed("mcp"),
                surface: Cow::Borrowed(spec.name),
                path,
                source: "literal-path".to_string(),
                reason: format!("exact config path `{rel}` exists"),
            });
        }
    }
    for pattern in spec.glob_paths {
        let absolute_pattern = target_root.join(pattern);
        for entry in glob::glob(&absolute_pattern.to_string_lossy())? {
            let Ok(path) = entry else {
                continue;
            };
            if path.is_file() && seen.insert(path.clone()) {
                entries.push(DryRunEntry {
                    adapter: Cow::Borrowed("mcp"),
                    surface: Cow::Borrowed(spec.name),
                    path,
                    source: "glob-path".to_string(),
                    reason: format!("glob `{pattern}` matched"),
                });
            }
        }
    }
    for search in workspace_searches_for_spec(spec) {
        for entry in WalkDir::new(target_root)
            .max_depth(search.max_depth)
            .into_iter()
            .filter_entry(|entry| keep_entry(entry, search.skip_dirs))
            .filter_map(Result::ok)
        {
            if entry.file_type().is_file()
                && entry.file_name() == search.filename
                && parent_matches(&entry, search.parent_dir)
            {
                let path = entry.into_path();
                if seen.insert(path.clone()) {
                    entries.push(DryRunEntry {
                        adapter: Cow::Borrowed("mcp"),
                        surface: Cow::Borrowed(spec.name),
                        path,
                        source: "workspace-search".to_string(),
                        reason: format!(
                            "bounded workspace search matched filename `{}` at max depth {}",
                            search.filename, search.max_depth
                        ),
                    });
                }
            }
        }
    }
    if let Some(search) = spec.package_root_search {
        for package_root in package_roots(target_root, search)? {
            let mut primary_detected = false;
            for rel in search.primary_paths {
                let path = package_root.join(rel);
                if path.is_file() && seen.insert(path.clone()) {
                    primary_detected = true;
                    entries.push(DryRunEntry {
                        adapter: Cow::Borrowed("mcp"),
                        surface: Cow::Borrowed(spec.name),
                        path,
                        source: "package-root-search".to_string(),
                        reason: format!(
                            "package root `{}/{}` matched primary path `{rel}`",
                            search.base, search.package_glob
                        ),
                    });
                } else if path.is_file() {
                    primary_detected = true;
                }
            }
            for rel in search.primary_glob_paths {
                let pattern = package_root.join(rel);
                for entry in glob::glob(&pattern.to_string_lossy())? {
                    let Ok(path) = entry else {
                        continue;
                    };
                    if path.is_file() && seen.insert(path.clone()) {
                        primary_detected = true;
                        entries.push(DryRunEntry {
                            adapter: Cow::Borrowed("mcp"),
                            surface: Cow::Borrowed(spec.name),
                            path,
                            source: "package-root-search".to_string(),
                            reason: format!(
                                "package root `{}/{}` matched primary glob `{rel}`",
                                search.base, search.package_glob
                            ),
                        });
                    } else if path.is_file() {
                        primary_detected = true;
                    }
                }
            }
            if !primary_detected {
                continue;
            }
            for rel in search.auxiliary_glob_paths {
                let pattern = package_root.join(rel);
                for entry in glob::glob(&pattern.to_string_lossy())? {
                    let Ok(path) = entry else {
                        continue;
                    };
                    if path.is_file() && seen.insert(path.clone()) {
                        entries.push(DryRunEntry {
                            adapter: Cow::Borrowed("mcp"),
                            surface: Cow::Borrowed(spec.name),
                            path,
                            source: "package-root-auxiliary".to_string(),
                            reason: format!(
                                "package root auxiliary glob `{rel}` would be read with primary inventory"
                            ),
                        });
                    }
                }
            }
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let detected = !entries.is_empty();
    let reason = if detected {
        format!("{} readable config path(s) would be opened", entries.len())
    } else {
        "no matching config paths found; surface would not trigger".to_string()
    };
    Ok(DryRunSurface {
        adapter: Cow::Borrowed("mcp"),
        surface: Cow::Borrowed(spec.name),
        detected,
        entries,
        reason,
    })
}

fn dry_run_custom_surface(target_root: &Path, spec: &CustomSurfaceSpec) -> Result<DryRunSurface> {
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let canonical_target_root = target_root
        .canonicalize()
        .with_context(|| format!("canonicalize scan target {}", target_root.display()))?;
    for rel in &spec.paths {
        let path = target_root.join(rel);
        if path.is_file()
            && custom_path_stays_under_target(&canonical_target_root, &path)?
            && seen.insert(path.clone())
        {
            entries.push(DryRunEntry {
                adapter: Cow::Borrowed("mcp"),
                surface: Cow::Owned(spec.name.clone()),
                path,
                source: "user-defined literal-path".to_string(),
                reason: format!("custom surface exact config path `{rel}` exists"),
            });
        }
    }
    for pattern in &spec.glob_paths {
        let absolute_pattern = target_root.join(pattern);
        for entry in glob::glob(&absolute_pattern.to_string_lossy())? {
            let Ok(path) = entry else {
                continue;
            };
            if path.is_file()
                && custom_path_stays_under_target(&canonical_target_root, &path)?
                && seen.insert(path.clone())
            {
                entries.push(DryRunEntry {
                    adapter: Cow::Borrowed("mcp"),
                    surface: Cow::Owned(spec.name.clone()),
                    path,
                    source: "user-defined glob-path".to_string(),
                    reason: format!("custom surface glob `{pattern}` matched"),
                });
            }
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let detected = !entries.is_empty();
    let reason = if detected {
        format!(
            "{} user-defined readable config path(s) would be opened; lower-trust custom surface",
            entries.len()
        )
    } else {
        "no matching user-defined config paths found; surface would not trigger".to_string()
    };
    Ok(DryRunSurface {
        adapter: Cow::Borrowed("mcp"),
        surface: Cow::Owned(spec.name.clone()),
        detected,
        entries,
        reason,
    })
}

fn parent_matches(entry: &DirEntry, expected_parent: Option<&str>) -> bool {
    let Some(expected_parent) = expected_parent else {
        return true;
    };
    entry
        .path()
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        == Some(expected_parent)
}

fn keep_entry(entry: &DirEntry, skip_dirs: &[&str]) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    entry
        .file_name()
        .to_str()
        .is_none_or(|name| !skip_dirs.contains(&name))
}

pub fn read_config(path: &Path, format: ConfigFormat) -> Result<Value> {
    let raw = fs::read_to_string(path)?;
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    match format {
        ConfigFormat::Json => Ok(serde_json::from_str(raw)?),
        ConfigFormat::JsonOrYaml => serde_json::from_str(raw)
            .or_else(|_| serde_yaml::from_str(raw))
            .map_err(Into::into),
        ConfigFormat::Toml => {
            let value: toml::Value = toml::from_str(raw)?;
            Ok(serde_json::to_value(value)?)
        }
    }
}

pub fn parse_value(
    surface: &str,
    source_path: &Path,
    value: &Value,
    roots: &[&[&str]],
) -> Vec<ToolProvider> {
    let roots: Vec<Vec<&str>> = roots.iter().map(|root| root.to_vec()).collect();
    parse_value_with_source(
        surface,
        source_path,
        value,
        &roots,
        DiscoverySource::BuiltIn,
    )
}

fn parse_value_with_source(
    surface: &str,
    source_path: &Path,
    value: &Value,
    roots: &[Vec<&str>],
    discovery_source: DiscoverySource,
) -> Vec<ToolProvider> {
    if let Some(provider) = metadata_provider(surface, source_path, value, discovery_source) {
        return vec![provider];
    }

    let mut providers = Vec::new();
    for root in roots {
        let Some(object) = pointer_for_path(value, root).and_then(Value::as_object) else {
            continue;
        };
        for (name, config) in object {
            if let Some(provider) =
                provider_from_config(surface, source_path, name, config, discovery_source)
            {
                providers.push(provider);
            }
        }
    }
    if let Some(provider) = grant_state_provider(surface, source_path, value, discovery_source)
        && (providers.is_empty() || surface == "claude-desktop")
    {
        providers.push(provider);
    }
    providers
}

pub fn is_grant_state_provider(provider: &ToolProvider) -> bool {
    matches!(
        (provider.surface.as_str(), provider.name.as_str()),
        ("claude-code", CLAUDE_CODE_GRANT_STATE_PROVIDER_NAME)
            | ("claude-desktop", CLAUDE_DESKTOP_GRANT_STATE_PROVIDER_NAME)
            | (
                "claude-cowork",
                claude_cowork::COWORK_GRANT_STATE_PROVIDER_NAME
            )
            | (
                "claude-code-desktop",
                claude_cowork::CLAUDE_CODE_DESKTOP_GRANT_STATE_PROVIDER_NAME
            )
            | ("codex-cli", CODEX_CLI_GRANT_STATE_PROVIDER_NAME)
            | ("codex-app", CODEX_APP_GRANT_STATE_PROVIDER_NAME)
            | ("codex-app", codex_cli::CODEX_APP_FULL_ACCESS_PROVIDER_NAME)
    )
}

fn grant_state_provider(
    surface: &str,
    source_path: &Path,
    value: &Value,
    discovery_source: DiscoverySource,
) -> Option<ToolProvider> {
    let name = match surface {
        "claude-code" if has_claude_code_saved_grants(value) => {
            CLAUDE_CODE_GRANT_STATE_PROVIDER_NAME
        }
        "claude-desktop" if has_claude_desktop_trusted_folders(value) => {
            CLAUDE_DESKTOP_GRANT_STATE_PROVIDER_NAME
        }
        "codex-cli" if has_codex_project_grants(value) => CODEX_CLI_GRANT_STATE_PROVIDER_NAME,
        _ => return None,
    };

    Some(ToolProvider {
        surface: surface.to_string(),
        name: name.to_string(),
        transport: Transport::Unknown(UnknownConfig {
            reason: "saved approval config without MCP registration".to_string(),
        }),
        source_path: Some(source_path.to_path_buf()),
        discovery_source,
        extension: None,
        declared_tools: Vec::new(),
    })
}

fn has_claude_code_allow_rules(value: &Value) -> bool {
    value
        .pointer("/permissions/allow")
        .and_then(Value::as_array)
        .is_some_and(|rules| rules.iter().any(|rule| rule.as_str().is_some()))
}

fn has_claude_code_saved_grants(value: &Value) -> bool {
    has_claude_code_allow_rules(value) || has_accept_edits_grant(value)
}

pub(crate) fn has_accept_edits_grant(value: &Value) -> bool {
    value
        .get("acceptEdits")
        .is_some_and(accept_edits_value_has_grant)
}

fn accept_edits_value_has_grant(value: &Value) -> bool {
    match value {
        Value::Bool(true) => true,
        Value::String(value) => matches!(
            value
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect::<String>()
                .as_str(),
            "true"
                | "allow"
                | "allowed"
                | "approve"
                | "approved"
                | "always"
                | "alwaysallow"
                | "enabled"
                | "on"
        ),
        Value::Object(object) => [
            "enabled",
            "approved",
            "allowed",
            "alwaysAllow",
            "approvalMode",
            "state",
            "value",
        ]
        .iter()
        .any(|key| object.get(*key).is_some_and(accept_edits_value_has_grant)),
        _ => false,
    }
}

fn has_claude_desktop_trusted_folders(value: &Value) -> bool {
    value
        .pointer("/preferences/localAgentModeTrustedFolders")
        .and_then(Value::as_array)
        .is_some_and(|folders| {
            folders.iter().any(|folder| {
                folder
                    .as_str()
                    .is_some_and(|path| super::is_supported_fs_path(path.trim()))
            })
        })
}

fn has_codex_project_grants(value: &Value) -> bool {
    value
        .pointer("/projects")
        .and_then(Value::as_object)
        .is_some_and(|projects| {
            projects.values().any(|project| {
                project.as_object().is_some_and(|object| {
                    object
                        .get("approval_policy")
                        .and_then(Value::as_str)
                        .is_some()
                        || object.get("sandbox_mode").and_then(Value::as_str).is_some()
                })
            })
        })
}

fn metadata_provider(
    surface: &str,
    source_path: &Path,
    value: &Value,
    discovery_source: DiscoverySource,
) -> Option<ToolProvider> {
    let object = value.as_object()?;
    let name = object
        .get("serverName")
        .or_else(|| object.get("serverIdentifier"))
        .and_then(Value::as_str)?;
    // Cursor's SERVER_METADATA.json may carry transport fields (command/url)
    // alongside the metadata identifiers; enrich when they are present.
    if let Some(provider) =
        provider_from_config(surface, source_path, name, value, discovery_source)
    {
        return Some(provider);
    }
    Some(ToolProvider {
        surface: surface.to_string(),
        name: name.to_string(),
        transport: Transport::Unknown(UnknownConfig {
            reason: "metadata-only MCP registration; command/url not present".to_string(),
        }),
        source_path: Some(source_path.to_path_buf()),
        discovery_source,
        extension: None,
        declared_tools: Vec::new(),
    })
}

fn pointer_for_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |current, segment| {
        current.as_object().and_then(|object| object.get(*segment))
    })
}

fn provider_from_config(
    surface: &str,
    source_path: &Path,
    name: &str,
    config: &Value,
    discovery_source: DiscoverySource,
) -> Option<ToolProvider> {
    let object = config.as_object()?;
    if object
        .get("disabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    if let Some(url) = first_string(object, &["url", "sseUrl", "serverUrl", "endpoint"]) {
        let transport = if url.starts_with("ws://") || url.starts_with("wss://") {
            Transport::WebSocket(WsConfig { url })
        } else {
            Transport::HttpSse(HttpConfig {
                url,
                headers: string_map(object.get("headers")),
                tls_leaf_sha256: None,
            })
        };
        return Some(ToolProvider {
            surface: surface.to_string(),
            name: name.to_string(),
            transport,
            source_path: Some(source_path.to_path_buf()),
            discovery_source,
            extension: None,
            declared_tools: Vec::new(),
        });
    }

    let Some(command) = first_string(object, &["command", "cmd", "path"]) else {
        return Some(ToolProvider {
            surface: surface.to_string(),
            name: name.to_string(),
            transport: Transport::Unknown(UnknownConfig {
                reason: "MCP registration did not include a string command/url".to_string(),
            }),
            source_path: Some(source_path.to_path_buf()),
            discovery_source,
            extension: None,
            declared_tools: Vec::new(),
        });
    };
    let args = string_array(object.get("args"));
    let env = string_map(object.get("env"));
    Some(ToolProvider {
        surface: surface.to_string(),
        name: name.to_string(),
        transport: Transport::Stdio(StdioConfig { command, args, env }),
        source_path: Some(source_path.to_path_buf()),
        discovery_source,
        extension: None,
        declared_tools: Vec::new(),
    })
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
        .collect()
}

pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name)
}
