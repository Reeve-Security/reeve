use aibom_core::{ProviderIdentity, ToolProvider, Transport, sha256_hex};
use anyhow::{Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandSpec {
    Npx { package: String },
    PnpmDlx { package: String },
    Uvx { package: String },
    PipxRun { package: String },
    NodePath { path: PathBuf },
    PythonModule { module: String },
    AbsolutePath { path: PathBuf },
    Unknown { command: String, args: Vec<String> },
}

pub trait PackageLocator {
    fn locate(&self, spec: &CommandSpec) -> Result<Option<LocatedPackage>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedPackage {
    pub package_dir: PathBuf,
    pub entry_point: Option<PathBuf>,
    pub published_artifact: Option<PathBuf>,
}

pub struct NpmLocator;
pub struct PnpmLocator;
pub struct UvLocator;
pub struct PipxLocator;
pub struct SystemPathLocator;

impl PackageLocator for NpmLocator {
    fn locate(&self, _spec: &CommandSpec) -> Result<Option<LocatedPackage>> {
        Ok(None)
    }
}

impl PackageLocator for PnpmLocator {
    fn locate(&self, _spec: &CommandSpec) -> Result<Option<LocatedPackage>> {
        Ok(None)
    }
}

impl PackageLocator for UvLocator {
    fn locate(&self, _spec: &CommandSpec) -> Result<Option<LocatedPackage>> {
        Ok(None)
    }
}

impl PackageLocator for PipxLocator {
    fn locate(&self, _spec: &CommandSpec) -> Result<Option<LocatedPackage>> {
        Ok(None)
    }
}

impl PackageLocator for SystemPathLocator {
    fn locate(&self, spec: &CommandSpec) -> Result<Option<LocatedPackage>> {
        let path = match spec {
            CommandSpec::AbsolutePath { path } | CommandSpec::NodePath { path } => path,
            _ => return Ok(None),
        };
        if path.is_file() {
            return Ok(Some(LocatedPackage {
                package_dir: path
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .to_path_buf(),
                entry_point: Some(path.clone()),
                published_artifact: None,
            }));
        }
        Ok(None)
    }
}

pub fn parse_command(command: &str, args: &[String]) -> CommandSpec {
    match command {
        "npx" => {
            let package = args
                .iter()
                .filter(|arg| arg.as_str() != "-y" && arg.as_str() != "--yes")
                .find(|arg| !arg.starts_with('-'))
                .cloned();
            package
                .map(|package| CommandSpec::Npx { package })
                .unwrap_or_else(|| CommandSpec::Unknown {
                    command: command.to_string(),
                    args: args.to_vec(),
                })
        }
        "pnpm" if args.first().is_some_and(|arg| arg == "dlx") => args
            .iter()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .cloned()
            .map(|package| CommandSpec::PnpmDlx { package })
            .unwrap_or_else(|| CommandSpec::Unknown {
                command: command.to_string(),
                args: args.to_vec(),
            }),
        "uvx" => args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .cloned()
            .map(|package| CommandSpec::Uvx { package })
            .unwrap_or_else(|| CommandSpec::Unknown {
                command: command.to_string(),
                args: args.to_vec(),
            }),
        "pipx" if args.first().is_some_and(|arg| arg == "run") => args
            .iter()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .cloned()
            .map(|package| CommandSpec::PipxRun { package })
            .unwrap_or_else(|| CommandSpec::Unknown {
                command: command.to_string(),
                args: args.to_vec(),
            }),
        "node" => args
            .first()
            .map(|path| CommandSpec::NodePath {
                path: PathBuf::from(path),
            })
            .unwrap_or_else(|| CommandSpec::Unknown {
                command: command.to_string(),
                args: args.to_vec(),
            }),
        "python" | "python3" if args.first().is_some_and(|arg| arg == "-m") => args
            .get(1)
            .cloned()
            .map(|module| CommandSpec::PythonModule { module })
            .unwrap_or_else(|| CommandSpec::Unknown {
                command: command.to_string(),
                args: args.to_vec(),
            }),
        _ if Path::new(command).is_absolute() => CommandSpec::AbsolutePath {
            path: PathBuf::from(command),
        },
        _ => CommandSpec::Unknown {
            command: command.to_string(),
            args: args.to_vec(),
        },
    }
}

pub fn fingerprint(provider: &ToolProvider) -> Result<ProviderIdentity> {
    let (name, version, purl, spec, forced_bom_ref) =
        if let Some(extension) = provider.extension.as_ref() {
            (
                extension
                    .name
                    .clone()
                    .unwrap_or_else(|| extension.id.clone()),
                extension.version.clone(),
                None,
                transport_command_spec(&provider.transport),
                Some(format!("mcpb:{}", normalize_id(&extension.id))),
            )
        } else {
            match &provider.transport {
                Transport::Stdio(stdio) => {
                    let spec = parse_command(&stdio.command, &stdio.args);
                    let package = package_from_spec(&spec).unwrap_or_else(|| provider.name.clone());
                    let (name, version) = split_package_version(&package);
                    let purl = package_to_purl(&name, version.as_deref());
                    (name, version, purl, Some(spec), None)
                }
                Transport::HttpSse(http) => (
                    provider.name.clone(),
                    None,
                    None,
                    Some(CommandSpec::Unknown {
                        command: http.url.clone(),
                        args: Vec::new(),
                    }),
                    None,
                ),
                Transport::WebSocket(ws) => (
                    provider.name.clone(),
                    None,
                    None,
                    Some(CommandSpec::Unknown {
                        command: ws.url.clone(),
                        args: Vec::new(),
                    }),
                    None,
                ),
                Transport::Unknown(_) => (provider.name.clone(), None, None, None, None),
            }
        };

    let mut entry_point = None;
    let mut entry_point_sha256 = None;
    let mut published_artifact_sha256 = None;
    let mut published_artifact_reason =
        Some("published artifact not found in local cache".to_string());

    if let Some(spec) = spec.as_ref() {
        let locators: [&dyn PackageLocator; 5] = [
            &SystemPathLocator,
            &NpmLocator,
            &PnpmLocator,
            &UvLocator,
            &PipxLocator,
        ];
        for locator in locators {
            if let Some(located) = locator.locate(spec)? {
                if let Some(path) = located.entry_point {
                    let bytes = fs::read(&path)?;
                    entry_point_sha256 = Some(sha256_hex(&bytes));
                    entry_point = Some(path);
                }
                if let Some(path) = located.published_artifact {
                    let bytes = fs::read(path)?;
                    published_artifact_sha256 = Some(sha256_hex(&bytes));
                    published_artifact_reason = None;
                }
                break;
            }
        }
    }

    let bom_ref = forced_bom_ref
        .or_else(|| purl.clone())
        .unwrap_or_else(|| format!("mcp:{}", normalize_id(&name)));
    Ok(ProviderIdentity {
        bom_ref,
        name,
        version,
        purl,
        publisher: None,
        entry_point,
        entry_point_sha256,
        published_artifact_sha256,
        published_artifact_reason,
        sigstore_ref: None,
    })
}

fn transport_command_spec(transport: &Transport) -> Option<CommandSpec> {
    match transport {
        Transport::Stdio(stdio) => Some(parse_command(&stdio.command, &stdio.args)),
        Transport::HttpSse(http) => Some(CommandSpec::Unknown {
            command: http.url.clone(),
            args: Vec::new(),
        }),
        Transport::WebSocket(ws) => Some(CommandSpec::Unknown {
            command: ws.url.clone(),
            args: Vec::new(),
        }),
        Transport::Unknown(_) => None,
    }
}

fn package_from_spec(spec: &CommandSpec) -> Option<String> {
    match spec {
        CommandSpec::Npx { package }
        | CommandSpec::PnpmDlx { package }
        | CommandSpec::Uvx { package }
        | CommandSpec::PipxRun { package } => Some(package.clone()),
        CommandSpec::PythonModule { module } => Some(module.clone()),
        CommandSpec::AbsolutePath { path } | CommandSpec::NodePath { path } => path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_string),
        CommandSpec::Unknown { .. } => None,
    }
}

pub fn split_package_version(package: &str) -> (String, Option<String>) {
    if package.starts_with('@') {
        let Some(index) = package.rfind('@') else {
            return (package.to_string(), None);
        };
        if index > 0 {
            return (
                package[..index].to_string(),
                Some(package[index + 1..].to_string()),
            );
        }
        return (package.to_string(), None);
    }
    match package.rsplit_once('@') {
        Some((name, version)) if !name.is_empty() && !version.is_empty() => {
            (name.to_string(), Some(version.to_string()))
        }
        _ => (package.to_string(), None),
    }
}

pub fn package_to_purl(name: &str, version: Option<&str>) -> Option<String> {
    if name.contains('/') || name.chars().all(valid_package_char) {
        let encoded = if let Some(rest) = name.strip_prefix('@') {
            format!("%40{rest}")
        } else {
            name.to_string()
        };
        return Some(match version {
            Some(version) => format!("pkg:npm/{encoded}@{version}"),
            None => format!("pkg:npm/{encoded}"),
        });
    }
    None
}

fn valid_package_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@' | '/')
}

pub fn normalize_id(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            out.push(ch);
        } else if matches!(ch, '-' | '_' | ':' | '.') {
            out.push('-');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out.trim_matches('-').to_string()
    }
}

pub fn command_args(provider: &ToolProvider) -> Result<(&str, &[String])> {
    match &provider.transport {
        Transport::Stdio(stdio) => Ok((&stdio.command, &stdio.args)),
        _ => Err(anyhow!("provider is not stdio")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_staged_command_specs() {
        assert_eq!(
            parse_command("npx", &["-y".into(), "@mcp/server@1.2.3".into()]),
            CommandSpec::Npx {
                package: "@mcp/server@1.2.3".into()
            }
        );
        assert_eq!(
            parse_command("pnpm", &["dlx".into(), "@mcp/server".into()]),
            CommandSpec::PnpmDlx {
                package: "@mcp/server".into()
            }
        );
        assert_eq!(
            parse_command("python3", &["-m".into(), "mcp_server".into()]),
            CommandSpec::PythonModule {
                module: "mcp_server".into()
            }
        );
    }

    #[test]
    fn builds_npm_purls_without_fake_versions() {
        let (name, version) =
            split_package_version("@modelcontextprotocol/server-filesystem@2.3.1");
        assert_eq!(name, "@modelcontextprotocol/server-filesystem");
        assert_eq!(version.as_deref(), Some("2.3.1"));
        assert_eq!(
            package_to_purl(&name, version.as_deref()).as_deref(),
            Some("pkg:npm/%40modelcontextprotocol/server-filesystem@2.3.1")
        );
    }
}
