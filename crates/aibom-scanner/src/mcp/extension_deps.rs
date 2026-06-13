use crate::mcp::fingerprint::package_to_purl;
use aibom_core::ToolProvider;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

type DependencyMap = BTreeMap<DependencyKey, NpmDependency>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DependencyKey {
    name: String,
    version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmDependency {
    pub name: String,
    pub version: Option<String>,
    pub purl: String,
    pub scope: String,
    pub source: DependencySource,
    pub source_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencySource {
    PackageLock,
    PackageJson,
    NodeModulesPackageJson,
}

impl DependencySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PackageLock => "package-lock",
            Self::PackageJson => "package-json",
            Self::NodeModulesPackageJson => "node-modules-package-json",
        }
    }
}

pub fn collect_npm_dependencies(provider: &ToolProvider) -> Result<Vec<NpmDependency>> {
    let Some(root) = provider
        .extension
        .as_ref()
        .and_then(|extension| extension.install_root.as_ref())
    else {
        return Ok(Vec::new());
    };
    collect_npm_dependencies_from_root(root)
}

pub fn collect_npm_dependencies_from_root(root: &Path) -> Result<Vec<NpmDependency>> {
    let lock_path = root.join("package-lock.json");
    if lock_path.is_file() {
        return parse_package_lock(&lock_path)
            .with_context(|| format!("parse npm dependency lock {}", lock_path.display()));
    }

    let mut deps = DependencyMap::new();
    let manifest_path = root.join("package.json");
    if manifest_path.is_file() {
        for dependency in parse_package_json(&manifest_path)
            .with_context(|| format!("parse npm package manifest {}", manifest_path.display()))?
        {
            insert_dependency_record(&mut deps, dependency);
        }
    }

    for dependency in parse_node_modules_package_jsons(root)? {
        insert_dependency_record(&mut deps, dependency);
    }

    Ok(deps.into_values().collect())
}

fn parse_package_lock(path: &Path) -> Result<Vec<NpmDependency>> {
    let raw = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let mut deps = DependencyMap::new();

    if let Some(packages) = value.pointer("/packages").and_then(Value::as_object) {
        for (package_path, package) in packages {
            let Some(name) = package_name_from_lock_path(package_path) else {
                continue;
            };
            let version = package
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string);
            insert_dependency(
                &mut deps,
                name,
                version,
                lock_scope(package),
                DependencySource::PackageLock,
                path,
            );
        }
    }

    if deps.is_empty()
        && let Some(dependencies) = value.pointer("/dependencies").and_then(Value::as_object)
    {
        collect_lock_v1_dependencies(dependencies, path, &mut deps);
    }

    Ok(deps.into_values().collect())
}

fn collect_lock_v1_dependencies(
    dependencies: &serde_json::Map<String, Value>,
    path: &Path,
    deps: &mut DependencyMap,
) {
    for (name, entry) in dependencies {
        let version = entry
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string);
        insert_dependency(
            deps,
            name.clone(),
            version,
            "runtime",
            DependencySource::PackageLock,
            path,
        );
        if let Some(children) = entry.get("dependencies").and_then(Value::as_object) {
            collect_lock_v1_dependencies(children, path, deps);
        }
    }
}

fn parse_package_json(path: &Path) -> Result<Vec<NpmDependency>> {
    let raw = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let mut deps = DependencyMap::new();

    for (section, scope) in [
        ("dependencies", "runtime"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
        ("devDependencies", "dev"),
    ] {
        let Some(entries) = value.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, spec) in entries {
            let version = spec.as_str().and_then(exact_version).map(str::to_string);
            insert_dependency(
                &mut deps,
                name.clone(),
                version,
                scope,
                DependencySource::PackageJson,
                path,
            );
        }
    }

    for section in ["bundledDependencies", "bundleDependencies"] {
        let Some(entries) = value.get(section).and_then(Value::as_array) else {
            continue;
        };
        for name in entries.iter().filter_map(Value::as_str) {
            insert_dependency(
                &mut deps,
                name.to_string(),
                None,
                "bundled",
                DependencySource::PackageJson,
                path,
            );
        }
    }

    Ok(deps.into_values().collect())
}

fn parse_node_modules_package_jsons(root: &Path) -> Result<Vec<NpmDependency>> {
    let node_modules = root.join("node_modules");
    if !node_modules.is_dir() {
        return Ok(Vec::new());
    }

    let mut deps = DependencyMap::new();
    for entry in WalkDir::new(&node_modules)
        .follow_links(false)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if !entry.file_type().is_file()
            || entry.path().file_name().and_then(|name| name.to_str()) != Some("package.json")
        {
            continue;
        }
        parse_installed_package_json(entry.path(), &mut deps)
            .with_context(|| format!("parse npm installed package {}", entry.path().display()))?;
    }

    Ok(deps.into_values().collect())
}

fn parse_installed_package_json(path: &Path, deps: &mut DependencyMap) -> Result<()> {
    let raw = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let Some(name) = value.get("name").and_then(Value::as_str) else {
        return Ok(());
    };
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string);
    insert_dependency(
        deps,
        name.to_string(),
        version,
        "installed",
        DependencySource::NodeModulesPackageJson,
        path,
    );
    Ok(())
}

fn insert_dependency(
    deps: &mut DependencyMap,
    name: String,
    version: Option<String>,
    scope: &str,
    source: DependencySource,
    source_path: &Path,
) {
    let Some(name) = canonical_npm_package_name(&name) else {
        return;
    };
    let Some(purl) = package_to_purl(&name, version.as_deref()) else {
        return;
    };
    insert_dependency_record(
        deps,
        NpmDependency {
            name,
            version,
            purl,
            scope: scope.to_string(),
            source,
            source_path: source_path.to_path_buf(),
        },
    );
}

fn insert_dependency_record(deps: &mut DependencyMap, dependency: NpmDependency) {
    let key = DependencyKey {
        name: dependency.name.clone(),
        version: dependency.version.clone(),
    };
    if key.version.is_some() {
        deps.remove(&DependencyKey {
            name: key.name.clone(),
            version: None,
        });
    } else if deps
        .keys()
        .any(|existing| existing.name == key.name && existing.version.is_some())
    {
        return;
    }
    deps.entry(key).or_insert(dependency);
}

fn canonical_npm_package_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut parts = name.split('/');
    let first = parts.next()?;
    if first.is_empty() {
        return None;
    }
    if first.starts_with('@') {
        let package = parts.next()?;
        if first.len() == 1 || package.is_empty() {
            return None;
        }
        Some(format!("{first}/{package}"))
    } else {
        Some(first.to_string())
    }
}

fn package_name_from_lock_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let parts: Vec<_> = path.split('/').collect();
    let index = parts.iter().rposition(|part| *part == "node_modules")?;
    let name = *parts.get(index + 1)?;
    if name.is_empty() {
        return None;
    }
    if name.starts_with('@') {
        let package = *parts.get(index + 2)?;
        if package.is_empty() {
            return None;
        }
        Some(format!("{name}/{package}"))
    } else {
        Some(name.to_string())
    }
}

fn lock_scope(package: &Value) -> &'static str {
    if package
        .get("dev")
        .and_then(Value::as_bool)
        .unwrap_or_default()
    {
        "dev"
    } else if package
        .get("optional")
        .and_then(Value::as_bool)
        .unwrap_or_default()
    {
        "optional"
    } else {
        "runtime"
    }
}

fn exact_version(spec: &str) -> Option<&str> {
    let spec = spec.trim().strip_prefix('=').unwrap_or(spec.trim());
    if spec.is_empty()
        || spec
            .chars()
            .any(|ch| matches!(ch, '^' | '~' | '>' | '<' | '*' | 'x' | 'X' | '|' | ' '))
        || spec.contains(':')
        || spec.starts_with("git")
        || spec.starts_with("file")
        || spec.starts_with("link")
        || spec.starts_with("workspace")
    {
        return None;
    }
    spec.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
        .then_some(spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn reads_package_lock_packages_without_walking_node_modules() {
        let root = TempDir::new().unwrap();
        fs::write(
            root.path().join("package-lock.json"),
            r#"{
  "name": "desktop-commander",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "desktop-commander", "version": "0.2.8"},
    "node_modules/minimatch": {"version": "9.0.5"},
    "node_modules/@modelcontextprotocol/sdk": {"version": "1.12.0"},
    "node_modules/example/node_modules/debug": {"version": "4.3.7", "dev": true}
  }
}"#,
        )
        .unwrap();
        fs::create_dir_all(root.path().join("node_modules/left-pad")).unwrap();
        fs::write(
            root.path().join("node_modules/left-pad/package.json"),
            r#"{"name":"left-pad","version":"1.3.0"}"#,
        )
        .unwrap();

        let deps = collect_npm_dependencies_from_root(root.path()).unwrap();
        let purls: Vec<_> = deps.iter().map(|dep| dep.purl.as_str()).collect();

        assert_eq!(
            purls,
            vec![
                "pkg:npm/%40modelcontextprotocol/sdk@1.12.0",
                "pkg:npm/debug@4.3.7",
                "pkg:npm/minimatch@9.0.5",
            ]
        );
        assert_eq!(deps[1].scope, "dev");
    }

    #[test]
    fn reads_package_json_with_exact_versions_only() {
        let root = TempDir::new().unwrap();
        fs::write(
            root.path().join("package.json"),
            r#"{
  "dependencies": {"exact": "1.2.3", "range": "^2.0.0"},
  "devDependencies": {"dev-only": "=0.1.0"},
  "bundledDependencies": ["bundled"]
}"#,
        )
        .unwrap();

        let deps = collect_npm_dependencies_from_root(root.path()).unwrap();
        let purls: Vec<_> = deps.iter().map(|dep| dep.purl.as_str()).collect();

        assert_eq!(
            purls,
            vec![
                "pkg:npm/bundled",
                "pkg:npm/dev-only@0.1.0",
                "pkg:npm/exact@1.2.3",
                "pkg:npm/range",
            ]
        );
    }

    #[test]
    fn replaces_bare_manifest_dependency_when_installed_version_is_known() {
        let root = TempDir::new().unwrap();
        fs::write(
            root.path().join("package.json"),
            r#"{
  "dependencies": {
    "rxjs": "^6.6.7",
    "rxjs/ajax": "^6.6.7",
    "rxjs/operators": "^6.6.7",
    "rxjs/webSocket": "^6.6.7"
  }
}"#,
        )
        .unwrap();
        fs::create_dir_all(root.path().join("node_modules/rxjs")).unwrap();
        fs::write(
            root.path().join("node_modules/rxjs/package.json"),
            r#"{"name":"rxjs","version":"6.6.7"}"#,
        )
        .unwrap();

        let deps = collect_npm_dependencies_from_root(root.path()).unwrap();
        let purls: Vec<_> = deps.iter().map(|dep| dep.purl.as_str()).collect();

        assert_eq!(purls, vec!["pkg:npm/rxjs@6.6.7"]);
    }

    #[test]
    fn folds_deep_import_names_without_truncating_scoped_packages() {
        let root = TempDir::new().unwrap();
        fs::write(
            root.path().join("package-lock.json"),
            r#"{
  "name": "extension",
  "lockfileVersion": 1,
  "dependencies": {
    "rxjs": {"version": "6.6.7"},
    "rxjs/ajax": {"version": "6.6.7"},
    "rxjs/operators": {"version": "6.6.7"},
    "rxjs/webSocket": {"version": "6.6.7"},
    "@scope/name": {"version": "1.2.3"},
    "@scope/name/subpath": {"version": "1.2.3"}
  }
}"#,
        )
        .unwrap();

        let deps = collect_npm_dependencies_from_root(root.path()).unwrap();
        let purls: Vec<_> = deps.iter().map(|dep| dep.purl.as_str()).collect();

        assert_eq!(
            purls,
            vec!["pkg:npm/%40scope/name@1.2.3", "pkg:npm/rxjs@6.6.7"]
        );
    }

    #[test]
    fn falls_back_to_installed_node_modules_packages() {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("node_modules/minimatch")).unwrap();
        fs::write(
            root.path().join("node_modules/minimatch/package.json"),
            r#"{"name":"minimatch","version":"9.0.5"}"#,
        )
        .unwrap();
        fs::create_dir_all(
            root.path()
                .join("node_modules/@modelcontextprotocol/sdk/node_modules/debug"),
        )
        .unwrap();
        fs::write(
            root.path()
                .join("node_modules/@modelcontextprotocol/sdk/package.json"),
            r#"{"name":"@modelcontextprotocol/sdk","version":"1.12.0"}"#,
        )
        .unwrap();
        fs::write(
            root.path()
                .join("node_modules/@modelcontextprotocol/sdk/node_modules/debug/package.json"),
            r#"{"name":"debug","version":"4.3.7"}"#,
        )
        .unwrap();

        let deps = collect_npm_dependencies_from_root(root.path()).unwrap();
        let purls: Vec<_> = deps.iter().map(|dep| dep.purl.as_str()).collect();

        assert_eq!(
            purls,
            vec![
                "pkg:npm/%40modelcontextprotocol/sdk@1.12.0",
                "pkg:npm/debug@4.3.7",
                "pkg:npm/minimatch@9.0.5",
            ]
        );
        assert!(
            deps.iter()
                .all(|dep| dep.source == DependencySource::NodeModulesPackageJson)
        );
        assert!(deps.iter().all(|dep| dep.scope == "installed"));
    }
}
