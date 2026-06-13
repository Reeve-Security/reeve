use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}

pub fn cli_scan_target_dir() -> PathBuf {
    repo_root()
        .join("crates")
        .join("aibom-cli")
        .join("tests")
        .join("data")
        .join("cli-scan-target")
}

pub fn positive_fixture_triplet(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = repo_root()
        .join("schema")
        .join("examples")
        .join("fixtures")
        .join("positive")
        .join(name);
    (
        find_named(&dir, ".cdx.json"),
        find_named(&dir, ".aibom.json"),
        find_named_excluding(&dir, ".sigstore.fixture.json", ".sensitive-data."),
    )
}

pub fn negative_fixture_dirs_for_validate_artifacts() -> Vec<PathBuf> {
    let root = repo_root()
        .join("schema")
        .join("examples")
        .join("fixtures")
        .join("negative");
    let mut dirs: Vec<_> = fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && has_suffix(path, ".cdx.json")
                && !expected_error_code(path).starts_with("crypto.")
        })
        .collect();
    dirs.sort();
    dirs
}

pub fn expected_error_code(fixture_dir: &Path) -> String {
    let manifest: Value =
        serde_json::from_slice(&fs::read(fixture_dir.join("manifest.json")).unwrap()).unwrap();
    manifest["expectedErrorCode"].as_str().unwrap().to_string()
}

pub fn optional_bundle(dir: &Path) -> Option<PathBuf> {
    let fixture = find_optional_named_excluding(dir, ".sigstore.fixture.json", ".sensitive-data.");
    if fixture.is_some() {
        fixture
    } else {
        find_optional_named_excluding(dir, ".sigstore.json", ".sensitive-data.")
    }
}

pub fn sensitive_report_bundle(dir: &Path) -> Option<PathBuf> {
    let fixture = find_optional_named(dir, ".sensitive-data.sigstore.fixture.json");
    if fixture.is_some() {
        fixture
    } else {
        find_optional_named(dir, ".sensitive-data.sigstore.json")
    }
}

pub fn find_triplet(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        find_named(dir, ".cdx.json"),
        find_named(dir, ".aibom.json"),
        find_named_excluding(dir, ".sigstore.fixture.json", ".sensitive-data."),
    )
}

pub fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

pub fn tempdir_with_rigged_mcp_config() -> TempDir {
    let temp = TempDir::new().unwrap();
    let rigged = repo_root()
        .join("crates")
        .join("aibom-scanner")
        .join("tests")
        .join("mcp")
        .join("rigged-server")
        .join("server.py");
    let config = serde_json::json!({
        "mcpServers": {
            "rigged": {
                "command": "python3",
                "args": [rigged.display().to_string()]
            }
        }
    });
    fs::write(
        temp.path().join(".mcp.json"),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    temp
}

pub fn observed_contains(aibom: &Value, id: &str, path_or_host: Option<&str>) -> bool {
    let Some(components) = aibom.pointer("/aibom/components").and_then(Value::as_array) else {
        return false;
    };
    components.iter().any(|component| {
        component
            .pointer("/capabilities/observed")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|cap| {
                if cap.pointer("/id").and_then(Value::as_str) != Some(id) {
                    return false;
                }
                match path_or_host {
                    Some(expected) => {
                        cap.pointer("/qualifiers/path")
                            .or_else(|| cap.pointer("/qualifiers/host"))
                            .and_then(Value::as_str)
                            == Some(expected)
                    }
                    None => true,
                }
            })
    })
}

pub fn policy_verdict_contains(aibom: &Value, policy_id: &str, status: &str) -> bool {
    aibom
        .pointer("/aibom/policyVerdicts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|verdict| {
            verdict.pointer("/policyId").and_then(Value::as_str) == Some(policy_id)
                && verdict.pointer("/status").and_then(Value::as_str) == Some(status)
        })
}

pub fn sandbox_exec_available() -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    std::process::Command::new("sandbox-exec")
        .arg("-p")
        .arg("(version 1)(allow default)")
        .arg("/usr/bin/true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn has_suffix(dir: &Path, suffix: &str) -> bool {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(suffix))
        })
}

fn find_named(dir: &Path, suffix: &str) -> PathBuf {
    find_optional_named(dir, suffix)
        .unwrap_or_else(|| panic!("missing *{suffix} in {}", dir.display()))
}

fn find_named_excluding(dir: &Path, suffix: &str, exclude: &str) -> PathBuf {
    find_optional_named_excluding(dir, suffix, exclude)
        .unwrap_or_else(|| panic!("missing *{suffix} in {}", dir.display()))
}

fn find_optional_named(dir: &Path, suffix: &str) -> Option<PathBuf> {
    find_optional_named_excluding(dir, suffix, "")
}

fn find_optional_named_excluding(dir: &Path, suffix: &str, exclude: &str) -> Option<PathBuf> {
    let mut matches: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.ends_with(suffix) && (exclude.is_empty() || !name.contains(exclude))
                })
        })
        .collect();
    matches.sort();
    match matches.as_slice() {
        [path] => Some(path.clone()),
        [] => None,
        _ => panic!("multiple *{suffix} in {}", dir.display()),
    }
}
