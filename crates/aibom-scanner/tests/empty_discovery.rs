use aibom_core::Target;
use aibom_scanner::scan_target;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn empty_discovery_emits_empty_valid_aibom() {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();

    let artifacts = scan_target(&Target::filesystem(root.path().to_path_buf()), out.path())
        .await
        .expect("empty discovery should not be an error");

    let aibom: Value = serde_json::from_slice(&fs::read(&artifacts.aibom_path).unwrap()).unwrap();
    let cdx: Value = serde_json::from_slice(&fs::read(&artifacts.cdx_path).unwrap()).unwrap();

    assert_eq!(aibom["aibom"]["schemaVersion"], "0.2.0");
    assert_eq!(
        aibom["aibom"]["components"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(aibom["aibom"]["evidence"].as_array().map(Vec::len), Some(0));
    assert_eq!(cdx["components"].as_array().map(Vec::len), Some(0));
    assert!(
        fs::read_dir(out.path())
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().contains("sigstore")),
        "scanner crate must not write Sigstore bundles; CLI/signing layer owns signing"
    );
}
