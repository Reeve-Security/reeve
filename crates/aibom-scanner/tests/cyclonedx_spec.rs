//! Validates Reeve's emitted CycloneDX output against the OFFICIAL CycloneDX
//! 1.5 JSON schema (bundled under tests/data/cyclonedx/). The format was proven
//! spec-valid by external tooling on 2026-06-12; this committed test guards it
//! from silent regression. Replaces the prior shallow `bomFormat == "CycloneDX"`
//! check with full structural schema validation (components, purls, dependency
//! graph, hashes, externalReferences).

use aibom_core::Target;
use aibom_scanner::scan_target;
use jsonschema::{Retrieve, Uri, Validator};
use serde_json::Value;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

const BOM_SCHEMA: &str = include_str!("data/cyclonedx/bom-1.5.schema.json");
const SPDX_SCHEMA: &str = include_str!("data/cyclonedx/spdx.schema.json");
const JSF_SCHEMA: &str = include_str!("data/cyclonedx/jsf-0.82.schema.json");

/// Resolves the CycloneDX schema's external `$ref`s (`spdx.schema.json`,
/// `jsf-0.82.schema.json`) to the locally bundled copies so validation runs
/// fully offline against the real spec.
struct BundledRetriever {
    spdx: Arc<Value>,
    jsf: Arc<Value>,
}

impl Retrieve for BundledRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let s = uri.as_str();
        if s.ends_with("spdx.schema.json") {
            Ok((*self.spdx).clone())
        } else if s.ends_with("jsf-0.82.schema.json") {
            Ok((*self.jsf).clone())
        } else {
            Err(format!("unexpected external $ref during CycloneDX validation: {s}").into())
        }
    }
}

fn cyclonedx_validator() -> Validator {
    let bom: Value = serde_json::from_str(BOM_SCHEMA).expect("bundled bom-1.5 schema parses");
    let spdx: Value = serde_json::from_str(SPDX_SCHEMA).expect("bundled spdx schema parses");
    let jsf: Value = serde_json::from_str(JSF_SCHEMA).expect("bundled jsf schema parses");
    jsonschema::options()
        .with_retriever(BundledRetriever {
            spdx: Arc::new(spdx),
            jsf: Arc::new(jsf),
        })
        .build(&bom)
        .expect("CycloneDX 1.5 schema compiles")
}

/// Builds a Cowork target whose scan emits a CDX with: an extension component,
/// plain + scoped (`%40`-encoded) npm dependency purls, and a dependency graph.
fn scan_cowork_extension_cdx() -> Value {
    let root = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let claude_root = root
        .path()
        .join("AppData/Local/Packages/Claude_cw123/LocalCache/Roaming/Claude");
    fs::create_dir_all(&claude_root).unwrap();
    fs::write(
        claude_root.join("claude_desktop_config.json"),
        r#"{"theme":"dark"}"#,
    )
    .unwrap();
    fs::write(
        claude_root.join("extensions-installations.json"),
        r#"{
  "extensions": [
    {
      "id": "manifest",
      "name": "PDF Tools",
      "version": "1.2.0",
      "path": "mcpb:manifest",
      "signatureInfo": {"status": "unsigned"},
      "server": {"type": "node", "command": "node", "args": ["${__dirname}/index.js"]},
      "tools": [{"name": "read_file"}]
    }
  ]
}"#,
    )
    .unwrap();
    let ext = claude_root.join("Claude Extensions/com.example.pdf-tools");
    fs::create_dir_all(&ext).unwrap();
    fs::write(
        ext.join("manifest.json"),
        r#"{"name":"PDF Tools","version":"1.2.0"}"#,
    )
    .unwrap();
    // package-lock with a plain dep + a scoped dep -> exercises %40 purl encoding.
    fs::write(
        ext.join("package-lock.json"),
        r#"{
  "name": "pdf-tools", "version": "1.2.0", "lockfileVersion": 2,
  "packages": {
    "": {"name":"pdf-tools","version":"1.2.0"},
    "node_modules/lodash": {"version":"4.17.20"},
    "node_modules/@babel/traverse": {"version":"7.23.0"}
  },
  "dependencies": {
    "lodash": {"version":"4.17.20"},
    "@babel/traverse": {"version":"7.23.0"}
  }
}"#,
    )
    .unwrap();
    fs::create_dir_all(claude_root.join("Claude Extensions Settings")).unwrap();
    fs::write(
        claude_root.join("Claude Extensions Settings/com.example.pdf-tools.json"),
        r#"{"isEnabled":true}"#,
    )
    .unwrap();

    let artifacts = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(scan_target(
            &Target::filesystem(root.path().to_path_buf()),
            out.path(),
        ))
        .unwrap();
    serde_json::from_slice(&artifacts.cdx_bytes).unwrap()
}

// launch-proof: #474
#[test]
fn emitted_cyclonedx_validates_against_official_1_5_schema() {
    let validator = cyclonedx_validator();
    let cdx = scan_cowork_extension_cdx();

    // Sanity: the fixture really produced the shapes we care about.
    assert_eq!(cdx["bomFormat"], "CycloneDX");
    assert_eq!(cdx["specVersion"], "1.5");
    let purls: Vec<&str> = cdx["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["purl"].as_str())
        .collect();
    assert!(
        purls.iter().any(|p| p.contains("%40babel")),
        "fixture should emit a scoped (%40-encoded) purl: {purls:?}"
    );

    let errors: Vec<String> = validator.iter_errors(&cdx).map(|e| e.to_string()).collect();
    assert!(
        errors.is_empty(),
        "emitted CycloneDX is NOT valid against the official 1.5 schema:\n{}",
        errors.join("\n")
    );
}

// launch-proof: #474
#[test]
fn validator_rejects_broken_cyclonedx() {
    // Negative control: prove the validator actually validates structure, so the
    // positive test above cannot pass vacuously.
    let validator = cyclonedx_validator();
    let cdx = scan_cowork_extension_cdx();
    assert!(validator.is_valid(&cdx), "baseline must be valid");

    // Break the component `type` enum (schema enumerates allowed values).
    let mut cdx_bad_type = cdx.clone();
    cdx_bad_type["components"][0]["type"] = Value::String("not-a-real-type".to_string());
    assert!(
        !validator.is_valid(&cdx_bad_type),
        "validator must reject a component with a type outside the schema enum"
    );

    // Remove a required top-level field.
    let mut cdx_no_format = cdx.clone();
    cdx_no_format.as_object_mut().unwrap().remove("bomFormat");
    assert!(
        !validator.is_valid(&cdx_no_format),
        "validator must reject a CDX missing the required bomFormat field"
    );
}
