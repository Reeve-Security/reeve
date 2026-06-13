use std::fs;
use std::path::PathBuf;

use serde_json::Value;

const EXPECTED_POSITIVE_FIXTURES: usize = 8;
const EXPECTED_NEGATIVE_FIXTURES: usize = 6;
const FORBIDDEN_PRIVACY_FIELDS: &[&str] = &[
    "contentSnippet",
    "conversationContent",
    "rawConversationContent",
    "rawSecret",
    "secretHash",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf()
}

fn validator() -> jsonschema::Validator {
    let schema_path = repo_root().join("schema/sensitive-data-report-v0.1.0.json");
    let schema: Value = serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn secret_rule_pack_validator() -> jsonschema::Validator {
    let schema_path = repo_root().join("schema/secret-rule-pack-v0.1.0.json");
    let schema: Value = serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

#[test]
fn positive_sensitive_data_report_fixtures_validate() {
    let validator = validator();
    let mut fixture_count = 0;

    for path in fixture_paths("positive") {
        fixture_count += 1;

        let report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(
            validator.is_valid(&report),
            "{} should validate",
            path.display()
        );
    }

    assert_eq!(
        fixture_count, EXPECTED_POSITIVE_FIXTURES,
        "expected {EXPECTED_POSITIVE_FIXTURES} positive fixtures"
    );
}

#[test]
fn negative_sensitive_data_report_fixtures_reject() {
    let validator = validator();
    let mut fixture_count = 0;

    for path in fixture_paths("negative") {
        fixture_count += 1;

        let report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(
            !validator.is_valid(&report),
            "{} should fail validation",
            path.display()
        );
    }

    assert_eq!(
        fixture_count, EXPECTED_NEGATIVE_FIXTURES,
        "expected {EXPECTED_NEGATIVE_FIXTURES} negative fixtures"
    );
}

#[test]
fn positive_sensitive_data_report_fixtures_cover_supported_surfaces() {
    let mut seen = Vec::new();
    let mut metadata_only = false;
    let mut pattern_scan = false;

    for path in fixture_paths("positive") {
        let report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let body = &report["sensitiveDataReport"];
        metadata_only |= body["inputs"]["metadataInventory"] == true
            && body["inputs"]["contentPatternScan"] == false;
        pattern_scan |= body["inputs"]["contentPatternScan"] == true
            && !body["findings"].as_array().unwrap().is_empty();

        for surface in body["surfaces"].as_array().unwrap() {
            seen.push((
                surface["surface"].as_str().unwrap().to_owned(),
                surface["redactedRoot"].as_str().unwrap().to_owned(),
            ));
        }
    }

    for expected in [
        (
            "claude-desktop",
            "~/Library/Application Support/Claude/projects/",
        ),
        ("claude-desktop", "~/AppData/Roaming/Claude/projects/"),
        ("claude-code", "~/.claude/projects/"),
        (
            "codex-app",
            "~/Library/Application Support/Codex/archived_sessions/",
        ),
        ("codex-app", "~/.codex/sessions/"),
        ("codex-cli", "~/.codex/sessions/"),
        (
            "claude-cowork",
            "~/Library/Application Support/Claude/local-agent-mode-sessions/*/*/",
        ),
        (
            "claude-cowork",
            "~/AppData/Roaming/Claude/local-agent-mode-sessions/*/*/",
        ),
        (
            "claude-cowork",
            "~/AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/",
        ),
        ("cursor", "~/.cursor/projects/*/agent-transcripts/*/"),
    ] {
        assert!(
            seen.iter()
                .any(|surface| surface.0 == expected.0 && surface.1 == expected.1),
            "missing positive sensitive-data fixture for {expected:?}; saw {seen:?}"
        );
    }

    assert!(metadata_only, "expected at least one metadata-only fixture");
    assert!(pattern_scan, "expected at least one pattern-scan fixture");
}

#[test]
fn sensitive_data_report_privacy_field_fixtures_are_explicit() {
    for path in fixture_paths("positive") {
        let report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for field in FORBIDDEN_PRIVACY_FIELDS {
            assert!(
                !contains_key(&report, field),
                "positive fixture {} must not serialize {field}",
                path.display()
            );
        }
    }

    for field in FORBIDDEN_PRIVACY_FIELDS {
        let has_negative_fixture = fixture_paths("negative").into_iter().any(|path| {
            let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            contains_key(&report, field)
        });
        assert!(
            has_negative_fixture,
            "expected negative fixture exercising forbidden field {field}"
        );
    }
}

fn fixture_paths(kind: &str) -> Vec<PathBuf> {
    let root = repo_root()
        .join("schema/fixtures/sensitive-data-report")
        .join(kind);
    let mut paths: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
}

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(key) || object.values().any(|value| contains_key(value, key))
        }
        Value::Array(values) => values.iter().any(|value| contains_key(value, key)),
        _ => false,
    }
}

#[test]
fn positive_secret_rule_pack_fixtures_validate() {
    let validator = secret_rule_pack_validator();
    let root = repo_root().join("schema/fixtures/secret-rule-pack/positive");
    let mut fixture_count = 0;

    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        fixture_count += 1;

        let report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(
            validator.is_valid(&report),
            "{} should validate",
            path.display()
        );
    }

    assert_eq!(fixture_count, 1, "expected one positive fixture");
}

#[test]
fn negative_secret_rule_pack_fixtures_reject() {
    let validator = secret_rule_pack_validator();
    let root = repo_root().join("schema/fixtures/secret-rule-pack/negative");
    let mut fixture_count = 0;

    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        fixture_count += 1;

        let report: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(
            !validator.is_valid(&report),
            "{} should fail validation",
            path.display()
        );
    }

    assert_eq!(fixture_count, 1, "expected one negative fixture");
}
