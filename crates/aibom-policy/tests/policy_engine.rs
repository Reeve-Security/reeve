use aibom_policy::{PolicyConfig, SignatureFacts, evaluate, evaluate_sensitive_data_report};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;

#[test]
fn rego_sources_pass_opa_tests() {
    let opa = std::env::var("OPA_BIN").unwrap_or_else(|_| "opa".to_string());
    let status = Command::new(opa)
        .arg("test")
        .arg(repo_root().join("policies"))
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn fixture_rule_a_emits_deny() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = read_json(repo_root().join(
        "schema/fixtures/aibom-v0.1.0/positive/03-undeclared-egress-delta/fixture-03.aibom.json",
    ));
    let cdx = read_json(repo_root().join(
        "schema/fixtures/aibom-v0.1.0/positive/03-undeclared-egress-delta/fixture-03.cdx.json",
    ));
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            Some(&cdx),
            &SignatureFacts::default(),
            &PolicyConfig::default(),
        ))
        .unwrap();
    let policy_03: Vec<_> = verdicts
        .iter()
        .filter(|v| v.policy_id == "declared-observed-capability-match")
        .collect();
    assert!(
        !policy_03.is_empty(),
        "expected at least one policy-03 verdict, got {:?}",
        verdicts
    );
    assert_eq!(format!("{:?}", policy_03[0].status), "Deny");
}

#[test]
fn rule_b_stub_warn_emits_warn() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = json!({
        "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
        "aibom": {
            "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
            "components": [{
                "bom-ref": "pkg:npm/playwright@1.0.0",
                "capabilities": {
                    "declared": [{
                        "evidence": ["ev-001"],
                        "id": "mcp:tool:call",
                        "qualifiers": {"tool_name": "browser_navigate"},
                        "source": "declared"
                    }],
                    "observed": [{
                        "evidence": ["ev-002"],
                        "id": "exec:subprocess",
                        "qualifiers": {"cmd": "env"},
                        "source": "observed"
                    }]
                }
            }],
            "evidence": [],
            "scan": {
                "adapter": {"name": "mcp", "version": "0.1.0"},
                "scanId": "fixture-rule-b",
                "scanner": {"name": "reeve", "version": "0.1.0"},
                "timestamp": "2026-04-24T00:00:00Z"
            },
            "schemaVersion": "0.1.0"
        }
    });
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            None,
            &SignatureFacts::default(),
            &PolicyConfig::default(),
        ))
        .unwrap();
    let policy_03: Vec<_> = verdicts
        .iter()
        .filter(|v| v.policy_id == "declared-observed-capability-match")
        .collect();
    assert!(
        !policy_03.is_empty(),
        "expected at least one policy-03 verdict, got {:?}",
        verdicts
    );
    assert_eq!(format!("{:?}", policy_03[0].status), "Warn");
}

#[test]
fn fixture_unknown_extension_warns() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = read_json(repo_root().join(
        "schema/fixtures/aibom-v0.1.0/positive/08-reverse-dns-extension/fixture-08.aibom.json",
    ));
    let cdx = read_json(repo_root().join(
        "schema/fixtures/aibom-v0.1.0/positive/08-reverse-dns-extension/fixture-08.cdx.json",
    ));
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            Some(&cdx),
            &SignatureFacts::default(),
            &PolicyConfig::default(),
        ))
        .unwrap();
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].policy_id, "no-unknown-extension-capability");
    assert_eq!(format!("{:?}", verdicts[0].status), "Warn");
}

#[test]
fn publisher_allowlist_uses_verified_signature_subject_not_claimed_publisher() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = clean_aibom(
        "pkg:npm/%40modelcontextprotocol/server-filesystem@2.3.1",
        "2026-04-24T00:00:00Z",
    );
    let cdx = json!({
        "components": [{
            "bom-ref": "pkg:npm/%40modelcontextprotocol/server-filesystem@2.3.1",
            "publisher": "Untrusted Claimed Publisher"
        }]
    });
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            Some(&cdx),
            &SignatureFacts {
                present: true,
                verified: true,
                issuer: Some("https://token.actions.githubusercontent.com".to_string()),
                subject: Some("repo:evil/publisher:ref:refs/heads/main".to_string()),
                bundle_version: None,
            },
            &PolicyConfig {
                publisher_allowlist: Some(vec![
                    "repo:trusted/publisher:ref:refs/heads/main".to_string(),
                ]),
                ..PolicyConfig::default()
            },
        ))
        .unwrap();
    assert_policy_status(&verdicts, "publisher-allowlist", "Deny");
}

#[test]
fn maximum_scan_age_denies_stale_scan_when_configured() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = clean_aibom(
        "pkg:npm/%40modelcontextprotocol/server-filesystem@2.3.1",
        "2026-04-20T00:00:00Z",
    );
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            None,
            &SignatureFacts::default(),
            &PolicyConfig {
                max_scan_age_seconds: Some(86_400),
                policy_time: Some("2026-04-22T00:00:00Z".to_string()),
                ..PolicyConfig::default()
            },
        ))
        .unwrap();
    assert_policy_status(&verdicts, "maximum-scan-age", "Deny");
}

#[test]
fn trusted_package_source_denies_prefix_spoofed_purl_type_when_configured() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = clean_aibom("pkg:npm-malicious/evil@1.0.0", "2026-04-24T00:00:00Z");
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            None,
            &SignatureFacts::default(),
            &PolicyConfig {
                trusted_package_sources: Some(vec!["pkg:npm".to_string()]),
                ..PolicyConfig::default()
            },
        ))
        .unwrap();
    assert_policy_status(&verdicts, "trusted-package-source", "Deny");
}

#[test]
fn no_version_downgrade_denies_version_below_configured_floor() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = clean_aibom(
        "pkg:npm/%40modelcontextprotocol/server-filesystem@2.2.0",
        "2026-04-24T00:00:00Z",
    );
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            None,
            &SignatureFacts::default(),
            &PolicyConfig {
                minimum_package_versions: Some(std::collections::BTreeMap::from([(
                    "pkg:npm/%40modelcontextprotocol/server-filesystem".to_string(),
                    "2.3.1".to_string(),
                )])),
                ..PolicyConfig::default()
            },
        ))
        .unwrap();
    assert_policy_status(&verdicts, "no-version-downgrade", "Deny");
}

#[test]
fn risky_grant_policy_denies_elevation_grant() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = granted_aibom(json!([{
        "evidence": ["ev-grant-001"],
        "id": "exec:subprocess",
        "qualifiers": {"cmd": "sudo", "argCount": 2},
        "source": "granted"
    }]));
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            None,
            &SignatureFacts::default(),
            &PolicyConfig::default(),
        ))
        .unwrap();
    assert_policy_status(&verdicts, "risky-grant", "Deny");
}

#[test]
fn v0_3_windows_profile_write_fixture_warns_risky_grant() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = read_json(repo_root().join(
        "schema/fixtures/aibom-v0.3.0/policy/03-policy-12-windows-profile-write-warn/fixture-03.aibom.json",
    ));
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            None,
            &SignatureFacts::default(),
            &PolicyConfig::default(),
        ))
        .unwrap();
    assert_policy_status(&verdicts, "risky-grant", "Warn");
}

#[test]
fn risky_grant_policy_dedupes_duplicate_broad_path_findings() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let aibom = filesystem_registration_root_aibom("C:\\Users\\reeveadmin");
    let verdicts = runtime
        .block_on(evaluate(
            &aibom,
            None,
            &SignatureFacts::default(),
            &PolicyConfig::default(),
        ))
        .unwrap();
    let risky: Vec<_> = verdicts
        .iter()
        .filter(|verdict| verdict.policy_id == "risky-grant")
        .collect();

    assert_eq!(
        risky.len(),
        1,
        "expected one risky-grant verdict: {risky:?}"
    );
    assert_eq!(format!("{:?}", risky[0].status), "Warn");
    assert_eq!(risky[0].references.len(), 2);
}

#[test]
fn sensitive_data_report_policies_warn_without_raw_secret_claims() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let report = sensitive_data_report(
        json!([{
            "fileCount": 12,
            "newestModified": "2026-05-11T09:12:00Z",
            "oldestModified": "2026-05-11T09:12:00Z",
            "redactedRoot": "~/AppData/Roaming/Claude/projects/",
            "surface": "claude-desktop",
            "totalBytes": 8192
        }]),
        json!([{
            "confidence": "high",
            "evidence": {"id": "ev-sensitive-001", "sourceRef": "conversation-session://claude-desktop/<path-1>"},
            "file": {
                "lastModified": "2026-05-11T09:12:00Z",
                "redactedPath": "~/AppData/Roaming/Claude/projects/<segment-1>/session.jsonl",
                "sizeBytes": 8192
            },
            "findingId": "finding-001",
            "humanReviewRequired": true,
            "matchCount": 1,
            "patternClass": "aws-access-key",
            "ruleId": "reeve.default.aws-access-key",
            "rulePackVersion": "2026.05.0",
            "surface": "claude-desktop"
        }]),
        json!({
            "contentPatternScan": true,
            "customRules": [],
            "metadataInventory": true,
            "rulePacks": [{"id": "reeve-default-conversation-secrets", "version": "2026.05.0"}],
            "scannerVersion": "0.3.0-dev",
            "suppressions": []
        }),
    );

    let verdicts = runtime
        .block_on(evaluate_sensitive_data_report(
            &report,
            &PolicyConfig {
                sensitive_data_max_file_count: Some(10),
                sensitive_data_max_total_bytes: Some(4096),
                ..PolicyConfig::default()
            },
        ))
        .unwrap();

    assert_policy_status(&verdicts, "sensitive-data-volume", "Warn");
    assert_policy_status(&verdicts, "sensitive-secret-pattern", "Warn");
    assert!(
        verdicts
            .iter()
            .find(|verdict| verdict.policy_id == "sensitive-secret-pattern")
            .unwrap()
            .justification
            .contains("needs human review")
    );
}

#[test]
fn sensitive_data_report_policy_suppression_and_malformed_cases() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let suppressed = sensitive_data_report(
        json!([]),
        json!([{
            "confidence": "high",
            "file": {"redactedPath": "~/AppData/Roaming/Claude/projects/<segment-1>/session.jsonl", "sizeBytes": 42},
            "findingId": "finding-001",
            "matchCount": 1,
            "patternClass": "aws-access-key",
            "ruleId": "reeve.default.aws-access-key",
            "rulePackVersion": "2026.05.0",
            "suppressed": true,
            "suppressionId": "known-test-key",
            "surface": "claude-desktop"
        }]),
        json!({
            "contentPatternScan": true,
            "customRules": [],
            "metadataInventory": true,
            "rulePacks": [{"id": "reeve-default-conversation-secrets", "version": "2026.05.0"}],
            "scannerVersion": "0.3.0-dev",
            "suppressions": [{"id": "conversation-suppressions"}]
        }),
    );
    let suppressed_verdicts = runtime
        .block_on(evaluate_sensitive_data_report(
            &suppressed,
            &PolicyConfig::default(),
        ))
        .unwrap();
    assert!(
        suppressed_verdicts
            .iter()
            .all(|verdict| verdict.policy_id != "sensitive-secret-pattern"),
        "suppressed findings should not emit sensitive-secret-pattern warnings: {suppressed_verdicts:?}"
    );

    let malformed = sensitive_data_report(
        json!([]),
        json!([]),
        json!({
            "contentPatternScan": true,
            "customRules": [],
            "metadataInventory": true,
            "rulePacks": [],
            "scannerVersion": "0.3.0-dev",
            "suppressions": []
        }),
    );
    let malformed_verdicts = runtime
        .block_on(evaluate_sensitive_data_report(
            &malformed,
            &PolicyConfig::default(),
        ))
        .unwrap();
    assert_policy_status(&malformed_verdicts, "sensitive-secret-pattern", "Deny");
}

#[test]
fn policy_depth_contract_fixtures_emit_expected_verdicts() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let cases = [
        (
            "38-policy-02-publisher-allowlist-deny",
            "38",
            "publisher-allowlist",
            PolicyConfig {
                publisher_allowlist: Some(vec![
                    "repo:trusted/publisher:ref:refs/heads/main".to_string(),
                ]),
                ..PolicyConfig::default()
            },
            SignatureFacts {
                present: true,
                verified: true,
                issuer: Some("https://token.actions.githubusercontent.com".to_string()),
                subject: Some("repo:evil/publisher:ref:refs/heads/main".to_string()),
                bundle_version: None,
            },
        ),
        (
            "39-policy-05-maximum-scan-age-deny",
            "39",
            "maximum-scan-age",
            PolicyConfig {
                max_scan_age_seconds: Some(86_400),
                policy_time: Some("2026-04-22T00:00:00Z".to_string()),
                ..PolicyConfig::default()
            },
            SignatureFacts::default(),
        ),
        (
            "40-policy-08-trusted-package-source-deny",
            "40",
            "trusted-package-source",
            PolicyConfig {
                trusted_package_sources: Some(vec!["pkg:npm".to_string()]),
                ..PolicyConfig::default()
            },
            SignatureFacts::default(),
        ),
        (
            "41-policy-09-no-version-downgrade-deny",
            "41",
            "no-version-downgrade",
            PolicyConfig {
                minimum_package_versions: Some(std::collections::BTreeMap::from([(
                    "pkg:npm/%40modelcontextprotocol/server-filesystem".to_string(),
                    "2.3.1".to_string(),
                )])),
                ..PolicyConfig::default()
            },
            SignatureFacts::default(),
        ),
    ];

    for (dir, scan_id, policy_id, config, signature) in cases {
        let fixture_dir = repo_root().join(format!("schema/fixtures/aibom-v0.1.0/policy/{dir}"));
        let aibom = read_json(fixture_dir.join(format!("fixture-{scan_id}.aibom.json")));
        let cdx = read_json(fixture_dir.join(format!("fixture-{scan_id}.cdx.json")));
        let verdicts = runtime
            .block_on(evaluate(&aibom, Some(&cdx), &signature, &config))
            .unwrap();
        assert_policy_status(&verdicts, policy_id, "Deny");
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn read_json(path: PathBuf) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn assert_policy_status(verdicts: &[aibom_core::PolicyVerdict], policy_id: &str, status: &str) {
    let verdict = verdicts
        .iter()
        .find(|verdict| verdict.policy_id == policy_id)
        .unwrap_or_else(|| panic!("expected {policy_id} verdict, got {verdicts:?}"));
    assert_eq!(format!("{:?}", verdict.status), status);
}

fn clean_aibom(bom_ref: &str, timestamp: &str) -> Value {
    json!({
        "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
        "aibom": {
            "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
            "components": [{
                "bom-ref": bom_ref,
                "capabilities": {
                    "declared": [{
                        "evidence": ["ev-001"],
                        "id": "fs:read",
                        "qualifiers": {},
                        "source": "declared"
                    }],
                    "observed": [{
                        "evidence": ["ev-002"],
                        "id": "fs:read",
                        "qualifiers": {},
                        "source": "observed"
                    }]
                }
            }],
            "evidence": [],
            "scan": {
                "adapter": {"name": "mcp", "version": "0.1.0"},
                "scanId": "policy-deepening-fixture",
                "scanner": {"name": "reeve", "version": "0.1.0"},
                "timestamp": timestamp
            },
            "schemaVersion": "0.1.0"
        }
    })
}

fn granted_aibom(granted: Value) -> Value {
    json!({
        "$schema": "https://aibom.example/schemas/aibom-v0.2.0.json",
        "aibom": {
            "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
            "components": [{
                "bom-ref": "pkg:test/granted@1.0.0",
                "source": "built-in",
                "capabilities": {
                    "declared": [{
                        "evidence": ["ev-001"],
                        "id": "fs:read",
                        "qualifiers": {},
                        "source": "declared"
                    }],
                    "observed": [{
                        "evidence": ["ev-002"],
                        "id": "fs:read",
                        "qualifiers": {},
                        "source": "observed"
                    }],
                    "granted": granted
                }
            }],
            "evidence": [{
                "id": "ev-grant-001",
                "kind": "granted-permission",
                "reference": "file:///fixture/.claude/settings.json#permissions.allow[0]"
            }],
            "scan": {
                "adapter": {"name": "mcp", "version": "0.2.0"},
                "scanId": "risky-grant-policy-fixture",
                "scanner": {"name": "reeve", "version": "0.2.0"},
                "timestamp": "2026-04-30T00:00:00Z"
            },
            "schemaVersion": "0.2.0"
        }
    })
}

fn filesystem_registration_root_aibom(path: &str) -> Value {
    json!({
        "$schema": "https://aibom.example/schemas/aibom-v0.3.0.json",
        "aibom": {
            "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
            "components": [{
                "bom-ref": "pkg:npm/%40modelcontextprotocol/server-filesystem",
                "source": "built-in",
                "capabilities": {
                    "declared": [
                        {
                            "evidence": ["ev-001"],
                            "id": "mcp:modelcontextprotocolserver-filesystem",
                            "qualifiers": {},
                            "source": "declared"
                        },
                        {
                            "evidence": ["ev-001"],
                            "id": "fs:read",
                            "qualifiers": {"path": path},
                            "source": "declared"
                        },
                        {
                            "evidence": ["ev-001"],
                            "id": "fs:write",
                            "qualifiers": {"path": path},
                            "source": "declared"
                        }
                    ],
                    "observed": [],
                    "granted": []
                }
            }],
            "evidence": [{
                "id": "ev-001",
                "kind": "mcp-registration",
                "reference": "file:///fixture/mcp.json"
            }],
            "scan": {
                "adapter": {"name": "mcp", "version": "0.3.0"},
                "scanId": "risky-grant-dedupe-fixture",
                "scanner": {"name": "reeve", "version": "0.3.0"},
                "timestamp": "2026-05-26T00:00:00Z"
            },
            "schemaVersion": "0.3.0"
        }
    })
}

fn sensitive_data_report(surfaces: Value, findings: Value, inputs: Value) -> Value {
    json!({
        "$schema": "https://aibom.example/schemas/sensitive-data-report-v0.1.0.json",
        "sensitiveDataReport": {
            "canonicalization": "RFC8785-JCS+reeve-sensitive-data-report-array-order-v0.1",
            "findings": findings,
            "inputs": inputs,
            "redaction": {
                "mode": "default-redacted",
                "pathStrategy": "user-controlled-segments"
            },
            "reportId": "sdr-policy-test",
            "scan": {
                "scanId": "scan-policy-test",
                "scanner": {"name": "reeve", "version": "0.3.0-dev"},
                "timestamp": "2026-05-11T10:00:00Z"
            },
            "schemaVersion": "0.1.0",
            "surfaces": surfaces
        }
    })
}
