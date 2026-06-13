use aibom_core::{
    AIBOM_PREDICATE_TYPE, AIBOM_SCHEMA_VERSION, IN_TOTO_STATEMENT_TYPE,
    SENSITIVE_DATA_REPORT_PREDICATE_TYPE, sha256_hex,
};
use serde_json::{Map, Value, json};

#[derive(Debug, Clone)]
pub struct ArtifactPair<'a> {
    pub cdx_name: &'a str,
    pub cdx_bytes: &'a [u8],
    pub aibom_name: &'a str,
    pub aibom_bytes: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct SensitiveDataReportArtifact<'a> {
    pub report_name: &'a str,
    pub report_bytes: &'a [u8],
}

#[derive(Debug, Clone)]
struct StatementSubject<'a> {
    name: &'a str,
    bytes: &'a [u8],
    role: &'a str,
}

pub fn build_statement(pair: &ArtifactPair<'_>) -> Value {
    build_attestation_statement(
        &[
            StatementSubject {
                name: pair.aibom_name,
                bytes: pair.aibom_bytes,
                role: "aibom-sidecar",
            },
            StatementSubject {
                name: pair.cdx_name,
                bytes: pair.cdx_bytes,
                role: "cyclonedx",
            },
        ],
        AIBOM_PREDICATE_TYPE,
        AIBOM_SCHEMA_VERSION,
        "RFC8785-JCS+aibom-array-order-v0.1",
    )
}

pub fn build_sensitive_data_report_statement(report: &SensitiveDataReportArtifact<'_>) -> Value {
    build_attestation_statement(
        &[StatementSubject {
            name: report.report_name,
            bytes: report.report_bytes,
            role: "sensitive-data-report",
        }],
        SENSITIVE_DATA_REPORT_PREDICATE_TYPE,
        "0.1.0",
        "RFC8785-JCS+reeve-sensitive-data-report-array-order-v0.1",
    )
}

fn build_attestation_statement(
    subjects: &[StatementSubject<'_>],
    predicate_type: &str,
    schema_version: &str,
    canonicalization: &str,
) -> Value {
    let mut roles = Map::new();
    let subjects = subjects
        .iter()
        .map(|subject| {
            roles.insert(subject.name.to_string(), json!(subject.role));
            json!({
                "name": subject.name,
                "digest": {"sha256": sha256_hex(subject.bytes)}
            })
        })
        .collect::<Vec<_>>();
    json!({
        "_type": IN_TOTO_STATEMENT_TYPE,
        "predicateType": predicate_type,
        "subject": subjects,
        "predicate": {
            "artifactRoles": roles,
            "canonicalization": canonicalization,
            "schemaVersion": schema_version
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_has_two_subjects_and_roles() {
        let pair = ArtifactPair {
            cdx_name: "scan.cdx.json",
            cdx_bytes: b"cdx",
            aibom_name: "scan.aibom.json",
            aibom_bytes: b"aibom",
        };
        let statement = build_statement(&pair);
        assert_eq!(
            statement
                .pointer("/subject")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            statement
                .pointer("/predicate/artifactRoles/scan.aibom.json")
                .and_then(Value::as_str),
            Some("aibom-sidecar")
        );
    }

    // launch-proof: #333 Signed sensitive-data report
    #[test]
    fn sensitive_data_report_statement_has_one_subject_and_dedicated_predicate() {
        let report = SensitiveDataReportArtifact {
            report_name: "scan.sensitive-data.json",
            report_bytes: br#"{"sensitiveDataReport":{"schemaVersion":"0.1.0"}}"#,
        };
        let statement = build_sensitive_data_report_statement(&report);
        assert_eq!(
            statement.pointer("/predicateType").and_then(Value::as_str),
            Some(SENSITIVE_DATA_REPORT_PREDICATE_TYPE)
        );
        assert_eq!(
            statement
                .pointer("/subject")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            statement
                .pointer("/predicate/artifactRoles/scan.sensitive-data.json")
                .and_then(Value::as_str),
            Some("sensitive-data-report")
        );
    }
}
