use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub mod adapter;
pub use adapter::*;

pub const AIBOM_SCHEMA_URL: &str = "https://aibom.example/schemas/aibom-v0.1.0.json";
pub const AIBOM_SCHEMA_VERSION: &str = "0.1.0";
pub const AIBOM_SCHEMA_URL_V2: &str = "https://aibom.example/schemas/aibom-v0.2.0.json";
pub const AIBOM_SCHEMA_VERSION_V2: &str = "0.2.0";
pub const AIBOM_SCHEMA_URL_V3: &str = "https://aibom.example/schemas/aibom-v0.3.0.json";
pub const AIBOM_SCHEMA_VERSION_V3: &str = "0.3.0";
pub const AIBOM_SUPPORTED_SCHEMA_VERSIONS: &[&str] = &[
    AIBOM_SCHEMA_VERSION,
    AIBOM_SCHEMA_VERSION_V2,
    AIBOM_SCHEMA_VERSION_V3,
];
pub const AIBOM_PREDICATE_TYPE: &str = "https://aibom.example/attestation/aibom/v0.1";
pub const SENSITIVE_DATA_REPORT_PREDICATE_TYPE: &str =
    "https://aibom.example/attestation/sensitive-data-report/v0.1";
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const SIGSTORE_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationStage {
    SchemaValidation,
    SemanticValidation,
    Canonicalization,
    HashMatch,
    AttestationShape,
    AttestationBinding,
    CryptoVerification,
}

impl fmt::Display for ValidationStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SchemaValidation => "schema-validation",
            Self::SemanticValidation => "semantic-validation",
            Self::Canonicalization => "canonicalization",
            Self::HashMatch => "hash-match",
            Self::AttestationShape => "attestation-shape",
            Self::AttestationBinding => "attestation-binding",
            Self::CryptoVerification => "crypto-verification",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    #[serde(rename = "aibom.version_mismatch")]
    AibomVersionMismatch,
    #[serde(rename = "capability.id.core_unregistered")]
    CapabilityIdCoreUnregistered,
    #[serde(rename = "capability.id.namespace_reserved")]
    CapabilityIdNamespaceReserved,
    #[serde(rename = "capability.qualifiers.key_not_in_allowed_set")]
    CapabilityQualifiersKeyNotInAllowedSet,
    #[serde(rename = "capability.qualifiers.path_invalid")]
    CapabilityQualifiersPathInvalid,
    #[serde(rename = "capability.evidence.min_items")]
    CapabilityEvidenceMinItems,
    #[serde(rename = "capability.source.array_mismatch")]
    CapabilitySourceArrayMismatch,
    #[serde(rename = "capability.additional_property")]
    CapabilityAdditionalProperty,
    #[serde(rename = "cdx.externalReferences.duplicate_type_url")]
    CdxExternalReferencesDuplicateTypeUrl,
    #[serde(rename = "schema.generic_violation")]
    SchemaGenericViolation,
    #[serde(rename = "aibom.components.bom_ref_duplicate")]
    AibomComponentsBomRefDuplicate,
    #[serde(rename = "aibom.evidence.id_duplicate")]
    AibomEvidenceIdDuplicate,
    #[serde(rename = "aibom.evidence_ref.dangling_reference")]
    AibomEvidenceRefDanglingReference,
    #[serde(rename = "aibom.component.bom_ref_missing_in_cdx")]
    AibomComponentBomRefMissingInCdx,
    #[serde(rename = "cdx.externalReferences.url_mismatch")]
    CdxExternalReferencesUrlMismatch,
    #[serde(rename = "canonicalization.byte_drift")]
    CanonicalizationByteDrift,
    #[serde(rename = "cdx.externalReferences.hash_mismatch")]
    CdxExternalReferencesHashMismatch,
    #[serde(rename = "attestation.payloadType_mismatch")]
    AttestationPayloadTypeMismatch,
    #[serde(rename = "attestation.statement_type_mismatch")]
    AttestationStatementTypeMismatch,
    #[serde(rename = "attestation.predicateType_mismatch")]
    AttestationPredicateTypeMismatch,
    #[serde(rename = "attestation.predicate_schemaVersion_mismatch")]
    AttestationPredicateSchemaVersionMismatch,
    #[serde(rename = "attestation.subject_count")]
    AttestationSubjectCount,
    #[serde(rename = "attestation.subject_name_duplicate")]
    AttestationSubjectNameDuplicate,
    #[serde(rename = "attestation.digest_algorithm")]
    AttestationDigestAlgorithm,
    #[serde(rename = "attestation.artifactRoles_mismatch")]
    AttestationArtifactRolesMismatch,
    #[serde(rename = "attestation.subject_role_mismatch")]
    AttestationSubjectRoleMismatch,
    #[serde(rename = "attestation.payload_decode")]
    AttestationPayloadDecode,
    #[serde(rename = "attestation.subject_name_unexpected")]
    AttestationSubjectNameUnexpected,
    #[serde(rename = "attestation.subject_digest_mismatch")]
    AttestationSubjectDigestMismatch,
    #[serde(rename = "crypto.fulcio_chain_untrusted")]
    CryptoFulcioChainUntrusted,
    #[serde(rename = "crypto.oidc_issuer_not_allowed")]
    CryptoOidcIssuerNotAllowed,
    #[serde(rename = "crypto.oidc_subject_not_allowed")]
    CryptoOidcSubjectNotAllowed,
    #[serde(rename = "crypto.rekor_inclusion_invalid")]
    CryptoRekorInclusionInvalid,
    #[serde(rename = "crypto.rekor_time_outside_cert_window")]
    CryptoRekorTimeOutsideCertWindow,
    #[serde(rename = "crypto.tuf_metadata_stale_or_invalid")]
    CryptoTufMetadataStaleOrInvalid,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AibomVersionMismatch => "aibom.version_mismatch",
            Self::CapabilityIdCoreUnregistered => "capability.id.core_unregistered",
            Self::CapabilityIdNamespaceReserved => "capability.id.namespace_reserved",
            Self::CapabilityQualifiersKeyNotInAllowedSet => {
                "capability.qualifiers.key_not_in_allowed_set"
            }
            Self::CapabilityQualifiersPathInvalid => "capability.qualifiers.path_invalid",
            Self::CapabilityEvidenceMinItems => "capability.evidence.min_items",
            Self::CapabilitySourceArrayMismatch => "capability.source.array_mismatch",
            Self::CapabilityAdditionalProperty => "capability.additional_property",
            Self::CdxExternalReferencesDuplicateTypeUrl => {
                "cdx.externalReferences.duplicate_type_url"
            }
            Self::SchemaGenericViolation => "schema.generic_violation",
            Self::AibomComponentsBomRefDuplicate => "aibom.components.bom_ref_duplicate",
            Self::AibomEvidenceIdDuplicate => "aibom.evidence.id_duplicate",
            Self::AibomEvidenceRefDanglingReference => "aibom.evidence_ref.dangling_reference",
            Self::AibomComponentBomRefMissingInCdx => "aibom.component.bom_ref_missing_in_cdx",
            Self::CdxExternalReferencesUrlMismatch => "cdx.externalReferences.url_mismatch",
            Self::CanonicalizationByteDrift => "canonicalization.byte_drift",
            Self::CdxExternalReferencesHashMismatch => "cdx.externalReferences.hash_mismatch",
            Self::AttestationPayloadTypeMismatch => "attestation.payloadType_mismatch",
            Self::AttestationStatementTypeMismatch => "attestation.statement_type_mismatch",
            Self::AttestationPredicateTypeMismatch => "attestation.predicateType_mismatch",
            Self::AttestationPredicateSchemaVersionMismatch => {
                "attestation.predicate_schemaVersion_mismatch"
            }
            Self::AttestationSubjectCount => "attestation.subject_count",
            Self::AttestationSubjectNameDuplicate => "attestation.subject_name_duplicate",
            Self::AttestationDigestAlgorithm => "attestation.digest_algorithm",
            Self::AttestationArtifactRolesMismatch => "attestation.artifactRoles_mismatch",
            Self::AttestationSubjectRoleMismatch => "attestation.subject_role_mismatch",
            Self::AttestationPayloadDecode => "attestation.payload_decode",
            Self::AttestationSubjectNameUnexpected => "attestation.subject_name_unexpected",
            Self::AttestationSubjectDigestMismatch => "attestation.subject_digest_mismatch",
            Self::CryptoFulcioChainUntrusted => "crypto.fulcio_chain_untrusted",
            Self::CryptoOidcIssuerNotAllowed => "crypto.oidc_issuer_not_allowed",
            Self::CryptoOidcSubjectNotAllowed => "crypto.oidc_subject_not_allowed",
            Self::CryptoRekorInclusionInvalid => "crypto.rekor_inclusion_invalid",
            Self::CryptoRekorTimeOutsideCertWindow => "crypto.rekor_time_outside_cert_window",
            Self::CryptoTufMetadataStaleOrInvalid => "crypto.tuf_metadata_stale_or_invalid",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CanonicalizationError {
    #[error("failed to serialize JSON string")]
    String(#[from] serde_json::Error),
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

pub fn canonicalize_json(value: &Value) -> Result<Vec<u8>, CanonicalizationError> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalizationError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => out.extend_from_slice(serde_json::to_string(string)?.as_bytes()),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(object) => write_object_canonical(object, out)?,
    }
    Ok(())
}

fn write_object_canonical(
    object: &Map<String, Value>,
    out: &mut Vec<u8>,
) -> Result<(), CanonicalizationError> {
    out.push(b'{');
    let mut keys: Vec<_> = object.keys().collect();
    keys.sort();
    for (index, key) in keys.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(serde_json::to_string(key)?.as_bytes());
        out.push(b':');
        write_canonical(&object[key], out)?;
    }
    out.push(b'}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_object_key_order() {
        let value: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(canonicalize_json(&value).unwrap(), br#"{"a":1,"b":2}"#);
    }
}
