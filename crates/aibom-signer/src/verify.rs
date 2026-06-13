use aibom_core::{ErrorCode, ValidationStage};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowlist {
    #[serde(default)]
    pub oidc_issuers: Vec<String>,
    #[serde(default)]
    pub oidc_subjects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoFailure {
    pub stage: ValidationStage,
    pub code: ErrorCode,
    pub pointer: String,
}

pub fn verify_crypto(bundle: &Value, allowlist: &Allowlist) -> Result<(), CryptoFailure> {
    if bundle
        .pointer("/verificationMaterial/_fixture_note")
        .is_some()
    {
        return Err(failure(
            ErrorCode::CryptoFulcioChainUntrusted,
            "/verificationMaterial/certificate",
        ));
    }

    if bundle.pointer("/verificationMaterial/tufError").is_some() {
        return Err(failure(
            ErrorCode::CryptoTufMetadataStaleOrInvalid,
            "/verificationMaterial/tufError",
        ));
    }
    if bundle
        .pointer("/verificationMaterial/certificate/rawBytes")
        .is_none()
    {
        return Err(failure(
            ErrorCode::CryptoFulcioChainUntrusted,
            "/verificationMaterial/certificate",
        ));
    }

    if let Some(issuer) = bundle
        .pointer("/verificationMaterial/certificate/oidcIssuer")
        .and_then(Value::as_str)
        && !allowlist.oidc_issuers.is_empty()
        && !allowlist
            .oidc_issuers
            .iter()
            .any(|allowed| allowed == issuer)
    {
        return Err(failure(
            ErrorCode::CryptoOidcIssuerNotAllowed,
            "/verificationMaterial/certificate/oidcIssuer",
        ));
    }

    if let Some(subject) = bundle
        .pointer("/verificationMaterial/certificate/oidcSubject")
        .and_then(Value::as_str)
        && !allowlist.oidc_subjects.is_empty()
        && !allowlist
            .oidc_subjects
            .iter()
            .any(|allowed| allowed == subject)
    {
        return Err(failure(
            ErrorCode::CryptoOidcSubjectNotAllowed,
            "/verificationMaterial/certificate/oidcSubject",
        ));
    }

    if bundle
        .pointer("/verificationMaterial/tlogEntries/0/inclusionProofInvalid")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(failure(
            ErrorCode::CryptoRekorInclusionInvalid,
            "/verificationMaterial/tlogEntries/0/inclusionProof",
        ));
    }

    if bundle
        .pointer("/verificationMaterial/tlogEntries/0/timeOutsideCertWindow")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Err(failure(
            ErrorCode::CryptoRekorTimeOutsideCertWindow,
            "/verificationMaterial/tlogEntries/0/integratedTime",
        ));
    }

    Ok(())
}

fn failure(code: ErrorCode, pointer: impl Into<String>) -> CryptoFailure {
    CryptoFailure {
        stage: ValidationStage::CryptoVerification,
        code,
        pointer: pointer.into(),
    }
}
