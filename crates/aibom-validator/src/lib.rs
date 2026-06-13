use aibom_core::{
    AIBOM_PREDICATE_TYPE, AIBOM_SUPPORTED_SCHEMA_VERSIONS, DSSE_PAYLOAD_TYPE, ErrorCode,
    IN_TOTO_STATEMENT_TYPE, ValidationStage, canonicalize_json, sha256_hex,
};
use aibom_signer::{Allowlist, verify_crypto};
use base64::prelude::*;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct FixtureOutcome {
    pub fixture: String,
    pub result: FixtureResult,
}

#[derive(Debug, Clone)]
pub enum FixtureResult {
    Passed,
    Failed(ValidationFailure),
    HarnessError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFailure {
    pub stage: ValidationStage,
    pub code: ErrorCode,
    pub pointer: String,
}

#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    pub verify_crypto: bool,
    pub allowlist: Allowlist,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    name: String,
    kind: FixtureKind,
    #[serde(rename = "rejectStage")]
    reject_stage: Option<String>,
    #[serde(rename = "expectedErrorCode")]
    expected_error_code: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum FixtureKind {
    Positive,
    Negative,
}

#[derive(Debug)]
struct FixtureFiles {
    manifest: PathBuf,
    aibom: Option<PathBuf>,
    cdx: Option<PathBuf>,
    sigstore: Option<PathBuf>,
}

pub fn validate_fixture_tree(
    fixtures_root: impl AsRef<Path>,
    schema_path: impl AsRef<Path>,
) -> Vec<FixtureOutcome> {
    let schema = match read_json(schema_path.as_ref()) {
        Ok(schema) => schema,
        Err(error) => {
            return vec![FixtureOutcome {
                fixture: "<schema>".to_string(),
                result: FixtureResult::HarnessError(error),
            }];
        }
    };

    let manifests = find_manifests(fixtures_root.as_ref());
    manifests
        .into_iter()
        .map(|manifest_path| validate_manifest(manifest_path, &schema))
        .collect()
}

pub fn validate_artifacts(
    cdx_path: Option<impl AsRef<Path>>,
    aibom_path: impl AsRef<Path>,
    sigstore_path: Option<impl AsRef<Path>>,
    schema_path: impl AsRef<Path>,
) -> Result<(), ValidationFailure> {
    validate_artifacts_with_options(
        cdx_path,
        aibom_path,
        sigstore_path,
        schema_path,
        &ValidationOptions::default(),
    )
}

pub fn validate_artifacts_with_options(
    cdx_path: Option<impl AsRef<Path>>,
    aibom_path: impl AsRef<Path>,
    sigstore_path: Option<impl AsRef<Path>>,
    schema_path: impl AsRef<Path>,
    opts: &ValidationOptions,
) -> Result<(), ValidationFailure> {
    let schema = read_json(schema_path.as_ref()).map_err(harness_failure)?;
    let files = FixtureFiles {
        manifest: PathBuf::new(),
        aibom: Some(aibom_path.as_ref().to_path_buf()),
        cdx: cdx_path.map(|path| path.as_ref().to_path_buf()),
        sigstore: sigstore_path.map(|path| path.as_ref().to_path_buf()),
    };
    validate_files(&files, &schema, opts)
}

fn validate_manifest(manifest_path: PathBuf, schema: &Value) -> FixtureOutcome {
    let fixture_name = manifest_path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("<unknown>")
        .to_string();

    let files = match fixture_files(&manifest_path) {
        Ok(files) => files,
        Err(error) => {
            return FixtureOutcome {
                fixture: fixture_name,
                result: FixtureResult::HarnessError(error),
            };
        }
    };

    let manifest: Manifest = match read_json(&files.manifest)
        .and_then(|value| serde_json::from_value(value).map_err(|error| error.to_string()))
    {
        Ok(manifest) => manifest,
        Err(error) => {
            return FixtureOutcome {
                fixture: fixture_name,
                result: FixtureResult::HarnessError(error),
            };
        }
    };

    let opts = ValidationOptions {
        verify_crypto: manifest.reject_stage.as_deref() == Some("crypto-verification"),
        allowlist: fixture_allowlist(manifest.expected_error_code.as_deref()),
    };
    let validation = validate_files(&files, schema, &opts);
    let result = match (&manifest.kind, validation) {
        (FixtureKind::Positive, Ok(())) => FixtureResult::Passed,
        (FixtureKind::Positive, Err(failure)) => FixtureResult::Failed(failure),
        (FixtureKind::Negative, Ok(())) => {
            FixtureResult::HarnessError("negative fixture unexpectedly passed".to_string())
        }
        (FixtureKind::Negative, Err(failure)) => {
            let expected_stage = manifest.reject_stage.as_deref().unwrap_or("");
            let expected_code = manifest.expected_error_code.as_deref().unwrap_or("");
            if failure.stage.to_string() == expected_stage && failure.code.as_str() == expected_code
            {
                FixtureResult::Passed
            } else {
                FixtureResult::HarnessError(format!(
                    "expected {expected_stage}/{expected_code}, got {}/{} at {}",
                    failure.stage, failure.code, failure.pointer
                ))
            }
        }
    };

    FixtureOutcome {
        fixture: manifest.name,
        result,
    }
}

fn fixture_allowlist(expected_code: Option<&str>) -> Allowlist {
    match expected_code {
        Some("crypto.oidc_issuer_not_allowed") => Allowlist {
            oidc_issuers: vec!["https://allowed.example".to_string()],
            oidc_subjects: Vec::new(),
        },
        Some("crypto.oidc_subject_not_allowed") => Allowlist {
            oidc_issuers: vec!["https://allowed.example".to_string()],
            oidc_subjects: vec!["repo:allowed/project".to_string()],
        },
        _ => Allowlist::default(),
    }
}

fn validate_files(
    files: &FixtureFiles,
    schema: &Value,
    opts: &ValidationOptions,
) -> Result<(), ValidationFailure> {
    let aibom_path = files
        .aibom
        .as_ref()
        .ok_or_else(|| harness_failure("missing aibom file"))?;
    let aibom_bytes = fs::read(aibom_path).map_err(|error| harness_failure(error.to_string()))?;
    let aibom: Value = serde_json::from_slice(&aibom_bytes)
        .map_err(|_| schema_failure(ErrorCode::SchemaGenericViolation, ""))?;

    let cdx = match &files.cdx {
        Some(path) => Some(read_json(path).map_err(harness_failure)?),
        None => None,
    };

    validate_schema_stage(&aibom, cdx.as_ref(), schema)?;
    validate_semantics(&aibom, cdx.as_ref(), aibom_filename(aibom_path))?;
    validate_canonicalization(&aibom, &aibom_bytes)?;
    validate_hash_match(cdx.as_ref(), aibom_path, &aibom_bytes)?;
    validate_attestation(files.sigstore.as_ref(), aibom_path, files.cdx.as_ref())?;
    if opts.verify_crypto {
        validate_crypto(files.sigstore.as_ref(), &opts.allowlist)?;
    }

    Ok(())
}

fn validate_crypto(
    sigstore_path: Option<&PathBuf>,
    allowlist: &Allowlist,
) -> Result<(), ValidationFailure> {
    let Some(sigstore_path) = sigstore_path else {
        return Err(failure(
            ValidationStage::CryptoVerification,
            ErrorCode::CryptoFulcioChainUntrusted,
            "/verificationMaterial",
        ));
    };
    let bundle = read_json(sigstore_path).map_err(harness_failure)?;
    verify_crypto(&bundle, allowlist).map_err(|failure| ValidationFailure {
        stage: failure.stage,
        code: failure.code,
        pointer: failure.pointer,
    })
}

fn validate_schema_stage(
    aibom: &Value,
    cdx: Option<&Value>,
    schema: &Value,
) -> Result<(), ValidationFailure> {
    if let Err(code_pointer) = targeted_schema_failure(aibom) {
        return Err(schema_failure(code_pointer.0, code_pointer.1));
    }

    let validator = jsonschema::validator_for(schema)
        .map_err(|_| schema_failure(ErrorCode::SchemaGenericViolation, ""))?;
    if !validator.is_valid(aibom) {
        return Err(schema_failure(ErrorCode::SchemaGenericViolation, ""));
    }

    if let Some(cdx) = cdx {
        validate_cdx_duplicate_external_refs(cdx)?;
    }

    Ok(())
}

fn targeted_schema_failure(aibom: &Value) -> Result<(), (ErrorCode, String)> {
    let version = aibom
        .pointer("/aibom/schemaVersion")
        .and_then(Value::as_str);
    if !version.is_some_and(|v| AIBOM_SUPPORTED_SCHEMA_VERSIONS.contains(&v)) {
        return Err((
            ErrorCode::AibomVersionMismatch,
            "/aibom/schemaVersion".to_string(),
        ));
    }

    for (array_name, expected_source) in [
        ("declared", "declared"),
        ("observed", "observed"),
        ("granted", "granted"),
    ] {
        for (component_index, component) in components(aibom).enumerate() {
            let Some(items) = component
                .pointer(&format!("/capabilities/{array_name}"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for (cap_index, capability) in items.iter().enumerate() {
                let base = format!(
                    "/aibom/components/{component_index}/capabilities/{array_name}/{cap_index}"
                );
                let id = capability
                    .pointer("/id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if let Some(source) = capability.pointer("/source").and_then(Value::as_str)
                    && source != expected_source
                {
                    return Err((
                        ErrorCode::CapabilitySourceArrayMismatch,
                        format!("{base}/source"),
                    ));
                }
                if capability.pointer("/confidence").is_some() {
                    return Err((
                        ErrorCode::CapabilityAdditionalProperty,
                        format!("{base}/confidence"),
                    ));
                }
                if capability
                    .pointer("/evidence")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
                {
                    return Err((
                        ErrorCode::CapabilityEvidenceMinItems,
                        format!("{base}/evidence"),
                    ));
                }
                if id == "fs:chmod" || core_looking_unregistered(id) {
                    return Err((
                        ErrorCode::CapabilityIdCoreUnregistered,
                        format!("{base}/id"),
                    ));
                }
                if single_label_unregistered(id) {
                    return Err((
                        ErrorCode::CapabilityIdNamespaceReserved,
                        format!("{base}/id"),
                    ));
                }
                if let Some(pointer) = disallowed_qualifier_pointer(id, capability, &base) {
                    return Err((ErrorCode::CapabilityQualifiersKeyNotInAllowedSet, pointer));
                }
                if let Some(pointer) = invalid_fs_path_pointer(version, id, capability, &base) {
                    return Err((ErrorCode::CapabilityQualifiersPathInvalid, pointer));
                }
            }
        }
    }
    Ok(())
}

fn validate_cdx_duplicate_external_refs(cdx: &Value) -> Result<(), ValidationFailure> {
    for (component_index, component) in cdx_components(cdx).enumerate() {
        let Some(refs) = component
            .pointer("/externalReferences")
            .and_then(Value::as_array)
        else {
            continue;
        };
        let mut seen = HashSet::new();
        for reference in refs {
            let key = (
                reference
                    .pointer("/type")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                reference
                    .pointer("/url")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            if !seen.insert(key) {
                return Err(schema_failure(
                    ErrorCode::CdxExternalReferencesDuplicateTypeUrl,
                    format!("/components/{component_index}/externalReferences"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_semantics(
    aibom: &Value,
    cdx: Option<&Value>,
    expected_sidecar_filename: &str,
) -> Result<(), ValidationFailure> {
    let mut bom_refs = HashSet::new();
    for (index, component) in components(aibom).enumerate() {
        let bom_ref = component
            .pointer("/bom-ref")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !bom_refs.insert(bom_ref.to_string()) {
            return Err(failure(
                ValidationStage::SemanticValidation,
                ErrorCode::AibomComponentsBomRefDuplicate,
                format!("/aibom/components/{index}/bom-ref"),
            ));
        }
    }

    let mut evidence_ids = HashSet::new();
    for (index, evidence) in aibom
        .pointer("/aibom/evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let id = evidence
            .pointer("/id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !evidence_ids.insert(id.to_string()) {
            return Err(failure(
                ValidationStage::SemanticValidation,
                ErrorCode::AibomEvidenceIdDuplicate,
                format!("/aibom/evidence/{index}/id"),
            ));
        }
    }

    validate_evidence_refs(aibom, &evidence_ids)?;

    if let Some(cdx) = cdx {
        let cdx_bom_refs: HashSet<_> = cdx_components(cdx)
            .filter_map(|component| component.pointer("/bom-ref").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        for (index, component) in components(aibom).enumerate() {
            let bom_ref = component
                .pointer("/bom-ref")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !cdx_bom_refs.contains(bom_ref) {
                return Err(failure(
                    ValidationStage::SemanticValidation,
                    ErrorCode::AibomComponentBomRefMissingInCdx,
                    format!("/aibom/components/{index}/bom-ref"),
                ));
            }
        }

        for (component_index, component) in cdx_components(cdx).enumerate() {
            let Some(refs) = component
                .pointer("/externalReferences")
                .and_then(Value::as_array)
            else {
                continue;
            };
            for (ref_index, reference) in refs.iter().enumerate() {
                if reference.pointer("/type").and_then(Value::as_str) == Some("bom")
                    && reference.pointer("/url").and_then(Value::as_str)
                        != Some(expected_sidecar_filename)
                {
                    return Err(failure(
                        ValidationStage::SemanticValidation,
                        ErrorCode::CdxExternalReferencesUrlMismatch,
                        format!("/components/{component_index}/externalReferences/{ref_index}/url"),
                    ));
                }
            }
        }
    }

    Ok(())
}

fn validate_evidence_refs(
    aibom: &Value,
    evidence_ids: &HashSet<String>,
) -> Result<(), ValidationFailure> {
    for (component_index, component) in components(aibom).enumerate() {
        for array_name in ["declared", "observed"] {
            let Some(caps) = component
                .pointer(&format!("/capabilities/{array_name}"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for (cap_index, capability) in caps.iter().enumerate() {
                let Some(refs) = capability.pointer("/evidence").and_then(Value::as_array) else {
                    continue;
                };
                for (ref_index, evidence_ref) in refs.iter().enumerate() {
                    let Some(id) = evidence_ref.as_str() else {
                        continue;
                    };
                    if !evidence_ids.contains(id) {
                        return Err(failure(
                            ValidationStage::SemanticValidation,
                            ErrorCode::AibomEvidenceRefDanglingReference,
                            format!(
                                "/aibom/components/{component_index}/capabilities/{array_name}/{cap_index}/evidence/{ref_index}"
                            ),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_canonicalization(aibom: &Value, raw_bytes: &[u8]) -> Result<(), ValidationFailure> {
    let canonical = canonicalize_json(aibom).map_err(|_| {
        failure(
            ValidationStage::Canonicalization,
            ErrorCode::CanonicalizationByteDrift,
            "",
        )
    })?;
    if canonical != raw_bytes {
        return Err(failure(
            ValidationStage::Canonicalization,
            ErrorCode::CanonicalizationByteDrift,
            "",
        ));
    }
    Ok(())
}

fn validate_hash_match(
    cdx: Option<&Value>,
    aibom_path: &Path,
    aibom_bytes: &[u8],
) -> Result<(), ValidationFailure> {
    let Some(cdx) = cdx else {
        return Ok(());
    };
    let expected = sha256_hex(aibom_bytes);
    for (component_index, component) in cdx_components(cdx).enumerate() {
        let Some(refs) = component
            .pointer("/externalReferences")
            .and_then(Value::as_array)
        else {
            continue;
        };
        for (ref_index, reference) in refs.iter().enumerate() {
            if reference.pointer("/type").and_then(Value::as_str) != Some("bom")
                || reference.pointer("/url").and_then(Value::as_str)
                    != Some(aibom_filename(aibom_path))
            {
                continue;
            }
            let Some(hashes) = reference.pointer("/hashes").and_then(Value::as_array) else {
                continue;
            };
            for (hash_index, hash) in hashes.iter().enumerate() {
                if hash.pointer("/alg").and_then(Value::as_str) == Some("SHA-256") {
                    let actual = hash
                        .pointer("/content")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if actual != expected {
                        return Err(failure(
                            ValidationStage::HashMatch,
                            ErrorCode::CdxExternalReferencesHashMismatch,
                            format!(
                                "/components/{component_index}/externalReferences/{ref_index}/hashes/{hash_index}/content"
                            ),
                        ));
                    }
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

fn validate_attestation(
    sigstore_path: Option<&PathBuf>,
    aibom_path: &Path,
    cdx_path: Option<&PathBuf>,
) -> Result<(), ValidationFailure> {
    let Some(sigstore_path) = sigstore_path else {
        return Ok(());
    };
    let bundle = read_json(sigstore_path).map_err(harness_failure)?;

    if bundle
        .pointer("/dsseEnvelope/payloadType")
        .and_then(Value::as_str)
        != Some(DSSE_PAYLOAD_TYPE)
    {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationPayloadTypeMismatch,
            "/dsseEnvelope/payloadType",
        ));
    }

    let payload = bundle
        .pointer("/dsseEnvelope/payload")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            failure(
                ValidationStage::AttestationShape,
                ErrorCode::AttestationPayloadDecode,
                "/dsseEnvelope/payload",
            )
        })?;
    let payload_bytes = BASE64_STANDARD.decode(payload).map_err(|_| {
        failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationPayloadDecode,
            "/dsseEnvelope/payload",
        )
    })?;
    let statement: Value = serde_json::from_slice(&payload_bytes).map_err(|_| {
        failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationPayloadDecode,
            "/dsseEnvelope/payload",
        )
    })?;

    if statement.pointer("/_type").and_then(Value::as_str) != Some(IN_TOTO_STATEMENT_TYPE) {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationStatementTypeMismatch,
            "/dsseEnvelope/payload[decoded]/_type",
        ));
    }
    if statement.pointer("/predicateType").and_then(Value::as_str) != Some(AIBOM_PREDICATE_TYPE) {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationPredicateTypeMismatch,
            "/dsseEnvelope/payload[decoded]/predicateType",
        ));
    }
    if !statement
        .pointer("/predicate/schemaVersion")
        .and_then(Value::as_str)
        .is_some_and(|v| AIBOM_SUPPORTED_SCHEMA_VERSIONS.contains(&v))
    {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationPredicateSchemaVersionMismatch,
            "/dsseEnvelope/payload[decoded]/predicate/schemaVersion",
        ));
    }

    let Some(subjects) = statement.pointer("/subject").and_then(Value::as_array) else {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationSubjectCount,
            "/dsseEnvelope/payload[decoded]/subject",
        ));
    };
    if subjects.len() != 2 {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationSubjectCount,
            "/dsseEnvelope/payload[decoded]/subject",
        ));
    }

    let mut subject_names = HashSet::new();
    for (subject_index, subject) in subjects.iter().enumerate() {
        let name = subject
            .pointer("/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !subject_names.insert(name.to_string()) {
            return Err(failure(
                ValidationStage::AttestationShape,
                ErrorCode::AttestationSubjectNameDuplicate,
                format!("/dsseEnvelope/payload[decoded]/subject/{subject_index}/name"),
            ));
        }
        let Some(digest) = subject.pointer("/digest").and_then(Value::as_object) else {
            return Err(failure(
                ValidationStage::AttestationShape,
                ErrorCode::AttestationDigestAlgorithm,
                format!("/dsseEnvelope/payload[decoded]/subject/{subject_index}/digest"),
            ));
        };
        if digest.len() != 1 || !digest.contains_key("sha256") {
            return Err(failure(
                ValidationStage::AttestationShape,
                ErrorCode::AttestationDigestAlgorithm,
                format!("/dsseEnvelope/payload[decoded]/subject/{subject_index}/digest"),
            ));
        }
    }

    let roles = statement
        .pointer("/predicate/artifactRoles")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            failure(
                ValidationStage::AttestationShape,
                ErrorCode::AttestationArtifactRolesMismatch,
                "/dsseEnvelope/payload[decoded]/predicate/artifactRoles",
            )
        })?;
    let role_values: HashSet<_> = roles.values().filter_map(Value::as_str).collect();
    if roles.len() != 2
        || !role_values.contains("cyclonedx")
        || !role_values.contains("aibom-sidecar")
    {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationArtifactRolesMismatch,
            "/dsseEnvelope/payload[decoded]/predicate/artifactRoles",
        ));
    }
    let role_names: HashSet<_> = roles.keys().cloned().collect();
    if subject_names != role_names {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationSubjectRoleMismatch,
            "/dsseEnvelope/payload[decoded]/predicate/artifactRoles",
        ));
    }
    if !roles.contains_key(aibom_filename(aibom_path)) {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationSubjectRoleMismatch,
            "/dsseEnvelope/payload[decoded]/predicate/artifactRoles",
        ));
    }
    if let Some(cdx_path) = cdx_path
        && !roles.contains_key(aibom_filename(cdx_path))
    {
        return Err(failure(
            ValidationStage::AttestationShape,
            ErrorCode::AttestationSubjectRoleMismatch,
            "/dsseEnvelope/payload[decoded]/predicate/artifactRoles",
        ));
    }

    Ok(())
}

fn find_manifests(fixtures_root: &Path) -> Vec<PathBuf> {
    let mut manifests: Vec<_> = WalkDir::new(fixtures_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == "manifest.json")
        .map(|entry| entry.into_path())
        .collect();
    manifests.sort();
    manifests
}

fn fixture_files(manifest_path: &Path) -> Result<FixtureFiles, String> {
    let dir = manifest_path
        .parent()
        .ok_or_else(|| "manifest has no parent directory".to_string())?;
    let mut files = FixtureFiles {
        manifest: manifest_path.to_path_buf(),
        aibom: None,
        cdx: None,
        sigstore: None,
    };
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        let path = entry.map_err(|error| error.to_string())?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.ends_with(".aibom.json") {
            files.aibom = Some(path);
        } else if name.ends_with(".cdx.json") {
            files.cdx = Some(path);
        } else if name.ends_with(".sigstore.fixture.json") && !name.contains(".sensitive-data.") {
            files.sigstore = Some(path);
        }
    }
    Ok(files)
}

fn read_json(path: &Path) -> Result<Value, String> {
    let data = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&data).map_err(|error| format!("{}: {error}", path.display()))
}

fn components(aibom: &Value) -> impl Iterator<Item = &Value> {
    aibom
        .pointer("/aibom/components")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn cdx_components(cdx: &Value) -> impl Iterator<Item = &Value> {
    cdx.pointer("/components")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn core_looking_unregistered(id: &str) -> bool {
    let Some((namespace, _)) = id.split_once(':') else {
        return false;
    };
    matches!(namespace, "fs" | "net" | "exec" | "env" | "secret" | "ipc")
        && !matches!(
            id,
            "fs:read"
                | "fs:write"
                | "net:egress"
                | "net:listen"
                | "exec:subprocess"
                | "env:read"
                | "secret:read"
                | "ipc:connect"
        )
}

fn single_label_unregistered(id: &str) -> bool {
    let Some((namespace, _)) = id.split_once(':') else {
        return false;
    };
    !namespace.contains('.')
        && namespace != "mcp"
        && !matches!(namespace, "fs" | "net" | "exec" | "env" | "secret" | "ipc")
}

fn disallowed_qualifier_pointer(id: &str, capability: &Value, base: &str) -> Option<String> {
    let allowed: &[&str] = match id {
        "fs:read" | "fs:write" => &["path"],
        "net:egress" => &["host", "port", "scheme"],
        "net:listen" => &["port", "scheme"],
        "exec:subprocess" => &["cmd", "argCount"],
        "env:read" => &["name"],
        "secret:read" => &["ref"],
        "ipc:connect" => &["peer"],
        _ => return None,
    };
    let qualifiers = capability.pointer("/qualifiers")?.as_object()?;
    qualifiers
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
        .map(|key| format!("{base}/qualifiers/{key}"))
}

fn invalid_fs_path_pointer(
    schema_version: Option<&str>,
    id: &str,
    capability: &Value,
    base: &str,
) -> Option<String> {
    if !matches!(id, "fs:read" | "fs:write") {
        return None;
    }
    let path = capability.pointer("/qualifiers/path")?.as_str()?;
    let valid = match schema_version {
        Some("0.3.0") => is_absolute_posix_path(path) || is_absolute_windows_path(path),
        _ => is_absolute_posix_path(path),
    };
    (!valid).then(|| format!("{base}/qualifiers/path"))
}

fn is_absolute_posix_path(path: &str) -> bool {
    path.starts_with('/')
}

fn is_absolute_windows_path(path: &str) -> bool {
    is_windows_drive_absolute(path) || is_windows_unc_absolute(path)
}

fn is_windows_drive_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn is_windows_unc_absolute(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(r"\\").or_else(|| path.strip_prefix("//")) else {
        return false;
    };
    let mut parts = rest.split(['\\', '/']).filter(|part| !part.is_empty());
    parts.next().is_some() && parts.next().is_some()
}

fn aibom_filename(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
}

fn schema_failure(code: ErrorCode, pointer: impl Into<String>) -> ValidationFailure {
    failure(ValidationStage::SchemaValidation, code, pointer)
}

fn failure(
    stage: ValidationStage,
    code: ErrorCode,
    pointer: impl Into<String>,
) -> ValidationFailure {
    ValidationFailure {
        stage,
        code,
        pointer: pointer.into(),
    }
}

fn harness_failure(message: impl Into<String>) -> ValidationFailure {
    failure(
        ValidationStage::SchemaValidation,
        ErrorCode::SchemaGenericViolation,
        message.into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn fixture_set_matches_manifests() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let outcomes = validate_fixture_tree(
            repo.join("schema/fixtures/aibom-v0.1.0"),
            repo.join("schema/aibom-v0.1.0.json"),
        );
        let failures: Vec<_> = outcomes
            .iter()
            .filter(|outcome| !matches!(outcome.result, FixtureResult::Passed))
            .collect();
        assert!(failures.is_empty(), "fixture failures: {failures:#?}");
        assert_eq!(outcomes.len(), 41);
    }

    #[test]
    fn v0_2_0_fixture_set_matches_manifests() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let outcomes = validate_fixture_tree(
            repo.join("schema/fixtures/aibom-v0.2.0"),
            repo.join("schema/aibom-v0.2.0.json"),
        );
        let failures: Vec<_> = outcomes
            .iter()
            .filter(|outcome| !matches!(outcome.result, FixtureResult::Passed))
            .collect();
        assert!(
            failures.is_empty(),
            "v0.2.0 fixture failures: {failures:#?}"
        );
        assert_eq!(outcomes.len(), 2);
    }

    #[test]
    fn v0_3_0_fixture_set_matches_manifests() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let outcomes = validate_fixture_tree(
            repo.join("schema/fixtures/aibom-v0.3.0"),
            repo.join("schema/aibom-v0.3.0.json"),
        );
        let failures: Vec<_> = outcomes
            .iter()
            .filter(|outcome| !matches!(outcome.result, FixtureResult::Passed))
            .collect();
        assert!(
            failures.is_empty(),
            "v0.3.0 fixture failures: {failures:#?}"
        );
        assert_eq!(outcomes.len(), 3);
    }
}
