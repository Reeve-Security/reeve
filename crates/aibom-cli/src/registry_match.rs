//! Package-coordinate extraction and purl normalization for
//! `--registry-source` matching (issue #431, ADR-0046).
//!
//! Matching is purl-first: a component purl that exactly matches a
//! registry server's declared package coordinate is the strongest public
//! identity signal we have. This module never invents purls — only npm
//! and PyPI registry types have a defined purl derivation here; every
//! other registry type is reported as `unsupported-registry`.

use serde_json::Value;

/// Coordinate carries a registry-declared package with an explicit
/// purl-derivation status so consumers can distinguish "matched",
/// "cannot match yet", and "will never match via purl".
///
/// The non-purl fields are part of the coordinate contract even though
/// today's lookup only consumes `purl`; tests assert them directly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct Coordinate {
    pub registry_type: String,
    pub identifier: String,
    pub version: Option<String>,
    /// Normalized purl when derivable (npm/PyPI only).
    pub purl: Option<String>,
    /// One of `ok`, `no-version`, `unsupported-registry`,
    /// `invalid-coordinate`.
    pub purl_status: &'static str,
}

pub const PURL_STATUS_OK: &str = "ok";
pub const PURL_STATUS_NO_VERSION: &str = "no-version";
pub const PURL_STATUS_UNSUPPORTED_REGISTRY: &str = "unsupported-registry";
pub const PURL_STATUS_INVALID_COORDINATE: &str = "invalid-coordinate";

/// Normalizes a purl string into a canonical matching form:
/// lowercase scheme and type, percent-decoded then minimally re-encoded
/// path segments (so `pkg:npm/%40scope/name` == `pkg:npm/@scope/name`),
/// qualifiers and subpath stripped, version kept when present.
///
/// Returns `None` for inputs that are not parseable purls. Never invents
/// fields.
pub fn normalize_purl(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let scheme = trimmed.get(..4)?;
    if !scheme.eq_ignore_ascii_case("pkg:") {
        return None;
    }
    let rest = trimmed[4..].trim_start_matches('/');
    let rest = rest.split_once('#').map(|(head, _)| head).unwrap_or(rest);
    let rest = rest.split_once('?').map(|(head, _)| head).unwrap_or(rest);
    let (type_part, remainder) = rest.split_once('/')?;
    let purl_type = type_part.trim().to_ascii_lowercase();
    if purl_type.is_empty()
        || !purl_type
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '+'))
    {
        return None;
    }

    let (path_part, version_part) = split_version(remainder);
    let mut segments: Vec<String> = path_part
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_decode)
        .collect();
    if segments.is_empty() {
        return None;
    }
    match purl_type.as_str() {
        "npm" => {
            for segment in &mut segments {
                *segment = segment.to_ascii_lowercase();
            }
        }
        "pypi" => {
            for segment in &mut segments {
                *segment = segment.to_ascii_lowercase().replace('_', "-");
            }
        }
        _ => {}
    }
    if segments.last().is_none_or(|name| name.is_empty()) {
        return None;
    }

    let encoded: Vec<String> = segments.iter().map(|s| percent_encode(s)).collect();
    let mut normalized = format!("pkg:{}/{}", purl_type, encoded.join("/"));
    if let Some(version) = version_part {
        let decoded = percent_decode(version);
        if !decoded.is_empty() {
            normalized.push('@');
            normalized.push_str(&percent_encode(&decoded));
        }
    }
    Some(normalized)
}

/// Drops the trailing `@version` from a normalized purl, if present.
pub fn purl_without_version(purl: &str) -> String {
    let (path_part, _) = split_version(purl);
    path_part.to_string()
}

/// Splits `name[@version]` where the version separator is the last `@`
/// that appears after the last `/`. A leading `@` in the final segment
/// (npm scope without a name, malformed) is not treated as a version
/// separator.
fn split_version(value: &str) -> (&str, Option<&str>) {
    let segment_start = value.rfind('/').map(|index| index + 1).unwrap_or(0);
    match value[segment_start..].rfind('@') {
        Some(at) if at > 0 => {
            let split = segment_start + at;
            (&value[..split], Some(&value[split + 1..]))
        }
        _ => (value, None),
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (
                (bytes[index + 1] as char).to_digit(16),
                (bytes[index + 2] as char).to_digit(16),
            )
        {
            out.push((high * 16 + low) as u8);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Minimal re-encoding so canonical forms compare equal: encodes only
/// the characters that are structurally meaningful inside a purl
/// component (`%`, `@`, `/`, `?`, `#`) plus whitespace.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '@' => out.push_str("%40"),
            '/' => out.push_str("%2F"),
            '?' => out.push_str("%3F"),
            '#' => out.push_str("%23"),
            ' ' => out.push_str("%20"),
            _ => out.push(ch),
        }
    }
    out
}

/// Extracts package coordinates from a registry server fixture
/// (`servers/<publisher>/<name>.json` contract shape). Reads
/// `declaredMetadata.packages[]` from the selected latest version record
/// and derives purls for npm and PyPI registry types only.
pub fn package_coordinates_from_server(server: &Value) -> Vec<Coordinate> {
    let Some(record) = selected_version_record(server) else {
        return Vec::new();
    };
    let Some(packages) = record
        .pointer("/declaredMetadata/packages")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    let mut coordinates = Vec::new();
    for package in packages {
        let registry_type = package
            .get("registryType")
            .or_else(|| package.get("registry_type"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);
        let identifier = package
            .get("identifier")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let (Some(registry_type), Some(identifier)) = (registry_type, identifier) else {
            continue;
        };
        let version = package
            .get("version")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        coordinates.push(coordinate_from_parts(registry_type, identifier, version));
    }
    coordinates
}

fn coordinate_from_parts(
    registry_type: String,
    identifier: String,
    version: Option<String>,
) -> Coordinate {
    if !matches!(registry_type.as_str(), "npm" | "pypi") {
        return Coordinate {
            registry_type,
            identifier,
            version,
            purl: None,
            purl_status: PURL_STATUS_UNSUPPORTED_REGISTRY,
        };
    }
    let raw = match &version {
        Some(version) => format!("pkg:{registry_type}/{identifier}@{version}"),
        None => format!("pkg:{registry_type}/{identifier}"),
    };
    match normalize_purl(&raw) {
        Some(purl) => {
            let purl_status = if version.is_some() {
                PURL_STATUS_OK
            } else {
                PURL_STATUS_NO_VERSION
            };
            Coordinate {
                registry_type,
                identifier,
                version,
                purl: Some(purl),
                purl_status,
            }
        }
        None => Coordinate {
            registry_type,
            identifier,
            version,
            purl: None,
            purl_status: PURL_STATUS_INVALID_COORDINATE,
        },
    }
}

/// Mirrors the version-record selection used for hosted-endpoint
/// indexing: explicit `latestVersion` match first, then
/// `registryMetadata.isLatest`, then the first record.
fn selected_version_record(server: &Value) -> Option<&Value> {
    let versions = server.get("versions").and_then(Value::as_array)?;
    let latest_version = server.get("latestVersion").and_then(Value::as_str);
    versions
        .iter()
        .find(|record| {
            latest_version.is_some_and(|version| {
                record
                    .pointer("/canonicalIdentity/version")
                    .and_then(Value::as_str)
                    == Some(version)
            })
        })
        .or_else(|| {
            versions.iter().find(|record| {
                record
                    .pointer("/registryMetadata/isLatest")
                    .and_then(Value::as_bool)
                    == Some(true)
            })
        })
        .or_else(|| versions.first())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // launch-proof: #431
    #[test]
    fn normalize_purl_treats_encoded_and_raw_npm_scope_as_equal() {
        let encoded = normalize_purl("pkg:npm/%40scope/name@1.0.0");
        let raw = normalize_purl("pkg:npm/@scope/name@1.0.0");
        assert_eq!(encoded, raw);
        assert_eq!(encoded.as_deref(), Some("pkg:npm/%40scope/name@1.0.0"));
    }

    // launch-proof: #431
    #[test]
    fn normalize_purl_lowercases_scheme_type_and_npm_name() {
        assert_eq!(
            normalize_purl("PKG:NPM/%40Scope/Name@1.0.0").as_deref(),
            Some("pkg:npm/%40scope/name@1.0.0")
        );
    }

    // launch-proof: #431
    #[test]
    fn normalize_purl_strips_qualifiers_and_subpath_keeps_version() {
        assert_eq!(
            normalize_purl("pkg:npm/left-pad@1.2.3?os=linux&arch=x86#src/index.js").as_deref(),
            Some("pkg:npm/left-pad@1.2.3")
        );
        assert_eq!(
            normalize_purl("pkg:npm/left-pad").as_deref(),
            Some("pkg:npm/left-pad")
        );
    }

    // launch-proof: #431
    #[test]
    fn normalize_purl_normalizes_pypi_underscores_and_case() {
        assert_eq!(
            normalize_purl("pkg:pypi/Some_Package@2.31.0").as_deref(),
            Some("pkg:pypi/some-package@2.31.0")
        );
    }

    // launch-proof: #431
    #[test]
    fn normalize_purl_rejects_non_purl_input() {
        assert_eq!(normalize_purl("not-a-purl"), None);
        assert_eq!(normalize_purl("pkg:npm"), None);
        assert_eq!(normalize_purl("pkg:/name"), None);
        assert_eq!(normalize_purl(""), None);
    }

    // launch-proof: #431
    #[test]
    fn purl_without_version_strips_only_trailing_version() {
        assert_eq!(
            purl_without_version("pkg:npm/%40scope/name@1.0.0"),
            "pkg:npm/%40scope/name"
        );
        assert_eq!(
            purl_without_version("pkg:npm/%40scope/name"),
            "pkg:npm/%40scope/name"
        );
    }

    fn server_fixture(packages: Value) -> Value {
        json!({
            "publisher": "acme",
            "name": "demo",
            "latestVersion": "1.0.1",
            "versions": [{
                "canonicalIdentity": {
                    "name": "acme/demo",
                    "publisher": "acme",
                    "packageName": "demo",
                    "version": "1.0.1"
                },
                "declaredMetadata": { "packages": packages },
                "registryMetadata": { "status": "active", "isLatest": true }
            }]
        })
    }

    // launch-proof: #431
    #[test]
    fn package_coordinates_extracts_scoped_npm_purl() {
        let server = server_fixture(json!([
            { "registryType": "npm", "identifier": "@acme/demo-mcp", "version": "1.2.3" }
        ]));
        let coordinates = package_coordinates_from_server(&server);
        assert_eq!(coordinates.len(), 1);
        assert_eq!(
            coordinates[0].purl.as_deref(),
            Some("pkg:npm/%40acme/demo-mcp@1.2.3")
        );
        assert_eq!(coordinates[0].purl_status, PURL_STATUS_OK);
    }

    // launch-proof: #431
    #[test]
    fn package_coordinates_extracts_pypi_purl_and_multiple_packages() {
        let server = server_fixture(json!([
            { "registryType": "npm", "identifier": "left-pad", "version": "1.2.3" },
            { "registryType": "pypi", "identifier": "requests", "version": "2.31.0" }
        ]));
        let coordinates = package_coordinates_from_server(&server);
        assert_eq!(coordinates.len(), 2);
        assert_eq!(
            coordinates[0].purl.as_deref(),
            Some("pkg:npm/left-pad@1.2.3")
        );
        assert_eq!(
            coordinates[1].purl.as_deref(),
            Some("pkg:pypi/requests@2.31.0")
        );
    }

    // launch-proof: #431
    #[test]
    fn package_coordinates_marks_missing_version_and_keeps_versionless_purl() {
        let server = server_fixture(json!([
            { "registryType": "npm", "identifier": "@acme/demo-mcp" }
        ]));
        let coordinates = package_coordinates_from_server(&server);
        assert_eq!(coordinates.len(), 1);
        assert_eq!(coordinates[0].purl_status, PURL_STATUS_NO_VERSION);
        assert_eq!(
            coordinates[0].purl.as_deref(),
            Some("pkg:npm/%40acme/demo-mcp")
        );
    }

    // launch-proof: #431
    #[test]
    fn package_coordinates_marks_unsupported_registry_type_without_inventing_purls() {
        let server = server_fixture(json!([
            { "registryType": "oci", "identifier": "ghcr.io/acme/demo", "version": "1.0.0" }
        ]));
        let coordinates = package_coordinates_from_server(&server);
        assert_eq!(coordinates.len(), 1);
        assert_eq!(coordinates[0].purl_status, PURL_STATUS_UNSUPPORTED_REGISTRY);
        assert_eq!(coordinates[0].purl, None);
    }

    // launch-proof: #431
    #[test]
    fn package_coordinates_uses_latest_version_record() {
        let server = json!({
            "publisher": "acme",
            "name": "demo",
            "latestVersion": "2.0.0",
            "versions": [
                {
                    "canonicalIdentity": { "version": "1.0.0" },
                    "declaredMetadata": { "packages": [
                        { "registryType": "npm", "identifier": "old-package", "version": "1.0.0" }
                    ]},
                    "registryMetadata": { "isLatest": false }
                },
                {
                    "canonicalIdentity": { "version": "2.0.0" },
                    "declaredMetadata": { "packages": [
                        { "registryType": "npm", "identifier": "new-package", "version": "2.0.0" }
                    ]},
                    "registryMetadata": { "isLatest": true }
                }
            ]
        });
        let coordinates = package_coordinates_from_server(&server);
        assert_eq!(coordinates.len(), 1);
        assert_eq!(coordinates[0].identifier, "new-package");
    }
}
