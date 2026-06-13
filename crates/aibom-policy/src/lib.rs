use aibom_core::{PolicyStatus, PolicyVerdict};
use anyhow::{Context, Result};
use opa_wasm::{Runtime, wasmtime};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct PolicyConfig {
    pub profile: String,
    pub extension_allowlist: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_allowlist: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_scan_age_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_package_sources: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_package_versions: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive_data_max_file_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive_data_max_total_bytes: Option<u64>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            extension_allowlist: vec!["mcp".to_string()],
            publisher_allowlist: None,
            max_scan_age_seconds: None,
            policy_time: None,
            trusted_package_sources: None,
            minimum_package_versions: None,
            sensitive_data_max_file_count: None,
            sensitive_data_max_total_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SignatureFacts {
    pub present: bool,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PolicyInput<'a> {
    aibom: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    cyclonedx: Option<&'a Value>,
    signature: &'a SignatureFacts,
    config: &'a PolicyConfig,
}

#[derive(Debug, Clone, Serialize)]
struct SensitivePolicyInput<'a> {
    #[serde(rename = "sensitiveDataReport")]
    sensitive_data_report: &'a Value,
    config: &'a PolicyConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RawVerdict {
    id: String,
    #[serde(rename = "policyId")]
    policy_id: String,
    #[serde(rename = "bomRef")]
    bom_ref: Option<String>,
    status: String,
    justification: String,
    #[serde(default)]
    references: Vec<String>,
}

pub async fn evaluate(
    aibom_root: &Value,
    cyclonedx: Option<&Value>,
    signature: &SignatureFacts,
    config: &PolicyConfig,
) -> Result<Vec<PolicyVerdict>> {
    let aibom = aibom_root
        .get("aibom")
        .context("missing aibom root object")?;
    let input = PolicyInput {
        aibom,
        cyclonedx,
        signature,
        config,
    };
    evaluate_input(&input).await
}

pub async fn evaluate_sensitive_data_report(
    report_root: &Value,
    config: &PolicyConfig,
) -> Result<Vec<PolicyVerdict>> {
    let sensitive_data_report = report_root
        .get("sensitiveDataReport")
        .context("missing sensitiveDataReport root object")?;
    let input = SensitivePolicyInput {
        sensitive_data_report,
        config,
    };
    evaluate_input(&input).await
}

async fn evaluate_input<T: Serialize>(input: &T) -> Result<Vec<PolicyVerdict>> {
    let wasm_config = wasmtime::Config::new();
    let engine = wasmtime::Engine::new(&wasm_config)?;
    let module = wasmtime::Module::new(&engine, POLICY_WASM)?;
    let mut store = wasmtime::Store::new(&engine, ());
    let runtime = Runtime::new(&mut store, &module).await?;
    let data: Value =
        serde_json::from_str(POLICY_DATA).context("failed to parse compiled OPA data")?;
    let policy = runtime.with_data(&mut store, &data).await?;
    let raw: Value = policy
        .evaluate(&mut store, "reeve/policy/verdicts", &input)
        .await?;
    let raw_verdicts = decode_verdicts(raw)?;
    let mut verdicts: Vec<_> = raw_verdicts
        .into_iter()
        .map(|verdict| -> Result<PolicyVerdict> {
            Ok(PolicyVerdict {
                id: verdict.id,
                policy_id: verdict.policy_id,
                bom_ref: verdict.bom_ref,
                status: parse_status(&verdict.status)?,
                justification: verdict.justification,
                references: verdict.references,
                evidence: Vec::new(),
            })
        })
        .collect::<Result<_>>()?;
    dedupe_verdicts(&mut verdicts);
    sort_verdicts(&mut verdicts);
    Ok(verdicts)
}

fn dedupe_verdicts(verdicts: &mut Vec<PolicyVerdict>) {
    let mut deduped: BTreeMap<VerdictSemanticKey, PolicyVerdict> = BTreeMap::new();
    let mut passthrough = Vec::new();
    for verdict in std::mem::take(verdicts) {
        if verdict.policy_id != "risky-grant" {
            passthrough.push(verdict);
            continue;
        }
        let key = VerdictSemanticKey::from(&verdict);
        match deduped.get_mut(&key) {
            Some(existing) => merge_duplicate_verdict(existing, verdict),
            None => {
                deduped.insert(key, verdict);
            }
        }
    }
    verdicts.extend(passthrough);
    verdicts.extend(deduped.into_values());
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct VerdictSemanticKey {
    policy_id: String,
    rule_family: String,
    bom_ref: Option<String>,
    justification: String,
}

impl From<&PolicyVerdict> for VerdictSemanticKey {
    fn from(verdict: &PolicyVerdict) -> Self {
        Self {
            policy_id: verdict.policy_id.clone(),
            rule_family: verdict_rule_family(&verdict.id, &verdict.policy_id),
            bom_ref: verdict.bom_ref.clone(),
            justification: verdict.justification.clone(),
        }
    }
}

fn verdict_rule_family(id: &str, policy_id: &str) -> String {
    if let Some(rule_marker) = id.find("-rule-") {
        let rule_name_start = rule_marker + "-rule-".len();
        let rule_name_end = id[rule_name_start..]
            .find('-')
            .map(|offset| rule_name_start + offset)
            .unwrap_or(id.len());
        return id[..rule_name_end].to_string();
    }

    let mut family = id;
    while let Some((prefix, suffix)) = family.rsplit_once('-') {
        if suffix.chars().all(|ch| ch.is_ascii_digit()) {
            family = prefix;
        } else {
            break;
        }
    }

    if family.is_empty() {
        policy_id.to_string()
    } else {
        family.to_string()
    }
}

fn merge_duplicate_verdict(existing: &mut PolicyVerdict, verdict: PolicyVerdict) {
    if verdict.id < existing.id {
        existing.id = verdict.id;
    }
    extend_unique(&mut existing.references, verdict.references);
    extend_unique(&mut existing.evidence, verdict.evidence);
}

fn extend_unique(existing: &mut Vec<String>, incoming: Vec<String>) {
    for value in incoming {
        if !existing.contains(&value) {
            existing.push(value);
        }
    }
}

pub fn sort_verdicts(verdicts: &mut [PolicyVerdict]) {
    verdicts.sort_by(|left, right| {
        left.policy_id
            .cmp(&right.policy_id)
            .then_with(|| left.bom_ref.cmp(&right.bom_ref))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn parse_status(value: &str) -> Result<PolicyStatus> {
    Ok(match value {
        "allow" => PolicyStatus::Allow,
        "deny" => PolicyStatus::Deny,
        "warn" => PolicyStatus::Warn,
        _ => anyhow::bail!("unknown policy status {value}"),
    })
}

fn decode_verdicts(value: Value) -> Result<Vec<RawVerdict>> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    if let Ok(verdicts) = serde_json::from_value::<Vec<RawVerdict>>(value.clone()) {
        return Ok(verdicts);
    }
    if let Some(entries) = value.as_array() {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        if let Some(first) = entries[0].get("result") {
            return Ok(serde_json::from_value(first.clone())?);
        }
    }
    Err(anyhow::anyhow!("unexpected policy result shape: {value}"))
}

const POLICY_WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/policy.wasm"));
const POLICY_DATA: &str = include_str!(concat!(env!("OUT_DIR"), "/data.json"));
