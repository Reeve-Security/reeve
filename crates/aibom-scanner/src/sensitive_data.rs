use aibom_core::{Target, canonicalize_json, sha256_hex};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;

const SENSITIVE_DATA_SCHEMA_URL: &str =
    "https://aibom.example/schemas/sensitive-data-report-v0.1.0.json";
const SENSITIVE_DATA_SCHEMA_VERSION: &str = "0.1.0";
const SENSITIVE_DATA_CANONICALIZATION: &str =
    "RFC8785-JCS+reeve-sensitive-data-report-array-order-v0.1";
const DEFAULT_RULE_PACK_ID: &str = "reeve-default-conversation-secrets";
const DEFAULT_RULE_PACK_VERSION: &str = "2026.06.0";
const DEFAULT_RULE_PACK_CANONICAL: &str = "reeve-default-conversation-secrets@2026.06.0:anthropic-api-key,aws-access-key,jwt,oauth-client-secret,openai-api-key,private-key-pem,stripe-key";
const MIN_SECRET_BODY_ENTROPY: f64 = 2.5;
const KNOWN_PLACEHOLDER_SECRET_TOKENS: &[&str] =
    &["AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLEFAKE"];
const PLACEHOLDER_SECRET_MARKERS: &[&str] = &["example", "dummy", "placeholder", "fake"];

#[derive(Debug, Clone, Default)]
pub struct SensitiveDataScanOptions {
    pub scan_conversation_secrets: bool,
    pub suppressions_file: Option<PathBuf>,
    pub conversation_rules_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
struct ConversationRoot {
    surface: &'static str,
    relative_root: &'static str,
    redacted_root: &'static str,
    matcher: ConversationRootMatcher,
    gate: ConversationRootGate,
    file_filter: ConversationFileFilter,
}

#[derive(Debug, Clone, Copy)]
enum ConversationRootMatcher {
    Literal,
    Glob,
}

#[derive(Debug, Clone, Copy)]
enum ConversationRootGate {
    Always,
    CodexAppMarkerPresent,
    CodexAppMarkerAbsent,
}

#[derive(Debug, Clone, Copy)]
enum ConversationFileFilter {
    AllFiles,
    LevelDbLogsOnly,
}

#[derive(Debug, Clone)]
struct ResolvedConversationRoot {
    root: &'static ConversationRoot,
    path: PathBuf,
}

const CONVERSATION_ROOTS: &[ConversationRoot] = &[
    ConversationRoot {
        surface: "claude-desktop",
        relative_root: "Library/Application Support/Claude/projects",
        redacted_root: "~/Library/Application Support/Claude/projects/",
        matcher: ConversationRootMatcher::Literal,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "claude-desktop",
        relative_root: "AppData/Roaming/Claude/projects",
        redacted_root: "~/AppData/Roaming/Claude/projects/",
        matcher: ConversationRootMatcher::Literal,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "claude-code",
        relative_root: ".claude/projects",
        redacted_root: "~/.claude/projects/",
        matcher: ConversationRootMatcher::Literal,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "claude-code-desktop",
        relative_root: "Library/Application Support/Claude/claude-code-sessions/*/*",
        redacted_root: "~/Library/Application Support/Claude/claude-code-sessions/*/*/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "claude-code-desktop",
        relative_root: "AppData/Roaming/Claude/claude-code-sessions/*/*",
        redacted_root: "~/AppData/Roaming/Claude/claude-code-sessions/*/*/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "claude-code-desktop",
        relative_root: "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/claude-code-sessions/*/*",
        redacted_root: "~/AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/claude-code-sessions/*/*/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "claude-cowork",
        relative_root: "Library/Application Support/Claude/local-agent-mode-sessions/*/*",
        redacted_root: "~/Library/Application Support/Claude/local-agent-mode-sessions/*/*/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "claude-cowork",
        relative_root: "AppData/Roaming/Claude/local-agent-mode-sessions/*/*",
        redacted_root: "~/AppData/Roaming/Claude/local-agent-mode-sessions/*/*/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "claude-cowork",
        relative_root: "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*",
        redacted_root: "~/AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "claude-cowork",
        relative_root: "Library/Application Support/Claude/IndexedDB/*.leveldb",
        redacted_root: "~/Library/Application Support/Claude/IndexedDB/*.leveldb/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::LevelDbLogsOnly,
    },
    ConversationRoot {
        surface: "claude-cowork",
        relative_root: "AppData/Roaming/Claude/IndexedDB/*.leveldb",
        redacted_root: "~/AppData/Roaming/Claude/IndexedDB/*.leveldb/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::LevelDbLogsOnly,
    },
    ConversationRoot {
        surface: "claude-cowork",
        relative_root: "AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/IndexedDB/*.leveldb",
        redacted_root: "~/AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/IndexedDB/*.leveldb/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::LevelDbLogsOnly,
    },
    ConversationRoot {
        surface: "cursor",
        relative_root: ".cursor/projects/*/agent-transcripts/*",
        redacted_root: "~/.cursor/projects/*/agent-transcripts/*/",
        matcher: ConversationRootMatcher::Glob,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "codex-app",
        relative_root: "Library/Application Support/Codex/archived_sessions",
        redacted_root: "~/Library/Application Support/Codex/archived_sessions/",
        matcher: ConversationRootMatcher::Literal,
        gate: ConversationRootGate::Always,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "codex-app",
        relative_root: ".codex/sessions",
        redacted_root: "~/.codex/sessions/",
        matcher: ConversationRootMatcher::Literal,
        gate: ConversationRootGate::CodexAppMarkerPresent,
        file_filter: ConversationFileFilter::AllFiles,
    },
    ConversationRoot {
        surface: "codex-cli",
        relative_root: ".codex/sessions",
        redacted_root: "~/.codex/sessions/",
        matcher: ConversationRootMatcher::Literal,
        gate: ConversationRootGate::CodexAppMarkerAbsent,
        file_filter: ConversationFileFilter::AllFiles,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct SurfaceInventory {
    surface: &'static str,
    redacted_root: &'static str,
    file_count: u64,
    total_bytes: u64,
    oldest_modified: Option<DateTime<Utc>>,
    newest_modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PatternFinding {
    finding_id: String,
    surface: &'static str,
    redacted_path: String,
    size_bytes: u64,
    last_modified: DateTime<Utc>,
    pattern_class: String,
    rule_id: String,
    rule_pack_version: String,
    match_count: u64,
    confidence: String,
    suppressed: bool,
    suppression_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct BuiltInSecretRule {
    pattern_class: &'static str,
    rule_id: &'static str,
    confidence: &'static str,
    matcher: fn(&str) -> u64,
}

const DEFAULT_SECRET_RULES: &[BuiltInSecretRule] = &[
    BuiltInSecretRule {
        pattern_class: "anthropic-api-key",
        rule_id: "reeve.default.anthropic-api-key",
        confidence: "high",
        matcher: count_anthropic_keys,
    },
    BuiltInSecretRule {
        pattern_class: "aws-access-key",
        rule_id: "reeve.default.aws-access-key",
        confidence: "high",
        matcher: count_aws_access_keys,
    },
    BuiltInSecretRule {
        pattern_class: "jwt",
        rule_id: "reeve.default.jwt",
        confidence: "medium",
        matcher: count_jwts,
    },
    BuiltInSecretRule {
        pattern_class: "oauth-client-secret",
        rule_id: "reeve.default.oauth-client-secret",
        confidence: "medium",
        matcher: count_oauth_client_secrets,
    },
    BuiltInSecretRule {
        pattern_class: "openai-api-key",
        rule_id: "reeve.default.openai-api-key",
        confidence: "high",
        matcher: count_openai_keys,
    },
    BuiltInSecretRule {
        pattern_class: "private-key-pem",
        rule_id: "reeve.default.private-key-pem",
        confidence: "high",
        matcher: count_private_key_pem_blocks,
    },
    BuiltInSecretRule {
        pattern_class: "stripe-key",
        rule_id: "reeve.default.stripe-key",
        confidence: "high",
        matcher: count_stripe_keys,
    },
];

#[derive(Debug, Clone)]
struct CompiledSecretRule {
    pattern_class: String,
    rule_id: String,
    rule_pack_version: String,
    confidence: String,
    matcher: SecretRuleMatcher,
}

#[derive(Debug, Clone)]
enum SecretRuleMatcher {
    BuiltIn(fn(&str) -> u64),
    Regex(Regex),
}

impl CompiledSecretRule {
    fn count(&self, content: &str) -> u64 {
        match &self.matcher {
            SecretRuleMatcher::BuiltIn(matcher) => matcher(content),
            SecretRuleMatcher::Regex(regex) => regex.find_iter(content).count() as u64,
        }
    }
}

#[derive(Debug, Clone)]
struct CustomerRulePack {
    identity: CustomRulePackIdentity,
    rules: Vec<CompiledSecretRule>,
}

#[derive(Debug, Clone)]
struct CustomRulePackIdentity {
    id: String,
    version: String,
    digest: String,
    canonical_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct CustomerRulePackFile {
    #[serde(rename = "$schema")]
    _schema: Option<String>,
    rule_pack_id: String,
    rule_pack_version: String,
    rules: Vec<CustomerRuleSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct CustomerRuleSpec {
    rule_id: String,
    pattern_class: String,
    confidence: String,
    description: String,
    regex: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SuppressionsFile {
    #[serde(default)]
    suppressions: Vec<SuppressionSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct SuppressionSpec {
    id: String,
    #[serde(rename = "patternClass")]
    pattern_class: Option<String>,
    #[serde(rename = "pathContains")]
    path_contains: Option<String>,
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
    surface: Option<String>,
}

pub fn write_conversation_metadata_report(
    target: &Target,
    output_dir: &Path,
    scan_id: &str,
    timestamp: &str,
) -> Result<PathBuf> {
    write_sensitive_data_report(
        target,
        output_dir,
        scan_id,
        timestamp,
        &SensitiveDataScanOptions::default(),
    )
}

pub fn write_sensitive_data_report(
    target: &Target,
    output_dir: &Path,
    scan_id: &str,
    timestamp: &str,
    options: &SensitiveDataScanOptions,
) -> Result<PathBuf> {
    if options.conversation_rules_file.is_some() && !options.scan_conversation_secrets {
        bail!("conversation rules file requires scan_conversation_secrets=true");
    }
    let surfaces = inventory_conversation_metadata(&target.root)?;
    let suppressions = load_suppressions(options.suppressions_file.as_deref())?;
    let customer_rule_pack = if options.scan_conversation_secrets {
        load_customer_rule_pack(options.conversation_rules_file.as_deref())?
    } else {
        None
    };
    let rules = if options.scan_conversation_secrets {
        compile_secret_rules(customer_rule_pack.as_ref())
    } else {
        Vec::new()
    };
    let findings = if options.scan_conversation_secrets {
        scan_conversation_findings(&target.root, &rules, &suppressions)
            .with_context(|| format!("scan conversation secrets {}", target.root.display()))?
    } else {
        Vec::new()
    };
    let report_id = format!("sdr-{scan_id}");
    let filename = format!("{scan_id}.sensitive-data.json");
    let report = sensitive_data_report_value(SensitiveDataReportBuild {
        report_id: &report_id,
        scan_id,
        timestamp,
        target,
        surfaces: &surfaces,
        findings: &findings,
        options,
        customer_rule_pack: customer_rule_pack.as_ref(),
    })?;
    let bytes = canonicalize_json(&report)?;
    let path = output_dir.join(filename);
    fs::write(&path, bytes)?;
    Ok(path)
}

pub fn write_sensitive_data_sarif_report(
    report_path: &Path,
    output_dir: &Path,
    scan_id: &str,
) -> Result<PathBuf> {
    let bytes = fs::read(report_path)
        .with_context(|| format!("read sensitive-data report {}", report_path.display()))?;
    let report: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse sensitive-data report {}", report_path.display()))?;
    let sarif = sensitive_data_sarif_value(&report)?;
    let sarif_bytes = canonicalize_json(&sarif)?;
    let path = output_dir.join(format!("{scan_id}.sensitive-data.sarif.json"));
    fs::write(&path, sarif_bytes)?;
    Ok(path)
}

fn inventory_conversation_metadata(target_root: &Path) -> Result<Vec<SurfaceInventory>> {
    let mut by_root = BTreeMap::<(&'static str, &'static str), SurfaceInventory>::new();
    for resolved in resolved_conversation_roots(target_root)? {
        let inventory = inventory_root(&resolved.path, resolved.root).with_context(|| {
            format!(
                "inventory conversation metadata {}",
                resolved.path.display()
            )
        })?;
        if inventory.file_count == 0 {
            continue;
        }
        let key = (inventory.surface, inventory.redacted_root);
        by_root
            .entry(key)
            .and_modify(|current| merge_inventory(current, &inventory))
            .or_insert(inventory);
    }
    let mut inventories = by_root.into_values().collect::<Vec<_>>();
    inventories.sort_by(|a, b| {
        a.surface
            .cmp(b.surface)
            .then(a.redacted_root.cmp(b.redacted_root))
    });
    Ok(inventories)
}

fn inventory_root(path: &Path, root: &ConversationRoot) -> Result<SurfaceInventory> {
    let mut file_count = 0u64;
    let mut total_bytes = 0u64;
    let mut oldest_modified = None;
    let mut newest_modified = None;

    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        if !conversation_file_matches(entry.path(), root) {
            continue;
        }
        let metadata = entry.metadata()?;
        file_count += 1;
        total_bytes += metadata.len();
        if let Ok(modified) = metadata.modified() {
            let modified = DateTime::<Utc>::from(modified);
            oldest_modified = min_time(oldest_modified, modified);
            newest_modified = max_time(newest_modified, modified);
        }
    }

    Ok(SurfaceInventory {
        surface: root.surface,
        redacted_root: root.redacted_root,
        file_count,
        total_bytes,
        oldest_modified,
        newest_modified,
    })
}

fn merge_inventory(current: &mut SurfaceInventory, next: &SurfaceInventory) {
    current.file_count += next.file_count;
    current.total_bytes += next.total_bytes;
    current.oldest_modified = match (current.oldest_modified, next.oldest_modified) {
        (Some(current_time), Some(next_time)) => Some(current_time.min(next_time)),
        (None, Some(next_time)) => Some(next_time),
        (current_time, None) => current_time,
    };
    current.newest_modified = match (current.newest_modified, next.newest_modified) {
        (Some(current_time), Some(next_time)) => Some(current_time.max(next_time)),
        (None, Some(next_time)) => Some(next_time),
        (current_time, None) => current_time,
    };
}

fn scan_conversation_findings(
    target_root: &Path,
    rules: &[CompiledSecretRule],
    suppressions: &[SuppressionSpec],
) -> Result<Vec<PatternFinding>> {
    let mut findings = Vec::new();
    for resolved in resolved_conversation_roots(target_root)? {
        let root = resolved.root;
        let root_path = resolved.path;
        for entry in WalkDir::new(&root_path).follow_links(false) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            if !conversation_file_matches(entry.path(), root) {
                continue;
            }
            let metadata = entry.metadata()?;
            let bytes = fs::read(entry.path())?;
            let content = String::from_utf8_lossy(&bytes);
            let redacted_path = redacted_file_path(entry.path(), &root_path, root);
            let last_modified = metadata
                .modified()
                .map(DateTime::<Utc>::from)
                .unwrap_or_else(|_| DateTime::<Utc>::from(UNIX_EPOCH));

            for rule in rules {
                let match_count = rule.count(&content);
                if match_count == 0 {
                    continue;
                }
                let suppression = matching_suppression(
                    suppressions,
                    root.surface,
                    &redacted_path,
                    &rule.rule_id,
                    &rule.pattern_class,
                );
                findings.push(PatternFinding {
                    finding_id: String::new(),
                    surface: root.surface,
                    redacted_path: redacted_path.clone(),
                    size_bytes: metadata.len(),
                    last_modified,
                    pattern_class: rule.pattern_class.clone(),
                    rule_id: rule.rule_id.clone(),
                    rule_pack_version: rule.rule_pack_version.clone(),
                    match_count,
                    confidence: rule.confidence.clone(),
                    suppressed: suppression.is_some(),
                    suppression_id: suppression.map(|spec| spec.id.clone()),
                });
            }
        }
    }
    findings.sort_by(|a, b| {
        a.surface
            .cmp(b.surface)
            .then(a.redacted_path.cmp(&b.redacted_path))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    for (index, finding) in findings.iter_mut().enumerate() {
        finding.finding_id = format!("sdf-{index:04}");
    }
    Ok(findings)
}

fn conversation_file_matches(path: &Path, root: &ConversationRoot) -> bool {
    match root.file_filter {
        ConversationFileFilter::AllFiles => true,
        ConversationFileFilter::LevelDbLogsOnly => path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("log")),
    }
}

fn resolved_conversation_roots(target_root: &Path) -> Result<Vec<ResolvedConversationRoot>> {
    let mut resolved = Vec::new();
    for root in active_conversation_roots(target_root) {
        match root.matcher {
            ConversationRootMatcher::Literal => {
                let path = target_root.join(root.relative_root);
                if path.exists() {
                    resolved.push(ResolvedConversationRoot { root, path });
                }
            }
            ConversationRootMatcher::Glob => {
                let pattern = target_root.join(root.relative_root);
                for entry in glob::glob(&pattern.to_string_lossy())
                    .with_context(|| format!("resolve conversation root {}", pattern.display()))?
                {
                    let path = entry.with_context(|| {
                        format!("resolve conversation root {}", pattern.display())
                    })?;
                    if path.is_dir() {
                        resolved.push(ResolvedConversationRoot { root, path });
                    }
                }
            }
        }
    }
    resolved.sort_by(|a, b| {
        a.root
            .surface
            .cmp(b.root.surface)
            .then(a.root.redacted_root.cmp(b.root.redacted_root))
            .then(a.path.cmp(&b.path))
    });
    Ok(resolved)
}

fn active_conversation_roots(target_root: &Path) -> Vec<&'static ConversationRoot> {
    let codex_app_marker_present = codex_app_marker_present(target_root);
    CONVERSATION_ROOTS
        .iter()
        .filter(|root| match root.gate {
            ConversationRootGate::Always => true,
            ConversationRootGate::CodexAppMarkerPresent => codex_app_marker_present,
            ConversationRootGate::CodexAppMarkerAbsent => !codex_app_marker_present,
        })
        .collect()
}

fn codex_app_marker_present(target_root: &Path) -> bool {
    let path = target_root.join(".codex/config.toml");
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = content.parse::<toml::Value>() else {
        return false;
    };
    toml_table_present(&value, "plugins") || toml_table_present(&value, "marketplaces")
}

fn toml_table_present(value: &toml::Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(toml::Value::as_table)
        .is_some_and(|table| !table.is_empty())
}

fn load_suppressions(path: Option<&Path>) -> Result<Vec<SuppressionSpec>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let bytes = fs::read(path).with_context(|| format!("read suppressions {}", path.display()))?;
    let file: SuppressionsFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse suppressions {}", path.display()))?;
    Ok(file.suppressions)
}

fn load_customer_rule_pack(path: Option<&Path>) -> Result<Option<CustomerRulePack>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes =
        fs::read(path).with_context(|| format!("read conversation rules {}", path.display()))?;
    let file: CustomerRulePackFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse conversation rules {}", path.display()))?;
    validate_token("rulePackId", &file.rule_pack_id, 128)
        .with_context(|| format!("validate conversation rules {}", path.display()))?;
    validate_version_token("rulePackVersion", &file.rule_pack_version, 64)
        .with_context(|| format!("validate conversation rules {}", path.display()))?;
    ensure!(
        !file.rules.is_empty(),
        "conversation rules {} must include at least one rule",
        path.display()
    );
    ensure!(
        file.rules.len() <= 128,
        "conversation rules {} has too many rules; max 128",
        path.display()
    );

    let digest = sha256_hex(&bytes);
    let canonical_id = format!("{}@{}:{digest}", file.rule_pack_id, file.rule_pack_version);
    let mut seen_rule_ids = BTreeSet::new();
    let mut rules = Vec::with_capacity(file.rules.len());
    for (index, spec) in file.rules.into_iter().enumerate() {
        let context = format!(
            "validate conversation rules {} rules[{index}]",
            path.display()
        );
        validate_token("ruleId", &spec.rule_id, 192).with_context(|| context.clone())?;
        validate_token("patternClass", &spec.pattern_class, 128)
            .with_context(|| context.clone())?;
        validate_confidence(&spec.confidence).with_context(|| context.clone())?;
        ensure!(
            !spec.description.trim().is_empty(),
            "description must not be empty"
        );
        ensure!(
            spec.description.len() <= 512,
            "description too long; max 512 bytes"
        );
        ensure!(!spec.regex.trim().is_empty(), "regex must not be empty");
        ensure!(spec.regex.len() <= 4096, "regex too long; max 4096 bytes");
        ensure!(
            seen_rule_ids.insert(spec.rule_id.clone()),
            "duplicate ruleId {}",
            spec.rule_id
        );
        let matcher = RegexBuilder::new(&spec.regex)
            .size_limit(1_000_000)
            .build()
            .with_context(|| {
                format!(
                    "compile conversation rule regex {} in {} with Rust regex safe engine",
                    spec.rule_id,
                    path.display()
                )
            })?;
        rules.push(CompiledSecretRule {
            pattern_class: spec.pattern_class,
            rule_id: spec.rule_id,
            rule_pack_version: file.rule_pack_version.clone(),
            confidence: spec.confidence,
            matcher: SecretRuleMatcher::Regex(matcher),
        });
    }

    Ok(Some(CustomerRulePack {
        identity: CustomRulePackIdentity {
            id: file.rule_pack_id,
            version: file.rule_pack_version,
            digest,
            canonical_id,
        },
        rules,
    }))
}

fn compile_secret_rules(customer_rule_pack: Option<&CustomerRulePack>) -> Vec<CompiledSecretRule> {
    let mut rules = DEFAULT_SECRET_RULES
        .iter()
        .map(|rule| CompiledSecretRule {
            pattern_class: rule.pattern_class.to_string(),
            rule_id: rule.rule_id.to_string(),
            rule_pack_version: DEFAULT_RULE_PACK_VERSION.to_string(),
            confidence: rule.confidence.to_string(),
            matcher: SecretRuleMatcher::BuiltIn(rule.matcher),
        })
        .collect::<Vec<_>>();
    if let Some(pack) = customer_rule_pack {
        rules.extend(pack.rules.iter().cloned());
    }
    rules
}

fn validate_token(field: &str, value: &str, max_len: usize) -> Result<()> {
    ensure!(!value.is_empty(), "{field} must not be empty");
    ensure!(
        value.len() <= max_len,
        "{field} too long; max {max_len} bytes"
    );
    let mut chars = value.chars();
    let first = chars.next().expect("value is non-empty");
    ensure!(
        first.is_ascii_alphanumeric(),
        "{field} must start with ASCII letter or digit"
    );
    ensure!(
        chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-')),
        "{field} may contain only ASCII letters, digits, '.', '_', ':', '-'"
    );
    Ok(())
}

fn validate_version_token(field: &str, value: &str, max_len: usize) -> Result<()> {
    ensure!(!value.is_empty(), "{field} must not be empty");
    ensure!(
        value.len() <= max_len,
        "{field} too long; max {max_len} bytes"
    );
    let mut chars = value.chars();
    let first = chars.next().expect("value is non-empty");
    ensure!(
        first.is_ascii_alphanumeric(),
        "{field} must start with ASCII letter or digit"
    );
    ensure!(
        chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | '-')),
        "{field} may contain only ASCII letters, digits, '.', '_', '+', '-'"
    );
    Ok(())
}

fn validate_confidence(value: &str) -> Result<()> {
    match value {
        "low" | "medium" | "high" => Ok(()),
        _ => bail!("confidence must be one of low, medium, high"),
    }
}

fn matching_suppression<'a>(
    suppressions: &'a [SuppressionSpec],
    surface: &str,
    redacted_path: &str,
    rule_id: &str,
    pattern_class: &str,
) -> Option<&'a SuppressionSpec> {
    suppressions.iter().find(|spec| {
        spec.surface.as_deref().is_none_or(|value| value == surface)
            && spec.rule_id.as_deref().is_none_or(|value| value == rule_id)
            && spec
                .pattern_class
                .as_deref()
                .is_none_or(|value| value == pattern_class)
            && spec
                .path_contains
                .as_deref()
                .is_none_or(|value| redacted_path.contains(value))
    })
}

fn redacted_file_path(file: &Path, root_path: &Path, root: &ConversationRoot) -> String {
    let components: Vec<String> = file
        .strip_prefix(root_path)
        .ok()
        .into_iter()
        .flat_map(|relative| relative.components())
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    let joined = match components.as_slice() {
        [] => root.redacted_root.to_string(),
        [_single] => format!("{}<file-1>", root.redacted_root),
        [_redacted, rest @ ..] => format!("{}<segment-1>/{}", root.redacted_root, rest.join("/")),
    };
    // Interior segments can still carry home identity (nested home-rooted
    // paths or dash-encoded `.claude/projects` dirs) — redact them too (#468).
    crate::mcp::redact_home_identity(&joined)
}

fn min_time(current: Option<DateTime<Utc>>, candidate: DateTime<Utc>) -> Option<DateTime<Utc>> {
    Some(match current {
        Some(current) => current.min(candidate),
        None => candidate,
    })
}

fn max_time(current: Option<DateTime<Utc>>, candidate: DateTime<Utc>) -> Option<DateTime<Utc>> {
    Some(match current {
        Some(current) => current.max(candidate),
        None => candidate,
    })
}

struct SensitiveDataReportBuild<'a> {
    report_id: &'a str,
    scan_id: &'a str,
    timestamp: &'a str,
    target: &'a Target,
    surfaces: &'a [SurfaceInventory],
    findings: &'a [PatternFinding],
    options: &'a SensitiveDataScanOptions,
    customer_rule_pack: Option<&'a CustomerRulePack>,
}

fn sensitive_data_report_value(input: SensitiveDataReportBuild<'_>) -> Result<Value> {
    let options = input.options;
    let customer_rule_pack = input.customer_rule_pack;
    let suppressions = match options.suppressions_file.as_deref() {
        Some(path) => vec![file_identity("conversation-suppressions", path)?],
        None => Vec::new(),
    };
    let rule_packs = if options.scan_conversation_secrets {
        vec![json!({
            "digest": {
                "alg": "SHA-256",
                "content": sha256_hex(DEFAULT_RULE_PACK_CANONICAL.as_bytes())
            },
            "id": DEFAULT_RULE_PACK_ID,
            "version": DEFAULT_RULE_PACK_VERSION
        })]
    } else {
        Vec::new()
    };
    let custom_rules = match customer_rule_pack {
        Some(pack) => vec![custom_rule_pack_identity_value(&pack.identity)],
        None => Vec::new(),
    };
    Ok(json!({
        "$schema": SENSITIVE_DATA_SCHEMA_URL,
        "sensitiveDataReport": {
            "canonicalization": SENSITIVE_DATA_CANONICALIZATION,
            "findings": input.findings.iter().map(finding_value).collect::<Vec<_>>(),
            "inputs": {
                "contentPatternScan": options.scan_conversation_secrets,
                "customRules": custom_rules,
                "metadataInventory": true,
                "rulePacks": rule_packs,
                "scannerVersion": env!("CARGO_PKG_VERSION"),
                "suppressions": suppressions
            },
            "redaction": {
                "mode": "default-redacted",
                "pathStrategy": "user-controlled-segments",
                "segmentsRedacted": ["username", "project", "repository", "session", "directory"]
            },
            "reportId": input.report_id,
            "scan": {
                "scanId": input.scan_id,
                "scanner": {"name": "reeve", "version": env!("CARGO_PKG_VERSION")},
                // Redact home identity like the AIBOM target description (#468).
                "target": {"description": crate::mcp::redact_home_identity(&input.target.description), "kind": "filesystem"},
                "timestamp": input.timestamp
            },
            "schemaVersion": SENSITIVE_DATA_SCHEMA_VERSION,
            "surfaces": input.surfaces.iter().map(surface_value).collect::<Vec<_>>()
        }
    }))
}

fn surface_value(surface: &SurfaceInventory) -> Value {
    let mut value = json!({
        "fileCount": surface.file_count,
        "redactedRoot": surface.redacted_root,
        "surface": surface.surface,
        "totalBytes": surface.total_bytes
    });
    if let Some(oldest) = surface.oldest_modified {
        value["oldestModified"] = json!(format_time(oldest));
    }
    if let Some(newest) = surface.newest_modified {
        value["newestModified"] = json!(format_time(newest));
    }
    value
}

fn finding_value(finding: &PatternFinding) -> Value {
    let mut value = json!({
        "confidence": &finding.confidence,
        "evidence": {
            "id": format!("ev-{}", finding.finding_id),
            "sourceRef": format!("conversation-session://{}/{}", finding.surface, finding.redacted_path)
        },
        "file": {
            "lastModified": format_time(finding.last_modified),
            "redactedPath": &finding.redacted_path,
            "sizeBytes": finding.size_bytes
        },
        "findingId": &finding.finding_id,
        "humanReviewRequired": true,
        "matchCount": finding.match_count,
        "patternClass": &finding.pattern_class,
        "ruleId": &finding.rule_id,
        "rulePackVersion": &finding.rule_pack_version,
        "surface": finding.surface
    });
    if finding.suppressed {
        value["suppressed"] = json!(true);
        if let Some(id) = &finding.suppression_id {
            value["suppressionId"] = json!(id);
        }
    }
    value
}

fn custom_rule_pack_identity_value(identity: &CustomRulePackIdentity) -> Value {
    json!({
        "canonicalId": &identity.canonical_id,
        "digest": {"alg": "SHA-256", "content": &identity.digest},
        "id": &identity.id,
        "version": &identity.version
    })
}

fn sensitive_data_sarif_value(report: &Value) -> Result<Value> {
    let sensitive_report = report
        .get("sensitiveDataReport")
        .context("SARIF source missing sensitiveDataReport")?;
    let findings = sensitive_report
        .get("findings")
        .and_then(Value::as_array)
        .context("SARIF source missing sensitiveDataReport.findings array")?;

    let mut rule_indices = BTreeMap::<String, usize>::new();
    let mut rules = Vec::new();
    for finding in findings {
        let rule_id = finding_str(finding, "ruleId", "reeve.sensitive-data.unknown");
        if !rule_indices.contains_key(rule_id) {
            let index = rules.len();
            rule_indices.insert(rule_id.to_string(), index);
            rules.push(sarif_rule_value(finding));
        }
    }

    let results = findings
        .iter()
        .map(|finding| sarif_result_value(finding, &rule_indices))
        .collect::<Vec<_>>();
    let scan = sensitive_report.get("scan").unwrap_or(&Value::Null);
    let scanner_version = scan
        .pointer("/scanner/version")
        .and_then(Value::as_str)
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let mut run = json!({
        "automationDetails": {
            "id": scan.get("scanId").and_then(Value::as_str).unwrap_or("unknown")
        },
        "results": results,
        "tool": {
            "driver": {
                "informationUri": "https://github.com/Reeve-Security/reeve",
                "name": "Reeve sensitive-data scanner",
                "rules": rules,
                "semanticVersion": scanner_version
            }
        }
    });
    run["properties"] = json!({
        "redaction": sensitive_report.get("redaction").cloned().unwrap_or(Value::Null),
        "reportId": sensitive_report.get("reportId").cloned().unwrap_or(Value::Null),
        "scanId": scan.get("scanId").cloned().unwrap_or(Value::Null),
        "summary": {
            "findings": findings.len(),
            "suppressedFindings": findings
                .iter()
                .filter(|finding| finding.get("suppressed").and_then(Value::as_bool) == Some(true))
                .count()
        }
    });

    Ok(json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run]
    }))
}

fn sarif_rule_value(finding: &Value) -> Value {
    let rule_id = finding_str(finding, "ruleId", "reeve.sensitive-data.unknown");
    let pattern_class = finding_str(finding, "patternClass", "unknown");
    let confidence = finding_str(finding, "confidence", "unknown");
    json!({
        "id": rule_id,
        "name": pattern_class,
        "shortDescription": {
            "text": format!("Sensitive-data pattern: {pattern_class}")
        },
        "fullDescription": {
            "text": "Privacy-preserving sensitive-data finding. Reeve omits raw content, raw secret values, surrounding text, and secret hashes."
        },
        "defaultConfiguration": {
            "level": "warning"
        },
        "help": {
            "text": "Human review is required. Confirm whether the credential or token is real, then rotate or revoke it outside Reeve if confirmed."
        },
        "properties": {
            "category": "sensitive-data",
            "confidence": confidence,
            "precision": confidence
        }
    })
}

fn sarif_result_value(finding: &Value, rule_indices: &BTreeMap<String, usize>) -> Value {
    let rule_id = finding_str(finding, "ruleId", "reeve.sensitive-data.unknown");
    let pattern_class = finding_str(finding, "patternClass", "unknown");
    let confidence = finding_str(finding, "confidence", "unknown");
    let match_count = finding
        .get("matchCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let redacted_path = finding
        .pointer("/file/redactedPath")
        .and_then(Value::as_str)
        .unwrap_or("<redacted>");
    let suppressed = finding.get("suppressed").and_then(Value::as_bool) == Some(true);
    let level = if suppressed { "note" } else { "warning" };
    let mut result = json!({
        "level": level,
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": redacted_path
                }
            }
        }],
        "message": {
            "text": format!(
                "Human review required: {pattern_class} matched {match_count} time(s) with {confidence} confidence. Reeve omitted raw content, raw secret values, surrounding text, and secret hashes."
            )
        },
        "properties": {
            "confidence": confidence,
            "findingId": finding_str(finding, "findingId", "unknown"),
            "humanReviewRequired": true,
            "lastModified": finding.pointer("/file/lastModified").cloned().unwrap_or(Value::Null),
            "matchCount": match_count,
            "patternClass": pattern_class,
            "redacted": true,
            "severity": level,
            "sizeBytes": finding.pointer("/file/sizeBytes").cloned().unwrap_or(Value::Null),
            "surface": finding_str(finding, "surface", "unknown")
        },
        "ruleId": rule_id,
        "ruleIndex": rule_indices.get(rule_id).copied().unwrap_or(0)
    });
    if suppressed {
        let suppression_id = finding_str(finding, "suppressionId", "external-suppression");
        result["baselineState"] = json!("unchanged");
        result["suppressions"] = json!([{
            "justification": format!("Suppressed by {suppression_id}"),
            "kind": "external",
            "status": "accepted"
        }]);
        result["properties"]["suppressed"] = json!(true);
        result["properties"]["suppressionId"] = json!(suppression_id);
    }
    result
}

fn finding_str<'a>(finding: &'a Value, key: &str, fallback: &'a str) -> &'a str {
    finding.get(key).and_then(Value::as_str).unwrap_or(fallback)
}

fn file_identity(id: &str, path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read identity file {}", path.display()))?;
    Ok(json!({
        "digest": {"alg": "SHA-256", "content": sha256_hex(&bytes)},
        "id": id
    }))
}

fn candidate_tokens(content: &str) -> impl Iterator<Item = &str> {
    content
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
        .filter(|token| !token.is_empty())
}

fn count_anthropic_keys(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| {
            token.starts_with("sk-ant-")
                && token.len() >= 24
                && has_plausible_secret_body(token, &["sk-ant-api03-", "sk-ant-"])
        })
        .count() as u64
}

fn count_aws_access_keys(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| {
            token.len() == 20
                && token.starts_with("AKIA")
                && token
                    .chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
                && has_plausible_secret_body(token, &["AKIA"])
        })
        .count() as u64
}

fn count_jwts(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| {
            token.starts_with("eyJ")
                && token.matches('.').count() == 2
                && token
                    .split('.')
                    .all(|segment| segment.len() >= 10 && segment.chars().all(is_base64url_char))
        })
        .count() as u64
}

fn count_oauth_client_secrets(content: &str) -> u64 {
    content
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            (lower.contains("client_secret")
                || (lower.contains("oauth") && lower.contains("secret")))
                && candidate_tokens(line).any(|token| {
                    token.len() >= 16
                        && token
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
                })
        })
        .count() as u64
}

fn count_openai_keys(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| {
            (token.starts_with("sk-proj-") || token.starts_with("sk-"))
                && token.len() >= 24
                && !token.starts_with("sk-ant-")
                && !token.starts_with("sk_live_")
                && !token.starts_with("sk_test_")
                && has_plausible_secret_body(token, &["sk-proj-", "sk-"])
        })
        .count() as u64
}

fn count_private_key_pem_blocks(content: &str) -> u64 {
    static PRIVATE_KEY_PEM: OnceLock<Regex> = OnceLock::new();
    let regex = PRIVATE_KEY_PEM.get_or_init(|| {
        RegexBuilder::new(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        )
        .size_limit(1_000_000)
        .build()
        .expect("built-in private-key PEM regex compiles")
    });
    regex.find_iter(content).count() as u64
}

fn count_stripe_keys(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| {
            (token.starts_with("sk_live_") || token.starts_with("sk_test_"))
                && token.len() >= 24
                && has_plausible_secret_body(token, &["sk_live_", "sk_test_"])
        })
        .count() as u64
}

fn has_plausible_secret_body(token: &str, prefixes: &[&str]) -> bool {
    if is_placeholder_secret_token(token) {
        return false;
    }
    let body = prefixes
        .iter()
        .find_map(|prefix| token.strip_prefix(prefix))
        .unwrap_or(token);
    let normalized: String = body
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect();
    normalized.len() >= 8
        && !has_low_secret_entropy(&normalized)
        && shannon_entropy_bits_per_char(&normalized) >= MIN_SECRET_BODY_ENTROPY
}

fn is_placeholder_secret_token(token: &str) -> bool {
    if KNOWN_PLACEHOLDER_SECRET_TOKENS
        .iter()
        .any(|known| token.eq_ignore_ascii_case(known))
    {
        return true;
    }
    let lower = token.to_ascii_lowercase();
    PLACEHOLDER_SECRET_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
        || lower.contains("abcdefghijklmnopqrstuvwxyz")
        || lower.contains("0123456789")
}

fn has_low_secret_entropy(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    if chars.all(|ch| ch == first) {
        return true;
    }
    let unique = value.chars().collect::<BTreeSet<_>>().len();
    unique <= 4 || has_repeated_char_run(value, 8) || has_ascending_ascii_run(value, 8)
}

fn has_repeated_char_run(value: &str, min_run: usize) -> bool {
    let mut previous = None;
    let mut run = 0usize;
    for ch in value.chars() {
        if Some(ch) == previous {
            run += 1;
        } else {
            previous = Some(ch);
            run = 1;
        }
        if run >= min_run {
            return true;
        }
    }
    false
}

fn has_ascending_ascii_run(value: &str, min_run: usize) -> bool {
    let lower = value.to_ascii_lowercase();
    let mut previous = None;
    let mut run = 0usize;
    for byte in lower.bytes() {
        if previous.is_some_and(|prev| byte == prev + 1) {
            run += 1;
        } else {
            run = 1;
        }
        previous = Some(byte);
        if run >= min_run {
            return true;
        }
    }
    false
}

fn shannon_entropy_bits_per_char(value: &str) -> f64 {
    let len = value.len();
    if len == 0 {
        return 0.0;
    }
    let mut counts = BTreeMap::<u8, usize>::new();
    for byte in value.bytes() {
        *counts.entry(byte).or_default() += 1;
    }
    let len = len as f64;
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn is_base64url_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')
}

fn format_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeSet;
    use tempfile::tempdir;

    // launch-proof: #331 Conversation metadata opt-in
    // launch-proof: #361 Conversation scan Claude Code - macOS
    // launch-proof: #362 Conversation scan Claude Code - Windows
    // launch-proof: #363 Conversation scan Claude Code - Linux
    #[test]
    fn inventories_initial_conversation_surfaces_without_file_content() {
        let root = tempdir().unwrap();
        write_fixture(
            root.path(),
            "Library/Application Support/Claude/projects/SecretProject/session.jsonl",
            "raw secret-like content must never serialize",
        );
        write_fixture(
            root.path(),
            "AppData/Roaming/Claude/projects/WindowsSecretProject/session.jsonl",
            "windows raw secret-like content must never serialize",
        );
        write_fixture(
            root.path(),
            ".claude/projects/AcquisitionCodename/transcript.jsonl",
            "more content",
        );
        write_fixture(
            root.path(),
            ".codex/sessions/2026/rollout.jsonl",
            "codex session content",
        );

        let inventory = inventory_conversation_metadata(root.path()).unwrap();
        assert_eq!(inventory.len(), 4);

        let surfaces: Vec<_> = inventory.iter().map(|item| item.surface).collect();
        assert_eq!(
            surfaces,
            vec![
                "claude-code",
                "claude-desktop",
                "claude-desktop",
                "codex-cli"
            ]
        );
        assert!(inventory.iter().all(|item| item.file_count == 1));
        assert!(
            inventory
                .iter()
                .any(|item| item.redacted_root == "~/AppData/Roaming/Claude/projects/")
        );
        assert!(
            inventory
                .iter()
                .all(|item| !item.redacted_root.contains("SecretProject"))
        );
        assert!(
            inventory
                .iter()
                .all(|item| !item.redacted_root.contains("WindowsSecretProject"))
        );
        assert!(
            inventory
                .iter()
                .all(|item| !item.redacted_root.contains("AcquisitionCodename"))
        );
    }

    // launch-proof: #428 Conversation scan Codex App - macOS
    // launch-proof: #429 Conversation scan Codex App - Windows
    #[test]
    fn codex_app_conversation_roots_are_redacted_and_not_double_counted() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let aws_key = fixture_aws_access_key();
        write_fixture(
            root.path(),
            ".codex/config.toml",
            r#"
[marketplaces.default]
source_type = "registry"
source = "https://example.invalid"

[plugins."reviewer@default"]
enabled = true
"#,
        );
        write_fixture(
            root.path(),
            "Library/Application Support/Codex/archived_sessions/SecretMacSession/session.jsonl",
            &aws_key,
        );
        write_fixture(
            root.path(),
            ".codex/sessions/SecretWinSession/run-2026-06-05.jsonl",
            &aws_key,
        );

        let inventory = inventory_conversation_metadata(root.path()).unwrap();
        let codex_inventory = inventory
            .iter()
            .filter(|item| item.surface.starts_with("codex"))
            .collect::<Vec<_>>();
        assert_eq!(codex_inventory.len(), 2);
        assert!(
            codex_inventory
                .iter()
                .all(|item| item.surface == "codex-app")
        );
        assert!(
            codex_inventory.iter().any(|item| item.redacted_root
                == "~/Library/Application Support/Codex/archived_sessions/")
        );
        assert!(
            codex_inventory
                .iter()
                .any(|item| item.redacted_root == "~/.codex/sessions/")
        );

        let target = Target::filesystem(root.path().to_path_buf());
        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-06-05T10:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let findings = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap();

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding["surface"].as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["codex-app"])
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding["patternClass"] == "aws-access-key")
        );
        assert!(!report_text.contains(&aws_key));
        assert!(!report_text.contains("SecretMacSession"));
        assert!(!report_text.contains("SecretWinSession"));
        assert!(!report_text.contains("codex-cli"));
    }

    // launch-proof: #422 Conversation scan Claude Cowork - macOS
    // launch-proof: #423 Conversation scan Claude Cowork - Windows
    #[test]
    fn cowork_conversation_roots_are_redacted_and_aggregated() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let aws_key = fixture_aws_access_key();
        write_fixture(
            root.path(),
            "Library/Application Support/Claude/local-agent-mode-sessions/SecretOrg/SecretSession/messages.jsonl",
            &aws_key,
        );
        write_fixture(
            root.path(),
            "AppData/Roaming/Claude/local-agent-mode-sessions/WindowsOrg/WindowsSession/history.jsonl",
            &aws_key,
        );
        write_fixture(
            root.path(),
            "AppData/Local/Packages/Claude_abcdef/LocalCache/Roaming/Claude/local-agent-mode-sessions/PackageOrg/PackageSession/chat.jsonl",
            &aws_key,
        );
        write_fixture(
            root.path(),
            "AppData/Local/Packages/Claude_preview/LocalCache/Roaming/Claude/local-agent-mode-sessions/PackageOrgTwo/PackageSessionTwo/chat.jsonl",
            &aws_key,
        );

        let inventory = inventory_conversation_metadata(root.path()).unwrap();
        let cowork_inventory = inventory
            .iter()
            .filter(|item| item.surface == "claude-cowork")
            .collect::<Vec<_>>();
        assert_eq!(cowork_inventory.len(), 3);
        assert!(cowork_inventory.iter().any(|item| item.redacted_root
            == "~/Library/Application Support/Claude/local-agent-mode-sessions/*/*/"));
        assert!(
            cowork_inventory.iter().any(|item| item.redacted_root
                == "~/AppData/Roaming/Claude/local-agent-mode-sessions/*/*/")
        );
        assert!(cowork_inventory.iter().any(|item| {
            item.redacted_root
                == "~/AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/"
                && item.file_count == 2
        }));

        let target = Target::filesystem(root.path().to_path_buf());
        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-06-05T16:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let findings = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap();

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding["surface"].as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["claude-cowork"])
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding["patternClass"] == "aws-access-key")
        );
        assert!(report_text.contains(
            "~/Library/Application Support/Claude/local-agent-mode-sessions/*/*/<file-1>"
        ));
        assert!(report_text.contains(
            "~/AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/<file-1>"
        ));
        assert!(!report_text.contains(&aws_key));
        assert!(!report_text.contains("SecretOrg"));
        assert!(!report_text.contains("SecretSession"));
        assert!(!report_text.contains("WindowsOrg"));
        assert!(!report_text.contains("WindowsSession"));
        assert!(!report_text.contains("PackageOrg"));
        assert!(!report_text.contains("PackageSession"));
        assert!(!report_text.contains("Claude_abcdef"));
        assert!(!report_text.contains("Claude_preview"));
    }

    // launch-proof: #444 Claude Code desktop session surface
    #[test]
    fn claude_code_desktop_conversation_roots_are_redacted() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let aws_key = fixture_aws_access_key();
        write_fixture(
            root.path(),
            "Library/Application Support/Claude/claude-code-sessions/SecretOrg/SecretSession/local_123.json",
            &aws_key,
        );

        let target = Target::filesystem(root.path().to_path_buf());
        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-06-08T11:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let findings = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap();

        assert!(findings.iter().any(|finding| {
            finding["surface"] == "claude-code-desktop"
                && finding["patternClass"] == "aws-access-key"
                && finding["file"]["redactedPath"]
                    == "~/Library/Application Support/Claude/claude-code-sessions/*/*/<file-1>"
        }));
        assert!(!report_text.contains(&aws_key));
        assert!(!report_text.contains("SecretOrg"));
        assert!(!report_text.contains("SecretSession"));
    }

    // launch-proof: #448 Cowork IndexedDB LevelDB .log secret scan
    #[test]
    fn cowork_indexeddb_leveldb_log_files_are_scanned_but_ldb_files_are_not() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let log_key = fixture_aws_access_key();
        let ignored_ldb_key = "AKIA7Q4M2Z9X8C5N1P4S";
        write_fixture(
            root.path(),
            "AppData/Local/Packages/Claude_abcdef/LocalCache/Roaming/Claude/IndexedDB/https_claude.ai_0.indexeddb.leveldb/000003.log",
            &format!("leveldb wal plaintext {log_key}"),
        );
        write_fixture(
            root.path(),
            "AppData/Local/Packages/Claude_abcdef/LocalCache/Roaming/Claude/IndexedDB/https_claude.ai_0.indexeddb.leveldb/000004.ldb",
            ignored_ldb_key,
        );

        let target = Target::filesystem(root.path().to_path_buf());
        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-06-08T12:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let surfaces = report["sensitiveDataReport"]["surfaces"]
            .as_array()
            .unwrap();
        let findings = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap();

        assert!(surfaces.iter().any(|surface| {
            surface["surface"] == "claude-cowork"
                && surface["redactedRoot"]
                    == "~/AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/IndexedDB/*.leveldb/"
                && surface["fileCount"] == 1
        }));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["patternClass"], "aws-access-key");
        assert_eq!(
            findings[0]["file"]["redactedPath"],
            "~/AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/IndexedDB/*.leveldb/<file-1>"
        );
        assert!(!report_text.contains(&log_key));
        assert!(!report_text.contains(ignored_ldb_key));
        assert!(!report_text.contains("Claude_abcdef"));
        assert!(!report_text.contains("000003.log"));
        assert!(!report_text.contains("000004.ldb"));
    }

    // launch-proof: #448 Private-key PEM redaction integrity
    #[test]
    fn private_key_pem_blocks_emit_redacted_findings_without_key_body() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACCfixturebodymustneverappear9X8C5N1P3RabcDEF0123456789\n-----END OPENSSH PRIVATE KEY-----";
        write_fixture(
            root.path(),
            ".claude/projects/PrivateKeyProject/transcript.jsonl",
            pem,
        );

        let target = Target::filesystem(root.path().to_path_buf());
        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-06-08T12:30:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let findings = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap();

        assert!(findings.iter().any(|finding| {
            finding["patternClass"] == "private-key-pem"
                && finding["ruleId"] == "reeve.default.private-key-pem"
                && finding["matchCount"] == 1
        }));
        assert!(!report_text.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!report_text.contains("fixturebodymustneverappear"));
        assert!(!report_text.contains("END OPENSSH PRIVATE KEY"));
        assert!(!report_text.contains("PrivateKeyProject"));
    }

    // launch-proof: #468
    #[test]
    fn report_target_description_and_nested_encoded_paths_redact_home_identity() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        // Home-like target root + a conversation file under a dash-encoded
        // claude-projects dir nested inside a session store (the Windows rc.2
        // leak shape: `.claude/projects/C--Users-<name>-...`).
        let home = root.path().join("Users").join("alice");
        write_fixture(
            &home,
            ".claude/projects/C--Users-alice-AppData-Roaming/transcript.jsonl",
            &fixture_aws_access_key(),
        );

        let target = Target::filesystem(home.clone());
        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-06-12T09:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        assert!(
            !report_text.contains("alice"),
            "sensitive-data report leaked the home username: {report_text}"
        );
        let description = report["sensitiveDataReport"]["scan"]["target"]["description"]
            .as_str()
            .unwrap();
        assert!(
            description.contains("<redacted-home>"),
            "target description should redact the home segment: {description}"
        );
    }

    // launch-proof: #367 Conversation scan Cursor - macOS
    // launch-proof: #368 Conversation scan Cursor - Windows
    #[test]
    fn cursor_conversation_roots_are_redacted_and_aggregated() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let aws_key = fixture_aws_access_key();
        write_fixture(
            root.path(),
            ".cursor/projects/SecretProject/agent-transcripts/SecretSession/SecretSession.jsonl",
            &aws_key,
        );
        write_fixture(
            root.path(),
            ".cursor/projects/OtherSecretProject/agent-transcripts/OtherSecretSession/OtherSecretSession.jsonl",
            &aws_key,
        );

        let inventory = inventory_conversation_metadata(root.path()).unwrap();
        let cursor_inventory = inventory
            .iter()
            .find(|item| {
                item.surface == "cursor"
                    && item.redacted_root == "~/.cursor/projects/*/agent-transcripts/*/"
            })
            .expect("Cursor conversation inventory");
        assert_eq!(cursor_inventory.file_count, 2);

        let target = Target::filesystem(root.path().to_path_buf());
        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-06-05T17:30:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let findings = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap();

        assert_eq!(findings.len(), 2);
        assert!(
            findings.iter().all(|finding| {
                finding["surface"] == "cursor"
                    && finding["patternClass"] == "aws-access-key"
                    && finding["file"]["redactedPath"]
                        == "~/.cursor/projects/*/agent-transcripts/*/<file-1>"
            }),
            "Cursor transcript findings must stay redacted: {findings:?}"
        );
        assert!(!report_text.contains(&aws_key));
        assert!(!report_text.contains("SecretProject"));
        assert!(!report_text.contains("SecretSession"));
        assert!(!report_text.contains("OtherSecretProject"));
        assert!(!report_text.contains("OtherSecretSession"));
    }

    #[test]
    fn opt_in_report_contains_metadata_only() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        write_fixture(
            root.path(),
            ".claude/projects/AcquisitionCodename/transcript.jsonl",
            "AKIAIOSFODNN7EXAMPLE must not appear in report",
        );
        let target = Target::filesystem(root.path().to_path_buf());

        let path = write_conversation_metadata_report(
            &target,
            out.path(),
            "scan-test",
            "2026-05-11T10:00:00Z",
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();

        assert_eq!(
            report.pointer("/sensitiveDataReport/inputs/metadataInventory"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            report.pointer("/sensitiveDataReport/inputs/contentPatternScan"),
            Some(&Value::Bool(false))
        );
        assert!(
            report
                .pointer("/sensitiveDataReport/findings")
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(!report_text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!report_text.contains("AcquisitionCodename"));
    }

    // launch-proof: #361 Conversation scan Claude Code - macOS
    // launch-proof: #362 Conversation scan Claude Code - Windows
    // launch-proof: #363 Conversation scan Claude Code - Linux
    #[test]
    fn second_opt_in_emits_pattern_findings_without_raw_values() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let aws_key = fixture_aws_access_key();
        let anthropic_key = fixture_anthropic_key();
        let openai_key = fixture_openai_key();
        let stripe_key = fixture_stripe_key();
        let jwt = [
            "eyJhbGciOiJIUzI1NiJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
            "signature__",
        ]
        .concat();
        write_fixture(
            root.path(),
            ".claude/projects/AcquisitionCodename/transcript.jsonl",
            &format!(
                "aws={aws_key}\nanthropic={anthropic_key}\nopenai={openai_key}\nstripe={stripe_key}\njwt={jwt}\nclient_secret = oauth_secret_value_12345"
            ),
        );
        let target = Target::filesystem(root.path().to_path_buf());

        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-05-11T10:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let findings = report
            .pointer("/sensitiveDataReport/findings")
            .unwrap()
            .as_array()
            .unwrap();

        assert_eq!(
            report.pointer("/sensitiveDataReport/inputs/contentPatternScan"),
            Some(&Value::Bool(true))
        );
        assert!(
            !report
                .pointer("/sensitiveDataReport/inputs/rulePacks")
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            report["sensitiveDataReport"]["inputs"]["rulePacks"][0]["version"],
            DEFAULT_RULE_PACK_VERSION
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding["patternClass"] == "aws-access-key")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding["patternClass"] == "anthropic-api-key")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding["patternClass"] == "openai-api-key")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding["patternClass"] == "stripe-key")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding["patternClass"] == "jwt")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding["patternClass"] == "oauth-client-secret")
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding["humanReviewRequired"] == true)
        );
        assert!(!report_text.contains(&aws_key));
        assert!(!report_text.contains(&anthropic_key));
        assert!(!report_text.contains(&openai_key));
        assert!(!report_text.contains(&stripe_key));
        assert!(!report_text.contains(&jwt));
        assert!(!report_text.contains("AcquisitionCodename"));
    }

    #[test]
    fn default_secret_rules_ignore_placeholder_and_low_entropy_examples() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let aws_example = "AKIAIOSFODNN7EXAMPLE";
        let aws_example_fake = "AKIAIOSFODNN7EXAMPLEFAKE";
        let anthropic_repeated = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let anthropic_sequence = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        write_fixture(
            root.path(),
            ".claude/projects/DocsExamples/transcript.jsonl",
            &format!(
                "AWS_ACCESS_KEY_ID={aws_example}\nbackup={aws_example}\nlegacy={aws_example_fake}\nANTHROPIC_API_KEY={anthropic_repeated}\nANTHROPIC_API_KEY={anthropic_sequence}\n"
            ),
        );
        let target = Target::filesystem(root.path().to_path_buf());

        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-05-11T10:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let findings = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap();

        assert!(
            findings.is_empty(),
            "placeholder keys must not fire: {findings:?}"
        );
        assert!(!report_text.contains(aws_example));
        assert!(!report_text.contains(aws_example_fake));
        assert!(!report_text.contains(anthropic_repeated));
        assert!(!report_text.contains(anthropic_sequence));
        assert!(!report_text.contains("DocsExamples"));
    }

    #[test]
    fn suppressions_mark_false_positive_findings() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let suppressions = tempdir().unwrap();
        write_fixture(
            root.path(),
            ".claude/projects/FalsePositiveProject/transcript.jsonl",
            &fixture_aws_access_key(),
        );
        let suppressions_path = suppressions.path().join("suppressions.json");
        fs::write(
            &suppressions_path,
            serde_json::to_vec(&json!({
                "suppressions": [{
                    "id": "known-test-key",
                    "ruleId": "reeve.default.aws-access-key",
                    "surface": "claude-code"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let target = Target::filesystem(root.path().to_path_buf());

        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-05-11T10:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: Some(suppressions_path),
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let finding = &report["sensitiveDataReport"]["findings"][0];

        assert_eq!(finding["suppressed"], true);
        assert_eq!(finding["suppressionId"], "known-test-key");
        assert_eq!(
            report["sensitiveDataReport"]["inputs"]["suppressions"][0]["id"],
            "conversation-suppressions"
        );
    }

    // launch-proof: #358 Conversation scan Claude Desktop - macOS
    // launch-proof: #364 Conversation scan Codex CLI - macOS
    // launch-proof: #365 Conversation scan Codex CLI - Windows
    // launch-proof: #366 Conversation scan Codex CLI - Linux
    #[test]
    fn supported_surfaces_redact_user_controlled_names_in_metadata_and_findings() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let aws_key = fixture_aws_access_key();

        write_fixture(
            root.path(),
            "Library/Application Support/Claude/projects/FounderPlaybook/session.jsonl",
            &aws_key,
        );
        write_fixture(
            root.path(),
            ".claude/projects/AcquisitionCodename/transcript.jsonl",
            &aws_key,
        );
        write_fixture(
            root.path(),
            ".codex/sessions/SecretWorkspace/run-2026-05-14.jsonl",
            &aws_key,
        );

        let target = Target::filesystem(root.path().to_path_buf());
        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-05-11T10:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let surfaces = report["sensitiveDataReport"]["surfaces"]
            .as_array()
            .unwrap();
        let findings = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap();

        let surface_names: Vec<_> = surfaces
            .iter()
            .map(|surface| surface["surface"].as_str().unwrap())
            .collect();
        assert_eq!(
            surface_names,
            vec!["claude-code", "claude-desktop", "codex-cli"]
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding["surface"].as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["claude-code", "claude-desktop", "codex-cli"])
        );
        assert!(findings.iter().all(|finding| {
            finding["file"]["redactedPath"]
                .as_str()
                .is_some_and(|path| path.contains("<segment-1>/"))
        }));
        assert!(report_text.contains("~/.claude/projects/<segment-1>/transcript.jsonl"));
        assert!(
            report_text.contains(
                "~/Library/Application Support/Claude/projects/<segment-1>/session.jsonl"
            )
        );
        assert!(report_text.contains("~/.codex/sessions/<segment-1>/run-2026-05-14.jsonl"));
        assert!(!report_text.contains("FounderPlaybook"));
        assert!(!report_text.contains("AcquisitionCodename"));
        assert!(!report_text.contains("SecretWorkspace"));
        assert!(!report_text.contains(&aws_key));
    }

    #[test]
    fn malformed_suppressions_file_returns_contextual_error() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let suppressions = tempdir().unwrap();
        let suppressions_path = suppressions.path().join("broken-suppressions.json");
        fs::write(&suppressions_path, "{\"suppressions\": [").unwrap();

        let target = Target::filesystem(root.path().to_path_buf());
        let err = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-05-11T10:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: Some(suppressions_path.clone()),
                conversation_rules_file: None,
            },
        )
        .unwrap_err();
        let err_text = format!("{err:#}");

        assert!(err_text.contains("parse suppressions"));
        assert!(err_text.contains("broken-suppressions.json"));
    }

    // launch-proof: #332 Custom rule packs
    #[test]
    fn custom_rule_pack_adds_findings_without_rule_or_match_leakage() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let rules_dir = tempdir().unwrap();
        let custom_secret = "ACMESECRETALPHA999";
        write_fixture(
            root.path(),
            ".claude/projects/InternalLaunch/transcript.jsonl",
            custom_secret,
        );
        let (rules_path, digest, canonical_id) = write_customer_rule_pack(
            rules_dir.path(),
            "customer-rules.json",
            "acme.internal-token",
            "acme-internal-token",
            "ACMESECRET[A-Z0-9]{8}",
        );
        let target = Target::filesystem(root.path().to_path_buf());

        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-05-11T10:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: Some(rules_path),
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let report_text = serde_json::to_string(&report).unwrap();
        let findings = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap();
        let custom_rules = report["sensitiveDataReport"]["inputs"]["customRules"]
            .as_array()
            .unwrap();

        let finding = findings
            .iter()
            .find(|finding| finding["ruleId"] == "acme.internal-token")
            .expect("custom rule finding");
        assert_eq!(finding["patternClass"], "acme-internal-token");
        assert_eq!(finding["rulePackVersion"], "2026.05.0");
        assert_eq!(finding["matchCount"], 1);
        assert_eq!(custom_rules.len(), 1);
        assert_eq!(custom_rules[0]["id"], "acme-conversation-secrets");
        assert_eq!(custom_rules[0]["version"], "2026.05.0");
        assert_eq!(custom_rules[0]["digest"]["content"], digest);
        assert_eq!(custom_rules[0]["canonicalId"], canonical_id);
        assert!(!report_text.contains(custom_secret));
        assert!(!report_text.contains("ACMESECRET"));
        assert!(!report_text.contains("InternalLaunch"));
    }

    #[test]
    fn suppressions_apply_to_custom_rule_findings() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let rules_dir = tempdir().unwrap();
        let suppressions = tempdir().unwrap();
        write_fixture(
            root.path(),
            ".claude/projects/InternalLaunch/transcript.jsonl",
            "ACMESECRETALPHA999",
        );
        let (rules_path, _, _) = write_customer_rule_pack(
            rules_dir.path(),
            "customer-rules.json",
            "acme.internal-token",
            "acme-internal-token",
            "ACMESECRET[A-Z0-9]{8}",
        );
        let suppressions_path = suppressions.path().join("suppressions.json");
        fs::write(
            &suppressions_path,
            serde_json::to_vec(&json!({
                "suppressions": [{
                    "id": "accepted-internal-token",
                    "ruleId": "acme.internal-token",
                    "surface": "claude-code"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let target = Target::filesystem(root.path().to_path_buf());

        let path = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-05-11T10:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: Some(suppressions_path),
                conversation_rules_file: Some(rules_path),
            },
        )
        .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let finding = report["sensitiveDataReport"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["ruleId"] == "acme.internal-token")
            .expect("custom rule finding");

        assert_eq!(finding["suppressed"], true);
        assert_eq!(finding["suppressionId"], "accepted-internal-token");
    }

    #[test]
    fn malformed_customer_rule_pack_fails_closed_with_context() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let rules_dir = tempdir().unwrap();
        write_fixture(
            root.path(),
            ".claude/projects/InternalLaunch/transcript.jsonl",
            "ACMESECRETALPHA999",
        );
        let rules_path = rules_dir.path().join("broken-rules.json");
        fs::write(
            &rules_path,
            serde_json::to_vec(&json!({
                "rulePackId": "acme-conversation-secrets",
                "rulePackVersion": "2026.05.0",
                "rules": [{
                    "ruleId": "acme.bad-lookahead",
                    "patternClass": "acme-internal-token",
                    "confidence": "high",
                    "description": "Rust regex rejects look-around, keeping scans linear-time.",
                    "regex": "(?=ACMESECRET)ACMESECRET[A-Z0-9]+"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let target = Target::filesystem(root.path().to_path_buf());

        let err = write_sensitive_data_report(
            &target,
            out.path(),
            "scan-test",
            "2026-05-11T10:00:00Z",
            &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: Some(rules_path.clone()),
            },
        )
        .unwrap_err();
        let err_text = format!("{err:#}");

        assert!(err_text.contains("compile conversation rule regex"));
        assert!(err_text.contains("acme.bad-lookahead"));
        assert!(err_text.contains("broken-rules.json"));
    }

    fn write_customer_rule_pack(
        root: &Path,
        file_name: &str,
        rule_id: &str,
        pattern_class: &str,
        regex: &str,
    ) -> (PathBuf, String, String) {
        let path = root.join(file_name);
        let bytes = serde_json::to_vec(&json!({
            "$schema": "https://aibom.example/schemas/secret-rule-pack-v0.1.0.json",
            "rulePackId": "acme-conversation-secrets",
            "rulePackVersion": "2026.05.0",
            "rules": [{
                "ruleId": rule_id,
                "patternClass": pattern_class,
                "confidence": "high",
                "description": "Detect fixture-only internal token prefix.",
                "regex": regex
            }]
        }))
        .unwrap();
        fs::write(&path, &bytes).unwrap();
        let digest = sha256_hex(&bytes);
        let canonical_id = format!("acme-conversation-secrets@2026.05.0:{digest}");
        (path, digest, canonical_id)
    }

    fn write_fixture(root: &Path, relative: &str, content: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn fixture_aws_access_key() -> String {
        "AKIA7Q4M2Z9X8C5N1P3R".to_string()
    }

    fn fixture_anthropic_key() -> String {
        "sk-ant-api03-vB7qL9mR2xT6pW4zY8nC0dE5fG1h".to_string()
    }

    fn fixture_openai_key() -> String {
        "sk-proj-vB7qL9mR2xT6pW4zY8nC0dE5fG1h".to_string()
    }

    fn fixture_stripe_key() -> String {
        "sk_live_vB7qL9mR2xT6pW4zY8nC0dE5fG1h".to_string()
    }
}
