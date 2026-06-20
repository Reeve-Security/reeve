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
// Bound memory for the conversation content scan so a single huge file or a
// flood of medium files cannot exhaust RAM or stall a fleet/MDM scan (#6, #13).
// Files at or under the per-file cap take the whole-read path. Files over the
// cap are streamed in bounded chunks (constant memory) rather than skipped, so
// a secret in a large transcript is still detected (#13). The total-byte budget
// is a runtime/I-O bound, not a memory control: once it is exceeded the scan
// stops reading further files and records an explicit incomplete-coverage
// summary so the gap is auditable, never a silent drop.
const MAX_CONVERSATION_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CONVERSATION_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
// Streaming window size for oversized files. Only one chunk plus the overlap
// carry are held in memory at once, so peak memory is bounded regardless of
// file size (#13).
const CONVERSATION_SCAN_CHUNK_BYTES: usize = 1024 * 1024;
// Bytes of the previous window carried forward so a secret straddling a chunk
// boundary is still matched. This MUST be at least as large as the longest
// secret any rule can match; otherwise a long secret split across a boundary
// could be missed. The default rules match short tokens (AWS 20 bytes, JWTs,
// stripe/anthropic/openai keys) and PEM blocks; an 8 KiB carry comfortably
// exceeds a single-line key and a wrapped PEM header/footer pair, and customer
// regex rule bodies are capped at 4096 bytes by load_customer_rule_pack (#13).
const CONVERSATION_SCAN_OVERLAP_BYTES: usize = 8 * 1024;
// Fixed-window streaming can dedup a match across a chunk boundary only when the
// match span is no larger than the overlap carry: a match longer than the carry
// could begin before the carried region and end after it, so the
// "end > carry_len" dedup test cannot tell whether the previous window already
// counted it. We therefore bound the guaranteed-correct match span to the
// overlap size. Built-in token rules match short tokens (<= a few dozen bytes),
// so they are always within this bound. The PEM block rule is unbounded but is
// handled out of band by a dedicated stateful marker scanner on the streaming
// path (see PemMarkerScanner), so it does not rely on this bound. Customer regex
// rules whose match span could exceed this bound cannot be guaranteed on the
// streaming path; rather than silently under-match, such a rule is flagged at
// load and surfaced as an explicit ruleCoverageWarning when applied to an
// oversized (streamed) file (#13).
const MAX_MATCH_SPAN: usize = CONVERSATION_SCAN_OVERLAP_BYTES;
const PEM_PRIVATE_KEY_PATTERN_CLASS: &str = "private-key-pem";
const RULE_COVERAGE_WARNING_SPAN_EXCEEDS_WINDOW: &str = "match-span-may-exceed-streaming-window";
// Assembled from split fragments so no contiguous AWS-shaped literal sits in
// source (#33). `concat!` is const-evaluated, so these are byte-identical to the
// prior literals at compile time and runtime matching is unchanged.
const KNOWN_PLACEHOLDER_SECRET_TOKENS: &[&str] = &[
    concat!("AKIA", "IOSFODNN7", "EXAMPLE"),
    concat!("AKIA", "IOSFODNN7", "EXAMPLE", "FAKE"),
];
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

// Non-fatal notice that a conversation file was not scanned as text during the
// content scan. Surfaced in the report so a skip is auditable telemetry, not a
// silent drop. Carries only the redacted path and size, never file content. The
// only skip reason now is genuinely unscannable binary content; oversized files
// are streamed, and total-budget truncation is reported via the explicit
// incomplete-coverage summary instead of a per-file skip (#6, #13).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SkippedFile {
    surface: &'static str,
    redacted_path: String,
    size_bytes: u64,
    reason: SkipReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkipReason {
    BinarySkipped,
}

impl SkipReason {
    fn as_str(self) -> &'static str {
        match self {
            SkipReason::BinarySkipped => "binary",
        }
    }
}

// Explicit record that the total-byte runtime budget stopped the scan before
// every file was read. This is the source of truth for the coverage gap: it
// counts how many files and bytes went unscanned and why, so a truncated scan
// is auditable rather than a silent stop (#13).
#[derive(Debug, Clone, PartialEq, Eq)]
struct IncompleteCoverage {
    reason: &'static str,
    unscanned_file_count: u64,
    unscanned_byte_count: u64,
}

const INCOMPLETE_COVERAGE_TOTAL_BYTE_BUDGET: &str = "total-byte-budget-exceeded";

// Explicit record that a customer rule whose match span could exceed the
// streaming window was applied to an oversized (streamed) file. Fixed-window
// streaming cannot guarantee an arbitrary unbounded regex catches a match that
// straddles a chunk boundary, so rather than silently under-match we surface the
// rule id and reason here and warn at load. This is auditable telemetry, never a
// silent drop (#13). One entry per (rule id) regardless of how many oversized
// files it touched; the warning is about the rule's coverage, not a file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleCoverageWarning {
    rule_id: String,
    pattern_class: String,
    reason: &'static str,
}

// Per-scan bounds. Overridable so a hermetic test can force the streaming path
// and the budget summary with tiny files instead of writing hundreds of
// megabytes (#6, #13). chunk_bytes and overlap_bytes are tunable in tests so a
// boundary-straddling secret can be planted at a small, known chunk size.
#[derive(Debug, Clone, Copy)]
struct ConversationScanLimits {
    max_file_bytes: u64,
    max_total_bytes: u64,
    chunk_bytes: usize,
    overlap_bytes: usize,
}

impl Default for ConversationScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: MAX_CONVERSATION_FILE_BYTES,
            max_total_bytes: MAX_CONVERSATION_TOTAL_BYTES,
            chunk_bytes: CONVERSATION_SCAN_CHUNK_BYTES,
            overlap_bytes: CONVERSATION_SCAN_OVERLAP_BYTES,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ConversationScanResult {
    findings: Vec<PatternFinding>,
    skipped: Vec<SkippedFile>,
    incomplete_coverage: Option<IncompleteCoverage>,
    rule_coverage_warnings: Vec<RuleCoverageWarning>,
}

#[derive(Debug, Clone, Copy)]
struct BuiltInSecretRule {
    pattern_class: &'static str,
    rule_id: &'static str,
    confidence: &'static str,
    matcher: BuiltInMatcher,
}

// A built-in rule exposes both a whole-content count and a match-end-offset
// iterator. The streaming path needs end offsets to dedup across the overlap
// carry; both must agree on what a match is so stream-count equals whole-read
// count (#13).
#[derive(Debug, Clone, Copy)]
struct BuiltInMatcher {
    count: fn(&str) -> u64,
    ends: fn(&str) -> Vec<usize>,
}

const DEFAULT_SECRET_RULES: &[BuiltInSecretRule] = &[
    BuiltInSecretRule {
        pattern_class: "anthropic-api-key",
        rule_id: "reeve.default.anthropic-api-key",
        confidence: "high",
        matcher: BuiltInMatcher {
            count: count_anthropic_keys,
            ends: anthropic_key_ends,
        },
    },
    BuiltInSecretRule {
        pattern_class: "aws-access-key",
        rule_id: "reeve.default.aws-access-key",
        confidence: "high",
        matcher: BuiltInMatcher {
            count: count_aws_access_keys,
            ends: aws_access_key_ends,
        },
    },
    BuiltInSecretRule {
        pattern_class: "jwt",
        rule_id: "reeve.default.jwt",
        confidence: "medium",
        matcher: BuiltInMatcher {
            count: count_jwts,
            ends: jwt_ends,
        },
    },
    BuiltInSecretRule {
        pattern_class: "oauth-client-secret",
        rule_id: "reeve.default.oauth-client-secret",
        confidence: "medium",
        matcher: BuiltInMatcher {
            count: count_oauth_client_secrets,
            ends: oauth_client_secret_ends,
        },
    },
    BuiltInSecretRule {
        pattern_class: "openai-api-key",
        rule_id: "reeve.default.openai-api-key",
        confidence: "high",
        matcher: BuiltInMatcher {
            count: count_openai_keys,
            ends: openai_key_ends,
        },
    },
    BuiltInSecretRule {
        pattern_class: "private-key-pem",
        rule_id: "reeve.default.private-key-pem",
        confidence: "high",
        matcher: BuiltInMatcher {
            count: count_private_key_pem_blocks,
            ends: private_key_pem_block_ends,
        },
    },
    BuiltInSecretRule {
        pattern_class: "stripe-key",
        rule_id: "reeve.default.stripe-key",
        confidence: "high",
        matcher: BuiltInMatcher {
            count: count_stripe_keys,
            ends: stripe_key_ends,
        },
    },
];

#[derive(Debug, Clone)]
struct CompiledSecretRule {
    pattern_class: String,
    rule_id: String,
    rule_pack_version: String,
    confidence: String,
    matcher: SecretRuleMatcher,
    // True when the rule's regex could match a span larger than MAX_MATCH_SPAN,
    // so fixed-window streaming cannot guarantee it catches a boundary-straddling
    // match. Set only for customer regex rules at load (built-in token rules are
    // short; the PEM block is handled by the stateful marker scanner). When such
    // a rule runs on the streaming path, an explicit ruleCoverageWarning is
    // recorded instead of a silent under-match (#13).
    streaming_span_unbounded: bool,
}

#[derive(Debug, Clone)]
enum SecretRuleMatcher {
    BuiltIn(BuiltInMatcher),
    Regex(Regex),
}

impl CompiledSecretRule {
    fn count(&self, content: &str) -> u64 {
        match &self.matcher {
            SecretRuleMatcher::BuiltIn(matcher) => (matcher.count)(content),
            SecretRuleMatcher::Regex(regex) => regex.find_iter(content).count() as u64,
        }
    }

    // Byte end offsets of every match in `content`. Used by the streaming path
    // to dedup matches across the carried overlap region: a match counts in a
    // window only when its end offset lands beyond the overlap already counted
    // in the previous window (#13). End offsets are returned (not start) because
    // a match that the previous window truncated at the boundary must be counted
    // exactly once, in the window where it completes.
    fn match_ends(&self, content: &str) -> Vec<usize> {
        match &self.matcher {
            SecretRuleMatcher::BuiltIn(matcher) => (matcher.ends)(content),
            SecretRuleMatcher::Regex(regex) => regex
                .find_iter(content)
                .map(|matched| matched.end())
                .collect(),
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
    let scan_result = if options.scan_conversation_secrets {
        scan_conversation_findings(&target.root, &rules, &suppressions)
            .with_context(|| format!("scan conversation secrets {}", target.root.display()))?
    } else {
        ConversationScanResult::default()
    };
    let report_id = format!("sdr-{scan_id}");
    let filename = format!("{scan_id}.sensitive-data.json");
    let report = sensitive_data_report_value(SensitiveDataReportBuild {
        report_id: &report_id,
        scan_id,
        timestamp,
        target,
        surfaces: &surfaces,
        findings: &scan_result.findings,
        skipped: &scan_result.skipped,
        incomplete_coverage: scan_result.incomplete_coverage.as_ref(),
        rule_coverage_warnings: &scan_result.rule_coverage_warnings,
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
) -> Result<ConversationScanResult> {
    scan_conversation_findings_with_limits(
        target_root,
        rules,
        suppressions,
        ConversationScanLimits::default(),
    )
}

fn scan_conversation_findings_with_limits(
    target_root: &Path,
    rules: &[CompiledSecretRule],
    suppressions: &[SuppressionSpec],
    limits: ConversationScanLimits,
) -> Result<ConversationScanResult> {
    let mut findings = Vec::new();
    let mut skipped = Vec::new();
    let mut total_read_bytes: u64 = 0;
    let mut unscanned_file_count: u64 = 0;
    let mut unscanned_byte_count: u64 = 0;
    // Rule ids that ran on at least one oversized (streamed) file and whose match
    // span may exceed the streaming window, recorded once per rule so the
    // coverage limitation is auditable (#13).
    let mut warned_rule_ids = BTreeSet::<String>::new();
    let mut rule_coverage_warnings = Vec::new();
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
            let file_size = metadata.len();
            let redacted_path = redacted_file_path(entry.path(), &root_path, root);
            // Total-byte budget is a runtime/I-O bound, not a memory control.
            // Once it is exhausted, stop reading further files and tally them
            // into the explicit incomplete-coverage summary so the gap is
            // auditable rather than a silent stop (#13).
            if total_read_bytes >= limits.max_total_bytes {
                unscanned_file_count += 1;
                unscanned_byte_count = unscanned_byte_count.saturating_add(file_size);
                continue;
            }
            let last_modified = metadata
                .modified()
                .map(DateTime::<Utc>::from)
                .unwrap_or_else(|_| DateTime::<Utc>::from(UNIX_EPOCH));

            // Per-rule match counts for this file. Small files take the
            // whole-read path; oversized files are streamed in bounded chunks so
            // a secret in a large transcript is still detected without loading
            // the whole file into memory (#13).
            let streamed = file_size > limits.max_file_bytes;
            let scan = if streamed {
                scan_file_streaming(entry.path(), rules, &limits)?
            } else {
                scan_file_whole(entry.path(), rules)?
            };
            total_read_bytes = total_read_bytes.saturating_add(scan.bytes_scanned);

            // A customer rule whose match span may exceed the streaming window
            // was applied on the streaming path: record the coverage limitation
            // explicitly rather than letting a boundary-straddling match be
            // silently under-counted (#13). Recorded even on a binary file: the
            // rule still could not be guaranteed had the file been text.
            if streamed {
                for rule in rules.iter().filter(|rule| rule.streaming_span_unbounded) {
                    if warned_rule_ids.insert(rule.rule_id.clone()) {
                        rule_coverage_warnings.push(RuleCoverageWarning {
                            rule_id: rule.rule_id.clone(),
                            pattern_class: rule.pattern_class.clone(),
                            reason: RULE_COVERAGE_WARNING_SPAN_EXCEEDS_WINDOW,
                        });
                    }
                }
            }

            match scan.outcome {
                FileScanOutcome::Binary => {
                    // NUL bytes / undecodable content: genuinely unscannable as
                    // text, so record skip telemetry rather than streaming it.
                    skipped.push(SkippedFile {
                        surface: root.surface,
                        redacted_path: redacted_path.clone(),
                        size_bytes: file_size,
                        reason: SkipReason::BinarySkipped,
                    });
                }
                FileScanOutcome::Scanned(match_counts) => {
                    for (rule, match_count) in rules.iter().zip(match_counts) {
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
                            size_bytes: file_size,
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
        }
    }
    let incomplete_coverage = if unscanned_file_count > 0 {
        Some(IncompleteCoverage {
            reason: INCOMPLETE_COVERAGE_TOTAL_BYTE_BUDGET,
            unscanned_file_count,
            unscanned_byte_count,
        })
    } else {
        None
    };
    findings.sort_by(|a, b| {
        a.surface
            .cmp(b.surface)
            .then(a.redacted_path.cmp(&b.redacted_path))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    for (index, finding) in findings.iter_mut().enumerate() {
        finding.finding_id = format!("sdf-{index:04}");
    }
    skipped.sort_by(|a, b| {
        a.surface
            .cmp(b.surface)
            .then(a.redacted_path.cmp(&b.redacted_path))
            .then(a.reason.as_str().cmp(b.reason.as_str()))
    });
    rule_coverage_warnings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    Ok(ConversationScanResult {
        findings,
        skipped,
        incomplete_coverage,
        rule_coverage_warnings,
    })
}

// Result of scanning one conversation file: how many bytes were read (charged
// to the runtime budget) and either per-rule match counts or a binary skip.
struct FileScan {
    bytes_scanned: u64,
    outcome: FileScanOutcome,
}

enum FileScanOutcome {
    // Per-rule match counts, in the same order as `rules`.
    Scanned(Vec<u64>),
    // Genuinely unscannable as text (contains a NUL byte / undecodable).
    Binary,
}

// Whole-read path for files at or under the per-file cap. Reads the file once,
// decodes lossily, and counts matches per rule exactly as before (#13).
fn scan_file_whole(path: &Path, rules: &[CompiledSecretRule]) -> Result<FileScan> {
    let bytes = fs::read(path)?;
    let bytes_scanned = bytes.len() as u64;
    if bytes.contains(&0) {
        return Ok(FileScan {
            bytes_scanned,
            outcome: FileScanOutcome::Binary,
        });
    }
    let content = String::from_utf8_lossy(&bytes);
    let match_counts = rules.iter().map(|rule| rule.count(&content)).collect();
    Ok(FileScan {
        bytes_scanned,
        outcome: FileScanOutcome::Scanned(match_counts),
    })
}

fn is_utf8_char_start(byte: u8) -> bool {
    // Continuation bytes are 0b10xxxxxx; everything else starts a char.
    (byte & 0xC0) != 0x80
}

// Length of the longest prefix of `bytes` that ends on a complete UTF-8
// sequence boundary. A trailing incomplete multibyte sequence (a lead byte whose
// continuation bytes have not all arrived) is excluded so it can be held back and
// completed by the next read. A standalone invalid byte (not the start of an
// incomplete-but-valid lead sequence) is included so it decodes to U+FFFD here
// rather than being held indefinitely (#13).
fn utf8_complete_prefix_len(bytes: &[u8]) -> usize {
    // Scan back over at most the last few bytes to find a lead byte; if the
    // sequence it starts is incomplete, cut before it.
    let len = bytes.len();
    let mut index = len;
    // Walk back over continuation bytes (max 3 for UTF-8).
    let mut continuation = 0usize;
    while index > 0 && !is_utf8_char_start(bytes[index - 1]) && continuation < 3 {
        index -= 1;
        continuation += 1;
    }
    if index == 0 {
        // No lead byte found within range: nothing to hold back.
        return len;
    }
    let lead = bytes[index - 1];
    let expected = utf8_sequence_len(lead);
    let have = len - (index - 1);
    if expected > 1 && have < expected {
        // Incomplete trailing sequence: hold back the lead + its continuations.
        index - 1
    } else {
        // Complete sequence (or a non-lead/invalid byte that decodes alone).
        len
    }
}

// Expected total byte length of a UTF-8 sequence given its lead byte. Returns 1
// for ASCII and for invalid lead bytes (they decode to a single U+FFFD).
fn utf8_sequence_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead >= 0xF0 {
        4
    } else if lead >= 0xE0 {
        3
    } else if lead >= 0xC0 {
        2
    } else {
        1
    }
}

// Stateful scanner for `-----BEGIN ... PRIVATE KEY-----` ... `-----END ...
// PRIVATE KEY-----` blocks across streaming windows. The whole-content regex
// (`[\s\S]+?` between the markers) can match a span larger than the overlap
// carry, so the "end > carry_len" dedup cannot guarantee a long PEM block that
// straddles a chunk boundary is counted exactly once: it would be MISSED.
// Silently dropping a private key is unacceptable (#13). This scanner instead
// tracks only whether we are currently inside a block; it counts one match each
// time a BEGIN marker is followed (eventually, across any number of chunks) by
// an END marker. Memory is O(window): it holds no accumulated block bytes, only
// the "inside" flag. To detect a marker split across the boundary, the window
// already includes the OVERLAP carry; markers are short (well under OVERLAP), so
// a marker straddling the boundary is wholly present in some window.
struct PemMarkerScanner {
    inside: bool,
    count: u64,
    // The last few bytes of the previously fed text, retained so a marker split
    // across two feeds is still found. Bounded at PEM_TAIL_BYTES, so memory stays
    // O(1) regardless of how large the PEM block (or file) is.
    tail: String,
}

// A PEM marker is `-----BEGIN ` + `[A-Z0-9 ]*` label + `PRIVATE KEY-----`. The
// fixed and required text is 11 + 16 = 27 bytes (BEGIN) / 9 + 16 = 25 bytes
// (END); a generous tail covers any realistic label run so a marker straddling
// a feed boundary is wholly visible in some feed without retaining block bytes.
const PEM_TAIL_BYTES: usize = 128;

// Maximum length of the `[A-Z0-9 ]` label run between `-----BEGIN `/`-----END `
// and `PRIVATE KEY-----`. Real labels are short (e.g. "OPENSSH", "RSA",
// "EC", "ENCRYPTED"), well under 30 chars. Bounding it makes the whole-read
// regex and the streaming `find_pem_marker` AGREE: with a 64-char cap the full
// BEGIN marker is at most 11 + 64 + 16 = 91 bytes, comfortably inside the
// PEM_TAIL_BYTES (128) carry, so a marker is always wholly visible in one feed.
// An unbounded label would let the whole-read regex match a marker the streaming
// path silently misses once the label run exceeds the tail (#13).
const PEM_LABEL_MAX_BYTES: usize = 64;

impl PemMarkerScanner {
    fn new() -> Self {
        Self {
            inside: false,
            count: 0,
            tail: String::new(),
        }
    }

    // Feed the bytes of this window that were NOT already consumed by the
    // previous window (i.e. the bytes past the carry prefix), so a stream byte is
    // fed exactly once. `fresh` is the decoded window text starting at the first
    // byte past the carry overlap. The retained tail from the prior feed is
    // prepended so a marker straddling the feed seam is still matched; the tail
    // bytes were never themselves counted as a transition, so prepending them
    // cannot double-count.
    fn feed(&mut self, fresh: &str) {
        let combined = if self.tail.is_empty() {
            fresh.to_string()
        } else {
            format!("{}{fresh}", self.tail)
        };
        let mut consumed = 0usize;
        let mut rest = combined.as_str();
        loop {
            if self.inside {
                match find_pem_end(rest) {
                    Some(end_idx) => {
                        self.inside = false;
                        self.count += 1;
                        consumed += end_idx;
                        rest = &rest[end_idx..];
                    }
                    None => break,
                }
            } else {
                match find_pem_begin(rest) {
                    Some(begin_idx) => {
                        self.inside = true;
                        consumed += begin_idx;
                        rest = &rest[begin_idx..];
                    }
                    None => break,
                }
            }
        }
        // Retain a bounded tail of the not-yet-consumed bytes so a marker that
        // begins here but completes in the next feed is still found. Cut on a
        // char boundary to keep the retained tail valid UTF-8.
        let unconsumed = &combined[consumed..];
        let keep = PEM_TAIL_BYTES.min(unconsumed.len());
        let mut cut = unconsumed.len() - keep;
        while cut < unconsumed.len() && !unconsumed.is_char_boundary(cut) {
            cut += 1;
        }
        self.tail = unconsumed[cut..].to_string();
    }
}

// Returns the byte index just past a `-----BEGIN ...PRIVATE KEY-----` marker, or
// None. Mirrors the built-in regex marker shape: a `[A-Z0-9 ]` label run of at
// most PEM_LABEL_MAX_BYTES between BEGIN and PRIVATE KEY. The label bound keeps
// this streaming check in agreement with the whole-read regex (#13).
fn find_pem_begin(text: &str) -> Option<usize> {
    find_pem_marker(text, "-----BEGIN ")
}

fn find_pem_end(text: &str) -> Option<usize> {
    find_pem_marker(text, "-----END ")
}

fn find_pem_marker(text: &str, prefix: &str) -> Option<usize> {
    let suffix = "PRIVATE KEY-----";
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find(prefix) {
        let prefix_start = search_from + rel;
        let after_prefix = prefix_start + prefix.len();
        // An optional `[A-Z0-9 ]*` label run sits between the prefix and the
        // `PRIVATE KEY-----` suffix. Search for the suffix and accept it only
        // when every byte between the prefix and the suffix is a label char.
        let rest = &text[after_prefix..];
        if let Some(suffix_rel) = rest.find(suffix) {
            let label = &rest[..suffix_rel];
            let label_ok = label.len() <= PEM_LABEL_MAX_BYTES
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b' ');
            if label_ok {
                return Some(after_prefix + suffix_rel + suffix.len());
            }
        }
        // No valid suffix for this prefix; advance and keep looking.
        search_from = after_prefix;
    }
    None
}

// Streaming path for oversized files. Holds at most one chunk plus a fixed
// OVERLAP carry in memory, so peak memory is bounded regardless of file size.
//
// Overlap/dedup: each window is `carry || chunk`. The carry is the last
// OVERLAP bytes of the previous window. For the first window every match is
// counted. For later windows a match counts only when its end offset lands
// beyond the carried overlap region (end > carry_len): matches that end inside
// the carry were already counted in the previous window, while a match the
// previous window truncated at the boundary completes here and is counted once.
//
// Coordinate space: both `carry_len` and every match-end offset are byte indices
// into the SAME decoded window string. `carry_len` is the byte length of the
// decoded carry prefix, not the raw carried byte count, so the comparison is
// apples-to-apples even when the carry or chunk holds multibyte or invalid-UTF-8
// content (invalid bytes decode to a 3-byte U+FFFD) (#13).
//
// The bound holds only for rules whose match span is <= MAX_MATCH_SPAN. The PEM
// block rule is unbounded, so on this path it is detected by the stateful
// PemMarkerScanner instead of its regex; customer rules whose span may exceed
// the window are surfaced as ruleCoverageWarnings by the caller (#13).
fn scan_file_streaming(
    path: &Path,
    rules: &[CompiledSecretRule],
    limits: &ConversationScanLimits,
) -> Result<FileScan> {
    use std::io::Read;

    let chunk_bytes = limits.chunk_bytes.max(1);
    let overlap_bytes = limits.overlap_bytes;
    let mut file = fs::File::open(path)?;
    let mut chunk = vec![0u8; chunk_bytes];
    // `carry` always holds COMPLETE, valid UTF-8 bytes: a multibyte char split by
    // a read boundary is held in `pending_tail` (raw bytes) and re-attached to
    // the front of the next chunk, so no char is ever split across the lossy
    // decode of two windows. This keeps the decoded-window coordinate space
    // consistent: decoding `carry` alone yields exactly the prefix of the full
    // window, so carry_len (decoded carry length) is a valid char boundary and an
    // apples-to-apples dedup bound for the match-end offsets (#13).
    let mut carry: Vec<u8> = Vec::new();
    let mut pending_tail: Vec<u8> = Vec::new();
    let mut match_counts = vec![0u64; rules.len()];
    let mut bytes_scanned: u64 = 0;
    let mut first_window = true;
    let mut pem_scanner = PemMarkerScanner::new();

    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        bytes_scanned = bytes_scanned.saturating_add(read as u64);
        if chunk[..read].contains(&0) {
            // A NUL byte anywhere marks the file as binary; abandon streaming
            // and report it as unscannable text rather than emitting findings.
            return Ok(FileScan {
                bytes_scanned,
                outcome: FileScanOutcome::Binary,
            });
        }
        // Prepend any incomplete multibyte char held back from the previous read
        // so a char split across the raw read boundary is decoded as one char.
        let mut fresh = std::mem::take(&mut pending_tail);
        fresh.extend_from_slice(&chunk[..read]);
        // Hold back a trailing incomplete UTF-8 sequence (a multibyte char the
        // read cut in half) for the next iteration so it is not decoded as a
        // lone U+FFFD here and another U+FFFD there. A genuinely invalid byte is
        // not an incomplete sequence and stays in `fresh` to decode as U+FFFD.
        let split = utf8_complete_prefix_len(&fresh);
        pending_tail = fresh.split_off(split);

        let raw_carry_len = carry.len();
        let mut window = carry;
        window.extend_from_slice(&fresh);
        let window_text = String::from_utf8_lossy(&window);
        // carry decodes to exactly the prefix of window_text (both are complete
        // UTF-8 at the seam), so its decoded byte length is the dedup boundary.
        let carry_len = String::from_utf8_lossy(&window[..raw_carry_len]).len();
        for (rule, count) in rules.iter().zip(match_counts.iter_mut()) {
            // The PEM block rule is handled by the stateful marker scanner
            // below; skip its (potentially boundary-missing) regex here (#13).
            if rule.pattern_class == PEM_PRIVATE_KEY_PATTERN_CLASS
                && matches!(rule.matcher, SecretRuleMatcher::BuiltIn(_))
            {
                continue;
            }
            for end in rule.match_ends(&window_text) {
                if first_window || end > carry_len {
                    *count += 1;
                }
            }
        }
        // Feed only the fresh (post-carry) portion of the window to the PEM
        // marker scanner so a marker in the overlap is not counted twice.
        pem_scanner.feed(&window_text[carry_len..]);
        // Carry the tail OVERLAP bytes into the next window. Cut on a UTF-8 char
        // boundary so the carry stays complete valid UTF-8.
        let keep = overlap_bytes.min(window.len());
        let mut cut = window.len() - keep;
        while cut < window.len() && !is_utf8_char_start(window[cut]) {
            cut += 1;
        }
        carry = window.split_off(cut);
        first_window = false;
    }

    // A truncated file can leave an incomplete trailing multibyte sequence in
    // `pending_tail` that never completed. Decode it (lossily, as U+FFFD) in a
    // final window so the tail is still scanned and stream output matches the
    // whole-read path (#13).
    if !pending_tail.is_empty() {
        let raw_carry_len = carry.len();
        let mut window = carry;
        window.extend_from_slice(&pending_tail);
        let window_text = String::from_utf8_lossy(&window);
        let carry_len = String::from_utf8_lossy(&window[..raw_carry_len]).len();
        for (rule, count) in rules.iter().zip(match_counts.iter_mut()) {
            if rule.pattern_class == PEM_PRIVATE_KEY_PATTERN_CLASS
                && matches!(rule.matcher, SecretRuleMatcher::BuiltIn(_))
            {
                continue;
            }
            for end in rule.match_ends(&window_text) {
                if first_window || end > carry_len {
                    *count += 1;
                }
            }
        }
        pem_scanner.feed(&window_text[carry_len..]);
    }

    // Fold the stateful PEM count into the PEM rule's slot, if that rule is
    // active.
    if pem_scanner.count > 0 {
        for (rule, count) in rules.iter().zip(match_counts.iter_mut()) {
            if rule.pattern_class == PEM_PRIVATE_KEY_PATTERN_CLASS
                && matches!(rule.matcher, SecretRuleMatcher::BuiltIn(_))
            {
                *count = pem_scanner.count;
            }
        }
    }

    Ok(FileScan {
        bytes_scanned,
        outcome: FileScanOutcome::Scanned(match_counts),
    })
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
                    "compile conversation rule regex {} in {} with ReDoS-resistant Rust regex engine",
                    spec.rule_id,
                    path.display()
                )
            })?;
        let streaming_span_unbounded = regex_span_may_exceed_window(&spec.regex);
        if streaming_span_unbounded {
            // Fixed-window streaming cannot guarantee an unbounded regex catches
            // a match straddling a chunk boundary. Warn at load so the operator
            // sees it even before a report is read; the report also carries an
            // explicit ruleCoverageWarning when the rule runs on an oversized
            // file. Never a silent drop (#13).
            eprintln!(
                "reeve: conversation rule {} may match a span larger than the {MAX_MATCH_SPAN}-byte streaming window; matches in oversized files that straddle a chunk boundary are not guaranteed and will be reported as a ruleCoverageWarning",
                spec.rule_id
            );
        }
        rules.push(CompiledSecretRule {
            pattern_class: spec.pattern_class,
            rule_id: spec.rule_id,
            rule_pack_version: file.rule_pack_version.clone(),
            confidence: spec.confidence,
            matcher: SecretRuleMatcher::Regex(matcher),
            streaming_span_unbounded,
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

// Could this customer regex match a span larger than MAX_MATCH_SPAN, so that a
// boundary-straddling match in an oversized streamed file is not guaranteed to
// be deduped correctly?
//
// We answer with a PROVABLE upper bound on the match length, not a hand-rolled
// scan of quantifier counts. `regex_syntax::parse` lowers the pattern to an HIR
// whose `properties().maximum_len()` is the largest possible match length in
// BYTES (`None` == provably unbounded). Crucially this folds in the repeated
// atom / group length and concatenation, so `(ab){5000}` (10 KB),
// `[A-Za-z]{5000}[0-9]{5000}` (10 KB), and `x{5000}y{5000}` (10 KB) all report
// their true span rather than just a per-quantifier count.
//
// A rule is streaming-safe ONLY when the bound is `Some(n)` with
// `n <= MAX_MATCH_SPAN`. Every other outcome (unbounded `None`, a bound over the
// window, or a pattern that fails to parse here) is flagged. This is
// safe-by-default for a secret scanner: over-flagging a rule that is actually
// fine is acceptable, a silent under-count is not (#13).
fn regex_span_may_exceed_window(regex: &str) -> bool {
    match regex_syntax::parse(regex) {
        Ok(hir) => match hir.properties().maximum_len() {
            Some(max_len) => max_len > MAX_MATCH_SPAN,
            None => true, // Provably unbounded (`+`, `*`, `{N,}`, ...): flag.
        },
        // If the AST cannot be built here we cannot prove the bound, so flag
        // rather than risk a silent miss. (The rule is compiled separately by
        // `regex::Regex`; a parse divergence is itself worth surfacing.)
        Err(_) => true,
    }
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
            // Built-in token rules match short spans; the PEM block rule is
            // handled by the stateful marker scanner on the streaming path, so
            // no built-in needs the unbounded-span warning (#13).
            streaming_span_unbounded: false,
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
    skipped: &'a [SkippedFile],
    incomplete_coverage: Option<&'a IncompleteCoverage>,
    rule_coverage_warnings: &'a [RuleCoverageWarning],
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
    let mut report = json!({
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
    });
    // Surface skipped (binary/unscannable) files as auditable telemetry. Omit
    // the key entirely when nothing was skipped so normal reports keep their
    // existing shape (#6, #13).
    if !input.skipped.is_empty() {
        report["sensitiveDataReport"]["skipped"] = input
            .skipped
            .iter()
            .map(skipped_value)
            .collect::<Vec<_>>()
            .into();
    }
    // The total-byte runtime budget stopped the scan before every file was
    // read: emit an explicit coverage gap so it is auditable, not silent (#13).
    // Omitted when the scan read every file.
    if let Some(coverage) = input.incomplete_coverage {
        report["sensitiveDataReport"]["incompleteCoverage"] = json!({
            "reason": coverage.reason,
            "unscannedFileCount": coverage.unscanned_file_count,
            "unscannedByteCount": coverage.unscanned_byte_count
        });
    }
    // A customer rule whose match span may exceed the fixed streaming window ran
    // on an oversized file: surface the coverage limitation explicitly so a
    // possible under-match is auditable, never silent (#13). Omitted when no
    // such rule applied.
    if !input.rule_coverage_warnings.is_empty() {
        report["sensitiveDataReport"]["ruleCoverageWarnings"] = input
            .rule_coverage_warnings
            .iter()
            .map(rule_coverage_warning_value)
            .collect::<Vec<_>>()
            .into();
    }
    Ok(report)
}

fn skipped_value(skipped: &SkippedFile) -> Value {
    json!({
        "reason": skipped.reason.as_str(),
        "redactedPath": &skipped.redacted_path,
        "sizeBytes": skipped.size_bytes,
        "surface": skipped.surface
    })
}

fn rule_coverage_warning_value(warning: &RuleCoverageWarning) -> Value {
    json!({
        "patternClass": &warning.pattern_class,
        "reason": warning.reason,
        "ruleId": &warning.rule_id
    })
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

// Yields (token, end-byte-offset) for every candidate token. The end offset is
// the byte index just past the token in `content`, used by the streaming path
// to dedup across the overlap carry (#13). Offsets are derived from the real
// byte positions in `content` via char_indices, so they are correct regardless
// of delimiter byte-width: a multibyte delimiter (or a multibyte U+FFFD that the
// lossy decode inserted for invalid input) must not be assumed to be one byte,
// or the end offsets drift past a chunk boundary and the dedup miscounts (#13).
fn candidate_tokens_with_ends(content: &str) -> impl Iterator<Item = (&str, usize)> {
    let is_token_char = |ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.');
    let mut tokens = Vec::new();
    let mut token_start: Option<usize> = None;
    for (index, ch) in content.char_indices() {
        if is_token_char(ch) {
            if token_start.is_none() {
                token_start = Some(index);
            }
        } else if let Some(start) = token_start.take() {
            tokens.push((&content[start..index], index));
        }
    }
    if let Some(start) = token_start {
        tokens.push((&content[start..], content.len()));
    }
    tokens.into_iter()
}

// Shared end-offset helper for token rules: an end offset per token the
// predicate accepts. count and ends stay in lockstep this way (#13).
fn token_match_ends(content: &str, predicate: fn(&str) -> bool) -> Vec<usize> {
    candidate_tokens_with_ends(content)
        .filter(|(token, _)| predicate(token))
        .map(|(_, end)| end)
        .collect()
}

fn is_anthropic_key(token: &str) -> bool {
    token.starts_with("sk-ant-")
        && token.len() >= 24
        && has_plausible_secret_body(token, &["sk-ant-api03-", "sk-ant-"])
}

fn count_anthropic_keys(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| is_anthropic_key(token))
        .count() as u64
}

fn anthropic_key_ends(content: &str) -> Vec<usize> {
    token_match_ends(content, is_anthropic_key)
}

fn is_aws_access_key(token: &str) -> bool {
    token.len() == 20
        && token.starts_with("AKIA")
        && token
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        && has_plausible_secret_body(token, &["AKIA"])
}

fn count_aws_access_keys(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| is_aws_access_key(token))
        .count() as u64
}

fn aws_access_key_ends(content: &str) -> Vec<usize> {
    token_match_ends(content, is_aws_access_key)
}

fn is_jwt(token: &str) -> bool {
    token.starts_with("eyJ")
        && token.matches('.').count() == 2
        && token
            .split('.')
            .all(|segment| segment.len() >= 10 && segment.chars().all(is_base64url_char))
}

fn count_jwts(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| is_jwt(token))
        .count() as u64
}

fn jwt_ends(content: &str) -> Vec<usize> {
    token_match_ends(content, is_jwt)
}

fn oauth_client_secret_regex() -> &'static Regex {
    static OAUTH_CLIENT_SECRET: OnceLock<Regex> = OnceLock::new();
    OAUTH_CLIENT_SECRET.get_or_init(|| {
        RegexBuilder::new(
            r#"\b(?:oauth[_-]?client[_-]?secret|client[_-]?secret|oauth[_-]?secret)\b["']?\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9_.-]{15,})"#,
        )
        .case_insensitive(true)
        .size_limit(1_000_000)
        .build()
        .expect("built-in OAuth client-secret regex compiles")
    })
}

fn count_oauth_client_secrets(content: &str) -> u64 {
    oauth_client_secret_regex()
        .captures_iter(content)
        .filter_map(|captures| captures.get(1).map(|matched| matched.as_str()))
        .filter(|token| has_plausible_secret_body(token, &[]))
        .count() as u64
}

fn oauth_client_secret_ends(content: &str) -> Vec<usize> {
    oauth_client_secret_regex()
        .captures_iter(content)
        .filter_map(|captures| captures.get(1))
        .filter(|matched| has_plausible_secret_body(matched.as_str(), &[]))
        .map(|matched| matched.end())
        .collect()
}

fn is_openai_key(token: &str) -> bool {
    (token.starts_with("sk-proj-") || token.starts_with("sk-"))
        && token.len() >= 24
        && !token.starts_with("sk-ant-")
        && !token.starts_with("sk_live_")
        && !token.starts_with("sk_test_")
        && has_plausible_secret_body(token, &["sk-proj-", "sk-"])
}

fn count_openai_keys(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| is_openai_key(token))
        .count() as u64
}

fn openai_key_ends(content: &str) -> Vec<usize> {
    token_match_ends(content, is_openai_key)
}

fn private_key_pem_regex() -> &'static Regex {
    static PRIVATE_KEY_PEM: OnceLock<Regex> = OnceLock::new();
    PRIVATE_KEY_PEM.get_or_init(|| {
        // The label run is bounded to PEM_LABEL_MAX_BYTES (64) so this whole-read
        // regex and the streaming `find_pem_marker` agree: an unbounded `*` would
        // match a long-label marker the streaming path (which only retains
        // PEM_TAIL_BYTES) silently misses (#13).
        RegexBuilder::new(
            r"-----BEGIN [A-Z0-9 ]{0,64}PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]{0,64}PRIVATE KEY-----",
        )
        .size_limit(1_000_000)
        .build()
        .expect("built-in private-key PEM regex compiles")
    })
}

fn count_private_key_pem_blocks(content: &str) -> u64 {
    private_key_pem_regex().find_iter(content).count() as u64
}

fn private_key_pem_block_ends(content: &str) -> Vec<usize> {
    private_key_pem_regex()
        .find_iter(content)
        .map(|matched| matched.end())
        .collect()
}

fn is_stripe_key(token: &str) -> bool {
    (token.starts_with("sk_live_") || token.starts_with("sk_test_"))
        && token.len() >= 24
        && has_plausible_secret_body(token, &["sk_live_", "sk_test_"])
}

fn count_stripe_keys(content: &str) -> u64 {
    candidate_tokens(content)
        .filter(|token| is_stripe_key(token))
        .count() as u64
}

fn stripe_key_ends(content: &str) -> Vec<usize> {
    token_match_ends(content, is_stripe_key)
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

    #[test]
    fn cowork_indexeddb_leveldb_log_files_are_scanned_but_ldb_files_are_not() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let log_key = fixture_aws_access_key();
        let ignored_ldb_key = format!("AKIA{}", "7Q4M2Z9X8C5N1P4S");
        write_fixture(
            root.path(),
            "AppData/Local/Packages/Claude_abcdef/LocalCache/Roaming/Claude/IndexedDB/https_claude.ai_0.indexeddb.leveldb/000003.log",
            &format!("leveldb wal plaintext {log_key}"),
        );
        write_fixture(
            root.path(),
            "AppData/Local/Packages/Claude_abcdef/LocalCache/Roaming/Claude/IndexedDB/https_claude.ai_0.indexeddb.leveldb/000004.ldb",
            &ignored_ldb_key,
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
        assert!(!report_text.contains(&ignored_ldb_key));
        assert!(!report_text.contains("Claude_abcdef"));
        assert!(!report_text.contains("000003.log"));
        assert!(!report_text.contains("000004.ldb"));
    }

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

    // The AWS docs placeholder key, assembled from split fragments (#33) so no
    // contiguous AKIA-shaped literal sits in source; byte-identical at runtime.
    fn fixture_aws_placeholder_key() -> String {
        format!("AKIA{}", "IOSFODNN7EXAMPLE")
    }

    #[test]
    fn opt_in_report_contains_metadata_only() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let placeholder = fixture_aws_placeholder_key();
        write_fixture(
            root.path(),
            ".claude/projects/AcquisitionCodename/transcript.jsonl",
            &format!("{placeholder} must not appear in report"),
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
        assert!(!report_text.contains(&placeholder));
        assert!(!report_text.contains("AcquisitionCodename"));
    }

    #[test]
    fn second_opt_in_emits_pattern_findings_without_raw_values() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let aws_key = fixture_aws_access_key();
        let anthropic_key = fixture_anthropic_key();
        let openai_key = fixture_openai_key();
        let stripe_key = fixture_stripe_key();
        // JWT segments assembled from split fragments (#33): the `eyJ` header
        // prefix is joined at runtime so no contiguous JWT-shaped literal sits
        // in source. The concatenated value is byte-identical to before.
        let jwt = [
            "ey",
            "J",
            "hbGciOiJIUzI1NiJ9.",
            "ey",
            "J",
            "zdWIiOiIxMjM0NTY3ODkwIn0.",
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
    fn oauth_client_secret_rule_requires_secret_key_value_shape() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let oauth_secret = fixture_oauth_client_secret();
        write_fixture(
            root.path(),
            ".claude/projects/OAuthPositive/transcript.jsonl",
            &format!("client_secret = {oauth_secret}\n"),
        );
        write_fixture(
            root.path(),
            ".claude/projects/OAuthNegative/transcript.jsonl",
            "note=\"docs mention client_secret here\" request_id=01HY7R4BNFX9J7MM2Y8VD2AE7Q session_hash=2f8c9a7b6d5e4f301928374650abcdef\n",
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
        let oauth_findings = findings
            .iter()
            .filter(|finding| finding["patternClass"] == "oauth-client-secret")
            .collect::<Vec<_>>();

        assert_eq!(
            oauth_findings.len(),
            1,
            "only the actual client_secret key/value should fire: {oauth_findings:?}"
        );
        assert_eq!(oauth_findings[0]["matchCount"], 1);
        assert!(!report_text.contains(&oauth_secret));
        assert!(!report_text.contains("OAuthPositive"));
        assert!(!report_text.contains("OAuthNegative"));
    }

    #[test]
    fn default_secret_rules_ignore_placeholder_and_low_entropy_examples() {
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        // Assembled from split fragments (#33); byte-identical at runtime.
        let aws_example = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let aws_example_fake = format!("AKIA{}", "IOSFODNN7EXAMPLEFAKE");
        let anthropic_repeated =
            format!("sk-{}-{}", "ant", "api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let anthropic_sequence = format!("sk-{}-{}", "ant", "api03-abcdefghijklmnopqrstuvwxyz");
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
        assert!(!report_text.contains(&aws_example));
        assert!(!report_text.contains(&aws_example_fake));
        assert!(!report_text.contains(&anthropic_repeated));
        assert!(!report_text.contains(&anthropic_sequence));
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

    // Provider-shaped test fixtures are assembled from split fragments so no
    // contiguous provider-looking literal sits in source (#33). Each builder
    // returns bytes identical to the prior literal, so detection/redaction
    // assertions that reference these values are unchanged.
    fn fixture_aws_access_key() -> String {
        format!("AKIA{}", "7Q4M2Z9X8C5N1P3R")
    }

    fn fixture_anthropic_key() -> String {
        format!("sk-{}-{}", "ant", "api03-vB7qL9mR2xT6pW4zY8nC0dE5fG1h")
    }

    fn fixture_openai_key() -> String {
        format!("sk-{}-{}", "proj", "vB7qL9mR2xT6pW4zY8nC0dE5fG1h")
    }

    fn fixture_stripe_key() -> String {
        format!("sk_{}_{}", "live", "vB7qL9mR2xT6pW4zY8nC0dE5fG1h")
    }

    fn fixture_oauth_client_secret() -> String {
        "Q7mZ9pL2xT6vN4cR8sU0wY3aB5dE1fG9".to_string()
    }

    fn streaming_limits(max_file_bytes: u64, chunk_bytes: usize) -> ConversationScanLimits {
        ConversationScanLimits {
            max_file_bytes,
            max_total_bytes: MAX_CONVERSATION_TOTAL_BYTES,
            chunk_bytes,
            overlap_bytes: 64,
        }
    }

    #[test]
    fn oversized_conversation_file_is_streamed_and_secret_detected() {
        // A file larger than the per-file cap must be streamed in bounded
        // chunks and its secret detected, not skipped (#13). The whole file is
        // never loaded: chunk_bytes is far smaller than the file.
        let root = tempdir().unwrap();
        let aws_key = fixture_aws_access_key();
        // Pad the secret deep into the file so it lands well past the first
        // chunk, forcing multiple streaming windows.
        let filler = "x".repeat(4096);
        let content = format!("{filler}\naws={aws_key}\n{filler}");
        write_fixture(
            root.path(),
            ".claude/projects/HugeProject/transcript.jsonl",
            &content,
        );

        let rules = compile_secret_rules(None);
        // Tiny per-file cap forces the streaming path; 256-byte chunks force
        // many windows over a multi-kilobyte file.
        let limits = streaming_limits(64, 256);
        let result =
            scan_conversation_findings_with_limits(root.path(), &rules, &[], limits).unwrap();

        let aws_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|finding| finding.pattern_class == "aws-access-key")
            .collect();
        assert_eq!(
            aws_findings.len(),
            1,
            "streamed oversized file should yield exactly one aws finding: {:?}",
            result.findings
        );
        assert_eq!(aws_findings[0].match_count, 1);
        assert!(
            result.skipped.is_empty(),
            "oversized text file must be streamed, not skipped"
        );
        assert!(result.incomplete_coverage.is_none());
    }

    #[test]
    fn secret_straddling_chunk_boundary_is_detected() {
        // A secret split across a chunk boundary must still be matched thanks
        // to the overlap carry (#13). Place the 20-byte AWS key so it spans the
        // chunk edge: filler sized so the key starts a few bytes before the
        // boundary and ends a few bytes after it.
        let root = tempdir().unwrap();
        let aws_key = fixture_aws_access_key();
        let chunk = 64usize;
        // Key starts 10 bytes before the first chunk boundary so 10 of its 20
        // bytes land in chunk 0 and the rest in chunk 1. A space before the key
        // makes it a standalone candidate token (the filler is alphanumeric).
        let prefix_len = chunk - 10;
        let content = format!("{} {aws_key} tail", "y".repeat(prefix_len - 1));
        write_fixture(
            root.path(),
            ".claude/projects/StraddleProject/transcript.jsonl",
            &content,
        );

        let rules = compile_secret_rules(None);
        let limits = streaming_limits(16, chunk);
        let result =
            scan_conversation_findings_with_limits(root.path(), &rules, &[], limits).unwrap();

        let aws_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|finding| finding.pattern_class == "aws-access-key")
            .collect();
        assert_eq!(
            aws_findings.len(),
            1,
            "boundary-straddling secret should be detected exactly once: {:?}",
            result.findings
        );
        assert_eq!(aws_findings[0].match_count, 1);
    }

    #[test]
    fn stream_count_equals_whole_read_count_without_double_counting() {
        // Streaming a mid-size file with several secrets, some near chunk
        // boundaries, must produce the same per-rule counts as a single
        // whole-file scan: no match dropped, none double-counted (#13).
        let root = tempdir().unwrap();
        let key_a = fixture_aws_access_key();
        let key_b = format!("AKIA{}", "7Q4M2Z9X8C5N1P4S");
        let key_c = format!("AKIA{}", "3D5F7H9K2M4P6R8T");
        // Vary spacing so keys fall at different positions relative to the
        // chunk grid.
        let content = format!(
            "{pad1}aws={key_a}\n{pad2}second={key_b}\n{pad3}third={key_c}\n",
            pad1 = "a".repeat(50),
            pad2 = "b".repeat(70),
            pad3 = "c".repeat(33),
        );
        let relative = ".claude/projects/MidSize/transcript.jsonl";
        write_fixture(root.path(), relative, &content);
        let rules = compile_secret_rules(None);

        // Whole-read path: cap above file size.
        let whole = scan_conversation_findings_with_limits(
            root.path(),
            &rules,
            &[],
            ConversationScanLimits {
                max_file_bytes: content.len() as u64 + 1,
                max_total_bytes: MAX_CONVERSATION_TOTAL_BYTES,
                chunk_bytes: CONVERSATION_SCAN_CHUNK_BYTES,
                overlap_bytes: CONVERSATION_SCAN_OVERLAP_BYTES,
            },
        )
        .unwrap();

        // Streaming path: tiny cap and chunk so the same file streams.
        let streamed = scan_conversation_findings_with_limits(
            root.path(),
            &rules,
            &[],
            streaming_limits(16, 48),
        )
        .unwrap();

        let whole_aws = whole
            .findings
            .iter()
            .find(|finding| finding.pattern_class == "aws-access-key")
            .map(|finding| finding.match_count);
        let streamed_aws = streamed
            .findings
            .iter()
            .find(|finding| finding.pattern_class == "aws-access-key")
            .map(|finding| finding.match_count);
        assert_eq!(whole_aws, Some(3), "whole-read should see all three keys");
        assert_eq!(
            streamed_aws, whole_aws,
            "stream count must equal whole-read count with no double counting"
        );
    }

    #[test]
    fn binary_conversation_file_is_skipped_not_streamed() {
        // A file containing NUL bytes is genuinely unscannable as text: record
        // it via skip telemetry rather than streaming it as text (#13).
        let root = tempdir().unwrap();
        let binary = {
            let mut bytes = format!("AKIA{}", "7Q4M2Z9X8C5N1P3R").into_bytes();
            bytes.push(0); // NUL marks the content binary
            bytes.extend_from_slice(b"more");
            bytes
        };
        let relative = ".claude/projects/BinaryProject/blob.jsonl";
        let path = root.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &binary).unwrap();

        let rules = compile_secret_rules(None);
        // Small cap so the file streams; the NUL is still caught either way.
        let limits = streaming_limits(4, 8);
        let result =
            scan_conversation_findings_with_limits(root.path(), &rules, &[], limits).unwrap();

        assert!(
            result.findings.is_empty(),
            "binary content must not produce text findings"
        );
        assert_eq!(result.skipped.len(), 1, "binary file should be skipped");
        assert_eq!(result.skipped[0].reason, SkipReason::BinarySkipped);
        assert_eq!(result.skipped[0].reason.as_str(), "binary");
        assert!(!result.skipped[0].redacted_path.contains("BinaryProject"));
    }

    #[test]
    fn total_byte_budget_emits_explicit_incomplete_coverage_summary() {
        // Once the total-byte runtime budget is exhausted, remaining files go
        // unscanned and the scan records an EXPLICIT incomplete-coverage
        // summary (file/byte counts + reason), not a silent stop (#13).
        let root = tempdir().unwrap();
        for index in 0..4 {
            write_fixture(
                root.path(),
                &format!(".claude/projects/Flood{index}/session.jsonl"),
                "0123456789", // 10 bytes each
            );
        }
        let rules = compile_secret_rules(None);
        let limits = ConversationScanLimits {
            max_file_bytes: MAX_CONVERSATION_FILE_BYTES,
            max_total_bytes: 20,
            chunk_bytes: CONVERSATION_SCAN_CHUNK_BYTES,
            overlap_bytes: CONVERSATION_SCAN_OVERLAP_BYTES,
        };
        let result =
            scan_conversation_findings_with_limits(root.path(), &rules, &[], limits).unwrap();

        // Two files fit the 20-byte budget; the other two are unscanned and
        // reported via the summary, not as per-file skips.
        assert!(
            result.skipped.is_empty(),
            "budget truncation is reported via the summary, not skip telemetry"
        );
        let coverage = result
            .incomplete_coverage
            .expect("budget truncation must emit an incomplete-coverage summary");
        assert_eq!(coverage.reason, "total-byte-budget-exceeded");
        assert_eq!(coverage.unscanned_file_count, 2);
        assert_eq!(coverage.unscanned_byte_count, 20);
    }

    #[test]
    fn incomplete_coverage_summary_serializes_into_report() {
        // The summary must appear in the serialized report JSON so operators
        // see the coverage gap (#13).
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        for index in 0..3 {
            write_fixture(
                root.path(),
                &format!(".claude/projects/Flood{index}/session.jsonl"),
                &fixture_aws_access_key(),
            );
        }
        let rules = compile_secret_rules(None);
        let surfaces = inventory_conversation_metadata(root.path()).unwrap();
        let scan = scan_conversation_findings_with_limits(
            root.path(),
            &rules,
            &[],
            ConversationScanLimits {
                max_file_bytes: MAX_CONVERSATION_FILE_BYTES,
                max_total_bytes: 20,
                chunk_bytes: CONVERSATION_SCAN_CHUNK_BYTES,
                overlap_bytes: CONVERSATION_SCAN_OVERLAP_BYTES,
            },
        )
        .unwrap();
        let target = Target::filesystem(root.path().to_path_buf());
        let report = sensitive_data_report_value(SensitiveDataReportBuild {
            report_id: "sdr-test",
            scan_id: "scan-test",
            timestamp: "2026-06-18T10:00:00Z",
            target: &target,
            surfaces: &surfaces,
            findings: &scan.findings,
            skipped: &scan.skipped,
            incomplete_coverage: scan.incomplete_coverage.as_ref(),
            rule_coverage_warnings: &scan.rule_coverage_warnings,
            options: &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: None,
            },
            customer_rule_pack: None,
        })
        .unwrap();
        let _ = out;
        let coverage = &report["sensitiveDataReport"]["incompleteCoverage"];
        assert_eq!(coverage["reason"], "total-byte-budget-exceeded");
        assert!(coverage["unscannedFileCount"].as_u64().unwrap() >= 1);
        assert!(coverage["unscannedByteCount"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn long_pem_block_straddling_chunk_boundary_is_detected_once_when_streamed() {
        // A PEM private-key block LARGER than the overlap carry, straddling a
        // chunk boundary in an oversized streamed file, must be detected exactly
        // once. The unbounded `[\s\S]+?` regex would miss it across the
        // boundary; the stateful PemMarkerScanner catches it (#13). Fails before
        // the marker-scanner fix.
        let root = tempdir().unwrap();
        let chunk = 64usize;
        let overlap = 64usize;
        // Body far larger than chunk and overlap so BEGIN lands in an early
        // window and END lands many windows later, with the block spanning
        // multiple chunk boundaries.
        let body = "QWxpY2Vib2R5bXVzdG5ldmVyYXBwZWFy0123456789ABCDEF".repeat(40);
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
        );
        assert!(
            pem.len() > overlap,
            "fixture PEM must exceed the overlap carry to exercise the gap"
        );
        // Filler before and after so the block straddles interior boundaries.
        let filler = "x".repeat(100);
        let content = format!("{filler}\n{pem}\n{filler}");
        write_fixture(
            root.path(),
            ".claude/projects/LongPemProject/transcript.jsonl",
            &content,
        );

        let rules = compile_secret_rules(None);
        let limits = ConversationScanLimits {
            max_file_bytes: 16,
            max_total_bytes: MAX_CONVERSATION_TOTAL_BYTES,
            chunk_bytes: chunk,
            overlap_bytes: overlap,
        };
        let result =
            scan_conversation_findings_with_limits(root.path(), &rules, &[], limits).unwrap();

        let pem_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|finding| finding.pattern_class == "private-key-pem")
            .collect();
        assert_eq!(
            pem_findings.len(),
            1,
            "a long PEM block straddling chunk boundaries must be detected exactly once: {:?}",
            result.findings
        );
        assert_eq!(pem_findings[0].match_count, 1);
        assert!(
            result.skipped.is_empty(),
            "oversized text file with a PEM block must be streamed, not skipped"
        );
    }

    #[test]
    fn customer_rule_with_span_exceeding_window_emits_coverage_warning_when_streamed() {
        // A customer rule whose match span can exceed MAX_MATCH_SPAN, run on an
        // oversized (streamed) file, must produce an explicit ruleCoverageWarning
        // rather than a silent under-match (#13). Fails before the span-policy
        // telemetry is added.
        let root = tempdir().unwrap();
        let out = tempdir().unwrap();
        let rules_dir = tempdir().unwrap();
        let filler = "z".repeat(4096);
        write_fixture(
            root.path(),
            ".claude/projects/WideRuleProject/transcript.jsonl",
            &format!("{filler}\nbody text\n{filler}"),
        );
        // {10000} upper bound far exceeds the 8 KiB MAX_MATCH_SPAN.
        let (rules_path, _, _) = write_customer_rule_pack(
            rules_dir.path(),
            "wide-rule.json",
            "acme.wide-span",
            "acme-wide-span",
            "secret-[A-Za-z0-9]{10000}",
        );

        let customer_pack = load_customer_rule_pack(Some(&rules_path)).unwrap();
        let rules = compile_secret_rules(customer_pack.as_ref());
        let limits = streaming_limits(64, 256);
        let result =
            scan_conversation_findings_with_limits(root.path(), &rules, &[], limits).unwrap();

        assert_eq!(
            result.rule_coverage_warnings.len(),
            1,
            "an unbounded-span customer rule on a streamed file must warn: {:?}",
            result.rule_coverage_warnings
        );
        assert_eq!(result.rule_coverage_warnings[0].rule_id, "acme.wide-span");
        assert_eq!(
            result.rule_coverage_warnings[0].reason,
            RULE_COVERAGE_WARNING_SPAN_EXCEEDS_WINDOW
        );

        // The warning must also serialize into the report.
        let surfaces = inventory_conversation_metadata(root.path()).unwrap();
        let target = Target::filesystem(root.path().to_path_buf());
        let report = sensitive_data_report_value(SensitiveDataReportBuild {
            report_id: "sdr-test",
            scan_id: "scan-test",
            timestamp: "2026-06-18T10:00:00Z",
            target: &target,
            surfaces: &surfaces,
            findings: &result.findings,
            skipped: &result.skipped,
            incomplete_coverage: result.incomplete_coverage.as_ref(),
            rule_coverage_warnings: &result.rule_coverage_warnings,
            options: &SensitiveDataScanOptions {
                scan_conversation_secrets: true,
                suppressions_file: None,
                conversation_rules_file: Some(rules_path),
            },
            customer_rule_pack: customer_pack.as_ref(),
        })
        .unwrap();
        let _ = out;
        let warnings = report["sensitiveDataReport"]["ruleCoverageWarnings"]
            .as_array()
            .unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0]["ruleId"], "acme.wide-span");
        assert_eq!(
            warnings[0]["reason"],
            RULE_COVERAGE_WARNING_SPAN_EXCEEDS_WINDOW
        );
    }

    #[test]
    fn group_and_concat_quantifier_rules_are_flagged_when_streamed() {
        // Repetitions whose true span exceeds MAX_MATCH_SPAN only when the atom /
        // group length or concatenation is folded in. The old per-quantifier
        // count check inspected each `{N}` in isolation and let these through,
        // silently under-counting on the streaming path. The AST `maximum_len()`
        // bound folds in the repeated content and catches them (#13).
        // Each tuple: (rule_id suffix, pattern, span in bytes).
        let cases: &[(&str, &str, usize)] = &[
            ("group-ab", "(ab){5000}", 10_000),
            ("group-abcd", "(abcd){3000}", 12_000),
            ("noncap", "(?:0123456789){2000}", 20_000),
            ("concat-class", "[A-Za-z]{5000}[0-9]{5000}", 10_000),
            ("concat-lit", "x{5000}y{5000}", 10_000),
        ];
        for (suffix, pattern, span) in cases {
            assert!(
                *span > MAX_MATCH_SPAN,
                "test case {suffix} must exceed the streaming window to be meaningful"
            );
            let root = tempdir().unwrap();
            let rules_dir = tempdir().unwrap();
            let filler = "z".repeat(4096);
            write_fixture(
                root.path(),
                ".claude/projects/GroupRuleProject/transcript.jsonl",
                &format!("{filler}\nbody text\n{filler}"),
            );
            let rule_id = format!("acme.{suffix}");
            let (rules_path, _, _) = write_customer_rule_pack(
                rules_dir.path(),
                "group-rule.json",
                &rule_id,
                "acme-group-span",
                pattern,
            );
            let customer_pack = load_customer_rule_pack(Some(&rules_path)).unwrap();
            let rules = compile_secret_rules(customer_pack.as_ref());
            let limits = streaming_limits(64, 256);
            let result =
                scan_conversation_findings_with_limits(root.path(), &rules, &[], limits).unwrap();

            assert_eq!(
                result.rule_coverage_warnings.len(),
                1,
                "rule {rule_id} ({pattern}) spans {span} B > {MAX_MATCH_SPAN} B and must warn: {:?}",
                result.rule_coverage_warnings
            );
            assert_eq!(result.rule_coverage_warnings[0].rule_id, rule_id);
            assert_eq!(
                result.rule_coverage_warnings[0].reason,
                RULE_COVERAGE_WARNING_SPAN_EXCEEDS_WINDOW
            );
        }
    }

    #[test]
    fn short_bounded_customer_rule_is_not_flagged_when_streamed() {
        // A bounded rule whose provable max span is well under MAX_MATCH_SPAN must
        // NOT produce a ruleCoverageWarning: over-flagging is acceptable, but this
        // rule is genuinely streaming-safe (#13).
        let root = tempdir().unwrap();
        let rules_dir = tempdir().unwrap();
        let filler = "z".repeat(4096);
        write_fixture(
            root.path(),
            ".claude/projects/ShortRuleProject/transcript.jsonl",
            &format!("{filler}\nbody text\n{filler}"),
        );
        let (rules_path, _, _) = write_customer_rule_pack(
            rules_dir.path(),
            "short-rule.json",
            "acme.short-span",
            "acme-short-span",
            "secret-[A-Za-z0-9]{20}",
        );
        let customer_pack = load_customer_rule_pack(Some(&rules_path)).unwrap();
        let rules = compile_secret_rules(customer_pack.as_ref());
        let limits = streaming_limits(64, 256);
        let result =
            scan_conversation_findings_with_limits(root.path(), &rules, &[], limits).unwrap();

        assert!(
            result.rule_coverage_warnings.is_empty(),
            "a short bounded rule must not warn: {:?}",
            result.rule_coverage_warnings
        );
    }

    #[test]
    fn span_bound_classifies_quantifiers_correctly() {
        // Direct unit coverage of the AST `maximum_len()` bound used to flag
        // customer rules. Group/concat spans over the window are flagged; bounded
        // short spans are not; truly unbounded quantifiers are flagged (#13).
        // Over the window -> flagged.
        for over in [
            "(ab){5000}",
            "(abcd){3000}",
            "(?:0123456789){2000}",
            "[A-Za-z]{5000}[0-9]{5000}",
            "x{5000}y{5000}",
            "secret-[A-Za-z0-9]{10000}",
        ] {
            assert!(
                regex_span_may_exceed_window(over),
                "{over} spans more than {MAX_MATCH_SPAN} bytes and must be flagged"
            );
        }
        // Provably unbounded -> flagged.
        for unbounded in ["a+", "b*", "c{5000,}", "(ab)+"] {
            assert!(
                regex_span_may_exceed_window(unbounded),
                "{unbounded} is unbounded and must be flagged"
            );
        }
        // Bounded and within the window -> not flagged.
        for safe in [
            "secret-[A-Za-z0-9]{20}",
            "(ab){10}",
            "[0-9]{8}",
            "AKIA[A-Z0-9]{16}",
        ] {
            assert!(
                !regex_span_may_exceed_window(safe),
                "{safe} is bounded within {MAX_MATCH_SPAN} bytes and must not be flagged"
            );
        }
    }

    #[test]
    fn builtin_token_rules_and_pem_are_not_span_flagged() {
        // Built-in token rules are matched by exact functions (not the customer
        // span heuristic) and the PEM block is handled by the stateful
        // PemMarkerScanner, so no built-in carries the unbounded-span flag and
        // none is double-flagged (#13).
        let rules = compile_secret_rules(None);
        assert!(
            rules.iter().all(|rule| !rule.streaming_span_unbounded),
            "no built-in rule may carry the unbounded-span flag"
        );
        assert!(
            rules
                .iter()
                .any(|rule| rule.pattern_class == PEM_PRIVATE_KEY_PATTERN_CLASS),
            "the built-in PEM rule must still be present and unflagged"
        );
    }

    #[test]
    fn pem_label_bound_agrees_between_whole_read_and_streaming() {
        // A PEM marker whose label run exceeds PEM_LABEL_MAX_BYTES must be matched
        // by neither the whole-read regex nor the streaming marker scan, so the
        // two paths agree (#13). A normal-length label is matched by both.
        let long_label = "A".repeat(PEM_LABEL_MAX_BYTES + 10);
        let over = format!("-----BEGIN {long_label} PRIVATE KEY-----");
        assert!(
            find_pem_begin(&over).is_none(),
            "an over-length label must not be accepted by the streaming marker scan"
        );
        let over_block = format!("{over}\nbody\n-----END {long_label} PRIVATE KEY-----");
        assert_eq!(
            count_private_key_pem_blocks(&over_block),
            0,
            "an over-length label must not be matched by the whole-read regex"
        );

        // A realistic label must still match both paths.
        let ok = "-----BEGIN OPENSSH PRIVATE KEY-----";
        assert!(
            find_pem_begin(ok).is_some(),
            "a normal label must be accepted by the streaming marker scan"
        );
        let ok_block =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nbody\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(
            count_private_key_pem_blocks(ok_block),
            1,
            "a normal-label PEM block must be matched by the whole-read regex"
        );
    }

    #[test]
    fn multibyte_delimiter_near_boundary_does_not_drift_stream_count() {
        // Multibyte and invalid-UTF-8 bytes near a chunk boundary must not drift
        // the dedup count: stream count must equal whole-read count (#13). Fails
        // before the byte-offset-consistent dedup + char_indices token offsets.
        let root = tempdir().unwrap();
        let key_a = fixture_aws_access_key();
        let key_b = format!("AKIA{}", "7Q4M2Z9X8C5N1P4S");
        // Multibyte delimiters (emoji, accented text) and an invalid UTF-8 byte
        // sit right around where the chunk grid will fall, so the lossy decode
        // inserts multibyte chars and U+FFFD near the carry boundary.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice("café★".repeat(8).as_bytes());
        bytes.extend_from_slice(format!(" first={key_a} ").as_bytes());
        bytes.push(0xFF); // lone invalid byte -> U+FFFD on lossy decode
        bytes.extend_from_slice("naïve🚀delim".repeat(6).as_bytes());
        bytes.extend_from_slice(format!(" second={key_b} ").as_bytes());
        bytes.extend_from_slice("résumé".repeat(4).as_bytes());
        let relative = ".claude/projects/Multibyte/transcript.jsonl";
        let path = root.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &bytes).unwrap();

        let rules = compile_secret_rules(None);
        let whole = scan_conversation_findings_with_limits(
            root.path(),
            &rules,
            &[],
            ConversationScanLimits {
                max_file_bytes: bytes.len() as u64 + 1,
                max_total_bytes: MAX_CONVERSATION_TOTAL_BYTES,
                chunk_bytes: CONVERSATION_SCAN_CHUNK_BYTES,
                overlap_bytes: CONVERSATION_SCAN_OVERLAP_BYTES,
            },
        )
        .unwrap();

        let whole_aws = whole
            .findings
            .iter()
            .find(|finding| finding.pattern_class == "aws-access-key")
            .map(|finding| finding.match_count);
        assert_eq!(whole_aws, Some(2), "whole-read should see both keys");

        // Stream with several small chunk sizes so a chunk boundary falls inside
        // the multibyte/invalid runs and right next to each key.
        for chunk in [16usize, 17, 19, 23, 31, 48] {
            let streamed = scan_conversation_findings_with_limits(
                root.path(),
                &rules,
                &[],
                streaming_limits(8, chunk),
            )
            .unwrap();
            let streamed_aws = streamed
                .findings
                .iter()
                .find(|finding| finding.pattern_class == "aws-access-key")
                .map(|finding| finding.match_count);
            assert_eq!(
                streamed_aws, whole_aws,
                "stream count drifted with multibyte/invalid content at chunk size {chunk}"
            );
        }
    }
}
