use aibom_core::{
    AIBOM_SCHEMA_URL, AIBOM_SCHEMA_URL_V2, AIBOM_SCHEMA_URL_V3, AIBOM_SCHEMA_VERSION,
    AIBOM_SCHEMA_VERSION_V2, AIBOM_SCHEMA_VERSION_V3, IN_TOTO_STATEMENT_TYPE, PolicyStatus,
    PolicyVerdict, Target, Transport, canonicalize_json, sha256_hex,
};
use aibom_policy::{
    PolicyConfig, SignatureFacts, evaluate as evaluate_policies, evaluate_sensitive_data_report,
};
use aibom_scanner::mcp::discovery::{
    CustomSurfaceSpec, DryRunSurface, ScopeCatalogEntry, claude_cowork, custom_scope_catalog,
    discover_all, discover_all_with_custom, dry_run_surfaces_with_custom, is_grant_state_provider,
    load_custom_surfaces,
};
use aibom_scanner::mcp::output::{
    ProviderGroup, ScanArtifacts as ScannerScanArtifacts, ScanOptions,
};
use aibom_scanner::mcp::{McpAdapter, group_registrations, scan_target_with_options};
use aibom_signer::{
    Allowlist, ArtifactPair, OnlineSigstoreSigner, SensitiveDataReportArtifact,
    build_sensitive_data_report_statement, write_fixture_bundle,
    write_fixture_bundle_for_statement,
};
use aibom_validator::{
    FixtureResult, ValidationOptions, validate_artifacts_with_options, validate_fixture_tree,
};
use anyhow::{Context, Result, bail};
use base64::prelude::*;
use clap::{Parser, Subcommand, ValueEnum};
use regex::Regex;
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod registry_match;
mod registry_pagination;
use registry_pagination::{HttpPageFetcher, PaginatorConfig, fetch_all};

const SURFACE_CONFIG_PREDICATE_TYPE: &str = "https://aibom.example/attestation/surface-config/v0.1";
const FLEET_MANIFEST_PREDICATE_TYPE: &str = "https://aibom.example/attestation/fleet-manifest/v0.1";
const MCP_REGISTRY_SEED_PREDICATE_TYPE: &str =
    "https://aibom.example/attestation/mcp-registry-seed/v0.1";
const DEFAULT_SIGSTORE_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const DEFAULT_AIBOM_SCHEMA_RELATIVE_PATH: &str = "schema/aibom-v0.1.0.json";
const EMBEDDED_AIBOM_SCHEMA_V1_BYTES: &[u8] = include_bytes!("../../../schema/aibom-v0.1.0.json");
const EMBEDDED_AIBOM_SCHEMA_V2_BYTES: &[u8] = include_bytes!("../../../schema/aibom-v0.2.0.json");
const EMBEDDED_AIBOM_SCHEMA_V3_BYTES: &[u8] = include_bytes!("../../../schema/aibom-v0.3.0.json");
static SCHEMA_CACHE_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct EmbeddedAibomSchema {
    version: &'static str,
    url: &'static str,
    file_name: &'static str,
    bytes: &'static [u8],
}

const EMBEDDED_AIBOM_SCHEMAS: &[EmbeddedAibomSchema] = &[
    EmbeddedAibomSchema {
        version: AIBOM_SCHEMA_VERSION,
        url: AIBOM_SCHEMA_URL,
        file_name: "aibom-v0.1.0.json",
        bytes: EMBEDDED_AIBOM_SCHEMA_V1_BYTES,
    },
    EmbeddedAibomSchema {
        version: AIBOM_SCHEMA_VERSION_V2,
        url: AIBOM_SCHEMA_URL_V2,
        file_name: "aibom-v0.2.0.json",
        bytes: EMBEDDED_AIBOM_SCHEMA_V2_BYTES,
    },
    EmbeddedAibomSchema {
        version: AIBOM_SCHEMA_VERSION_V3,
        url: AIBOM_SCHEMA_URL_V3,
        file_name: "aibom-v0.3.0.json",
        bytes: EMBEDDED_AIBOM_SCHEMA_V3_BYTES,
    },
];

#[derive(Debug, Parser)]
#[command(name = "aibom")]
#[command(about = "Reeve AIBOM command line tools")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Validate {
        #[arg(default_value = "schema/examples/fixtures")]
        fixtures_dir: PathBuf,
        #[arg(long, default_value_os_t = default_schema_path())]
        schema: PathBuf,
    },
    ValidateArtifacts {
        #[arg(long)]
        cdx: PathBuf,
        #[arg(long)]
        aibom: PathBuf,
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Run Reeve's structural Sigstore-bundle checks: bundle shape,
        /// subject hashes, allowlist facts, and fixture rejection. For public
        /// Fulcio/Rekor proof, use cosign verify-blob.
        #[arg(long)]
        verify_crypto: bool,
        #[arg(long)]
        allowlist: Option<PathBuf>,
        #[arg(long)]
        schema: Option<PathBuf>,
    },
    Scan {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long, default_value = "mcp")]
        adapters: String,
        #[arg(long, default_value = "out")]
        output_dir: PathBuf,
        #[arg(long, default_value_t = true, conflicts_with = "skip_sign")]
        sign: bool,
        #[arg(long)]
        skip_sign: bool,
        /// Selects signing backend: real (cosign keyless; fail if cosign
        /// unavailable), fixture (deterministic placeholder bundle for
        /// tests/demos), or auto (use cosign when present, warn and emit
        /// fixture otherwise). Default: auto.
        #[arg(long, value_enum, env = "REEVE_SIGN_MODE")]
        sign_mode: Option<SignMode>,
        #[arg(long, conflicts_with = "no_profile")]
        profile: bool,
        #[arg(long)]
        no_profile: bool,
        #[arg(long)]
        profile_yes: bool,
        /// Execute discovered stdio MCP servers during introspection to call
        /// tools/list. Default scans do not execute MCP servers.
        #[arg(long)]
        introspect_execute: bool,
        /// Skip the interactive confirmation required by --introspect-execute.
        #[arg(long)]
        introspect_execute_yes: bool,
        #[arg(long, default_value_t = 30)]
        profile_timeout_per_tool: u64,
        #[arg(long, default_value_t = 120)]
        profile_timeout_total: u64,
        #[arg(long)]
        policy_check: bool,
        #[arg(long, default_value = "default")]
        policy_profile: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        surface: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long)]
        surface_config: Option<PathBuf>,
        #[arg(long)]
        no_system_config: bool,
        #[arg(long)]
        require_signed_config: bool,
        #[arg(long)]
        include_conversation_metadata: bool,
        #[arg(long)]
        scan_conversation_secrets: bool,
        #[arg(long)]
        conversation_suppressions_file: Option<PathBuf>,
        #[arg(long)]
        conversation_rules_file: Option<PathBuf>,
        /// Consult the published static MCP registry API contract rooted at
        /// this URL/path and emit a best-effort lookup report without failing
        /// the scan when the source is unavailable.
        #[arg(long)]
        registry_source: Option<String>,
        #[arg(long)]
        sensitive_data_sarif: bool,
        #[arg(long, env = "REEVE_SURFACE_CONFIG_SIGNER_IDENTITY_REGEXP")]
        signer_identity_regexp: Option<String>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    Report {
        #[arg(long)]
        aibom: PathBuf,
        #[arg(long, value_enum)]
        format: ReportFormat,
        #[arg(long)]
        output: PathBuf,
        /// Path to the sensitive-data report rendered into the Sensitive Data
        /// section. Defaults to the sibling `<scanid>.sensitive-data.json`
        /// next to `--aibom` when present.
        #[arg(long)]
        sensitive_data: Option<PathBuf>,
    },
    FleetReport {
        #[arg(long)]
        evidence_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = FleetReportFormat::Html)]
        format: FleetReportFormat,
    },
    FleetManifest {
        #[arg(long)]
        evidence_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        bundle: Option<PathBuf>,
        #[arg(long, default_value = "local dry run")]
        recording_scope: String,
        #[arg(long, value_enum, default_value_t = SignMode::Fixture)]
        sign_mode: SignMode,
    },
    McpRegistrySeed {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        bundle: Option<PathBuf>,
        #[arg(
            long,
            default_value = "https://registry.modelcontextprotocol.io/v0.1/servers"
        )]
        source_url: String,
        #[arg(long, value_enum, default_value_t = SignMode::Fixture)]
        sign_mode: SignMode,
    },
    /// Paginate the official MCP Registry API and write the merged page set
    /// (shaped as `{"servers":[...]}`) for `mcp-registry-seed --input`.
    McpRegistryFetch {
        #[arg(
            long,
            default_value = "https://registry.modelcontextprotocol.io/v0.1/servers"
        )]
        base_url: String,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long)]
        updated_since: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        scan_dir: PathBuf,
        /// Run Reeve's structural Sigstore-bundle checks: bundle shape,
        /// subject hashes, allowlist facts, and fixture rejection. For public
        /// Fulcio/Rekor proof, use cosign verify-blob.
        #[arg(long)]
        verify_crypto: bool,
        #[arg(long)]
        allowlist: Option<PathBuf>,
        #[arg(long)]
        schema: Option<PathBuf>,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    Scope {
        #[command(subcommand)]
        command: ScopeCommands,
    },
}

/// How the scan command should produce the Sigstore bundle.
///
/// `Real` requires cosign in PATH (or at `REEVE_COSIGN_BIN`) and fails loudly
/// when it is missing; it never silently downgrades to a fixture bundle.
/// `Fixture` always emits the deterministic placeholder bundle used by tests,
/// demos, and offline workflows. `Auto` matches legacy behavior: use cosign
/// when available, otherwise warn and emit a fixture bundle.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum SignMode {
    Real,
    Fixture,
    Auto,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Yaml,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ReportFormat {
    Html,
    Pdf,
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum FleetReportFormat {
    Html,
    Markdown,
    Json,
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    Check {
        scan_dir: PathBuf,
        #[arg(long, default_value = "default")]
        profile: String,
        /// Run Reeve's structural Sigstore-bundle checks: bundle shape,
        /// subject hashes, allowlist facts, and fixture rejection. For public
        /// Fulcio/Rekor proof, use cosign verify-blob.
        #[arg(long)]
        verify_crypto: bool,
        #[arg(long)]
        allowlist: Option<PathBuf>,
        #[arg(long)]
        schema: Option<PathBuf>,
    },
    CheckSensitive {
        report: PathBuf,
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long)]
        max_sensitive_files: Option<u64>,
        #[arg(long)]
        max_sensitive_bytes: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
enum ScopeCommands {
    List {
        #[arg(long)]
        surface: Vec<String>,
        #[arg(long)]
        surface_config: Option<PathBuf>,
        #[arg(long)]
        no_system_config: bool,
        #[arg(long)]
        require_signed_config: bool,
        #[arg(long, env = "REEVE_SURFACE_CONFIG_SIGNER_IDENTITY_REGEXP")]
        signer_identity_regexp: Option<String>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
}

struct ScanCommand {
    target: Option<PathBuf>,
    adapters: String,
    output_dir: PathBuf,
    sign_mode: SignMode,
    profile: bool,
    profile_yes: bool,
    introspect_execute: bool,
    introspect_execute_yes: bool,
    profile_timeout_per_tool: u64,
    profile_timeout_total: u64,
    policy_check: bool,
    policy_profile: String,
    dry_run: bool,
    surface: Vec<String>,
    exclude: Vec<String>,
    surface_config: Option<PathBuf>,
    no_system_config: bool,
    require_signed_config: bool,
    include_conversation_metadata: bool,
    scan_conversation_secrets: bool,
    conversation_suppressions_file: Option<PathBuf>,
    conversation_rules_file: Option<PathBuf>,
    registry_source: Option<String>,
    sensitive_data_sarif: bool,
    signer_identity_regexp: Option<String>,
    format: OutputFormat,
}

#[derive(Debug, Clone)]
struct SurfaceConfigOptions {
    no_system_config: bool,
    require_signed_config: bool,
    signer_identity_regexp: Option<String>,
}

struct PolicyCheckCommand {
    scan_dir: PathBuf,
    profile: String,
    verify_crypto: bool,
    allowlist: Option<PathBuf>,
    schema: Option<PathBuf>,
}

struct SensitivePolicyCheckCommand {
    report: PathBuf,
    profile: String,
    max_sensitive_files: Option<u64>,
    max_sensitive_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
struct ScanOutputArtifacts {
    scan_id: String,
    cdx_path: PathBuf,
    aibom_path: PathBuf,
    bundle_path: PathBuf,
    sensitive_report_path: Option<PathBuf>,
    sensitive_report_bundle_path: Option<PathBuf>,
    sensitive_sarif_path: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Validate {
            fixtures_dir,
            schema,
        } => validate(fixtures_dir, schema),
        Commands::ValidateArtifacts {
            cdx,
            aibom,
            bundle,
            verify_crypto,
            allowlist,
            schema,
        } => validate_artifact_paths(cdx, aibom, bundle, verify_crypto, allowlist, schema),
        Commands::Scan {
            target,
            adapters,
            output_dir,
            sign,
            skip_sign,
            sign_mode,
            profile,
            no_profile: _,
            profile_yes,
            introspect_execute,
            introspect_execute_yes,
            profile_timeout_per_tool,
            profile_timeout_total,
            policy_check,
            policy_profile,
            dry_run,
            surface,
            exclude,
            surface_config,
            no_system_config,
            require_signed_config,
            include_conversation_metadata,
            scan_conversation_secrets,
            conversation_suppressions_file,
            conversation_rules_file,
            registry_source,
            sensitive_data_sarif,
            signer_identity_regexp,
            format,
        } => scan(ScanCommand {
            target,
            adapters,
            output_dir,
            sign_mode: resolve_sign_mode(sign, skip_sign, sign_mode),
            profile,
            profile_yes,
            introspect_execute,
            introspect_execute_yes,
            profile_timeout_per_tool,
            profile_timeout_total,
            policy_check,
            policy_profile,
            dry_run,
            surface,
            exclude,
            surface_config,
            no_system_config,
            require_signed_config,
            include_conversation_metadata,
            scan_conversation_secrets,
            conversation_suppressions_file,
            conversation_rules_file,
            registry_source,
            sensitive_data_sarif,
            signer_identity_regexp,
            format,
        }),
        Commands::Report {
            aibom,
            format,
            output,
            sensitive_data,
        } => report(aibom, format, output, sensitive_data),
        Commands::FleetReport {
            evidence_dir,
            output,
            format,
        } => fleet_report(evidence_dir, output, format),
        Commands::FleetManifest {
            evidence_dir,
            output,
            bundle,
            recording_scope,
            sign_mode,
        } => fleet_manifest(evidence_dir, output, bundle, recording_scope, sign_mode),
        Commands::McpRegistrySeed {
            input,
            output,
            bundle,
            source_url,
            sign_mode,
        } => mcp_registry_seed(input, output, bundle, source_url, sign_mode),
        Commands::McpRegistryFetch {
            base_url,
            limit,
            updated_since,
            output,
        } => mcp_registry_fetch(base_url, limit, updated_since, output),
        Commands::Verify {
            scan_dir,
            verify_crypto,
            allowlist,
            schema,
        } => verify(scan_dir, verify_crypto, allowlist, schema),
        Commands::Policy { command } => match command {
            PolicyCommands::Check {
                scan_dir,
                profile,
                verify_crypto,
                allowlist,
                schema,
            } => policy_check(PolicyCheckCommand {
                scan_dir,
                profile,
                verify_crypto,
                allowlist,
                schema,
            }),
            PolicyCommands::CheckSensitive {
                report,
                profile,
                max_sensitive_files,
                max_sensitive_bytes,
            } => policy_check_sensitive(SensitivePolicyCheckCommand {
                report,
                profile,
                max_sensitive_files,
                max_sensitive_bytes,
            }),
        },
        Commands::Scope { command } => match command {
            ScopeCommands::List {
                surface,
                surface_config,
                no_system_config,
                require_signed_config,
                signer_identity_regexp,
                format,
            } => scope_list(
                surface,
                surface_config,
                SurfaceConfigOptions {
                    no_system_config,
                    require_signed_config,
                    signer_identity_regexp,
                },
                format,
            ),
        },
    }
}

fn validate(fixtures_dir: PathBuf, schema: PathBuf) -> Result<()> {
    let outcomes = validate_fixture_tree(fixtures_dir, schema);
    let mut failed = 0usize;
    for outcome in &outcomes {
        match &outcome.result {
            FixtureResult::Passed => println!("PASS {}", outcome.fixture),
            FixtureResult::Failed(failure) => {
                failed += 1;
                println!(
                    "FAIL {} {} {} {}",
                    outcome.fixture, failure.stage, failure.code, failure.pointer
                );
            }
            FixtureResult::HarnessError(error) => {
                failed += 1;
                println!("ERROR {} {}", outcome.fixture, error);
            }
        }
    }
    println!("{} fixtures checked, {} failures", outcomes.len(), failed);
    if failed > 0 {
        bail!("fixture validation failed");
    }
    Ok(())
}

fn validate_artifact_paths(
    cdx: PathBuf,
    aibom: PathBuf,
    bundle: Option<PathBuf>,
    verify_crypto: bool,
    allowlist: Option<PathBuf>,
    schema: Option<PathBuf>,
) -> Result<()> {
    let opts = ValidationOptions {
        verify_crypto,
        allowlist: read_allowlist(allowlist)?,
    };
    let schema = resolve_schema_path_for_aibom(&aibom, schema.as_deref())?;
    match validate_artifacts_with_options(Some(cdx), aibom, bundle, schema, &opts) {
        Ok(()) => {
            println!("PASS artifacts");
            Ok(())
        }
        Err(failure) => {
            println!(
                "FAIL artifacts {} {} {}",
                failure.stage, failure.code, failure.pointer
            );
            bail!("artifact validation failed")
        }
    }
}

fn scan(cmd: ScanCommand) -> Result<()> {
    if cmd.adapters != "mcp" {
        bail!("only --adapters mcp is supported");
    }
    let target_was_explicit = cmd.target.is_some();
    let root = cmd.target.unwrap_or_else(default_target);
    if cmd.dry_run {
        return scan_dry_run(
            root,
            cmd.surface,
            cmd.exclude,
            cmd.surface_config,
            SurfaceConfigOptions {
                no_system_config: cmd.no_system_config,
                require_signed_config: cmd.require_signed_config,
                signer_identity_regexp: cmd.signer_identity_regexp,
            },
            cmd.format,
        );
    }
    if !cmd.surface.is_empty() || !cmd.exclude.is_empty() {
        bail!("--surface/--exclude are currently supported only with --dry-run");
    }
    if cmd.sensitive_data_sarif
        && !(cmd.include_conversation_metadata || cmd.scan_conversation_secrets)
    {
        bail!(
            "--sensitive-data-sarif requires --include-conversation-metadata or --scan-conversation-secrets"
        );
    }
    let custom_surfaces = resolve_surface_config(
        cmd.surface_config.as_deref(),
        &SurfaceConfigOptions {
            no_system_config: cmd.no_system_config,
            require_signed_config: cmd.require_signed_config,
            signer_identity_regexp: cmd.signer_identity_regexp,
        },
    )?
    .surfaces;
    guard_empty_discovery(&root, &custom_surfaces, target_was_explicit)?;
    if cmd.profile && !cmd.profile_yes {
        confirm_profile()?;
    }
    if cmd.introspect_execute && !cmd.introspect_execute_yes {
        confirm_introspection_execution()?;
    }
    let target = Target::filesystem(root.clone());
    let runtime = tokio::runtime::Runtime::new()?;
    let sign = resolve_sign_requested(cmd.sign_mode)?;
    let artifacts = runtime.block_on(scan_target_with_options(
        &target,
        &cmd.output_dir,
        &ScanOptions {
            profile: cmd.profile,
            introspect_execute: cmd.introspect_execute,
            profile_timeout_per_tool_seconds: cmd.profile_timeout_per_tool,
            profile_timeout_total_seconds: cmd.profile_timeout_total,
            custom_surfaces: custom_surfaces.clone(),
            include_conversation_metadata: cmd.include_conversation_metadata,
            scan_conversation_secrets: cmd.scan_conversation_secrets,
            conversation_suppressions_file: cmd.conversation_suppressions_file,
            conversation_rules_file: cmd.conversation_rules_file,
            sensitive_data_sarif: cmd.sensitive_data_sarif,
        },
    ))?;
    let final_artifacts =
        write_scan_bundles(&artifacts, &cmd.output_dir, sign && !cmd.policy_check)?;
    let registry_component_hints = match cmd.registry_source.as_deref() {
        Some(_) => Some(discover_registry_component_hints(
            &runtime,
            &root,
            &custom_surfaces,
        )?),
        None => None,
    };
    let registry_lookup_path = match cmd.registry_source.as_deref() {
        Some(source) => Some(consult_registry_source(
            source,
            &final_artifacts,
            &cmd.output_dir,
            registry_component_hints.as_ref(),
        )?),
        None => None,
    };
    if cmd.policy_check {
        let policy = PolicyCheckCommand {
            scan_dir: cmd.output_dir.clone(),
            profile: cmd.policy_profile,
            verify_crypto: false,
            allowlist: None,
            schema: None,
        };
        let outcome = runtime.block_on(apply_policy_check_for_artifacts(
            &policy,
            final_artifacts.clone(),
            Some(sign),
        ))?;
        print_policy_verdicts(&outcome.verdicts);
    }
    println!("scanId {}", final_artifacts.scan_id);
    println!("cdx {}", final_artifacts.cdx_path.display());
    println!("aibom {}", final_artifacts.aibom_path.display());
    println!("bundle {}", final_artifacts.bundle_path.display());
    if let Some(path) = registry_lookup_path {
        println!("registry-lookup {}", path.display());
    }
    if let Some(path) = final_artifacts.sensitive_report_path {
        println!("sensitive-data {}", path.display());
    }
    if let Some(path) = final_artifacts.sensitive_report_bundle_path {
        println!("sensitive-data-bundle {}", path.display());
    }
    if let Some(path) = final_artifacts.sensitive_sarif_path {
        println!("sensitive-data-sarif {}", path.display());
    }
    Ok(())
}

fn policy_check(cmd: PolicyCheckCommand) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let outcome = runtime.block_on(apply_policy_check(&cmd, None))?;
    print_policy_verdicts(&outcome.verdicts);
    println!("PASS policy-check {}", outcome.aibom_path.display());
    Ok(())
}

fn print_policy_verdicts(verdicts: &[PolicyVerdict]) {
    for verdict in verdicts {
        println!(
            "{} {} {} {}",
            policy_status_label(verdict.status),
            verdict.policy_id,
            verdict.bom_ref.clone().unwrap_or_else(|| "-".to_string()),
            verdict.justification
        );
    }
}

fn guard_empty_discovery(
    root: &Path,
    custom_surfaces: &[CustomSurfaceSpec],
    target_was_explicit: bool,
) -> Result<()> {
    let surfaces = dry_run_surfaces_with_custom(root, custom_surfaces)
        .with_context(|| format!("check discovery surfaces under {}", root.display()))?;
    if surfaces.iter().any(|surface| surface.detected) {
        return Ok(());
    }

    if target_was_explicit {
        eprintln!(
            "WARN: 0 MCP components discovered under --target {}; check --target before trusting an empty inventory",
            root.display()
        );
        return Ok(());
    }

    bail!(
        "scan discovered 0 MCP components under default target {} because --target was omitted; pass --target explicitly or scan the endpoint user home",
        root.display()
    )
}

fn policy_check_sensitive(cmd: SensitivePolicyCheckCommand) -> Result<()> {
    let report = read_json(&cmd.report)
        .with_context(|| format!("read sensitive-data report {}", cmd.report.display()))?;
    let runtime = tokio::runtime::Runtime::new()?;
    let verdicts = runtime.block_on(evaluate_sensitive_data_report(
        &report,
        &PolicyConfig {
            profile: cmd.profile,
            sensitive_data_max_file_count: cmd.max_sensitive_files,
            sensitive_data_max_total_bytes: cmd.max_sensitive_bytes,
            ..PolicyConfig::default()
        },
    ))?;
    for verdict in verdicts {
        println!(
            "{} {} {} {}",
            policy_status_label(verdict.status),
            verdict.policy_id,
            verdict.bom_ref.unwrap_or_else(|| "-".to_string()),
            verdict.justification
        );
    }
    println!("PASS policy-check-sensitive {}", cmd.report.display());
    Ok(())
}

fn scope_list(
    surface_filters: Vec<String>,
    surface_config: Option<PathBuf>,
    config_options: SurfaceConfigOptions,
    format: OutputFormat,
) -> Result<()> {
    let mut catalog = aibom_scanner::mcp::discovery::scope_catalog();
    let resolved = resolve_surface_config(surface_config.as_deref(), &config_options)?;
    catalog.extend(custom_scope_catalog(&resolved.surfaces));
    let entries = filter_catalog(catalog, &surface_filters);
    match format {
        OutputFormat::Human => {
            println!("{}", resolved.status.human_label());
            for entry in entries {
                let trust = if entry
                    .os_paths
                    .iter()
                    .any(|path| path.source.as_ref() == "user-defined")
                {
                    " user-defined lower-trust"
                } else {
                    ""
                };
                println!(
                    "surface {} adapter {}{}",
                    entry.surface, entry.adapter, trust
                );
                println!("  format {}", format_label(entry.format));
                for path in entry.os_paths {
                    println!("  {} {} {}", path.os, path.source, path.path);
                }
                if let Some(search) = entry.workspace_search {
                    let parent = search.parent_dir.unwrap_or("*");
                    println!(
                        "  workspace filename {} parent {} max-depth {}",
                        search.filename, parent, search.max_depth
                    );
                }
                for search in entry.workspace_searches {
                    let parent = search.parent_dir.unwrap_or("*");
                    println!(
                        "  workspace filename {} parent {} max-depth {}",
                        search.filename, parent, search.max_depth
                    );
                }
                for root in entry.roots {
                    let root = root
                        .iter()
                        .map(|segment| segment.as_ref())
                        .collect::<Vec<_>>()
                        .join(".");
                    println!("  root {root}");
                }
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        OutputFormat::Yaml => {
            print!("{}", serde_yaml::to_string(&entries)?);
        }
    }
    Ok(())
}

fn scan_dry_run(
    root: PathBuf,
    surface_filters: Vec<String>,
    exclude_filters: Vec<String>,
    surface_config: Option<PathBuf>,
    config_options: SurfaceConfigOptions,
    format: OutputFormat,
) -> Result<()> {
    let resolved = resolve_surface_config(surface_config.as_deref(), &config_options)?;
    let surfaces = filter_dry_run(
        dry_run_surfaces_with_custom(&root, &resolved.surfaces)?,
        &surface_filters,
        &exclude_filters,
    );
    match format {
        OutputFormat::Human => {
            println!("dry-run target {}", root.display());
            println!("dry-run reads no config contents and writes no AIBOM");
            println!("{}", resolved.status.human_label());
            for surface in surfaces {
                if surface.detected {
                    println!("DETECTED {} {}", surface.surface, surface.reason);
                    for entry in surface.entries {
                        println!(
                            "  WOULD_READ {} {} ({})",
                            entry.path.display(),
                            entry.source,
                            entry.reason
                        );
                    }
                } else {
                    println!("SKIP {} {}", surface.surface, surface.reason);
                }
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&surfaces)?);
        }
        OutputFormat::Yaml => {
            print!("{}", serde_yaml::to_string(&surfaces)?);
        }
    }
    Ok(())
}

struct ResolvedSurfaceConfig {
    surfaces: Vec<CustomSurfaceSpec>,
    status: SurfaceConfigStatus,
}

enum SurfaceConfigStatus {
    Explicit(PathBuf),
    SystemApplied(PathBuf),
    SystemMissing(PathBuf),
    SystemDisabled(PathBuf),
}

impl SurfaceConfigStatus {
    fn human_label(&self) -> String {
        match self {
            SurfaceConfigStatus::Explicit(path) => {
                format!("surface-config explicit {}", path.display())
            }
            SurfaceConfigStatus::SystemApplied(path) => {
                format!("surface-config system {} applied", path.display())
            }
            SurfaceConfigStatus::SystemMissing(path) => {
                format!("surface-config system {} missing", path.display())
            }
            SurfaceConfigStatus::SystemDisabled(path) => {
                format!("surface-config system {} disabled", path.display())
            }
        }
    }
}

fn resolve_surface_config(
    explicit: Option<&Path>,
    options: &SurfaceConfigOptions,
) -> Result<ResolvedSurfaceConfig> {
    if let Some(path) = explicit {
        return Ok(ResolvedSurfaceConfig {
            surfaces: load_signed_custom_surfaces(path, options)?,
            status: SurfaceConfigStatus::Explicit(path.to_path_buf()),
        });
    }

    let system_path = system_surface_config_path();
    if options.no_system_config {
        return Ok(ResolvedSurfaceConfig {
            surfaces: Vec::new(),
            status: SurfaceConfigStatus::SystemDisabled(system_path),
        });
    }

    let exists = system_path
        .try_exists()
        .with_context(|| format!("check system surface config {}", system_path.display()))?;
    if exists {
        Ok(ResolvedSurfaceConfig {
            surfaces: load_signed_custom_surfaces(&system_path, options)
                .with_context(|| format!("load system surface config {}", system_path.display()))?,
            status: SurfaceConfigStatus::SystemApplied(system_path),
        })
    } else {
        Ok(ResolvedSurfaceConfig {
            surfaces: Vec::new(),
            status: SurfaceConfigStatus::SystemMissing(system_path),
        })
    }
}

fn load_signed_custom_surfaces(
    config_path: &Path,
    options: &SurfaceConfigOptions,
) -> Result<Vec<CustomSurfaceSpec>> {
    verify_surface_config_bundle(config_path, options)?;
    load_custom_surfaces(config_path)
}

fn verify_surface_config_bundle(
    config_path: &Path,
    options: &SurfaceConfigOptions,
) -> Result<SurfaceConfigSignatureStatus> {
    let signature_path = surface_config_signature_path(config_path);
    if !signature_path.try_exists().with_context(|| {
        format!(
            "check surface config signature {}",
            signature_path.display()
        )
    })? {
        if options.require_signed_config {
            bail!(
                "surface config signature missing for {}; expected {}",
                config_path.display(),
                signature_path.display()
            );
        }
        eprintln!(
            "WARN surface config {} is unsigned; pass --require-signed-config to fail closed",
            config_path.display()
        );
        return Ok(SurfaceConfigSignatureStatus::Unsigned);
    }

    let config_bytes = std::fs::read(config_path)
        .with_context(|| format!("read surface config {}", config_path.display()))?;
    let bundle_bytes = std::fs::read(&signature_path)
        .with_context(|| format!("read surface config signature {}", signature_path.display()))?;
    let bundle: Value = serde_json::from_slice(&bundle_bytes).with_context(|| {
        format!(
            "parse surface config signature {}",
            signature_path.display()
        )
    })?;

    if is_fixture_surface_config_bundle(&bundle) {
        verify_fixture_surface_config_bundle(config_path, &config_bytes, &bundle, options)?;
    } else {
        verify_real_surface_config_bundle(config_path, &signature_path, options)?;
    }
    Ok(SurfaceConfigSignatureStatus::Verified)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurfaceConfigSignatureStatus {
    Verified,
    Unsigned,
}

fn surface_config_signature_path(config_path: &Path) -> PathBuf {
    let file_name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("surfaces.yaml");
    config_path.with_file_name(format!("{file_name}.sigstore.json"))
}

fn is_fixture_surface_config_bundle(bundle: &Value) -> bool {
    bundle
        .pointer("/verificationMaterial/_fixture_note")
        .and_then(Value::as_str)
        == Some("reeve surface-config fixture")
}

fn verify_fixture_surface_config_bundle(
    config_path: &Path,
    config_bytes: &[u8],
    bundle: &Value,
    options: &SurfaceConfigOptions,
) -> Result<()> {
    if std::env::var_os("REEVE_ACCEPT_FIXTURE_SURFACE_CONFIG_SIGNATURE").is_none() {
        bail!(
            "fixture surface config signature refused for {}; set REEVE_ACCEPT_FIXTURE_SURFACE_CONFIG_SIGNATURE=1 only in tests",
            config_path.display()
        );
    }
    let sig = bundle
        .pointer("/dsseEnvelope/signatures/0/sig")
        .and_then(Value::as_str)
        .context("surface config fixture signature missing")?;
    if sig != "FIXTURE_SURFACE_CONFIG_SIGNATURE" {
        bail!("surface config fixture signature invalid");
    }
    verify_surface_config_statement(bundle, config_path, config_bytes)?;
    verify_surface_config_signer_identity(bundle, options)?;
    Ok(())
}

fn verify_surface_config_statement(
    bundle: &Value,
    config_path: &Path,
    config_bytes: &[u8],
) -> Result<()> {
    let payload_type = bundle
        .pointer("/dsseEnvelope/payloadType")
        .and_then(Value::as_str)
        .context("surface config signature missing DSSE payloadType")?;
    if payload_type != aibom_core::DSSE_PAYLOAD_TYPE {
        bail!("surface config signature payloadType mismatch");
    }
    let payload = bundle
        .pointer("/dsseEnvelope/payload")
        .and_then(Value::as_str)
        .context("surface config signature missing DSSE payload")?;
    let statement_bytes = BASE64_STANDARD
        .decode(payload)
        .context("decode surface config signature payload")?;
    let statement: Value =
        serde_json::from_slice(&statement_bytes).context("parse surface config statement")?;
    if statement.pointer("/_type").and_then(Value::as_str)
        != Some(aibom_core::IN_TOTO_STATEMENT_TYPE)
    {
        bail!("surface config statement type mismatch");
    }
    if statement.pointer("/predicateType").and_then(Value::as_str)
        != Some(SURFACE_CONFIG_PREDICATE_TYPE)
    {
        bail!("surface config predicateType mismatch");
    }
    let subject = statement
        .pointer("/subject")
        .and_then(Value::as_array)
        .context("surface config statement missing subject")?;
    if subject.len() != 1 {
        bail!("surface config statement must name exactly one subject");
    }
    let expected_name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("surfaces.yaml");
    if subject[0].pointer("/name").and_then(Value::as_str) != Some(expected_name) {
        bail!("surface config statement subject name mismatch");
    }
    let expected_hash = sha256_hex(config_bytes);
    if subject[0].pointer("/digest/sha256").and_then(Value::as_str) != Some(expected_hash.as_str())
    {
        bail!("surface config signature hash mismatch");
    }
    Ok(())
}

fn verify_surface_config_signer_identity(
    bundle: &Value,
    options: &SurfaceConfigOptions,
) -> Result<()> {
    let Some(expected) = surface_config_signer_identity_regexp(options) else {
        bail!(
            "signed surface config requires --signer-identity-regexp or REEVE_SURFACE_CONFIG_SIGNER_IDENTITY_REGEXP"
        );
    };
    let subject = bundle
        .pointer("/verificationMaterial/certificate/oidcSubject")
        .and_then(Value::as_str)
        .context("surface config signature missing OIDC subject")?;
    let regexp = Regex::new(&expected).context("parse --signer-identity-regexp")?;
    if !regexp.is_match(subject) {
        bail!("surface config signer identity mismatch: {subject}");
    }
    Ok(())
}

fn verify_real_surface_config_bundle(
    config_path: &Path,
    signature_path: &Path,
    options: &SurfaceConfigOptions,
) -> Result<()> {
    let Some(expected) = surface_config_signer_identity_regexp(options) else {
        bail!(
            "signed surface config requires --signer-identity-regexp or REEVE_SURFACE_CONFIG_SIGNER_IDENTITY_REGEXP"
        );
    };
    let status = std::process::Command::new(cosign_binary())
        .args([
            "verify-blob",
            "--bundle",
            signature_path
                .to_str()
                .context("signature path is not UTF-8")?,
            "--certificate-identity-regexp",
            &expected,
            "--certificate-oidc-issuer",
            DEFAULT_SIGSTORE_OIDC_ISSUER,
            config_path
                .to_str()
                .context("surface config path is not UTF-8")?,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("spawn {}", cosign_binary().display()))?;
    if !status.success() {
        bail!(
            "cosign verify-blob failed for surface config {}",
            config_path.display()
        );
    }
    Ok(())
}

fn surface_config_signer_identity_regexp(options: &SurfaceConfigOptions) -> Option<String> {
    options
        .signer_identity_regexp
        .clone()
        .or_else(|| option_env!("REEVE_SURFACE_CONFIG_SIGNER_IDENTITY_REGEXP").map(str::to_string))
}

fn system_surface_config_path() -> PathBuf {
    if let Some(path) = std::env::var_os("REEVE_SYSTEM_SURFACE_CONFIG") {
        return PathBuf::from(path);
    }

    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Reeve/surfaces.yaml")
    } else if cfg!(target_os = "windows") {
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Reeve")
            .join("surfaces.yaml")
    } else {
        PathBuf::from("/etc/reeve/surfaces.yaml")
    }
}

fn filter_catalog(
    entries: Vec<ScopeCatalogEntry>,
    surface_filters: &[String],
) -> Vec<ScopeCatalogEntry> {
    entries
        .into_iter()
        .filter(|entry| surface_included(entry.surface.as_ref(), surface_filters, &[]))
        .collect()
}

fn filter_dry_run(
    entries: Vec<DryRunSurface>,
    surface_filters: &[String],
    exclude_filters: &[String],
) -> Vec<DryRunSurface> {
    entries
        .into_iter()
        .filter(|entry| surface_included(entry.surface.as_ref(), surface_filters, exclude_filters))
        .collect()
}

fn surface_included(surface: &str, include: &[String], exclude: &[String]) -> bool {
    (include.is_empty() || include.iter().any(|filter| filter == surface))
        && !exclude.iter().any(|filter| filter == surface)
}

fn format_label(format: aibom_scanner::mcp::discovery::ConfigFormat) -> &'static str {
    match format {
        aibom_scanner::mcp::discovery::ConfigFormat::Json => "json",
        aibom_scanner::mcp::discovery::ConfigFormat::JsonOrYaml => "json-or-yaml",
        aibom_scanner::mcp::discovery::ConfigFormat::Toml => "toml",
    }
}

fn write_scan_bundles(
    artifacts: &ScannerScanArtifacts,
    output_dir: &Path,
    sign: bool,
) -> Result<ScanOutputArtifacts> {
    let bundle_path = scan_bundle_path(output_dir, &artifacts.scan_id, sign);
    write_bundle(
        &bundle_path,
        &artifacts.cdx_path,
        &artifacts.aibom_path,
        sign,
        &artifacts.cdx_bytes,
        &artifacts.aibom_bytes,
    )?;
    let mut output = ScanOutputArtifacts {
        scan_id: artifacts.scan_id.clone(),
        cdx_path: artifacts.cdx_path.clone(),
        aibom_path: artifacts.aibom_path.clone(),
        bundle_path,
        sensitive_report_path: artifacts.sensitive_report_path.clone(),
        sensitive_report_bundle_path: None,
        sensitive_sarif_path: artifacts.sensitive_sarif_path.clone(),
    };
    match (
        artifacts.sensitive_report_path.as_ref(),
        artifacts.sensitive_report_bytes.as_ref(),
    ) {
        (Some(report_path), Some(report_bytes)) => {
            let report_bundle_path =
                sensitive_report_bundle_path(output_dir, &artifacts.scan_id, sign);
            write_sensitive_report_bundle(&report_bundle_path, report_path, report_bytes, sign)?;
            output.sensitive_report_bundle_path = Some(report_bundle_path);
        }
        (None, None) => {}
        _ => bail!("sensitive data report path/bytes mismatch"),
    };
    Ok(output)
}

fn scan_bundle_path(output_dir: &Path, scan_id: &str, sign: bool) -> PathBuf {
    output_dir.join(if sign {
        format!("{scan_id}.sigstore.json")
    } else {
        format!("{scan_id}.sigstore.fixture.json")
    })
}

fn sensitive_report_bundle_path(output_dir: &Path, scan_id: &str, sign: bool) -> PathBuf {
    output_dir.join(if sign {
        format!("{scan_id}.sensitive-data.sigstore.json")
    } else {
        format!("{scan_id}.sensitive-data.sigstore.fixture.json")
    })
}

fn write_sensitive_report_bundle(
    bundle_path: &Path,
    report_path: &Path,
    report_bytes: &[u8],
    sign: bool,
) -> Result<()> {
    let report_name = report_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("missing sensitive report filename")?;
    let statement = build_sensitive_data_report_statement(&SensitiveDataReportArtifact {
        report_name,
        report_bytes,
    });
    if sign {
        OnlineSigstoreSigner::from_env().sign_statement_to_bundle(
            &statement,
            report_bytes,
            bundle_path,
        )?;
    } else {
        write_fixture_bundle_for_statement(bundle_path, &statement)?;
    }
    Ok(())
}

async fn apply_policy_check(
    cmd: &PolicyCheckCommand,
    prefer_real_sign: Option<bool>,
) -> Result<PolicyCheckOutcome> {
    let artifacts = locate_scan_artifacts(&cmd.scan_dir)?;
    apply_policy_check_for_artifacts(cmd, artifacts, prefer_real_sign).await
}

async fn apply_policy_check_for_artifacts(
    cmd: &PolicyCheckCommand,
    artifacts: ScanOutputArtifacts,
    prefer_real_sign: Option<bool>,
) -> Result<PolicyCheckOutcome> {
    validate_artifacts_silent(
        &artifacts.cdx_path,
        &artifacts.aibom_path,
        Some(&artifacts.bundle_path),
        cmd.verify_crypto,
        cmd.allowlist.clone(),
        cmd.schema.as_deref(),
    )?;

    let mut aibom_root = read_json(&artifacts.aibom_path)?;
    let mut cdx_root = read_json(&artifacts.cdx_path)?;
    let bundle_root = read_json(&artifacts.bundle_path).ok();
    let signature = SignatureFacts {
        present: bundle_root.is_some(),
        verified: false,
        issuer: None,
        subject: None,
        bundle_version: bundle_root.as_ref().and_then(|bundle| {
            bundle
                .get("mediaType")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        }),
    };
    let mut verdicts = evaluate_policies(
        &aibom_root,
        Some(&cdx_root),
        &signature,
        &PolicyConfig {
            profile: cmd.profile.clone(),
            extension_allowlist: vec!["mcp".to_string()],
            ..PolicyConfig::default()
        },
    )
    .await?;
    let evidence_ids = rewrite_policy_payload(&mut aibom_root, &mut verdicts)?;
    let aibom_bytes = canonicalize_json(&aibom_root)?;
    let aibom_hash = sha256_hex(&aibom_bytes);
    update_cdx_hashes(&mut cdx_root, &artifacts.aibom_path, &aibom_hash)?;
    let cdx_bytes = canonicalize_json(&cdx_root)?;
    std::fs::write(&artifacts.aibom_path, &aibom_bytes)?;
    std::fs::write(&artifacts.cdx_path, &cdx_bytes)?;
    write_bundle(
        &artifacts.bundle_path,
        &artifacts.cdx_path,
        &artifacts.aibom_path,
        prefer_real_sign.unwrap_or_else(|| {
            artifacts
                .bundle_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".sigstore.json"))
                && cosign_available()
        }),
        &cdx_bytes,
        &aibom_bytes,
    )?;

    let _ = evidence_ids;
    Ok(PolicyCheckOutcome {
        aibom_path: artifacts.aibom_path,
        verdicts,
    })
}

fn rewrite_policy_payload(
    aibom_root: &mut Value,
    verdicts: &mut [PolicyVerdict],
) -> Result<Vec<String>> {
    let aibom = aibom_root
        .get_mut("aibom")
        .and_then(Value::as_object_mut)
        .context("missing aibom body")?;

    let scan_id = aibom
        .get("scan")
        .and_then(Value::as_object)
        .and_then(|scan| scan.get("scanId"))
        .and_then(Value::as_str)
        .unwrap_or("scan")
        .to_string();
    let evidence = aibom
        .get_mut("evidence")
        .and_then(Value::as_array_mut)
        .context("missing evidence ledger")?;
    evidence.retain(|entry| entry.get("kind").and_then(Value::as_str) != Some("policy-verdict"));
    let mut evidence_ids = Vec::new();
    let verdict_values: Vec<Value> = verdicts
        .iter_mut()
        .enumerate()
        .map(|(index, verdict)| {
            let evidence_id = format!("ev-policy-{index:03}");
            evidence_ids.push(evidence_id.clone());
            verdict.evidence = vec![evidence_id.clone()];
            evidence.push(json!({
                "id": evidence_id,
                "kind": "policy-verdict",
                "reference": format!("policy://{}/{}/{}", scan_id, verdict.policy_id, verdict.id)
            }));
            let mut value = json!({
                "id": verdict.id,
                "policyId": verdict.policy_id,
                "status": policy_status_text(verdict.status),
                "justification": verdict.justification,
                "references": verdict.references,
                "evidence": verdict.evidence,
            });
            if let Some(bom_ref) = &verdict.bom_ref {
                value["bomRef"] = json!(bom_ref);
            }
            value
        })
        .collect();
    evidence.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });
    aibom.insert("policyVerdicts".to_string(), Value::Array(verdict_values));
    Ok(evidence_ids)
}

fn update_cdx_hashes(cdx_root: &mut Value, aibom_path: &Path, hash: &str) -> Result<()> {
    let aibom_name = aibom_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("aibom filename missing")?;
    let components = cdx_root
        .get_mut("components")
        .and_then(Value::as_array_mut)
        .context("cyclonedx components missing")?;
    for component in components {
        let refs = component
            .get_mut("externalReferences")
            .and_then(Value::as_array_mut)
            .context("cyclonedx externalReferences missing")?;
        for ext_ref in refs {
            if ext_ref.get("type").and_then(Value::as_str) == Some("bom") {
                ext_ref["url"] = json!(aibom_name);
                if let Some(hashes) = ext_ref.get_mut("hashes").and_then(Value::as_array_mut) {
                    for digest in hashes {
                        if digest.get("alg").and_then(Value::as_str) == Some("SHA-256") {
                            digest["content"] = json!(hash);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn write_bundle(
    bundle_path: &Path,
    cdx_path: &Path,
    aibom_path: &Path,
    sign: bool,
    cdx_bytes: &[u8],
    aibom_bytes: &[u8],
) -> Result<()> {
    let cdx_name = cdx_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("missing cdx filename")?;
    let aibom_name = aibom_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("missing aibom filename")?;
    let pair = ArtifactPair {
        cdx_name,
        cdx_bytes,
        aibom_name,
        aibom_bytes,
    };
    if sign {
        OnlineSigstoreSigner::from_env().sign_pair_to_bundle(&pair, bundle_path)?;
    } else {
        write_fixture_bundle(bundle_path, &pair)?;
    }
    Ok(())
}

/// Resolve the user's `--sign / --skip-sign / --sign-mode / REEVE_SIGN_MODE`
/// inputs into a single `SignMode`. Precedence:
///
/// 1. `--skip-sign` forces `Fixture` (explicit opt-out for demos/tests).
/// 2. `--sign-mode` (or `REEVE_SIGN_MODE`, which clap reads as the same flag).
/// 3. The legacy `--sign` flag (default true) falls through to `Auto`.
fn resolve_sign_mode(sign: bool, skip_sign: bool, sign_mode: Option<SignMode>) -> SignMode {
    if skip_sign {
        return SignMode::Fixture;
    }
    if let Some(mode) = sign_mode {
        return mode;
    }
    if sign {
        SignMode::Auto
    } else {
        SignMode::Fixture
    }
}

/// Enforce the sign-mode decision: `Real` hard-fails when cosign is not
/// reachable so explicit real-signing cannot silently downgrade to a fixture
/// bundle. `Auto` keeps legacy behavior (use cosign when available, warn and
/// emit fixture otherwise). `Fixture` always emits the placeholder bundle.
fn resolve_sign_requested(mode: SignMode) -> Result<bool> {
    match mode {
        SignMode::Real => {
            if !cosign_available() {
                bail!(
                    "--sign-mode real requires 'cosign' in PATH (tried '{}'). \
                     Install cosign ('brew install cosign' on macOS, apt/yum on Linux, \
                     or https://docs.sigstore.dev/cosign/installation) \
                     or set REEVE_COSIGN_BIN to a working binary. \
                     To emit a deterministic fixture Sigstore bundle for tests or demos instead, \
                     pass --sign-mode fixture or --skip-sign.",
                    cosign_binary().display()
                );
            }
            Ok(true)
        }
        SignMode::Fixture => Ok(false),
        SignMode::Auto => {
            if cosign_available() {
                Ok(true)
            } else {
                eprintln!(
                    "WARN cosign unavailable; emitting fixture Sigstore bundle. \
                     Pass --sign-mode real to require cosign and fail explicitly."
                );
                Ok(false)
            }
        }
    }
}

fn validate_artifacts_silent(
    cdx: &Path,
    aibom: &Path,
    bundle: Option<&Path>,
    verify_crypto: bool,
    allowlist: Option<PathBuf>,
    schema: Option<&Path>,
) -> Result<()> {
    let opts = ValidationOptions {
        verify_crypto,
        allowlist: read_allowlist(allowlist)?,
    };
    let schema = resolve_schema_path_for_aibom(aibom, schema)?;
    validate_artifacts_with_options(Some(cdx), aibom, bundle, schema, &opts).map_err(|failure| {
        anyhow::anyhow!(
            "artifact validation failed: {} {} {}",
            failure.stage,
            failure.code,
            failure.pointer
        )
    })
}

fn locate_scan_artifacts(scan_dir: &Path) -> Result<ScanOutputArtifacts> {
    let cdx_path = find_one(scan_dir, ".cdx.json")?;
    let aibom_path = find_one(scan_dir, ".aibom.json")?;
    let bundle_path = find_one_excluding(scan_dir, ".sigstore.fixture.json", ".sensitive-data.")
        .or_else(|_| find_one_excluding(scan_dir, ".sigstore.json", ".sensitive-data."))?;
    let scan_id = aibom_path
        .file_stem()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".aibom"))
        .unwrap_or("scan")
        .to_string();
    Ok(ScanOutputArtifacts {
        scan_id,
        cdx_path,
        aibom_path,
        bundle_path,
        sensitive_report_path: find_one(scan_dir, ".sensitive-data.json").ok(),
        sensitive_report_bundle_path: find_one(scan_dir, ".sensitive-data.sigstore.fixture.json")
            .or_else(|_| find_one(scan_dir, ".sensitive-data.sigstore.json"))
            .ok(),
        sensitive_sarif_path: find_one(scan_dir, ".sensitive-data.sarif.json").ok(),
    })
}

fn confirm_profile() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("--profile requires --profile-yes when stdin is not interactive");
    }
    eprintln!(
        "Reeve is about to launch discovered MCP servers under an OS sandbox. The sandbox denies network egress and restricts filesystem writes to a dedicated tempdir. Continue? [y/N]"
    );
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        bail!("sandbox profiling cancelled");
    }
    Ok(())
}

fn confirm_introspection_execution() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "--introspect-execute requires --introspect-execute-yes when stdin is not interactive"
        );
    }
    eprintln!(
        "Reeve is about to execute discovered stdio MCP servers with your user privileges to request tools/list. This is separate from sandbox profiling. Continue? [y/N]"
    );
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
        bail!("stdio introspection cancelled");
    }
    Ok(())
}

fn cosign_binary() -> PathBuf {
    std::env::var_os("REEVE_COSIGN_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cosign"))
}

fn cosign_available() -> bool {
    std::process::Command::new(cosign_binary())
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn verify(
    scan_dir: PathBuf,
    verify_crypto: bool,
    allowlist: Option<PathBuf>,
    schema: Option<PathBuf>,
) -> Result<()> {
    let artifacts = locate_scan_artifacts(&scan_dir)?;
    validate_artifact_paths(
        artifacts.cdx_path,
        artifacts.aibom_path,
        Some(artifacts.bundle_path),
        verify_crypto,
        allowlist,
        schema,
    )
}

fn report(
    aibom_path: PathBuf,
    format: ReportFormat,
    output: PathBuf,
    sensitive_data: Option<PathBuf>,
) -> Result<()> {
    let aibom =
        read_json(&aibom_path).with_context(|| format!("read AIBOM {}", aibom_path.display()))?;
    let sensitive_path = match sensitive_data {
        Some(path) => Some(path),
        None => locate_sibling_sensitive_report(&aibom_path),
    };
    let sensitive = match sensitive_path.as_deref() {
        Some(path) => {
            let value = read_json(path)
                .with_context(|| format!("read sensitive-data report {}", path.display()))?;
            Some(value)
        }
        None => None,
    };
    let sensitive_input = sensitive_path
        .as_deref()
        .zip(sensitive.as_ref())
        .map(|(path, value)| SensitiveReportInput { path, value });
    let report = build_machine_report(&aibom, &aibom_path, sensitive_input)?;
    let bytes = match format {
        ReportFormat::Json => serde_json::to_vec_pretty(&report)?,
        ReportFormat::Html => render_report_html(&report).into_bytes(),
        ReportFormat::Pdf => render_report_pdf(&report),
    };
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output, bytes)?;
    println!("report {}", output.display());
    Ok(())
}

fn fleet_report(evidence_dir: PathBuf, output: PathBuf, format: FleetReportFormat) -> Result<()> {
    let report = build_fleet_report(&evidence_dir)?;
    let bytes = match format {
        FleetReportFormat::Json => serde_json::to_vec_pretty(&report)?,
        FleetReportFormat::Markdown => render_fleet_report_markdown(&report).into_bytes(),
        FleetReportFormat::Html => render_fleet_report_html(&report).into_bytes(),
    };
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output, bytes)?;
    println!("fleet-report {}", output.display());
    Ok(())
}

fn fleet_manifest(
    evidence_dir: PathBuf,
    output: PathBuf,
    bundle: Option<PathBuf>,
    recording_scope: String,
    sign_mode: SignMode,
) -> Result<()> {
    let manifest = build_fleet_manifest(&evidence_dir, &recording_scope)?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output, &manifest_bytes)?;

    let sign_real = resolve_sign_requested(sign_mode)?;
    let bundle_path =
        bundle.unwrap_or_else(|| default_fleet_manifest_bundle_path(&output, sign_real));
    if let Some(parent) = bundle_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let subject_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("fleet-manifest.json");
    let statement = build_fleet_manifest_statement(subject_name, &manifest_bytes);
    if sign_real {
        OnlineSigstoreSigner::from_env().sign_statement_to_bundle(
            &statement,
            &manifest_bytes,
            &bundle_path,
        )?;
    } else {
        write_fixture_bundle_for_statement(&bundle_path, &statement)?;
    }

    println!("fleet-manifest {}", output.display());
    println!("bundle {}", bundle_path.display());
    Ok(())
}

fn build_fleet_manifest(evidence_dir: &Path, recording_scope: &str) -> Result<Value> {
    let artifacts = find_fleet_endpoint_artifacts(evidence_dir)?;
    if artifacts.is_empty() {
        bail!(
            "no endpoint artifacts found under {}",
            evidence_dir.display()
        );
    }

    let mut by_endpoint = BTreeMap::<String, Vec<Value>>::new();
    let mut role_counts = BTreeMap::<String, usize>::new();
    for path in artifacts {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read endpoint artifact {}", path.display()))?;
        let role = fleet_artifact_role(&path)
            .with_context(|| format!("classify endpoint artifact {}", path.display()))?;
        *role_counts.entry(role.to_string()).or_default() += 1;
        let endpoint_id = fleet_endpoint_id(evidence_dir, &path);
        let rel_path = relative_slash_path(evidence_dir, &path)?;
        by_endpoint.entry(endpoint_id).or_default().push(json!({
            "path": rel_path,
            "fileName": path.file_name().and_then(|name| name.to_str()).unwrap_or(""),
            "role": role,
            "sha256": sha256_hex(&bytes),
            "sizeBytes": bytes.len()
        }));
    }

    let endpoints = by_endpoint
        .into_iter()
        .map(|(endpoint_id, artifacts)| {
            json!({
                "endpointId": endpoint_id,
                "artifactCount": artifacts.len(),
                "artifacts": artifacts
            })
        })
        .collect::<Vec<_>>();
    let total_artifacts = endpoints
        .iter()
        .filter_map(|endpoint| endpoint["artifactCount"].as_u64())
        .sum::<u64>();
    let generated_at_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    Ok(json!({
        "kind": "reeve-demo-fleet-manifest",
        "schemaVersion": "0.1.0",
        "recordingScope": recording_scope,
        "generatedAtUnix": generated_at_unix,
        "summary": {
            "endpoints": endpoints.len(),
            "artifacts": total_artifacts,
            "artifactRoles": role_counts
        },
        "endpoints": endpoints
    }))
}

fn build_fleet_manifest_statement(subject_name: &str, manifest_bytes: &[u8]) -> Value {
    let mut artifact_roles = serde_json::Map::new();
    artifact_roles.insert(subject_name.to_string(), json!("fleet-manifest"));
    json!({
        "_type": IN_TOTO_STATEMENT_TYPE,
        "predicateType": FLEET_MANIFEST_PREDICATE_TYPE,
        "subject": [{
            "name": subject_name,
            "digest": {"sha256": sha256_hex(manifest_bytes)}
        }],
        "predicate": {
            "artifactRoles": artifact_roles,
            "canonicalization": "JSON-pretty+stable-artifact-order-v0.1",
            "schemaVersion": "0.1.0"
        }
    })
}

fn default_fleet_manifest_bundle_path(output: &Path, sign_real: bool) -> PathBuf {
    let stem = output
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("fleet-manifest");
    let suffix = if sign_real {
        "sigstore.json"
    } else {
        "sigstore.fixture.json"
    };
    output.with_file_name(format!("{stem}.{suffix}"))
}

fn mcp_registry_fetch(
    base_url: String,
    limit: u32,
    updated_since: Option<String>,
    output: PathBuf,
) -> Result<()> {
    let fetcher = HttpPageFetcher::new().map_err(anyhow::Error::msg)?;
    let result = fetch_all(
        PaginatorConfig {
            base_url,
            limit,
            updated_since,
            max_retries: 5,
            backoff_base: Duration::from_secs(1),
        },
        &fetcher,
        &|delay| std::thread::sleep(delay),
    )
    .map_err(anyhow::Error::msg)?;
    let merged_bytes = canonicalize_json(&result.merged)?;
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output, &merged_bytes)
        .with_context(|| format!("write merged registry pages {}", output.display()))?;
    for page in &result.pages {
        println!(
            "page cursor {} sha256 {} bytes {} {}",
            page.cursor.as_deref().unwrap_or("-"),
            page.sha256,
            page.bytes.len(),
            page.url
        );
    }
    println!(
        "mcp-registry-fetch {} pages {} servers {}",
        result.pages.len(),
        result.servers.len(),
        output.display()
    );
    Ok(())
}

fn mcp_registry_seed(
    input: PathBuf,
    output: PathBuf,
    bundle: Option<PathBuf>,
    source_url: String,
    sign_mode: SignMode,
) -> Result<()> {
    let input_bytes = std::fs::read(&input)
        .with_context(|| format!("read registry input {}", input.display()))?;
    let registry_page: Value = serde_json::from_slice(&input_bytes)
        .with_context(|| format!("parse registry input {}", input.display()))?;
    let seed = build_mcp_registry_seed(&registry_page, &source_url, &input_bytes)?;
    let seed_bytes = canonicalize_json(&seed)?;
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output, &seed_bytes)?;

    let sign_real = resolve_sign_requested(sign_mode)?;
    let bundle_path =
        bundle.unwrap_or_else(|| default_mcp_registry_seed_bundle_path(&output, sign_real));
    if let Some(parent) = bundle_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let subject_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("mcp-registry-seed.json");
    let statement = build_mcp_registry_seed_statement(subject_name, &seed_bytes, &source_url);
    if sign_real {
        OnlineSigstoreSigner::from_env().sign_statement_to_bundle(
            &statement,
            &seed_bytes,
            &bundle_path,
        )?;
    } else {
        write_fixture_bundle_for_statement(&bundle_path, &statement)?;
    }

    println!("mcp-registry-seed {}", output.display());
    println!("bundle {}", bundle_path.display());
    Ok(())
}

fn build_mcp_registry_seed(
    registry_page: &Value,
    source_url: &str,
    input_bytes: &[u8],
) -> Result<Value> {
    let servers = registry_page
        .get("servers")
        .and_then(Value::as_array)
        .context("official registry page missing servers array")?;
    if servers.is_empty() {
        bail!("official registry page contains no servers");
    }

    let mut records = BTreeMap::<String, Value>::new();
    for entry in servers {
        let server = entry
            .get("server")
            .and_then(Value::as_object)
            .context("registry server entry missing server object")?;
        let name = server
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("registry server missing name")?;
        let version = server
            .get("version")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("registry server missing version")?;
        let (publisher, package_name) = split_registry_server_name(name);
        let registry_meta = entry
            .get("_meta")
            .and_then(|meta| meta.get("io.modelcontextprotocol.registry/official"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let dedupe_key = format!("official-mcp-registry|{name}|{version}");
        let record = json!({
            "id": format!("official-mcp-registry:{name}@{version}"),
            "dedupeKey": dedupe_key.clone(),
            "sourceRegistry": "official-mcp-registry",
            "sourceUrl": source_url,
            "canonicalIdentity": {
                "name": name,
                "publisher": publisher,
                "packageName": package_name,
                "version": version
            },
            "title": server.get("title").cloned().unwrap_or(Value::Null),
            "description": server.get("description").cloned().unwrap_or(Value::Null),
            "declaredMetadata": declared_registry_metadata(server),
            "registryMetadata": registry_meta
        });
        records.entry(dedupe_key).or_insert(record);
    }

    let records = records.into_values().collect::<Vec<_>>();
    let active = records
        .iter()
        .filter(|record| {
            record["registryMetadata"]["status"]
                .as_str()
                .is_some_and(|status| status == "active")
        })
        .count();
    let latest = records
        .iter()
        .filter(|record| {
            record["registryMetadata"]["isLatest"]
                .as_bool()
                .unwrap_or(false)
        })
        .count();
    Ok(json!({
        "kind": "reeve-mcp-registry-seed",
        "schemaVersion": "0.1.0",
        "source": {
            "kind": "official-mcp-registry",
            "url": source_url,
            "apiVersion": "v0.1",
            "termsUrl": "https://modelcontextprotocol.io/registry/terms-of-service",
            "inputSha256": sha256_hex(input_bytes)
        },
        "dedupe": {
            "keyFields": ["sourceRegistry", "canonicalIdentity.name", "canonicalIdentity.version"],
            "format": "official-mcp-registry|<name>|<version>"
        },
        "summary": {
            "sourceRecords": servers.len(),
            "records": records.len(),
            "activeRecords": active,
            "latestRecords": latest
        },
        "records": records
    }))
}

fn split_registry_server_name(name: &str) -> (Value, Value) {
    if let Some((publisher, package_name)) = name.split_once('/') {
        (json!(publisher), json!(package_name))
    } else {
        (Value::Null, json!(name))
    }
}

fn declared_registry_metadata(server: &serde_json::Map<String, Value>) -> Value {
    let mut metadata = serde_json::Map::new();
    for (key, value) in server {
        if !matches!(key.as_str(), "name" | "version" | "title" | "description") {
            metadata.insert(key.clone(), value.clone());
        }
    }
    Value::Object(metadata)
}

fn build_mcp_registry_seed_statement(
    subject_name: &str,
    seed_bytes: &[u8],
    source_url: &str,
) -> Value {
    let mut artifact_roles = serde_json::Map::new();
    artifact_roles.insert(subject_name.to_string(), json!("mcp-registry-seed"));
    json!({
        "_type": IN_TOTO_STATEMENT_TYPE,
        "predicateType": MCP_REGISTRY_SEED_PREDICATE_TYPE,
        "subject": [{
            "name": subject_name,
            "digest": {"sha256": sha256_hex(seed_bytes)}
        }],
        "predicate": {
            "artifactRoles": artifact_roles,
            "canonicalization": "RFC8785-JCS",
            "source": {
                "kind": "official-mcp-registry",
                "url": source_url,
                "apiVersion": "v0.1"
            },
            "schemaVersion": "0.1.0"
        }
    })
}

fn default_mcp_registry_seed_bundle_path(output: &Path, sign_real: bool) -> PathBuf {
    let stem = output
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("mcp-registry-seed");
    let suffix = if sign_real {
        "sigstore.json"
    } else {
        "sigstore.fixture.json"
    };
    output.with_file_name(format!("{stem}.{suffix}"))
}

fn find_fleet_endpoint_artifacts(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    collect_fleet_endpoint_artifacts(root, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_fleet_endpoint_artifacts(path: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if fleet_artifact_role(path).is_some() {
            paths.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !path.is_dir() {
        bail!("{} is not a directory or file", path.display());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            if entry_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "fleet")
            {
                continue;
            }
            collect_fleet_endpoint_artifacts(&entry_path, paths)?;
        } else if fleet_artifact_role(&entry_path).is_some() {
            paths.push(entry_path);
        }
    }
    Ok(())
}

fn fleet_artifact_role(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    if name.ends_with(".sensitive-data.sigstore.fixture.json") {
        Some("sensitive-data-sigstore-fixture")
    } else if name.ends_with(".sensitive-data.sigstore.json") {
        Some("sensitive-data-sigstore")
    } else if name.ends_with(".sensitive-data.sarif.json") {
        Some("sensitive-data-sarif")
    } else if name.ends_with(".sensitive-data.json") {
        Some("sensitive-data-report")
    } else if name.ends_with(".sigstore.fixture.json") {
        Some("sigstore-fixture")
    } else if name.ends_with(".sigstore.json") {
        Some("sigstore")
    } else if name.ends_with(".aibom.json") {
        Some("aibom-sidecar")
    } else if name.ends_with(".cdx.json") {
        Some("cyclonedx")
    } else {
        None
    }
}

fn fleet_endpoint_id(root: &Path, artifact_path: &Path) -> String {
    let rel = artifact_path.strip_prefix(root).unwrap_or(artifact_path);
    let parts = rel
        .components()
        .filter_map(|part| part.as_os_str().to_str())
        .collect::<Vec<_>>();
    if parts.len() >= 3 && parts[0] == "endpoints" {
        return parts[1].to_string();
    }
    artifact_path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn relative_slash_path(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside {}", path.display(), root.display()))?;
    Ok(rel
        .components()
        .filter_map(|part| part.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/"))
}

fn build_fleet_report(evidence_dir: &Path) -> Result<Value> {
    let paths = find_aibom_files(evidence_dir)
        .with_context(|| format!("discover AIBOM files under {}", evidence_dir.display()))?;
    let mut endpoints = Vec::new();
    let mut rows = Vec::new();
    let mut total_components = 0usize;
    let mut total_servers = 0usize;
    let mut total_granted_permission_evidence = 0usize;
    let mut total_policy_verdicts = 0usize;
    let mut operating_systems = BTreeSet::new();
    let mut platforms = BTreeSet::new();
    let mut scan_times = BTreeSet::new();
    let mut component_names = BTreeSet::new();
    let mut publishers = BTreeSet::new();
    let mut cve_matches = BTreeSet::new();
    let mut signed_by = BTreeSet::new();
    let mut policy_status_counts = BTreeMap::<String, usize>::new();

    for path in paths {
        let aibom = read_json(&path).with_context(|| format!("read AIBOM {}", path.display()))?;
        let endpoint = summarize_fleet_endpoint(&aibom, &path);
        total_components += endpoint["componentCount"].as_u64().unwrap_or(0) as usize;
        total_servers += endpoint["serverCount"].as_u64().unwrap_or(0) as usize;
        total_granted_permission_evidence += endpoint["grantedPermissionEvidenceCount"]
            .as_u64()
            .unwrap_or(0) as usize;
        total_policy_verdicts += endpoint["policyVerdictCount"].as_u64().unwrap_or(0) as usize;

        if let Some(os) = endpoint["os"].as_str().filter(|value| !value.is_empty()) {
            operating_systems.insert(os.to_string());
        }
        if let Some(platform) = endpoint["platform"]
            .as_str()
            .filter(|value| !value.is_empty())
        {
            platforms.insert(platform.to_string());
        }
        if let Some(scan_time) = endpoint["scanTime"]
            .as_str()
            .filter(|value| !value.is_empty())
        {
            scan_times.insert(scan_time.to_string());
        }
        for name in endpoint["componentNames"].as_array().into_iter().flatten() {
            if let Some(name) = name.as_str().filter(|value| !value.is_empty()) {
                component_names.insert(name.to_string());
            }
        }
        for publisher in endpoint["publishers"].as_array().into_iter().flatten() {
            if let Some(publisher) = publisher.as_str().filter(|value| !value.is_empty()) {
                publishers.insert(publisher.to_string());
            }
        }
        for cve in endpoint["cveMatches"].as_array().into_iter().flatten() {
            if let Some(cve) = cve.as_str().filter(|value| !value.is_empty()) {
                cve_matches.insert(cve.to_string());
            }
        }
        for signer in endpoint["signedBy"].as_array().into_iter().flatten() {
            if let Some(signer) = signer.as_str().filter(|value| !value.is_empty()) {
                signed_by.insert(signer.to_string());
            }
        }
        for (status, count) in endpoint["policyStatusCounts"]
            .as_object()
            .into_iter()
            .flatten()
        {
            *policy_status_counts.entry(status.clone()).or_default() +=
                count.as_u64().unwrap_or(0) as usize;
        }
        rows.push(flatten_fleet_endpoint(&endpoint));
        endpoints.push(endpoint);
    }
    let generated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();

    Ok(json!({
        "reportVersion": "0.1.0",
        "generatedAtUnix": generated_at_unix,
        "source": {
            "evidenceDir": evidence_dir.display().to_string(),
        },
        "summary": {
            "endpoints": endpoints.len(),
            "components": total_components,
            "servers": total_servers,
            "grantedPermissionEvidence": total_granted_permission_evidence,
            "policyVerdicts": total_policy_verdicts,
            "policyStatusCounts": policy_status_counts,
            "operatingSystems": operating_systems.into_iter().collect::<Vec<_>>(),
            "platforms": platforms.into_iter().collect::<Vec<_>>(),
            "scanTimes": scan_times.into_iter().collect::<Vec<_>>(),
            "distinctComponentNames": component_names.into_iter().collect::<Vec<_>>(),
            "distinctPublishers": publishers.into_iter().collect::<Vec<_>>(),
            "distinctCveMatches": cve_matches.into_iter().collect::<Vec<_>>(),
            "signedBy": signed_by.into_iter().collect::<Vec<_>>(),
        },
        "rows": rows,
        "endpoints": endpoints,
    }))
}

fn summarize_fleet_endpoint(aibom: &Value, path: &Path) -> Value {
    let components = array_at(aibom, &["/aibom/components", "/components"]);
    let evidence = array_at(aibom, &["/aibom/evidence", "/evidence"]);
    let policy_verdicts = array_at(aibom, &["/aibom/policyVerdicts", "/policyVerdicts"]);
    let mut component_names = BTreeSet::new();
    let mut publishers = BTreeSet::new();
    let mut cve_matches = BTreeSet::new();
    let mut granted_capability_evidence_refs = 0usize;

    for component in &components {
        if let Some(name) = component_name(component) {
            component_names.insert(name);
        }
        if let Some(publisher) = component_publisher(component) {
            publishers.insert(publisher);
        }
        collect_vulnerability_ids(component, &mut cve_matches);
        for grant in capabilities(component, "granted") {
            granted_capability_evidence_refs += grant
                .get("evidence")
                .and_then(Value::as_array)
                .map_or(1, Vec::len);
        }
    }

    let granted_permission_evidence = evidence
        .iter()
        .filter(|record| record.get("kind").and_then(Value::as_str) == Some("granted-permission"))
        .count();
    let mut policy_status_counts = BTreeMap::<String, usize>::new();
    for verdict in &policy_verdicts {
        let status = verdict
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        *policy_status_counts.entry(status.to_string()).or_default() += 1;
    }

    let os = first_string_at(
        aibom,
        &[
            "/aibom/scan/target/os",
            "/aibom/scan/platform/os",
            "/aibom/host/os",
            "/aibom/machine/os",
            "/aibom/platform/os",
            "/aibom/scan/os",
            "/os",
        ],
    )
    .or_else(|| find_string_field(aibom, "os"));
    let platform = first_string_at(
        aibom,
        &[
            "/aibom/scan/target/platform",
            "/aibom/scan/platform/name",
            "/aibom/host/platform",
            "/aibom/machine/platform",
            "/aibom/platform/name",
            "/aibom/scan/platform",
            "/platform",
        ],
    )
    .or_else(|| find_string_field(aibom, "platform"))
    .or_else(|| os.clone());
    let scan_time = first_string_at(
        aibom,
        &[
            "/aibom/scan/timestamp",
            "/aibom/scan/scannedAt",
            "/aibom/scan/scanTime",
            "/aibom/timestamp",
            "/metadata/timestamp",
            "/timestamp",
        ],
    )
    .or_else(|| find_string_field(aibom, "timestamp"))
    .or_else(|| find_string_field(aibom, "scanTime"));
    let scan_id = first_string_at(
        aibom,
        &[
            "/aibom/scan/target/description",
            "/aibom/scan/target/id",
            "/aibom/scan/scanId",
            "/aibom/endpoint/id",
            "/endpoint/id",
        ],
    )
    .unwrap_or_else(|| {
        path.file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string()
    });
    let hostname = first_string_at(
        aibom,
        &[
            "/aibom/scan/target/hostname",
            "/aibom/host/hostname",
            "/aibom/machine/hostname",
            "/hostname",
        ],
    )
    .or_else(|| find_string_field(aibom, "hostname"))
    .unwrap_or_else(|| scan_id.clone());
    let server_count = array_at(aibom, &["/aibom/servers", "/servers"])
        .len()
        .max(components.len());
    let mut signed_by = BTreeSet::new();
    collect_signer_identities(aibom, &mut signed_by);

    json!({
        "path": path.display().to_string(),
        "endpoint": scan_id,
        "hostname": hostname,
        "os": os,
        "platform": platform,
        "scanTime": scan_time,
        "componentCount": components.len(),
        "serverCount": server_count,
        "grantedPermissionEvidenceCount": granted_permission_evidence.max(granted_capability_evidence_refs),
        "policyVerdictCount": policy_verdicts.len(),
        "policyStatusCounts": policy_status_counts,
        "componentNames": component_names.into_iter().collect::<Vec<_>>(),
        "publishers": publishers.into_iter().collect::<Vec<_>>(),
        "cveMatches": cve_matches.into_iter().collect::<Vec<_>>(),
        "signedBy": signed_by.into_iter().collect::<Vec<_>>(),
        "machineReportPath": find_machine_report_path(path).map(|report| report.display().to_string()),
    })
}

fn flatten_fleet_endpoint(endpoint: &Value) -> Value {
    json!({
        "endpoint": endpoint["endpoint"].as_str().unwrap_or("unknown"),
        "hostname": endpoint["hostname"].as_str().unwrap_or("unknown"),
        "os": endpoint["os"].as_str().unwrap_or("unknown"),
        "platform": endpoint["platform"].as_str().unwrap_or("unknown"),
        "scanTime": endpoint["scanTime"].as_str().unwrap_or("unknown"),
        "componentCount": endpoint["componentCount"].as_u64().unwrap_or(0),
        "serverCount": endpoint["serverCount"].as_u64().unwrap_or(0),
        "grantedPermissionEvidenceCount": endpoint["grantedPermissionEvidenceCount"].as_u64().unwrap_or(0),
        "policyVerdictCount": endpoint["policyVerdictCount"].as_u64().unwrap_or(0),
        "componentNames": joined_strings(&endpoint["componentNames"]),
        "publishers": joined_strings(&endpoint["publishers"]),
        "cveMatches": joined_strings(&endpoint["cveMatches"]),
        "signedBy": joined_strings(&endpoint["signedBy"]),
        "sourcePath": endpoint["path"].as_str().unwrap_or("unknown"),
        "machineReportPath": endpoint["machineReportPath"].as_str().unwrap_or(""),
    })
}

fn find_machine_report_path(aibom_path: &Path) -> Option<PathBuf> {
    let file_name = aibom_path.file_name()?.to_str()?;
    let dir = aibom_path.parent()?;
    let mut candidates = Vec::new();
    if let Some(prefix) = file_name.strip_suffix(".aibom.json") {
        candidates.push(dir.join(format!("{prefix}.html")));
        candidates.push(dir.join(format!("{prefix}.aibom.html")));
    }
    candidates.push(dir.join("report.html"));
    candidates.push(dir.join("machine.html"));
    candidates.into_iter().find(|path| path.is_file())
}

fn find_aibom_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    collect_aibom_files(root, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_aibom_files(path: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".aibom.json"))
        {
            paths.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !path.is_dir() {
        bail!("{} is not a directory or file", path.display());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_aibom_files(&entry_path, paths)?;
        } else if entry_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".aibom.json"))
        {
            paths.push(entry_path);
        }
    }
    Ok(())
}

fn array_at(value: &Value, pointers: &[&str]) -> Vec<Value> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_array))
        .cloned()
        .unwrap_or_default()
}

fn first_string_at(value: &Value, pointers: &[&str]) -> Option<String> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
        .map(ToString::to_string)
}

fn find_string_field(value: &Value, field: &str) -> Option<String> {
    match value {
        Value::Object(object) => {
            if let Some(found) = object.get(field).and_then(Value::as_str) {
                return Some(found.to_string());
            }
            object
                .values()
                .find_map(|child| find_string_field(child, field))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|child| find_string_field(child, field)),
        _ => None,
    }
}

fn component_name(component: &Value) -> Option<String> {
    first_string_at(
        component,
        &[
            "/name",
            "/identity/name",
            "/package/name",
            "/metadata/name",
            "/purl",
            "/bom-ref",
        ],
    )
    .map(|name| {
        if name.starts_with("pkg:") {
            package_name_from_purl(&name).unwrap_or(name)
        } else {
            name
        }
    })
}

fn component_publisher(component: &Value) -> Option<String> {
    first_string_at(
        component,
        &[
            "/publisher",
            "/supplier/name",
            "/author",
            "/identity/publisher",
            "/package/publisher",
            "/provenance/publisher",
        ],
    )
}

fn collect_vulnerability_ids(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(vulnerabilities) = object.get("vulnerabilities").and_then(Value::as_array) {
                for record in vulnerabilities {
                    if let Some(id) = record.get("id").and_then(Value::as_str) {
                        ids.insert(id.to_string());
                    }
                }
            }
            for child in object.values() {
                collect_vulnerability_ids(child, ids);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_vulnerability_ids(child, ids);
            }
        }
        _ => {}
    }
}

fn collect_signer_identities(value: &Value, identities: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for key in [
                "oidcSubject",
                "certificateIdentity",
                "signerIdentity",
                "signer",
                "signedBy",
            ] {
                if let Some(identity) = object.get(key).and_then(Value::as_str) {
                    identities.insert(identity.to_string());
                }
            }
            for child in object.values() {
                collect_signer_identities(child, identities);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_signer_identities(child, identities);
            }
        }
        _ => {}
    }
}

fn package_name_from_purl(value: &str) -> Option<String> {
    let without_version = value.rsplit_once('@').map_or(value, |(package, _)| package);
    without_version
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(|name| name.replace("%40", "@"))
}

fn render_fleet_report_markdown(report: &Value) -> String {
    let summary = &report["summary"];
    let mut markdown = String::new();
    markdown.push_str("# Reeve Fleet Report\n\n");
    markdown.push_str("| Metric | Count |\n|---|---:|\n");
    for (label, key) in [
        ("Endpoints", "endpoints"),
        ("Components", "components"),
        ("Servers", "servers"),
        ("Granted-permission evidence", "grantedPermissionEvidence"),
        ("Policy verdicts", "policyVerdicts"),
    ] {
        markdown.push_str(&format!(
            "| {label} | {} |\n",
            summary[key].as_u64().unwrap_or(0)
        ));
    }
    markdown.push_str("\n## Endpoints\n\n");
    markdown.push_str(
        "| Hostname | OS / platform | Scan time | Components | Servers | Grants | Verdicts | Report |\n",
    );
    markdown.push_str("|---|---|---|---:|---:|---:|---:|---|\n");
    for endpoint in report["endpoints"].as_array().into_iter().flatten() {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            markdown_escape(endpoint["hostname"].as_str().unwrap_or("unknown")),
            markdown_escape(&endpoint_os_platform(endpoint)),
            markdown_escape(endpoint["scanTime"].as_str().unwrap_or("unknown")),
            endpoint["componentCount"].as_u64().unwrap_or(0),
            endpoint["serverCount"].as_u64().unwrap_or(0),
            endpoint["grantedPermissionEvidenceCount"]
                .as_u64()
                .unwrap_or(0),
            endpoint["policyVerdictCount"].as_u64().unwrap_or(0),
            markdown_escape(endpoint["machineReportPath"].as_str().unwrap_or("")),
        ));
    }
    markdown.push_str("\n## Distinct Components\n\n");
    markdown.push_str(&markdown_string_list(&summary["distinctComponentNames"]));
    markdown.push_str("\n## Distinct Publishers\n\n");
    markdown.push_str(&markdown_string_list(&summary["distinctPublishers"]));
    markdown.push_str("\n## Distinct CVE Matches\n\n");
    markdown.push_str(&markdown_string_list(&summary["distinctCveMatches"]));
    markdown.push_str("\n## Provenance\n\n");
    markdown.push_str(&format!(
        "- Generated at Unix time: {}\n- Signed by: {}\n- Total endpoints: {}\n",
        report["generatedAtUnix"].as_u64().unwrap_or(0),
        markdown_escape(&joined_strings(&summary["signedBy"])),
        summary["endpoints"].as_u64().unwrap_or(0),
    ));
    markdown
}

fn render_fleet_report_html(report: &Value) -> String {
    let summary = &report["summary"];
    let mut html = String::new();
    html.push_str(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Reeve Fleet Report</title>",
    );
    html.push_str("<style>body{font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;margin:32px;color:#17202a;line-height:1.45}table{border-collapse:collapse;width:100%;margin:16px 0}th,td{border:1px solid #d5d8dc;padding:8px;text-align:left;vertical-align:top}th{background:#f4f6f7}.meta{color:#566573}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0}.stat{border:1px solid #d5d8dc;border-radius:4px;padding:12px}.stat strong{display:block;font-size:24px}.pill{display:inline-block;background:#eef2f7;border-radius:4px;padding:2px 6px;margin:2px;font-family:ui-monospace,monospace}</style>");
    html.push_str("</head><body><h1>Reeve Fleet Report</h1>");
    html.push_str(&format!(
        "<p class=\"meta\">Evidence directory: <code>{}</code></p>",
        html_escape(
            report["source"]["evidenceDir"]
                .as_str()
                .unwrap_or("unknown")
        )
    ));
    html.push_str("<section class=\"grid\">");
    for (label, key) in [
        ("Endpoints", "endpoints"),
        ("Components", "components"),
        ("Servers", "servers"),
        ("Granted-permission evidence", "grantedPermissionEvidence"),
        ("Policy verdicts", "policyVerdicts"),
    ] {
        html.push_str(&format!(
            "<div class=\"stat\"><strong>{}</strong>{}</div>",
            summary[key].as_u64().unwrap_or(0),
            label
        ));
    }
    html.push_str("</section>");

    html.push_str("<h2>Endpoints</h2><table><thead><tr><th>Hostname</th><th>OS / platform</th><th>Scan time</th><th>Components</th><th>Servers</th><th>Grants</th><th>Policy verdicts</th><th>Report</th></tr></thead><tbody>");
    for endpoint in report["endpoints"].as_array().into_iter().flatten() {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(endpoint["hostname"].as_str().unwrap_or("unknown")),
            html_escape(&endpoint_os_platform(endpoint)),
            html_escape(endpoint["scanTime"].as_str().unwrap_or("unknown")),
            endpoint["componentCount"].as_u64().unwrap_or(0),
            endpoint["serverCount"].as_u64().unwrap_or(0),
            endpoint["grantedPermissionEvidenceCount"].as_u64().unwrap_or(0),
            endpoint["policyVerdictCount"].as_u64().unwrap_or(0),
            render_machine_report_link(endpoint),
        ));
    }
    html.push_str("</tbody></table>");
    html.push_str("<h2>Distinct Components</h2>");
    html.push_str(&render_html_string_pills(
        &summary["distinctComponentNames"],
    ));
    html.push_str("<h2>Distinct Publishers</h2>");
    html.push_str(&render_html_string_pills(&summary["distinctPublishers"]));
    html.push_str("<h2>Distinct CVE Matches</h2>");
    html.push_str(&render_html_string_pills(&summary["distinctCveMatches"]));
    html.push_str(&format!(
        "<footer class=\"meta\"><p>Generated at Unix time: {}. Signed by: {}. Total endpoints: {}.</p></footer>",
        report["generatedAtUnix"].as_u64().unwrap_or(0),
        html_escape(&joined_strings(&summary["signedBy"])),
        summary["endpoints"].as_u64().unwrap_or(0),
    ));
    html.push_str("</body></html>");
    html
}

fn endpoint_os_platform(endpoint: &Value) -> String {
    match (endpoint["os"].as_str(), endpoint["platform"].as_str()) {
        (Some(os), Some(platform)) if os != platform => format!("{os} / {platform}"),
        (Some(os), _) => os.to_string(),
        (_, Some(platform)) => platform.to_string(),
        _ => "unknown".to_string(),
    }
}

fn markdown_string_list(value: &Value) -> String {
    let items: Vec<_> = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if items.is_empty() {
        return "_None captured._\n".to_string();
    }
    let mut output = String::new();
    for item in items {
        output.push_str(&format!("- {}\n", markdown_escape(item)));
    }
    output
}

fn render_html_string_pills(value: &Value) -> String {
    let items: Vec<_> = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if items.is_empty() {
        return "<p class=\"meta\">None captured.</p>".to_string();
    }
    items
        .into_iter()
        .map(|item| format!("<span class=\"pill\">{}</span>", html_escape(item)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_machine_report_link(endpoint: &Value) -> String {
    let Some(path) = endpoint["machineReportPath"]
        .as_str()
        .filter(|value| !value.is_empty())
    else {
        return String::new();
    };
    format!("<a href=\"{}\">report</a>", html_escape(path))
}

fn joined_strings(value: &Value) -> String {
    let joined = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if joined.is_empty() {
        "not-captured".to_string()
    } else {
        joined
    }
}

fn markdown_escape(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

struct SensitiveReportInput<'a> {
    path: &'a Path,
    value: &'a Value,
}

/// Locate the sibling sensitive-data report written by `scan`:
/// `<scanid>.sensitive-data.json` next to `<scanid>.aibom.json`.
fn locate_sibling_sensitive_report(aibom_path: &Path) -> Option<PathBuf> {
    let file_name = aibom_path.file_name()?.to_str()?;
    let scan_id = file_name.strip_suffix(".aibom.json")?;
    let candidate = aibom_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{scan_id}.sensitive-data.json"));
    candidate.is_file().then_some(candidate)
}

/// Collapse machine join keys (`#instance-...` bom-ref fragments) so they
/// never render as human-facing content. Raw refs stay in the JSON artifacts.
fn strip_instance_fragments(value: &str) -> String {
    let marker = "#instance-";
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(pos) = rest.find(marker) {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos + marker.len()..];
        let end = tail
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Built-in discovery surface ids, longest first so instance fragments such
/// as `claude-code-desktop-...` resolve to the most specific surface.
const KNOWN_SURFACE_IDS: [&str; 12] = [
    "claude-code-desktop",
    "claude-desktop",
    "claude-cowork",
    "claude-code",
    "antigravity",
    "codex-cli",
    "codex-app",
    "continue",
    "factory",
    "cursor",
    "vscode",
    "zed",
];

fn surface_label(surface: &str) -> String {
    match surface {
        "claude-desktop" => "Claude Desktop".to_string(),
        "claude-cowork" => "Claude Cowork".to_string(),
        "claude-code" => "Claude Code".to_string(),
        "claude-code-desktop" => "Claude Code Desktop".to_string(),
        "codex-cli" => "Codex CLI".to_string(),
        "codex-app" => "Codex App".to_string(),
        "cursor" => "Cursor".to_string(),
        "continue" => "Continue".to_string(),
        "factory" => "Factory".to_string(),
        "zed" => "Zed".to_string(),
        "vscode" => "VS Code".to_string(),
        "antigravity" => "Antigravity".to_string(),
        "unattributed" => "Unattributed Surface".to_string(),
        other => other.to_string(),
    }
}

fn surface_from_instance_fragment(bom_ref: &str) -> Option<String> {
    let fragment = bom_ref.split("#instance-").nth(1)?;
    KNOWN_SURFACE_IDS
        .iter()
        .find(|surface| fragment.starts_with(**surface))
        .map(|surface| (*surface).to_string())
}

fn surface_from_evidence_reference(reference: &str) -> Option<String> {
    if let Some(rest) = reference.strip_prefix("mcp://") {
        let surface = rest.split('/').next()?;
        if !surface.is_empty() {
            return Some(surface.to_string());
        }
    }
    if reference.starts_with("claude-cowork://") {
        return Some("claude-cowork".to_string());
    }
    if reference.starts_with("codex-app://") {
        return Some("codex-app".to_string());
    }
    for (pattern, surface) in [
        ("/.cursor/", "cursor"),
        ("/.claude/", "claude-code"),
        (".claude.json", "claude-code"),
        ("claude_desktop_config.json", "claude-desktop"),
        ("/.codex/", "codex-cli"),
        ("/.continue/", "continue"),
        ("/.factory/", "factory"),
        ("/.zed/", "zed"),
        ("/.vscode/", "vscode"),
    ] {
        if reference.contains(pattern) {
            return Some(surface.to_string());
        }
    }
    None
}

/// Best-effort surface attribution from the AIBOM the report consumes:
/// capability qualifiers first, then the instance fragment, then evidence
/// references. Components without a derivable surface stay "unattributed".
fn surface_for_component(
    component: &Value,
    bom_ref: &str,
    evidence_by_id: &BTreeMap<String, String>,
) -> String {
    for kind in ["granted", "declared", "observed"] {
        for capability in capabilities(component, kind) {
            if let Some(surface) = capability
                .pointer("/qualifiers/surface")
                .and_then(Value::as_str)
            {
                return surface.to_string();
            }
        }
    }
    if let Some(surface) = surface_from_instance_fragment(bom_ref) {
        return surface;
    }
    for kind in ["granted", "declared", "observed"] {
        for capability in capabilities(component, kind) {
            for evidence_id in capability
                .get("evidence")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if let Some(reference) = evidence_by_id.get(evidence_id)
                    && let Some(surface) = surface_from_evidence_reference(reference)
                {
                    return surface;
                }
            }
        }
    }
    "unattributed".to_string()
}

fn capability_ids(capabilities: &[Value]) -> BTreeSet<String> {
    capabilities
        .iter()
        .filter_map(|capability| capability.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

/// Notable grants are facts worth surfacing in the rollup: wildcard
/// subprocess approvals, broad filesystem paths, and egress domains.
fn notable_grants(component_display: &str, granted: &[Value]) -> Vec<String> {
    let mut notes = Vec::new();
    for capability in granted {
        let Some(id) = capability.get("id").and_then(Value::as_str) else {
            continue;
        };
        let qualifiers = capability.get("qualifiers");
        if id.starts_with("exec:") {
            let wildcard = qualifiers
                .and_then(Value::as_object)
                .is_some_and(|qualifiers| {
                    qualifiers
                        .values()
                        .filter_map(Value::as_str)
                        .any(|value| value.contains('*'))
                });
            if wildcard {
                notes.push(format!(
                    "wildcard subprocess approval ({id}) on {component_display}"
                ));
            }
        }
        if id.starts_with("fs:")
            && let Some(path) = qualifiers
                .and_then(|qualifiers| qualifiers.get("path"))
                .and_then(Value::as_str)
            && (path == "/" || path == "~" || path.contains("**"))
        {
            notes.push(format!("broad {id} path {path} on {component_display}"));
        }
        if id.starts_with("net:")
            && let Some(host) = qualifiers
                .and_then(|qualifiers| qualifiers.get("domain").or_else(|| qualifiers.get("host")))
                .and_then(Value::as_str)
        {
            notes.push(format!("egress to {host} ({id}) on {component_display}"));
        }
    }
    notes.sort();
    notes.dedup();
    notes
}

fn policy_status_rank(status: &str) -> usize {
    match status {
        "deny" => 0,
        "warn" => 1,
        _ => 2,
    }
}

fn ranked_policy_findings(policy_verdicts: &[Value]) -> Vec<Value> {
    // Aggregate findings that render identically once machine join keys are
    // stripped (criterion 10, #472): the same status/policy/component/
    // justification across N instances is one human finding with a count.
    // The underlying verdict ids and evidence ids stay available per group
    // for drilldown; nothing is dropped from the machine JSON.
    let mut groups: BTreeMap<(usize, String, String, String), Vec<&Value>> = BTreeMap::new();
    for verdict in policy_verdicts {
        let status = verdict
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let policy_id = verdict
            .get("policyId")
            .or_else(|| verdict.get("policy_id"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let bom_ref = verdict
            .get("bomRef")
            .or_else(|| verdict.get("bom_ref"))
            .and_then(Value::as_str)
            .unwrap_or("-");
        let component = strip_instance_fragments(bom_ref);
        let justification = strip_instance_fragments(
            verdict
                .get("justification")
                .and_then(Value::as_str)
                .unwrap_or(""),
        );
        groups
            .entry((
                policy_status_rank(status),
                policy_id.to_string(),
                component,
                justification,
            ))
            .or_default()
            .push(verdict);
    }
    groups
        .into_iter()
        .enumerate()
        .map(
            |(index, ((_, policy_id, component, justification), verdicts))| {
                let status = verdicts[0]
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let verdict_ids: Vec<&str> = verdicts
                    .iter()
                    .filter_map(|v| v.get("id").and_then(Value::as_str))
                    .collect();
                let evidence_ids: Vec<&str> = verdicts
                    .iter()
                    .filter_map(|v| v.get("evidence").and_then(Value::as_array))
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                json!({
                    "anchor": format!("finding-{index}"),
                    "status": status,
                    "statusLabel": status.to_ascii_uppercase(),
                    "policyId": policy_id,
                    "component": component,
                    "justification": justification,
                    "findingCount": verdicts.len(),
                    "verdictIds": verdict_ids,
                    "evidenceIds": evidence_ids,
                })
            },
        )
        .collect()
}

fn build_sensitive_section(input: Option<&SensitiveReportInput<'_>>) -> Value {
    let Some(input) = input else {
        return json!({
            "available": false,
            "note": "no sensitive-data report supplied",
        });
    };
    let body = input
        .value
        .pointer("/sensitiveDataReport")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let findings = body
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let suppressed_count = findings
        .iter()
        .filter(|finding| finding.get("suppressed").and_then(Value::as_bool) == Some(true))
        .count();

    let mut classes: BTreeMap<(String, String), (u64, u64, BTreeSet<String>)> = BTreeMap::new();
    for finding in &findings {
        let class = finding
            .get("patternClass")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let surface = finding
            .get("surface")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let matches = finding
            .get("matchCount")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let entry = classes
            .entry((class, surface))
            .or_insert((0, 0, BTreeSet::new()));
        entry.0 += 1;
        entry.1 += matches;
        if let Some(path) = finding
            .pointer("/file/redactedPath")
            .and_then(Value::as_str)
        {
            entry.2.insert(path.to_string());
        }
    }
    let classes: Vec<Value> = classes
        .into_iter()
        .map(|((class, surface), (finding_count, match_count, paths))| {
            json!({
                "patternClass": class,
                "surface": surface,
                "findings": finding_count,
                "matches": match_count,
                "redactedPaths": paths.into_iter().collect::<Vec<_>>(),
            })
        })
        .collect();

    let surfaces: Vec<Value> = body
        .get("surfaces")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|surface| {
            json!({
                "surface": surface.get("surface").and_then(Value::as_str).unwrap_or("unknown"),
                "redactedRoot": surface.get("redactedRoot").and_then(Value::as_str).unwrap_or("unknown"),
                "fileCount": surface.get("fileCount").and_then(Value::as_u64).unwrap_or(0),
                "totalBytes": surface.get("totalBytes").and_then(Value::as_u64).unwrap_or(0),
            })
        })
        .collect();

    json!({
        "available": true,
        "reportFile": input
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("sensitive-data report"),
        "reportId": body.get("reportId").and_then(Value::as_str).unwrap_or("unknown"),
        "findingCount": findings.len(),
        "suppressedCount": suppressed_count,
        "classes": classes,
        "surfaces": surfaces,
    })
}

#[derive(Default)]
struct ProviderRollup {
    instance_count: usize,
    sources: BTreeSet<String>,
    declared: BTreeSet<String>,
    granted: BTreeSet<String>,
    observed: BTreeSet<String>,
    granted_permission_count: usize,
    notable: Vec<String>,
}

fn build_machine_report(
    aibom: &Value,
    aibom_path: &Path,
    sensitive: Option<SensitiveReportInput<'_>>,
) -> Result<Value> {
    let scan = aibom
        .pointer("/aibom/scan")
        .context("AIBOM missing /aibom/scan")?;
    let components = aibom
        .pointer("/aibom/components")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let evidence = aibom
        .pointer("/aibom/evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let policy_verdicts = aibom
        .pointer("/aibom/policyVerdicts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let evidence_by_id: BTreeMap<String, String> = evidence
        .iter()
        .filter_map(|record| {
            Some((
                record.get("id")?.as_str()?.to_string(),
                record.get("reference")?.as_str()?.to_string(),
            ))
        })
        .collect();

    let mut report_components = Vec::new();
    let mut granted_permissions = Vec::new();
    let mut declared_total = 0usize;
    let mut granted_total = 0usize;
    let mut observed_total = 0usize;
    let mut components_without_registry_identity = 0usize;
    let mut packages_without_version = 0usize;
    // (surface, display ref) -> rollup
    let mut rollups: BTreeMap<(String, String), ProviderRollup> = BTreeMap::new();

    for component in &components {
        let bom_ref = component
            .get("bom-ref")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let source = component
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let declared = capabilities(component, "declared");
        let granted = capabilities(component, "granted");
        let observed = capabilities(component, "observed");
        let declared_summary = capability_summary(&declared);
        let granted_summary = capability_summary(&granted);
        let observed_summary = capability_summary(&observed);
        declared_total += declared_summary.len();
        granted_total += granted_summary.len();
        observed_total += observed_summary.len();
        for cap in &granted {
            granted_permissions.push(json!({
                "component": bom_ref,
                "componentDisplay": strip_instance_fragments(bom_ref),
                "id": cap.get("id").cloned().unwrap_or(Value::Null),
                "qualifiers": cap.get("qualifiers").cloned().unwrap_or_else(|| json!({})),
                "evidence": cap.get("evidence").cloned().unwrap_or_else(|| json!([])),
            }));
        }
        report_components.push(json!({
            "bomRef": bom_ref,
            "source": source,
            "declared": declared_summary,
            "granted": granted_summary,
            "observed": observed_summary,
        }));

        let display_ref = strip_instance_fragments(bom_ref);
        if !display_ref.starts_with("pkg:") {
            components_without_registry_identity += 1;
        } else if !display_ref
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .contains('@')
        {
            // Package-identified but no resolvable version: no vulnerability
            // scanner can match it. Surface the gap instead of a silent zero
            // (criterion 9, #472). Scoped npm purls encode the scope as %40,
            // so a raw '@' in the final segment is exactly the version marker.
            packages_without_version += 1;
        }
        let surface = surface_for_component(component, bom_ref, &evidence_by_id);
        let rollup = rollups.entry((surface, display_ref.clone())).or_default();
        rollup.instance_count += 1;
        rollup.sources.insert(source.to_string());
        rollup.declared.extend(capability_ids(&declared_summary));
        rollup.granted.extend(capability_ids(&granted_summary));
        rollup.observed.extend(capability_ids(&observed_summary));
        rollup.granted_permission_count += granted.len();
        rollup
            .notable
            .extend(notable_grants(&display_ref, &granted));
    }

    // Surface rollups: one block per surface, providers aggregated across
    // repeated instances of the same provider.
    let mut by_surface: BTreeMap<String, Vec<(String, ProviderRollup)>> = BTreeMap::new();
    for ((surface, display_ref), rollup) in rollups {
        by_surface
            .entry(surface)
            .or_default()
            .push((display_ref, rollup));
    }
    let surface_rollups: Vec<Value> = by_surface
        .into_iter()
        .map(|(surface, providers)| {
            let component_count = providers.len();
            let instance_count: usize = providers
                .iter()
                .map(|(_, rollup)| rollup.instance_count)
                .sum();
            let granted_permission_count: usize = providers
                .iter()
                .map(|(_, rollup)| rollup.granted_permission_count)
                .sum();
            let mut notable: Vec<String> = providers
                .iter()
                .flat_map(|(_, rollup)| rollup.notable.iter().cloned())
                .collect();
            notable.sort();
            notable.dedup();
            let provider_values: Vec<Value> = providers
                .iter()
                .map(|(display_ref, rollup)| {
                    json!({
                        "provider": display_ref,
                        "instanceCount": rollup.instance_count,
                        "sources": rollup.sources.iter().collect::<Vec<_>>(),
                        "declared": rollup.declared.iter().collect::<Vec<_>>(),
                        "granted": rollup.granted.iter().collect::<Vec<_>>(),
                        "observed": rollup.observed.iter().collect::<Vec<_>>(),
                        "grantedPermissionCount": rollup.granted_permission_count,
                    })
                })
                .collect();
            json!({
                "surface": surface,
                "label": surface_label(&surface),
                "componentCount": component_count,
                "instanceCount": instance_count,
                "grantedPermissionCount": granted_permission_count,
                "notableGrants": notable,
                "providers": provider_values,
            })
        })
        .collect();

    let policy_findings = ranked_policy_findings(&policy_verdicts);
    // DENY/WARN totals count VERDICTS (facts), not aggregated display rows.
    let policy_deny = policy_verdicts
        .iter()
        .filter(|verdict| verdict["status"] == "deny")
        .count();
    let policy_warn = policy_verdicts
        .iter()
        .filter(|verdict| verdict["status"] == "warn")
        .count();
    let sensitive_section = build_sensitive_section(sensitive.as_ref());
    let sensitive_findings = sensitive_section
        .get("findingCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let canonical_hash = sha256_hex(&canonicalize_json(aibom)?);
    Ok(json!({
        "reportVersion": "0.2.0",
        "source": {
            "aibomPath": aibom_path.display().to_string(),
            "canonicalSha256": canonical_hash,
        },
        "machine": {
            "target": scan.pointer("/target/description").and_then(Value::as_str).unwrap_or("unknown"),
            "targetKind": scan.pointer("/target/kind").and_then(Value::as_str).unwrap_or("unknown"),
            "os": "not-captured",
            "hostname": "not-captured",
        },
        "scan": {
            "id": scan.get("scanId").and_then(Value::as_str).unwrap_or("unknown"),
            "timestamp": scan.get("timestamp").and_then(Value::as_str).unwrap_or("unknown"),
            "scanner": scan.pointer("/scanner/name").and_then(Value::as_str).unwrap_or("unknown"),
            "scannerVersion": scan.pointer("/scanner/version").and_then(Value::as_str).unwrap_or("unknown"),
            "adapter": scan.pointer("/adapter/name").and_then(Value::as_str).unwrap_or("unknown"),
            "adapterVersion": scan.pointer("/adapter/version").and_then(Value::as_str).unwrap_or("unknown"),
        },
        "schemaVersion": aibom
            .pointer("/aibom/schemaVersion")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
        "signature": aibom
            .pointer("/aibom/signature/signedBy")
            .and_then(Value::as_str)
            .map(Value::from)
            .unwrap_or(Value::Null),
        "summary": {
            "components": components.len(),
            "declaredCapabilities": declared_total,
            "grantedPermissions": granted_total,
            "observedCapabilities": observed_total,
            "evidenceRecords": evidence.len(),
            "policyVerdicts": policy_verdicts.len(),
            "policyDeny": policy_deny,
            "policyWarn": policy_warn,
            "sensitiveFindings": if sensitive_section["available"] == true {
                json!(sensitive_findings)
            } else {
                Value::Null
            },
            "componentsWithoutRegistryIdentity": components_without_registry_identity,
            "packagesWithoutVersion": packages_without_version,
        },
        "policyFindings": policy_findings,
        "sensitiveData": sensitive_section,
        "surfaceRollups": surface_rollups,
        "components": report_components,
        "grantedPermissions": granted_permissions,
        "evidence": evidence,
        "policyVerdicts": policy_verdicts,
    }))
}

fn capabilities(component: &Value, kind: &str) -> Vec<Value> {
    component
        .pointer(&format!("/capabilities/{kind}"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn capability_summary(capabilities: &[Value]) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut summary = Vec::new();
    for capability in capabilities {
        let Some(id) = capability.get("id").and_then(Value::as_str) else {
            continue;
        };
        if seen.insert(id.to_string()) {
            summary.push(capability.clone());
        }
    }
    summary
}

/// Escape for HTML after collapsing machine join keys: the default view must
/// never render `#instance-` bom-ref fragments as content.
fn display_text(value: &str) -> String {
    html_escape(&strip_instance_fragments(value))
}

fn render_report_html(report: &Value) -> String {
    let summary = &report["summary"];
    let scan = &report["scan"];
    let machine = &report["machine"];
    let sensitive = &report["sensitiveData"];
    let mut html = String::new();
    html.push_str(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Reeve Machine Report</title>",
    );
    html.push_str("<style>body{font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;margin:32px;color:#17202a}table{border-collapse:collapse;width:100%;margin:16px 0}th,td{border:1px solid #d5d8dc;padding:8px;text-align:left;vertical-align:top}th{background:#f4f6f7}.meta{color:#566573}.pill{display:inline-block;background:#eef2f7;border-radius:4px;padding:2px 6px;margin:1px;font-family:ui-monospace,monospace}.facts{font-size:1.05em}.status-deny{color:#922b21;font-weight:600}.status-warn{color:#9c640c;font-weight:600}</style>");
    html.push_str("</head><body>");

    // Header: scan id, timestamp, redacted target, Reeve version.
    html.push_str("<h1>Reeve Per-Machine Report</h1>");
    html.push_str(&format!(
        "<p class=\"meta\">Scan {} · {} · Target {} · Reeve {}</p>",
        display_text(scan["id"].as_str().unwrap_or("unknown")),
        display_text(scan["timestamp"].as_str().unwrap_or("unknown")),
        display_text(machine["target"].as_str().unwrap_or("unknown")),
        display_text(scan["scannerVersion"].as_str().unwrap_or("unknown")),
    ));

    // Executive Summary: policy outcomes plus facts. Reeve reports what the
    // policies decided and what the scan observed; it never invents a risk
    // score or a safe/dangerous verdict of its own.
    html.push_str("<h2 id=\"executive-summary\">Executive Summary</h2>");
    let mut facts = vec![format!(
        "Policy: {} DENY, {} WARN",
        summary["policyDeny"].as_u64().unwrap_or(0),
        summary["policyWarn"].as_u64().unwrap_or(0),
    )];
    if sensitive["available"] == true {
        facts.push(format!(
            "{} sensitive-data findings",
            sensitive["findingCount"].as_u64().unwrap_or(0)
        ));
    }
    facts.push(format!(
        "{} components ({} without package-registry identity)",
        summary["components"].as_u64().unwrap_or(0),
        summary["componentsWithoutRegistryIdentity"]
            .as_u64()
            .unwrap_or(0),
    ));
    let packages_without_version = summary["packagesWithoutVersion"].as_u64().unwrap_or(0);
    if packages_without_version > 0 {
        // Criterion 9 (#472): a package without a resolvable version cannot be
        // matched by any vulnerability scanner — show the gap, never a silent
        // zero. Fact framing, not a safety statement.
        facts.push(format!(
            "{packages_without_version} packages without a resolvable version — not vulnerability-scannable"
        ));
    }
    facts.push(format!(
        "{} granted permissions",
        summary["grantedPermissions"].as_u64().unwrap_or(0)
    ));
    facts.push(format!(
        "{} evidence records",
        summary["evidenceRecords"].as_u64().unwrap_or(0)
    ));
    html.push_str(&format!(
        "<p class=\"facts\">{}</p>",
        html_escape(&facts.join(" · "))
    ));
    if sensitive["available"] != true {
        html.push_str("<p class=\"meta\">No sensitive-data report supplied.</p>");
    }
    let findings = report["policyFindings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if findings.is_empty() {
        html.push_str("<p class=\"meta\">No policy findings recorded in this AIBOM.</p>");
    } else {
        html.push_str("<ul>");
        for finding in findings
            .iter()
            .filter(|finding| finding["status"] == "deny" || finding["status"] == "warn")
            .take(10)
        {
            let count = finding["findingCount"].as_u64().unwrap_or(1);
            let count_suffix = if count > 1 {
                format!(" ({count} findings)")
            } else {
                String::new()
            };
            html.push_str(&format!(
                "<li><a href=\"#{}\"><span class=\"status-{}\">{}</span> Policy {} — {}{}</a></li>",
                display_text(finding["anchor"].as_str().unwrap_or("policy-findings")),
                display_text(finding["status"].as_str().unwrap_or("unknown")),
                display_text(finding["statusLabel"].as_str().unwrap_or("UNKNOWN")),
                display_text(finding["policyId"].as_str().unwrap_or("unknown")),
                display_text(finding["justification"].as_str().unwrap_or("")),
                html_escape(&count_suffix),
            ));
        }
        html.push_str("</ul>");
    }

    // Policy findings ranked first: DENY before WARN, before any raw
    // inventory tables.
    html.push_str("<h2 id=\"policy-findings\">Policy Findings</h2>");
    if findings.is_empty() {
        html.push_str("<p class=\"meta\">No policy verdicts present. Run with --policy-check or `reeve policy check` to attach verdicts.</p>");
    } else {
        html.push_str("<table><thead><tr><th>Status</th><th>Policy</th><th>Component</th><th>Justification</th><th>Findings</th></tr></thead><tbody>");
        for finding in &findings {
            // Identically-rendered verdicts are one aggregated row with a
            // count (criterion 10); verdict/evidence ids live in the report
            // JSON for drilldown.
            html.push_str(&format!(
                "<tr id=\"{}\"><td><span class=\"status-{}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                display_text(finding["anchor"].as_str().unwrap_or("finding")),
                display_text(finding["status"].as_str().unwrap_or("unknown")),
                display_text(finding["statusLabel"].as_str().unwrap_or("UNKNOWN")),
                display_text(finding["policyId"].as_str().unwrap_or("unknown")),
                display_text(finding["component"].as_str().unwrap_or("-")),
                display_text(finding["justification"].as_str().unwrap_or("")),
                finding["findingCount"].as_u64().unwrap_or(1),
            ));
        }
        html.push_str("</tbody></table>");
    }

    // Sensitive Data: counts and redacted locations only. The sensitive-data
    // report is already redacted; this renders it, never secret values.
    if sensitive["available"] == true {
        html.push_str("<h2 id=\"sensitive-data\">Sensitive Data</h2>");
        html.push_str(&format!(
            "<p class=\"meta\">{} findings ({} suppressed) from {}.</p>",
            sensitive["findingCount"].as_u64().unwrap_or(0),
            sensitive["suppressedCount"].as_u64().unwrap_or(0),
            display_text(
                sensitive["reportFile"]
                    .as_str()
                    .unwrap_or("sensitive-data report")
            ),
        ));
        let classes = sensitive["classes"].as_array().cloned().unwrap_or_default();
        if !classes.is_empty() {
            html.push_str("<table><thead><tr><th>Finding class</th><th>Surface</th><th>Findings</th><th>Matches</th><th>Redacted location(s)</th></tr></thead><tbody>");
            for class in &classes {
                let paths = class["redactedPaths"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(display_text)
                    .collect::<Vec<_>>()
                    .join("<br>");
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                    display_text(class["patternClass"].as_str().unwrap_or("unknown")),
                    display_text(class["surface"].as_str().unwrap_or("unknown")),
                    class["findings"].as_u64().unwrap_or(0),
                    class["matches"].as_u64().unwrap_or(0),
                    paths,
                ));
            }
            html.push_str("</tbody></table>");
        }
        let surfaces = sensitive["surfaces"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if !surfaces.is_empty() {
            html.push_str("<table><thead><tr><th>Conversation surface</th><th>Redacted root</th><th>Files</th><th>Bytes</th></tr></thead><tbody>");
            for surface in &surfaces {
                html.push_str(&format!(
                    "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                    display_text(surface["surface"].as_str().unwrap_or("unknown")),
                    display_text(surface["redactedRoot"].as_str().unwrap_or("unknown")),
                    surface["fileCount"].as_u64().unwrap_or(0),
                    surface["totalBytes"].as_u64().unwrap_or(0),
                ));
            }
            html.push_str("</tbody></table>");
        }
    }

    // Agent Surfaces rollup: one block per surface, instances counted, never
    // dumped row-per-instance.
    html.push_str("<h2 id=\"agent-surfaces\">Agent Surfaces</h2>");
    for rollup in report["surfaceRollups"].as_array().into_iter().flatten() {
        html.push_str(&format!(
            "<h3>{}</h3><p class=\"meta\">{} components · {} instances · {} granted permissions</p>",
            display_text(rollup["label"].as_str().unwrap_or("unknown")),
            rollup["componentCount"].as_u64().unwrap_or(0),
            rollup["instanceCount"].as_u64().unwrap_or(0),
            rollup["grantedPermissionCount"].as_u64().unwrap_or(0),
        ));
        let notable = rollup["notableGrants"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if !notable.is_empty() {
            html.push_str("<ul>");
            for note in notable.iter().filter_map(Value::as_str) {
                html.push_str(&format!("<li>{}</li>", display_text(note)));
            }
            html.push_str("</ul>");
        }
        html.push_str("<table><thead><tr><th>Provider</th><th>Instances</th><th>Declared</th><th>Granted</th><th>Observed</th></tr></thead><tbody>");
        for provider in rollup["providers"].as_array().into_iter().flatten() {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                display_text(provider["provider"].as_str().unwrap_or("unknown")),
                provider["instanceCount"].as_u64().unwrap_or(0),
                render_capability_id_list(&provider["declared"]),
                render_capability_id_list(&provider["granted"]),
                render_capability_id_list(&provider["observed"]),
            ));
        }
        html.push_str("</tbody></table>");
    }

    // Detail appendix: aggregated inventory. Instance-suffixed bom-refs are
    // collapsed into provider rows with instance counts; raw refs stay in the
    // JSON artifacts.
    html.push_str("<h2 id=\"appendix\">Appendix: Inventory Detail</h2>");
    html.push_str("<h3>Discovered Components</h3><table><thead><tr><th>Component</th><th>Surface</th><th>Instances</th><th>Declared</th><th>Granted</th><th>Observed</th></tr></thead><tbody>");
    for rollup in report["surfaceRollups"].as_array().into_iter().flatten() {
        for provider in rollup["providers"].as_array().into_iter().flatten() {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                display_text(provider["provider"].as_str().unwrap_or("unknown")),
                display_text(rollup["label"].as_str().unwrap_or("unknown")),
                provider["instanceCount"].as_u64().unwrap_or(0),
                render_capability_id_list(&provider["declared"]),
                render_capability_id_list(&provider["granted"]),
                render_capability_id_list(&provider["observed"]),
            ));
        }
    }
    html.push_str("</tbody></table>");

    html.push_str("<h3>Granted Permissions</h3><table><thead><tr><th>Component</th><th>Capability</th><th>Qualifiers</th><th>Evidence</th></tr></thead><tbody>");
    for grant in report["grantedPermissions"]
        .as_array()
        .into_iter()
        .flatten()
    {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
            display_text(
                grant
                    .get("componentDisplay")
                    .or_else(|| grant.get("component"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            ),
            display_text(grant["id"].as_str().unwrap_or("unknown")),
            display_text(&grant["qualifiers"].to_string()),
            display_text(&grant["evidence"].to_string()),
        ));
    }
    html.push_str("</tbody></table>");

    html.push_str("<h3>Evidence Records</h3><table><thead><tr><th>ID</th><th>Kind</th><th>Reference</th></tr></thead><tbody>");
    for evidence in report["evidence"].as_array().into_iter().flatten() {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            display_text(evidence["id"].as_str().unwrap_or("unknown")),
            display_text(evidence["kind"].as_str().unwrap_or("unknown")),
            display_text(evidence["reference"].as_str().unwrap_or("")),
        ));
    }
    html.push_str("</tbody></table>");

    // Footer: evidence record count, signature reference, schema versions.
    html.push_str("<h2>Provenance</h2><p class=\"meta\">");
    html.push_str(&format!(
        "Evidence records: {}. AIBOM schema version: {}. ",
        summary["evidenceRecords"].as_u64().unwrap_or(0),
        display_text(report["schemaVersion"].as_str().unwrap_or("unknown")),
    ));
    if let Some(signed_by) = report["signature"].as_str() {
        html.push_str(&format!("Signed by: {}. ", display_text(signed_by)));
    }
    html.push_str("AIBOM canonical SHA-256: <code>");
    html.push_str(&display_text(
        report["source"]["canonicalSha256"]
            .as_str()
            .unwrap_or("unknown"),
    ));
    html.push_str("</code></p></body></html>");
    html
}

fn render_capability_id_list(value: &Value) -> String {
    let Some(items) = value.as_array() else {
        return String::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .map(|id| format!("<span class=\"pill\">{}</span>", display_text(id)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_report_pdf(report: &Value) -> Vec<u8> {
    let summary = &report["summary"];
    let scan = &report["scan"];
    let source = &report["source"];
    let sensitive_line = if report["sensitiveData"]["available"] == true {
        format!(
            "Sensitive-data findings: {}",
            report["sensitiveData"]["findingCount"]
                .as_u64()
                .unwrap_or(0)
        )
    } else {
        "Sensitive-data findings: no sensitive-data report supplied".to_string()
    };
    let lines = vec![
        "Reeve Per-Machine Report".to_string(),
        format!("Scan: {}", scan["id"].as_str().unwrap_or("unknown")),
        format!(
            "Timestamp: {}",
            scan["timestamp"].as_str().unwrap_or("unknown")
        ),
        format!(
            "Policy: {} DENY, {} WARN",
            summary["policyDeny"].as_u64().unwrap_or(0),
            summary["policyWarn"].as_u64().unwrap_or(0)
        ),
        sensitive_line,
        format!(
            "Components: {}",
            summary["components"].as_u64().unwrap_or(0)
        ),
        format!(
            "Declared capabilities: {}",
            summary["declaredCapabilities"].as_u64().unwrap_or(0)
        ),
        format!(
            "Granted permissions: {}",
            summary["grantedPermissions"].as_u64().unwrap_or(0)
        ),
        format!(
            "Observed capabilities: {}",
            summary["observedCapabilities"].as_u64().unwrap_or(0)
        ),
        format!(
            "Evidence records: {}",
            summary["evidenceRecords"].as_u64().unwrap_or(0)
        ),
        format!(
            "AIBOM SHA-256: {}",
            source["canonicalSha256"].as_str().unwrap_or("unknown")
        ),
    ];
    simple_pdf(&lines)
}

fn simple_pdf(lines: &[String]) -> Vec<u8> {
    let mut stream = String::new();
    stream.push_str("BT /F1 14 Tf 50 770 Td (");
    stream.push_str(&pdf_escape(
        lines.first().map(String::as_str).unwrap_or("Reeve Report"),
    ));
    stream.push_str(") Tj ET\n");
    let mut y = 740;
    for line in lines.iter().skip(1) {
        stream.push_str(&format!(
            "BT /F1 10 Tf 50 {y} Td ({}) Tj ET\n",
            pdf_escape(line)
        ));
        y -= 18;
    }

    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_string(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        format!("<< /Length {} >>\nstream\n{}endstream", stream.len(), stream),
    ];
    let mut pdf = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (idx, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", idx + 1, object).as_bytes());
    }
    let xref_offset = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            objects.len() + 1,
            xref_offset
        )
        .as_bytes(),
    );
    pdf
}

fn pdf_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
        .replace(['\r', '\n'], " ")
}

fn find_one(dir: &Path, suffix: &str) -> Result<PathBuf> {
    find_one_excluding(dir, suffix, "")
}

fn find_one_excluding(dir: &Path, suffix: &str, exclude: &str) -> Result<PathBuf> {
    let matches: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.ends_with(suffix) && (exclude.is_empty() || !name.contains(exclude))
                })
        })
        .collect();
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => bail!("no *{suffix} found in {}", dir.display()),
        _ => bail!("multiple *{suffix} files found in {}", dir.display()),
    }
}

fn read_allowlist(path: Option<PathBuf>) -> Result<Allowlist> {
    let Some(path) = path else {
        return Ok(Allowlist::default());
    };
    let bytes = std::fs::read(path)?;
    Ok(serde_yaml::from_slice(&bytes)?)
}

fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

#[derive(Debug)]
enum RegistrySource {
    Http { base: String, client: Client },
    File { root: PathBuf },
}

#[derive(Debug)]
enum RegistryFetchError {
    NotFound,
    Unavailable(String),
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RegistryHostedEndpoint {
    transport: String,
    url: String,
}

#[derive(Debug, Clone, Default)]
struct RegistryComponentHints {
    hosted_endpoints: Vec<RegistryHostedEndpoint>,
    /// True when every provider behind the component is scanner-synthetic
    /// state (grant/approval state, presence-only stores) rather than a
    /// registry-publishable artifact. Synthetic components are never
    /// token-searched into registry candidates.
    synthetic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryExactMatchCandidate {
    server_path: String,
    matched_endpoints: Vec<RegistryHostedEndpoint>,
}

#[derive(Debug, Default)]
struct RegistryExactMatchIndex {
    by_endpoint: BTreeMap<(String, String), BTreeSet<String>>,
    by_purl: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryPurlMatch {
    server_paths: Vec<String>,
    matched_purl_form: &'static str,
}

fn consult_registry_source(
    source: &str,
    artifacts: &ScanOutputArtifacts,
    output_dir: &Path,
    component_hints: Option<&BTreeMap<String, RegistryComponentHints>>,
) -> Result<PathBuf> {
    let registry = RegistrySource::new(source)?;
    let cdx = read_json(&artifacts.cdx_path)
        .with_context(|| format!("read CycloneDX {}", artifacts.cdx_path.display()))?;
    let mut warnings = Vec::new();
    let mut lookups = Vec::new();
    let mut source_failure: Option<String> = None;
    let exact_match_index = match RegistryExactMatchIndex::from_source(&registry) {
        Ok(index) => index,
        Err(RegistryFetchError::Unavailable(error)) | Err(RegistryFetchError::Invalid(error)) => {
            warnings.push(error.clone());
            source_failure = Some(error);
            None
        }
        Err(RegistryFetchError::NotFound) => None,
    };

    if let Some(components) = cdx.get("components").and_then(Value::as_array) {
        for component in components {
            let bom_ref = component
                .get("bom-ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let name = component
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let purl = component
                .get("purl")
                .and_then(Value::as_str)
                .map(str::to_string);
            let query_tokens = registry_query_tokens(&name, purl.as_deref());
            let component_hint = component_hints.and_then(|hints| hints.get(&bom_ref));
            let hosted_endpoints = component_hint
                .map(|hints| hints.hosted_endpoints.clone())
                .unwrap_or_default();
            let hosted_endpoints_json = registry_hosted_endpoints_json(&hosted_endpoints);
            let synthetic = match component_hint {
                Some(hint) => hint.synthetic,
                None => {
                    registry_component_synthetic_fallback(&name, purl.as_deref(), &hosted_endpoints)
                }
            };

            if synthetic {
                lookups.push(json!({
                    "bomRef": bom_ref,
                    "componentName": name,
                    "purl": purl,
                    "hostedEndpoints": hosted_endpoints_json,
                    "status": "not-applicable",
                    "note": "scanner-synthetic component; not a registry artifact",
                }));
                continue;
            }

            if let Some(error) = source_failure.as_ref() {
                lookups.push(json!({
                    "bomRef": bom_ref,
                    "componentName": name,
                    "purl": purl,
                    "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                    "hostedEndpoints": hosted_endpoints_json,
                    "status": "source-unavailable",
                    "error": error,
                }));
                continue;
            }

            let mut candidate_scores: BTreeMap<String, usize> = BTreeMap::new();
            let mut candidate_results: BTreeMap<String, Value> = BTreeMap::new();
            let mut candidate_tokens: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            let mut token_notes = Vec::new();
            let mut token_failure = None;

            // Stage 1: exact purl match against declared package
            // coordinates (file-tree sources only; the static HTTP
            // contract has no purl route yet).
            let normalized_purl = purl.as_deref().and_then(registry_match::normalize_purl);
            let purl_index_match = match (normalized_purl.as_deref(), exact_match_index.as_ref()) {
                (Some(normalized_purl), Some(index)) => index.match_purl(normalized_purl),
                _ => None,
            };
            if let Some(purl_match) = purl_index_match {
                if let [server_path] = purl_match.server_paths.as_slice() {
                    match registry.fetch_json(server_path) {
                        Ok(server_fixture) => {
                            lookups.push(json!({
                                "bomRef": bom_ref,
                                "componentName": name,
                                "purl": purl,
                                "normalizedPurl": normalized_purl,
                                "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                                "hostedEndpoints": hosted_endpoints_json,
                                "status": "matched-purl",
                                "matchStrategy": "purl-exact",
                                "matchedPurlForm": purl_match.matched_purl_form,
                                "serverPath": server_path,
                                "server": server_fixture,
                            }));
                            continue;
                        }
                        Err(RegistryFetchError::NotFound) => {
                            token_notes.push(format!(
                                "purl-exact match resolved to missing fixture '{server_path}'"
                            ));
                        }
                        Err(RegistryFetchError::Unavailable(error))
                        | Err(RegistryFetchError::Invalid(error)) => {
                            warnings.push(error.clone());
                            source_failure = Some(error.clone());
                            lookups.push(json!({
                                "bomRef": bom_ref,
                                "componentName": name,
                                "purl": purl,
                                "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                                "hostedEndpoints": hosted_endpoints_json,
                                "status": "source-unavailable",
                                "error": error,
                            }));
                            continue;
                        }
                    }
                } else {
                    let candidates: Vec<Value> = purl_match
                        .server_paths
                        .iter()
                        .map(|server_path| json!({ "serverPath": server_path }))
                        .collect();
                    lookups.push(json!({
                        "bomRef": bom_ref,
                        "componentName": name,
                        "purl": purl,
                        "normalizedPurl": normalized_purl,
                        "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                        "hostedEndpoints": hosted_endpoints_json,
                        "status": "ambiguous",
                        "matchStrategy": "purl-exact",
                        "matchedPurlForm": purl_match.matched_purl_form,
                        "candidates": candidates,
                    }));
                    continue;
                }
            }

            let exact_matches = match registry_exact_match_candidates(
                &registry,
                exact_match_index.as_ref(),
                &hosted_endpoints,
            ) {
                Ok(matches) => matches,
                Err(RegistryFetchError::Unavailable(error))
                | Err(RegistryFetchError::Invalid(error)) => {
                    warnings.push(error.clone());
                    source_failure = Some(error.clone());
                    lookups.push(json!({
                        "bomRef": bom_ref,
                        "componentName": name,
                        "purl": purl,
                        "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                        "hostedEndpoints": hosted_endpoints_json,
                        "status": "source-unavailable",
                        "error": error,
                    }));
                    continue;
                }
                Err(RegistryFetchError::NotFound) => Vec::new(),
            };

            if let Some(candidate) = exact_matches.first()
                && exact_matches.len() == 1
            {
                match registry.fetch_json(&candidate.server_path) {
                    Ok(server_fixture) => {
                        lookups.push(json!({
                            "bomRef": bom_ref,
                            "componentName": name,
                            "purl": purl,
                            "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                            "hostedEndpoints": hosted_endpoints_json,
                            "matchedHostedEndpoints": registry_hosted_endpoints_json(
                                &candidate.matched_endpoints
                            ),
                            "status": "matched-hosted-url",
                            "matchStrategy": "exact-hosted-url",
                            "serverPath": candidate.server_path,
                            "server": server_fixture,
                        }));
                        continue;
                    }
                    Err(RegistryFetchError::NotFound) => {
                        token_notes.push(format!(
                            "exact hosted URL match resolved to missing fixture '{}'",
                            candidate.server_path
                        ));
                    }
                    Err(RegistryFetchError::Unavailable(error))
                    | Err(RegistryFetchError::Invalid(error)) => {
                        warnings.push(error.clone());
                        source_failure = Some(error.clone());
                        lookups.push(json!({
                            "bomRef": bom_ref,
                            "componentName": name,
                            "purl": purl,
                            "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                            "hostedEndpoints": hosted_endpoints_json,
                            "status": "source-unavailable",
                            "error": error,
                        }));
                        continue;
                    }
                }
            }

            for token in &query_tokens {
                match registry.fetch_json(&format!("search/q/{token}.json")) {
                    Ok(search_fixture) => {
                        let Some(results) = search_fixture.get("results").and_then(Value::as_array)
                        else {
                            token_notes.push(format!(
                                "search fixture for token '{token}' did not contain a results array"
                            ));
                            continue;
                        };
                        for result in results {
                            let Some(server_path) =
                                result.get("serverPath").and_then(Value::as_str)
                            else {
                                continue;
                            };
                            *candidate_scores.entry(server_path.to_string()).or_default() += 1;
                            candidate_results
                                .entry(server_path.to_string())
                                .or_insert_with(|| result.clone());
                            candidate_tokens
                                .entry(server_path.to_string())
                                .or_default()
                                .insert(token.clone());
                        }
                    }
                    Err(RegistryFetchError::NotFound) => {}
                    Err(RegistryFetchError::Unavailable(error))
                    | Err(RegistryFetchError::Invalid(error)) => {
                        token_failure = Some(error);
                        break;
                    }
                }
            }

            if let Some(error) = token_failure {
                warnings.push(error.clone());
                source_failure = Some(error.clone());
                lookups.push(json!({
                    "bomRef": bom_ref,
                    "componentName": name,
                    "purl": purl,
                    "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                    "hostedEndpoints": hosted_endpoints_json,
                    "status": "source-unavailable",
                    "error": error,
                }));
                continue;
            }

            if exact_matches.len() > 1 {
                let exact_match_paths: BTreeSet<_> = exact_matches
                    .iter()
                    .map(|candidate| candidate.server_path.as_str())
                    .collect();
                let mut ranked_exact: Vec<_> = candidate_scores
                    .iter()
                    .filter(|(path, _)| exact_match_paths.contains(path.as_str()))
                    .map(|(path, score)| (path.clone(), *score))
                    .collect();
                ranked_exact.sort_by(|(path_a, score_a), (path_b, score_b)| {
                    score_b.cmp(score_a).then_with(|| path_a.cmp(path_b))
                });

                let build_ambiguous_exact_candidates = || -> Vec<Value> {
                    exact_matches
                        .iter()
                        .map(|candidate| {
                            json!({
                                "serverPath": candidate.server_path,
                                "matchedHostedEndpoints": registry_hosted_endpoints_json(
                                    &candidate.matched_endpoints
                                ),
                                "matchedQueryTokens": candidate_tokens
                                    .get(&candidate.server_path)
                                    .map(|tokens| tokens.iter().cloned().collect::<Vec<_>>())
                                    .unwrap_or_default(),
                            })
                        })
                        .collect()
                };

                if ranked_exact.is_empty() {
                    token_notes.push(
                        "token search did not narrow ambiguous exact hosted URL matches"
                            .to_string(),
                    );
                    lookups.push(json!({
                        "bomRef": bom_ref,
                        "componentName": name,
                        "purl": purl,
                        "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                        "hostedEndpoints": hosted_endpoints_json,
                        "status": "ambiguous",
                        "matchStrategy": "exact-hosted-url",
                        "candidates": build_ambiguous_exact_candidates(),
                        "notes": token_notes,
                    }));
                    continue;
                }

                let top_score = ranked_exact[0].1;
                let top_paths: Vec<_> = ranked_exact
                    .iter()
                    .filter(|(_, score)| *score == top_score)
                    .map(|(path, _)| path.clone())
                    .collect();
                if top_paths.len() > 1 {
                    token_notes.push(
                        "token search did not uniquely disambiguate exact hosted URL matches"
                            .to_string(),
                    );
                    lookups.push(json!({
                        "bomRef": bom_ref,
                        "componentName": name,
                        "purl": purl,
                        "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                        "hostedEndpoints": hosted_endpoints_json,
                        "status": "ambiguous",
                        "matchStrategy": "exact-hosted-url",
                        "candidates": build_ambiguous_exact_candidates(),
                        "notes": token_notes,
                    }));
                    continue;
                }

                let server_path = top_paths[0].clone();
                let Some(exact_candidate) = exact_matches
                    .iter()
                    .find(|candidate| candidate.server_path == server_path)
                else {
                    unreachable!("ranked exact match path must come from exact match candidates");
                };
                let search_result = candidate_results
                    .get(&server_path)
                    .cloned()
                    .unwrap_or_else(|| json!({ "serverPath": server_path }));
                match registry.fetch_json(&server_path) {
                    Ok(server_fixture) => {
                        lookups.push(json!({
                            "bomRef": bom_ref,
                            "componentName": name,
                            "purl": purl,
                            "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                            "hostedEndpoints": hosted_endpoints_json,
                            "matchedHostedEndpoints": registry_hosted_endpoints_json(
                                &exact_candidate.matched_endpoints
                            ),
                            "matchedQueryTokens": candidate_tokens
                                .remove(&server_path)
                                .map(|tokens| tokens.iter().cloned().collect::<Vec<_>>())
                                .unwrap_or_default(),
                            "status": "matched-hosted-url",
                            "matchStrategy": "exact-hosted-url+token-search",
                            "serverPath": server_path,
                            "searchResult": search_result,
                            "server": server_fixture,
                            "notes": token_notes,
                        }));
                    }
                    Err(RegistryFetchError::NotFound) => {
                        lookups.push(json!({
                            "bomRef": bom_ref,
                            "componentName": name,
                            "purl": purl,
                            "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                            "hostedEndpoints": hosted_endpoints_json,
                            "matchedHostedEndpoints": registry_hosted_endpoints_json(
                                &exact_candidate.matched_endpoints
                            ),
                            "matchedQueryTokens": candidate_tokens
                                .remove(&server_path)
                                .map(|tokens| tokens.iter().cloned().collect::<Vec<_>>())
                                .unwrap_or_default(),
                            "status": "search-match-only",
                            "matchStrategy": "exact-hosted-url+token-search",
                            "serverPath": server_path,
                            "searchResult": search_result,
                            "notes": token_notes,
                        }));
                    }
                    Err(RegistryFetchError::Unavailable(error))
                    | Err(RegistryFetchError::Invalid(error)) => {
                        warnings.push(error.clone());
                        source_failure = Some(error.clone());
                        lookups.push(json!({
                            "bomRef": bom_ref,
                            "componentName": name,
                            "purl": purl,
                            "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                            "hostedEndpoints": hosted_endpoints_json,
                            "status": "source-unavailable",
                            "error": error,
                        }));
                    }
                }
                continue;
            }

            if candidate_scores.is_empty() {
                lookups.push(json!({
                    "bomRef": bom_ref,
                    "componentName": name,
                    "purl": purl,
                    "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                    "hostedEndpoints": hosted_endpoints_json,
                    "status": "no-match",
                    "notes": token_notes,
                }));
                continue;
            }

            let mut ranked: Vec<_> = candidate_scores.into_iter().collect();
            ranked.sort_by(|(path_a, score_a), (path_b, score_b)| {
                score_b.cmp(score_a).then_with(|| path_a.cmp(path_b))
            });
            let top_score = ranked[0].1;
            let top_paths: Vec<_> = ranked
                .iter()
                .filter(|(_, score)| *score == top_score)
                .map(|(path, _)| path.clone())
                .collect();

            if top_paths.len() > 1 {
                let candidates: Vec<_> = top_paths
                    .iter()
                    .filter_map(|path| {
                        candidate_results.get(path).map(|result| {
                            json!({
                                "serverPath": path,
                                "searchResult": result,
                                "queryTokens": candidate_tokens
                                    .get(path)
                                    .map(|tokens| tokens.iter().cloned().collect::<Vec<_>>())
                                    .unwrap_or_default(),
                            })
                        })
                    })
                    .collect();
                lookups.push(json!({
                    "bomRef": bom_ref,
                    "componentName": name,
                    "purl": purl,
                    "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                    "hostedEndpoints": hosted_endpoints_json,
                    "status": "ambiguous",
                    "matchStrategy": "token-search",
                    "candidates": candidates,
                    "notes": token_notes,
                }));
                continue;
            }

            let server_path = top_paths[0].clone();
            let search_result = candidate_results
                .get(&server_path)
                .cloned()
                .unwrap_or_else(|| json!({ "serverPath": server_path }));
            match registry.fetch_json(&server_path) {
                Ok(server_fixture) => {
                    lookups.push(json!({
                        "bomRef": bom_ref,
                        "componentName": name,
                        "purl": purl,
                        "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                        "hostedEndpoints": hosted_endpoints_json,
                        "matchedQueryTokens": candidate_tokens
                            .remove(&server_path)
                            .map(|tokens| tokens.iter().cloned().collect::<Vec<_>>())
                            .unwrap_or_default(),
                        "status": "candidate",
                        "matchStrategy": "token-search",
                        "serverPath": server_path,
                        "searchResult": search_result,
                        "server": server_fixture,
                        "notes": token_notes,
                    }));
                }
                Err(RegistryFetchError::NotFound) => {
                    lookups.push(json!({
                        "bomRef": bom_ref,
                        "componentName": name,
                        "purl": purl,
                        "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                        "hostedEndpoints": hosted_endpoints_json,
                        "matchedQueryTokens": candidate_tokens
                            .remove(&server_path)
                            .map(|tokens| tokens.iter().cloned().collect::<Vec<_>>())
                            .unwrap_or_default(),
                        "status": "search-match-only",
                        "matchStrategy": "token-search",
                        "serverPath": server_path,
                        "searchResult": search_result,
                        "notes": token_notes,
                    }));
                }
                Err(RegistryFetchError::Unavailable(error))
                | Err(RegistryFetchError::Invalid(error)) => {
                    warnings.push(error.clone());
                    lookups.push(json!({
                        "bomRef": bom_ref,
                        "componentName": name,
                        "purl": purl,
                        "queryTokens": query_tokens.iter().cloned().collect::<Vec<_>>(),
                        "hostedEndpoints": hosted_endpoints_json,
                        "matchedQueryTokens": candidate_tokens
                            .remove(&server_path)
                            .map(|tokens| tokens.iter().cloned().collect::<Vec<_>>())
                            .unwrap_or_default(),
                        "status": "search-match-only",
                        "matchStrategy": "token-search",
                        "serverPath": server_path,
                        "searchResult": search_result,
                        "error": error,
                        "notes": token_notes,
                    }));
                }
            }
        }
    }

    warnings.sort();
    warnings.dedup();
    for warning in &warnings {
        eprintln!("WARN registry-source {warning}");
    }

    let report_path = output_dir.join(format!("{}.registry-lookup.json", artifacts.scan_id));
    let report = json!({
        "source": source,
        "contract": "mcp-registry-static-search-v1",
        "lookups": lookups,
        "warnings": warnings,
    });
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(report_path)
}

fn discover_registry_component_hints(
    runtime: &tokio::runtime::Runtime,
    root: &Path,
    custom_surfaces: &[CustomSurfaceSpec],
) -> Result<BTreeMap<String, RegistryComponentHints>> {
    let providers = if custom_surfaces.is_empty() {
        discover_all(root)?
    } else {
        discover_all_with_custom(root, custom_surfaces)?
    };
    let adapter = McpAdapter::new();
    let groups = runtime.block_on(group_registrations(&adapter, &providers))?;
    Ok(registry_component_hints_by_bom_ref(&groups))
}

fn registry_component_hints_by_bom_ref(
    groups: &[ProviderGroup],
) -> BTreeMap<String, RegistryComponentHints> {
    let mut hints = BTreeMap::new();
    let mut bom_ref_counts = BTreeMap::new();
    let mut used_bom_refs = BTreeSet::new();

    for (index, group) in groups.iter().enumerate() {
        let canonical = &group.occurrences[0];
        let bom_ref = registry_lookup_reserve_bom_ref(
            registry_lookup_unique_bom_ref(
                &group.identity.bom_ref,
                canonical,
                index,
                &mut bom_ref_counts,
            ),
            &mut used_bom_refs,
            &format!("component-{index}"),
        );
        let hosted_endpoints: BTreeSet<_> = group
            .occurrences
            .iter()
            .filter_map(registry_hosted_endpoint_from_provider)
            .collect();
        let synthetic = group
            .occurrences
            .iter()
            .all(registry_synthetic_state_provider);
        if !hosted_endpoints.is_empty() || synthetic {
            hints.insert(
                bom_ref,
                RegistryComponentHints {
                    hosted_endpoints: hosted_endpoints.into_iter().collect(),
                    synthetic,
                },
            );
        }
    }

    hints
}

/// True for providers the scanner synthesizes from local approval/grant
/// state or presence-only stores. These are evidence about the host, not
/// registry-publishable artifacts, so registry lookup must not search
/// them into candidates.
fn registry_synthetic_state_provider(provider: &aibom_core::ToolProvider) -> bool {
    is_grant_state_provider(provider)
        || claude_cowork::is_state_provider(provider)
        || matches!(
            (provider.surface.as_str(), provider.name.as_str()),
            (
                "claude-cowork",
                claude_cowork::COWORK_SESSION_METADATA_PROVIDER_NAME
            ) | (
                "claude-code-desktop",
                claude_cowork::CLAUDE_CODE_DESKTOP_SESSION_METADATA_PROVIDER_NAME
            )
        )
}

/// Conservative fallback when no component hints are available: a
/// component with no purl, no hosted endpoints, and a known
/// scanner-synthetic naming pattern is treated as synthetic.
fn registry_component_synthetic_fallback(
    name: &str,
    purl: Option<&str>,
    hosted_endpoints: &[RegistryHostedEndpoint],
) -> bool {
    if purl.is_some() || !hosted_endpoints.is_empty() {
        return false;
    }
    let mut normalized = String::new();
    for ch in name.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            normalized.push(ch);
        } else if !normalized.ends_with('-') {
            normalized.push('-');
        }
    }
    let normalized = normalized.trim_matches('-');
    normalized.ends_with("approval-state")
        || normalized.ends_with("approvalstate")
        || normalized.ends_with("approval-cache")
        || normalized.ends_with("connector-store")
        || normalized.ends_with("metadata-state")
}

fn registry_hosted_endpoint_from_provider(
    provider: &aibom_core::ToolProvider,
) -> Option<RegistryHostedEndpoint> {
    match &provider.transport {
        Transport::HttpSse(http) => Some(RegistryHostedEndpoint {
            transport: "streamable-http".to_string(),
            url: normalize_registry_endpoint_url(&http.url),
        }),
        Transport::WebSocket(ws) => Some(RegistryHostedEndpoint {
            transport: "websocket".to_string(),
            url: normalize_registry_endpoint_url(&ws.url),
        }),
        Transport::Stdio(_) | Transport::Unknown(_) => None,
    }
}

fn registry_lookup_unique_bom_ref(
    base: &str,
    provider: &aibom_core::ToolProvider,
    index: usize,
    seen: &mut BTreeMap<String, usize>,
) -> String {
    let count = seen.entry(base.to_string()).or_insert(0);
    if *count == 0 {
        *count += 1;
        return base.to_string();
    }
    *count += 1;
    format!(
        "{}#instance-{}-{}-{}",
        base,
        registry_lookup_normalize_fragment(&provider.surface),
        registry_lookup_normalize_fragment(&provider.name),
        index
    )
}

fn registry_lookup_normalize_fragment(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            out.push(ch);
        } else if matches!(ch, '-' | '_' | '.' | ':' | '/') {
            out.push('-');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out.trim_matches('-').to_string()
    }
}

fn registry_lookup_reserve_bom_ref(
    preferred: String,
    used: &mut BTreeSet<String>,
    suffix_hint: &str,
) -> String {
    if used.insert(preferred.clone()) {
        return preferred;
    }
    for index in 1.. {
        let candidate = format!("{preferred}#aibom-{suffix_hint}-{index}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("unbounded bom-ref suffix loop")
}

fn registry_hosted_endpoints_json(endpoints: &[RegistryHostedEndpoint]) -> Vec<Value> {
    endpoints
        .iter()
        .map(|endpoint| {
            json!({
                "transport": endpoint.transport,
                "url": endpoint.url,
            })
        })
        .collect()
}

fn normalize_registry_endpoint_url(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() > 1 {
        trimmed.trim_end_matches('/').to_string()
    } else {
        trimmed.to_string()
    }
}

fn registry_remote_transport_type(value: &str) -> Option<&'static str> {
    match value {
        "streamable-http" | "http" | "http-sse" | "sse" => Some("streamable-http"),
        "websocket" | "ws" => Some("websocket"),
        _ => None,
    }
}

fn registry_hosted_url_digest(endpoint: &RegistryHostedEndpoint) -> String {
    sha256_hex(format!("{}\n{}", endpoint.transport, endpoint.url).as_bytes())
}

fn registry_exact_match_candidates(
    registry: &RegistrySource,
    file_index: Option<&RegistryExactMatchIndex>,
    endpoints: &[RegistryHostedEndpoint],
) -> std::result::Result<Vec<RegistryExactMatchCandidate>, RegistryFetchError> {
    match registry {
        RegistrySource::File { .. } => Ok(file_index
            .map(|index| index.match_paths(endpoints))
            .unwrap_or_default()),
        RegistrySource::Http { .. } => {
            registry_exact_match_candidates_from_http(registry, endpoints)
        }
    }
}

fn registry_exact_match_candidates_from_http(
    registry: &RegistrySource,
    endpoints: &[RegistryHostedEndpoint],
) -> std::result::Result<Vec<RegistryExactMatchCandidate>, RegistryFetchError> {
    let mut matches: BTreeMap<String, BTreeSet<RegistryHostedEndpoint>> = BTreeMap::new();
    for endpoint in endpoints {
        let digest = registry_hosted_url_digest(endpoint);
        let relative_path = format!("servers/by-hosted-url/{}/{digest}.json", endpoint.transport);
        match registry.fetch_json(&relative_path) {
            Ok(response) => {
                let results = response
                    .get("results")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        RegistryFetchError::Invalid(format!(
                            "hosted URL fixture '{relative_path}' did not contain a results array"
                        ))
                    })?;
                for result in results {
                    let Some(server_path) = result.get("serverPath").and_then(Value::as_str) else {
                        return Err(RegistryFetchError::Invalid(format!(
                            "hosted URL fixture '{relative_path}' contained a result without serverPath"
                        )));
                    };
                    matches
                        .entry(server_path.to_string())
                        .or_default()
                        .insert(endpoint.clone());
                }
            }
            Err(RegistryFetchError::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(matches
        .into_iter()
        .map(
            |(server_path, matched_endpoints)| RegistryExactMatchCandidate {
                server_path,
                matched_endpoints: matched_endpoints.into_iter().collect(),
            },
        )
        .collect())
}

fn collect_registry_server_fixture_paths(root: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for publisher_entry in std::fs::read_dir(root)? {
        let publisher_entry = publisher_entry?;
        let publisher_path = publisher_entry.path();
        if !publisher_path.is_dir() {
            continue;
        }
        let Some(publisher_name) = publisher_path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if publisher_name.starts_with("by-") {
            continue;
        }
        for server_entry in std::fs::read_dir(&publisher_path)? {
            let server_entry = server_entry?;
            let server_path = server_entry.path();
            let is_json = server_path.extension().and_then(|ext| ext.to_str()) == Some("json");
            let is_sigstore_bundle = server_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".sigstore.json"));
            if is_json && !is_sigstore_bundle {
                files.push(server_path);
            }
        }
    }
    Ok(())
}

fn registry_server_fixture_hosted_endpoints(
    fixture: &Value,
) -> std::result::Result<Vec<RegistryHostedEndpoint>, RegistryFetchError> {
    let versions = fixture
        .get("versions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            RegistryFetchError::Invalid("server fixture missing versions array".to_string())
        })?;
    let latest_version = fixture.get("latestVersion").and_then(Value::as_str);
    let selected = versions
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
        .ok_or_else(|| RegistryFetchError::Invalid("server fixture had no versions".to_string()))?;
    let remotes = selected
        .pointer("/declaredMetadata/remotes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let endpoints: BTreeSet<_> = remotes
        .iter()
        .filter_map(|remote| {
            let transport = remote
                .get("type")
                .and_then(Value::as_str)
                .and_then(registry_remote_transport_type)?;
            let url = remote.get("url").and_then(Value::as_str)?;
            Some(RegistryHostedEndpoint {
                transport: transport.to_string(),
                url: normalize_registry_endpoint_url(url),
            })
        })
        .collect();
    Ok(endpoints.into_iter().collect())
}

impl RegistryExactMatchIndex {
    fn from_source(
        source: &RegistrySource,
    ) -> std::result::Result<Option<Self>, RegistryFetchError> {
        let RegistrySource::File { root } = source else {
            return Ok(None);
        };
        if !root.exists() {
            return Err(RegistryFetchError::Unavailable(format!(
                "registry-source path {} does not exist",
                root.display()
            )));
        }
        let servers_root = root.join("servers");
        if !servers_root.is_dir() {
            return Err(RegistryFetchError::Unavailable(format!(
                "registry-source path {} does not contain a servers/ fixture tree",
                root.display()
            )));
        }

        let mut fixture_paths = Vec::new();
        collect_registry_server_fixture_paths(&servers_root, &mut fixture_paths).map_err(
            |error| {
                RegistryFetchError::Unavailable(format!("walk {}: {error}", servers_root.display()))
            },
        )?;

        let mut by_endpoint: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        let mut by_purl: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for fixture_path in fixture_paths {
            let fixture = read_json(&fixture_path).map_err(|error| {
                RegistryFetchError::Invalid(format!(
                    "read {} as JSON: {error}",
                    fixture_path.display()
                ))
            })?;
            let server_path = fixture_path
                .strip_prefix(root)
                .map_err(|error| {
                    RegistryFetchError::Invalid(format!(
                        "strip registry-source prefix from {}: {error}",
                        fixture_path.display()
                    ))
                })?
                .to_string_lossy()
                .replace('\\', "/");
            for endpoint in registry_server_fixture_hosted_endpoints(&fixture)? {
                by_endpoint
                    .entry((endpoint.transport.clone(), endpoint.url.clone()))
                    .or_default()
                    .insert(server_path.clone());
            }
            for coordinate in registry_match::package_coordinates_from_server(&fixture) {
                let Some(purl) = coordinate.purl else {
                    continue;
                };
                let versionless = registry_match::purl_without_version(&purl);
                if versionless != purl {
                    by_purl
                        .entry(versionless)
                        .or_default()
                        .insert(server_path.clone());
                }
                by_purl.entry(purl).or_default().insert(server_path.clone());
            }
        }

        Ok(Some(Self {
            by_endpoint,
            by_purl,
        }))
    }

    /// Exact purl lookup: the normalized component purl first, then its
    /// version-less form (covers fixtures whose package coordinate has no
    /// version, and version drift between the discovered component and
    /// the latest published coordinate).
    fn match_purl(&self, normalized_purl: &str) -> Option<RegistryPurlMatch> {
        if let Some(server_paths) = self.by_purl.get(normalized_purl) {
            return Some(RegistryPurlMatch {
                server_paths: server_paths.iter().cloned().collect(),
                matched_purl_form: "exact",
            });
        }
        let versionless = registry_match::purl_without_version(normalized_purl);
        if versionless != normalized_purl
            && let Some(server_paths) = self.by_purl.get(&versionless)
        {
            return Some(RegistryPurlMatch {
                server_paths: server_paths.iter().cloned().collect(),
                matched_purl_form: "version-less",
            });
        }
        None
    }

    fn match_paths(
        &self,
        endpoints: &[RegistryHostedEndpoint],
    ) -> Vec<RegistryExactMatchCandidate> {
        let mut matches: BTreeMap<String, BTreeSet<RegistryHostedEndpoint>> = BTreeMap::new();
        for endpoint in endpoints {
            if let Some(server_paths) = self
                .by_endpoint
                .get(&(endpoint.transport.clone(), endpoint.url.clone()))
            {
                for server_path in server_paths {
                    matches
                        .entry(server_path.clone())
                        .or_default()
                        .insert(endpoint.clone());
                }
            }
        }
        matches
            .into_iter()
            .map(
                |(server_path, matched_endpoints)| RegistryExactMatchCandidate {
                    server_path,
                    matched_endpoints: matched_endpoints.into_iter().collect(),
                },
            )
            .collect()
    }
}

impl RegistrySource {
    fn new(source: &str) -> Result<Self> {
        if source.starts_with("http://") || source.starts_with("https://") {
            let client = Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .context("build registry-source HTTP client")?;
            return Ok(Self::Http {
                base: source.trim_end_matches('/').to_string(),
                client,
            });
        }

        let root = if let Some(path) = source.strip_prefix("file://") {
            PathBuf::from(path)
        } else {
            PathBuf::from(source)
        };
        Ok(Self::File { root })
    }

    fn fetch_json(&self, relative_path: &str) -> std::result::Result<Value, RegistryFetchError> {
        match self {
            Self::Http { base, client } => {
                let url = format!("{}/{}", base, relative_path.trim_start_matches('/'));
                let response = client.get(&url).send().map_err(|error| {
                    RegistryFetchError::Unavailable(format!("GET {url} failed: {error}"))
                })?;
                let status = response.status();
                if status.as_u16() == 404 {
                    return Err(RegistryFetchError::NotFound);
                }
                if !status.is_success() {
                    return Err(RegistryFetchError::Unavailable(format!(
                        "GET {url} returned {status}"
                    )));
                }
                response.json().map_err(|error| {
                    RegistryFetchError::Invalid(format!("decode {url} as JSON: {error}"))
                })
            }
            Self::File { root } => {
                if !root.exists() {
                    return Err(RegistryFetchError::Unavailable(format!(
                        "registry source root {} does not exist",
                        root.display()
                    )));
                }
                let path = root.join(relative_path);
                let bytes = std::fs::read(&path).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        RegistryFetchError::NotFound
                    } else {
                        RegistryFetchError::Unavailable(format!("read {}: {error}", path.display()))
                    }
                })?;
                serde_json::from_slice(&bytes).map_err(|error| {
                    RegistryFetchError::Invalid(format!(
                        "decode {} as JSON: {error}",
                        path.display()
                    ))
                })
            }
        }
    }
}

fn registry_query_tokens(name: &str, purl: Option<&str>) -> BTreeSet<String> {
    let token_regex = Regex::new(r"[a-z0-9]+").expect("valid registry token regex");
    let mut tokens = BTreeSet::new();
    for value in [Some(name), purl] {
        let Some(value) = value else {
            continue;
        };
        let lower = value.to_ascii_lowercase();
        for token in token_regex.find_iter(&lower) {
            let token = token.as_str();
            if token.len() >= 2 {
                tokens.insert(token.to_string());
            }
        }
    }
    tokens
}

fn default_target() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn default_schema_path() -> PathBuf {
    resolve_default_schema_path(Path::new(DEFAULT_AIBOM_SCHEMA_RELATIVE_PATH))
        .unwrap_or_else(|_| source_tree_schema_path())
}

fn resolve_default_schema_path(cwd_schema: &Path) -> Result<PathBuf> {
    if cwd_schema.exists() {
        return Ok(cwd_schema.to_path_buf());
    }

    if let Some(exe_schema) = current_exe_schema_path()
        && exe_schema.exists()
    {
        return Ok(exe_schema);
    }

    cached_embedded_schema_path()
}

fn resolve_schema_path_for_aibom(
    aibom_path: &Path,
    explicit_schema: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(schema) = explicit_schema {
        return Ok(schema.to_path_buf());
    }

    let aibom = read_json(aibom_path)
        .with_context(|| format!("read AIBOM {} for schema autodetect", aibom_path.display()))?;
    let version = aibom
        .pointer("/aibom/schemaVersion")
        .and_then(Value::as_str);
    let schema_url = aibom.get("$schema").and_then(Value::as_str);
    let url_version = schema_url.and_then(schema_version_for_url);

    if let (Some(version), Some(url_version)) = (version, url_version)
        && version != url_version
    {
        bail!(
            "AIBOM schema mismatch: $schema maps to version {url_version}, but aibom.schemaVersion is {version}"
        );
    }

    let detected_version = version
        .or(url_version)
        .context("AIBOM is missing aibom.schemaVersion and a supported $schema URL")?;
    let schema = embedded_schema_for_version(detected_version).with_context(|| {
        format!(
            "unsupported AIBOM schemaVersion {detected_version}; supported: {}",
            supported_schema_versions()
        )
    })?;
    cached_embedded_schema_path_for(schema)
}

fn schema_version_for_url(url: &str) -> Option<&'static str> {
    EMBEDDED_AIBOM_SCHEMAS
        .iter()
        .find(|schema| schema.url == url)
        .map(|schema| schema.version)
}

fn embedded_schema_for_version(version: &str) -> Option<EmbeddedAibomSchema> {
    EMBEDDED_AIBOM_SCHEMAS
        .iter()
        .copied()
        .find(|schema| schema.version == version)
}

fn supported_schema_versions() -> String {
    EMBEDDED_AIBOM_SCHEMAS
        .iter()
        .map(|schema| schema.version)
        .collect::<Vec<_>>()
        .join(", ")
}

fn current_exe_schema_path() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|path| {
        path.parent()
            .map(|dir| dir.join(DEFAULT_AIBOM_SCHEMA_RELATIVE_PATH))
    })
}

fn cached_embedded_schema_path() -> Result<PathBuf> {
    cached_embedded_schema_path_for(
        embedded_schema_for_version(AIBOM_SCHEMA_VERSION)
            .context("missing embedded default schema")?,
    )
}

fn cached_embedded_schema_path_for(schema: EmbeddedAibomSchema) -> Result<PathBuf> {
    let digest = sha256_hex(schema.bytes);
    let schema_dir = std::env::temp_dir().join("reeve").join("schema-cache");
    std::fs::create_dir_all(&schema_dir)?;
    let schema_path = schema_dir.join(format!("{}-{digest}.json", schema.file_name));
    match std::fs::read(&schema_path) {
        Ok(bytes) if bytes == schema.bytes => Ok(schema_path),
        _ => {
            write_embedded_schema_cache_file(&schema_dir, &schema_path, schema)?;
            Ok(schema_path)
        }
    }
}

fn write_embedded_schema_cache_file(
    schema_dir: &Path,
    schema_path: &Path,
    schema: EmbeddedAibomSchema,
) -> Result<()> {
    let counter = SCHEMA_CACHE_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_path = schema_dir.join(format!(
        ".{}-{}-{counter}.tmp",
        schema.file_name,
        std::process::id()
    ));

    std::fs::write(&tmp_path, schema.bytes)?;
    match std::fs::rename(&tmp_path, schema_path) {
        Ok(()) => Ok(()),
        Err(rename_error) => {
            if std::fs::read(schema_path)
                .map(|bytes| bytes == schema.bytes)
                .unwrap_or(false)
            {
                let _ = std::fs::remove_file(&tmp_path);
                return Ok(());
            }

            #[cfg(windows)]
            {
                let _ = std::fs::remove_file(schema_path);
                std::fs::rename(&tmp_path, schema_path)
                    .with_context(|| format!("install cached schema {}", schema_path.display()))?;
                Ok(())
            }

            #[cfg(not(windows))]
            {
                let _ = std::fs::remove_file(&tmp_path);
                Err(rename_error)
                    .with_context(|| format!("install cached schema {}", schema_path.display()))
            }
        }
    }
}

fn source_tree_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schema/aibom-v0.1.0.json")
}

fn policy_status_text(status: PolicyStatus) -> &'static str {
    match status {
        PolicyStatus::Allow => "allow",
        PolicyStatus::Deny => "deny",
        PolicyStatus::Warn => "warn",
    }
}

fn policy_status_label(status: PolicyStatus) -> &'static str {
    match status {
        PolicyStatus::Allow => "ALLOW",
        PolicyStatus::Deny => "DENY",
        PolicyStatus::Warn => "WARN",
    }
}

struct PolicyCheckOutcome {
    aibom_path: PathBuf,
    verdicts: Vec<PolicyVerdict>,
}

#[cfg(test)]
mod tests {
    use super::{
        EMBEDDED_AIBOM_SCHEMA_V1_BYTES, EMBEDDED_AIBOM_SCHEMA_V2_BYTES,
        EMBEDDED_AIBOM_SCHEMA_V3_BYTES, cached_embedded_schema_path_for,
        embedded_schema_for_version, resolve_default_schema_path, resolve_schema_path_for_aibom,
        source_tree_schema_path,
    };
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn resolve_default_schema_path_prefers_cwd_schema() {
        let root = TempDir::new().unwrap();
        let cwd_schema = root.path().join("schema/aibom-v0.1.0.json");
        fs::create_dir_all(cwd_schema.parent().unwrap()).unwrap();
        fs::write(&cwd_schema, br#"{"schema":"cwd"}"#).unwrap();

        let resolved = resolve_default_schema_path(&cwd_schema).unwrap();

        assert_eq!(resolved, cwd_schema);
    }

    #[test]
    fn resolve_default_schema_path_uses_embedded_fallback_when_cwd_missing() {
        let root = TempDir::new().unwrap();
        let missing_schema = root.path().join("schema/aibom-v0.1.0.json");

        let resolved = resolve_default_schema_path(&missing_schema).unwrap();

        assert!(resolved.exists());
        assert_ne!(resolved, source_tree_schema_path());
        assert_eq!(fs::read(&resolved).unwrap(), EMBEDDED_AIBOM_SCHEMA_V1_BYTES);
    }

    #[test]
    fn resolve_schema_path_for_aibom_detects_v2() {
        let root = TempDir::new().unwrap();
        let aibom = root.path().join("scan.aibom.json");
        fs::write(
            &aibom,
            serde_json::to_vec(&json!({
                "$schema": "https://aibom.example/schemas/aibom-v0.2.0.json",
                "aibom": {"schemaVersion": "0.2.0"}
            }))
            .unwrap(),
        )
        .unwrap();

        let resolved = resolve_schema_path_for_aibom(&aibom, None).unwrap();

        assert_eq!(fs::read(&resolved).unwrap(), EMBEDDED_AIBOM_SCHEMA_V2_BYTES);
    }

    #[test]
    fn resolve_schema_path_for_aibom_detects_v3() {
        let root = TempDir::new().unwrap();
        let aibom = root.path().join("scan.aibom.json");
        fs::write(
            &aibom,
            serde_json::to_vec(&json!({
                "$schema": "https://aibom.example/schemas/aibom-v0.3.0.json",
                "aibom": {"schemaVersion": "0.3.0"}
            }))
            .unwrap(),
        )
        .unwrap();

        let resolved = resolve_schema_path_for_aibom(&aibom, None).unwrap();

        assert_eq!(fs::read(&resolved).unwrap(), EMBEDDED_AIBOM_SCHEMA_V3_BYTES);
    }

    #[test]
    fn cached_embedded_schema_path_for_writes_requested_schema() {
        let schema = embedded_schema_for_version("0.2.0").unwrap();
        let resolved = cached_embedded_schema_path_for(schema).unwrap();

        assert_eq!(fs::read(&resolved).unwrap(), EMBEDDED_AIBOM_SCHEMA_V2_BYTES);
    }

    #[test]
    fn cached_embedded_schema_path_for_installs_atomically() {
        let schema = embedded_schema_for_version("0.2.0").unwrap();
        let handles: Vec<_> = (0..16)
            .map(|_| {
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        let resolved = cached_embedded_schema_path_for(schema).unwrap();
                        assert_eq!(fs::read(&resolved).unwrap(), EMBEDDED_AIBOM_SCHEMA_V2_BYTES);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
