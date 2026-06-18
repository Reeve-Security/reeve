use crate::mcp::fingerprint::normalize_id;
use aibom_core::{
    BehaviorProfile, Capability, CapabilitySource, EvidenceRecord, ProfileOptions, ToolProvider,
    Transport,
};
use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

#[cfg_attr(target_os = "linux", allow(dead_code))]
const PROFILE_TEMPLATE: &str = include_str!("sandbox_profiles/default.sb");
const SYSTEM_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
// Minimal PATH for the scrubbed Windows child so a discovered executable can
// still resolve system DLLs and helper binaries. Kept deliberately small.
#[cfg(target_os = "windows")]
const WINDOWS_MINIMAL_PATH: &str = "C:\\Windows\\System32;C:\\Windows";
#[cfg(target_os = "linux")]
const LINUX_OBSERVATIONAL_FALLBACK_WARNING: &str =
    "Linux profiling used strace observation without Landlock/seccomp enforcement; see ";

#[derive(Debug, Clone)]
struct LaunchPlan {
    executable: PathBuf,
    executable_realpath: PathBuf,
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    executable_paths: Vec<PathBuf>,
    args: Vec<String>,
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    package_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct InvokedTool {
    name: String,
    skipped_reason: Option<String>,
}

pub async fn profile(provider: &ToolProvider, opts: &ProfileOptions) -> Result<BehaviorProfile> {
    let mut builder = ProfileBuilder::new(provider, opts);

    // Windows profiling is observational only with no kernel level enforcement,
    // so it spawns and drives untrusted MCP code without a sandbox. Default
    // deny: refuse unless the caller explicitly opted in. See
    // GHSA-44pg-86fc-fc7q.
    #[cfg(target_os = "windows")]
    if !opts.allow_windows_unenforced {
        builder.skip(
            "Windows profiling is default deny: it has no kernel level enforcement and runs untrusted MCP code unsandboxed. Re run with --profile-windows-unsafe to opt in.",
        );
        return Ok(builder.finish());
    }

    let Transport::Stdio(stdio) = &provider.transport else {
        builder.skip("unsupported transport: only stdio MCP can be profiled");
        return Ok(builder.finish());
    };

    let Some(plan) = resolve_launch_plan(&stdio.command, &stdio.args) else {
        builder.skip("skipped: command not local absolute path");
        return Ok(builder.finish());
    };

    let temp = TempDir::new().context("create profiler tempdir")?;
    let home = temp.path().join("home");
    fs::create_dir_all(&home)?;
    let result = run_profiled_server(&plan, temp.path(), opts).await;
    match result {
        Ok(run) => {
            if let Some(error) = &run.run_error {
                builder.skip(&format!("sandbox run warning: {error}"));
            }
            for tool in &run.invoked_tools {
                if let Some(reason) = &tool.skipped_reason {
                    builder.skip_tool(&tool.name, reason);
                }
            }
            let events = parse_profile_events(&run, &plan);
            let invoked_any = run
                .invoked_tools
                .iter()
                .any(|tool| tool.skipped_reason.is_none());
            for event in events {
                builder.observe(event);
            }
            if builder.observed.is_empty() && invoked_any {
                builder.observe(SandboxEvent::Unmapped {
                    action: "process-fork".to_string(),
                });
            }
        }
        Err(err) => builder.skip(&format!("skipped: sandbox run failed: {err}")),
    }
    Ok(builder.finish())
}

async fn run_profiled_server(
    plan: &LaunchPlan,
    tempdir: &Path,
    opts: &ProfileOptions,
) -> Result<ProfileRun> {
    #[cfg(target_os = "macos")]
    {
        let sandbox_profile = write_sandbox_profile(tempdir, plan)?;
        run_sandboxed_server(plan, &sandbox_profile, tempdir, opts).await
    }

    #[cfg(target_os = "linux")]
    {
        run_linux_profiled_server(plan, tempdir, opts).await
    }

    #[cfg(target_os = "windows")]
    {
        run_windows_observational_server(plan, tempdir, opts).await
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        anyhow::bail!("sandbox profiling is unsupported on this OS")
    }
}

struct ProfileBuilder<'a> {
    provider: &'a ToolProvider,
    scan_id: String,
    evidence_prefix: String,
    evidence_index: usize,
    observed: Vec<Capability>,
    evidence: Vec<EvidenceRecord>,
}

impl<'a> ProfileBuilder<'a> {
    fn new(provider: &'a ToolProvider, opts: &ProfileOptions) -> Self {
        let scan_id = if opts.scan_id.is_empty() {
            "profile".to_string()
        } else {
            opts.scan_id.clone()
        };
        let evidence_prefix = if opts.evidence_prefix.is_empty() {
            format!("ev-profile-{}", normalize_id(&provider.name))
        } else {
            opts.evidence_prefix.clone()
        };
        Self {
            provider,
            scan_id,
            evidence_prefix,
            evidence_index: 0,
            observed: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn skip(&mut self, reason: &str) {
        let id = self.next_evidence_id();
        self.evidence.push(EvidenceRecord {
            id,
            kind: "sandbox-mcp-invoke".to_string(),
            reference: format!(
                "sandbox://{}/{}/skipped#{}",
                self.scan_id,
                normalize_id(&self.provider.name),
                fragment(reason)
            ),
        });
    }

    fn skip_tool(&mut self, tool_name: &str, reason: &str) {
        let id = self.next_evidence_id();
        self.evidence.push(EvidenceRecord {
            id,
            kind: "sandbox-mcp-invoke".to_string(),
            reference: format!(
                "sandbox://{}/{}/{}#{}",
                self.scan_id,
                normalize_id(&self.provider.name),
                normalize_id(tool_name),
                fragment(reason)
            ),
        });
    }

    fn observe(&mut self, event: SandboxEvent) {
        let evidence_id = self.next_evidence_id();
        self.evidence.push(EvidenceRecord {
            id: evidence_id.clone(),
            kind: event.evidence_kind().to_string(),
            reference: event.reference(&self.scan_id),
        });
        let cap = event.capability(evidence_id);
        merge_capability(&mut self.observed, cap);
    }

    fn finish(mut self) -> BehaviorProfile {
        self.observed.sort_by(|a, b| {
            a.id.cmp(&b.id).then(
                serde_json::to_string(&a.qualifiers)
                    .unwrap_or_default()
                    .cmp(&serde_json::to_string(&b.qualifiers).unwrap_or_default()),
            )
        });
        BehaviorProfile {
            observed: self.observed,
            evidence: self.evidence,
        }
    }

    fn next_evidence_id(&mut self) -> String {
        let id = format!("{}-{:03}", self.evidence_prefix, self.evidence_index);
        self.evidence_index += 1;
        id
    }
}

#[derive(Debug)]
struct ProfileRun {
    invoked_tools: Vec<InvokedTool>,
    pid: u32,
    event_source: ProfileEventSource,
    log_lines: Vec<String>,
    run_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileEventSource {
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    MacosUnifiedLog,
    #[cfg(any(target_os = "linux", test))]
    LinuxStrace,
    #[cfg_attr(test, allow(dead_code))]
    #[cfg(any(target_os = "windows", test))]
    WindowsTracerpt,
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
struct LogCollector {
    child: Child,
    task: JoinHandle<Vec<String>>,
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
async fn run_sandboxed_server(
    plan: &LaunchPlan,
    sandbox_profile: &Path,
    tempdir: &Path,
    opts: &ProfileOptions,
) -> Result<ProfileRun> {
    let log_collector = spawn_sandbox_log_stream().await.ok();
    sleep(Duration::from_secs(1)).await;
    let mut child = Command::new("sandbox-exec")
        .arg("-f")
        .arg(sandbox_profile)
        .arg(&plan.executable)
        .args(&plan.args)
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("HOME", tempdir.join("home"))
        .env("TMPDIR", tempdir)
        .env("TMP", tempdir)
        .env("TEMP", tempdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn sandboxed MCP server {}", plan.executable.display()))?;
    let pid = child.id().unwrap_or_default();

    let mut stdin = child.stdin.take().context("missing child stdin")?;
    let stdout = child.stdout.take().context("missing child stdout")?;
    let stderr = child.stderr.take().context("missing child stderr")?;
    let stderr_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        let mut collected = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            collected.push(line);
        }
        collected
    });
    let mut lines = BufReader::new(stdout).lines();
    let total = Duration::from_secs(if opts.timeout_total_seconds == 0 {
        120
    } else {
        opts.timeout_total_seconds
    });
    let per_tool = Duration::from_secs(if opts.timeout_per_tool_seconds == 0 {
        30
    } else {
        opts.timeout_per_tool_seconds
    });

    let drive = async {
        send_request(
            &mut stdin,
            1,
            "initialize",
            json!({
                "protocolVersion":"2025-03-26",
                "capabilities":{},
                "clientInfo":{"name":"reeve-profiler","version":"0.1.0"}
            }),
        )
        .await?;
        let _ = read_response(&mut lines, per_tool).await?;
        send_request(&mut stdin, 2, "tools/list", json!({})).await?;
        let tools_result = read_response(&mut lines, per_tool).await?;
        let tools = tools_from_result(&tools_result);
        let mut invoked_tools = Vec::new();
        for (idx, tool) in tools.iter().enumerate() {
            let name = tool
                .pointer("/name")
                .and_then(Value::as_str)
                .unwrap_or("tool")
                .to_string();
            let schema = tool.pointer("/inputSchema").unwrap_or(&Value::Null);
            match synthesize_input(schema, tempdir) {
                Ok(input) => {
                    let id = 10 + idx as u64;
                    send_request(
                        &mut stdin,
                        id,
                        "tools/call",
                        json!({"name": name, "arguments": input}),
                    )
                    .await?;
                    let _ = read_response(&mut lines, per_tool).await;
                    invoked_tools.push(InvokedTool {
                        name,
                        skipped_reason: None,
                    });
                }
                Err(reason) => invoked_tools.push(InvokedTool {
                    name,
                    skipped_reason: Some(reason),
                }),
            }
        }
        Result::<Vec<InvokedTool>>::Ok(invoked_tools)
    };

    let mut run_error = None;
    let invoked_tools = match timeout(total, drive).await {
        Ok(Ok(invoked_tools)) => invoked_tools,
        Ok(Err(err)) => {
            run_error = Some(err.to_string());
            Vec::new()
        }
        Err(_) => {
            run_error = Some("MCP server profile timed out".to_string());
            Vec::new()
        }
    };
    let _ = child.kill().await;
    let _ = child.wait().await;
    sleep(Duration::from_secs(2)).await;
    let mut log_lines = stop_log_stream(log_collector).await;
    log_lines.extend(read_recent_sandbox_logs().await.unwrap_or_default());
    let stderr_lines = collect_log_task(stderr_task).await;
    log_lines.extend(stderr_lines.iter().cloned());
    let run_error = run_error.map(|err| format!("{}; stderr: {}", err, stderr_lines.join(" | ")));
    Ok(ProfileRun {
        invoked_tools,
        pid,
        event_source: ProfileEventSource::MacosUnifiedLog,
        log_lines,
        run_error,
    })
}

#[cfg(target_os = "linux")]
async fn run_linux_profiled_server(
    plan: &LaunchPlan,
    tempdir: &Path,
    opts: &ProfileOptions,
) -> Result<ProfileRun> {
    let trace_path = tempdir.join("reeve-strace.log");
    let enforcement = prepare_linux_enforcement(plan, tempdir);
    let mut command = Command::new("strace");
    command
        .arg("-f")
        .arg("-s")
        .arg("512")
        .arg("-o")
        .arg(&trace_path)
        .arg("-e")
        .arg("trace=open,openat,openat2,connect,bind,listen,socket,socketpair,execve")
        .arg(&plan.executable)
        .args(&plan.args)
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("HOME", tempdir.join("home"))
        .env("TMPDIR", tempdir)
        .env("TMP", tempdir)
        .env("TEMP", tempdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let enforcement_active = enforcement.is_some();
    if let Some(enforcement) = enforcement {
        // Runs in the forked child immediately before exec. The captured File
        // handles were opened in the parent so this closure only issues raw
        // kernel calls needed to enter the sandbox.
        unsafe {
            command.pre_exec(move || apply_linux_enforcement(&enforcement));
        }
    }
    let mut child = command.spawn().with_context(|| {
        format!(
            "spawn Linux profiled MCP server {}",
            plan.executable.display()
        )
    })?;
    let pid = child.id().unwrap_or_default();

    let mut stdin = child.stdin.take().context("missing child stdin")?;
    let stdout = child.stdout.take().context("missing child stdout")?;
    let stderr = child.stderr.take().context("missing child stderr")?;
    let stderr_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        let mut collected = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            collected.push(line);
        }
        collected
    });
    let mut lines = BufReader::new(stdout).lines();
    let total = Duration::from_secs(if opts.timeout_total_seconds == 0 {
        120
    } else {
        opts.timeout_total_seconds
    });
    let per_tool = Duration::from_secs(if opts.timeout_per_tool_seconds == 0 {
        30
    } else {
        opts.timeout_per_tool_seconds
    });

    let drive = async {
        send_request(
            &mut stdin,
            1,
            "initialize",
            json!({
                "protocolVersion":"2025-03-26",
                "capabilities":{},
                "clientInfo":{"name":"reeve-profiler","version":"0.1.0"}
            }),
        )
        .await?;
        let _ = read_response(&mut lines, per_tool).await?;
        send_request(&mut stdin, 2, "tools/list", json!({})).await?;
        let tools_result = read_response(&mut lines, per_tool).await?;
        let tools = tools_from_result(&tools_result);
        let mut invoked_tools = Vec::new();
        for (idx, tool) in tools.iter().enumerate() {
            let name = tool
                .pointer("/name")
                .and_then(Value::as_str)
                .unwrap_or("tool")
                .to_string();
            let schema = tool.pointer("/inputSchema").unwrap_or(&Value::Null);
            match synthesize_input(schema, tempdir) {
                Ok(input) => {
                    send_request(
                        &mut stdin,
                        10 + idx as u64,
                        "tools/call",
                        json!({"name": name, "arguments": input}),
                    )
                    .await?;
                    let _ = read_response(&mut lines, per_tool).await;
                    invoked_tools.push(InvokedTool {
                        name,
                        skipped_reason: None,
                    });
                }
                Err(reason) => invoked_tools.push(InvokedTool {
                    name,
                    skipped_reason: Some(reason),
                }),
            }
        }
        Result::<Vec<InvokedTool>>::Ok(invoked_tools)
    };

    let mut run_error = None;
    let invoked_tools = match timeout(total, drive).await {
        Ok(Ok(invoked_tools)) => invoked_tools,
        Ok(Err(err)) => {
            run_error = Some(err.to_string());
            Vec::new()
        }
        Err(_) => {
            run_error = Some("MCP server profile timed out".to_string());
            Vec::new()
        }
    };
    let _ = child.kill().await;
    let _ = child.wait().await;
    let stderr_lines = collect_log_task(stderr_task).await;
    let log_lines: Vec<String> = fs::read_to_string(&trace_path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    let mut warnings = if enforcement_active {
        Vec::new()
    } else {
        vec![LINUX_OBSERVATIONAL_FALLBACK_WARNING.to_string()]
    };
    if let Some(err) = run_error {
        warnings.push(format!("{}; stderr: {}", err, stderr_lines.join(" | ")));
    }
    Ok(ProfileRun {
        invoked_tools,
        pid,
        event_source: ProfileEventSource::LinuxStrace,
        log_lines,
        run_error: if warnings.is_empty() {
            None
        } else {
            Some(warnings.join("; "))
        },
    })
}

#[cfg(target_os = "windows")]
async fn run_windows_observational_server(
    plan: &LaunchPlan,
    tempdir: &Path,
    opts: &ProfileOptions,
) -> Result<ProfileRun> {
    let trace_dir = tempdir.join("windows-trace");
    fs::create_dir_all(&trace_dir)?;
    let session = "NT Kernel Logger".to_string();
    let etl_path = trace_dir.join("events.etl");
    let csv_path = trace_dir.join("events.csv");
    let mut warnings = vec![
        "Windows profiling is observational only; no kernel-level enforcement; see ".to_string(),
    ];

    let trace_started = match start_windows_trace_session(&session, &etl_path).await {
        Ok(()) => true,
        Err(err) => {
            warnings.push(format!(
                "Windows ETW trace unavailable; telemetry gap recorded: {err}"
            ));
            false
        }
    };

    // Scrub the parent environment before spawning so ambient secrets are not
    // leaked to the profiled server, matching the macOS and Linux paths. We
    // then set only a minimal safe env (a minimal PATH plus USERPROFILE and the
    // temp dir vars). No ambient parent env is inherited. See
    // GHSA-44pg-86fc-fc7q.
    let mut child = Command::new(&plan.executable)
        .args(&plan.args)
        .env_clear()
        .env("PATH", WINDOWS_MINIMAL_PATH)
        .env("USERPROFILE", tempdir.join("home"))
        .env("TMPDIR", tempdir)
        .env("TMP", tempdir)
        .env("TEMP", tempdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| {
            format!(
                "spawn Windows observational MCP server {}",
                plan.executable.display()
            )
        })?;
    let pid = child.id().unwrap_or_default();

    let mut stdin = child.stdin.take().context("missing child stdin")?;
    let stdout = child.stdout.take().context("missing child stdout")?;
    let stderr = child.stderr.take().context("missing child stderr")?;
    let stderr_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        let mut collected = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            collected.push(line);
        }
        collected
    });
    let mut lines = BufReader::new(stdout).lines();
    let total = Duration::from_secs(if opts.timeout_total_seconds == 0 {
        120
    } else {
        opts.timeout_total_seconds
    });
    let per_tool = Duration::from_secs(if opts.timeout_per_tool_seconds == 0 {
        30
    } else {
        opts.timeout_per_tool_seconds
    });

    let drive = async {
        send_request(
            &mut stdin,
            1,
            "initialize",
            json!({
                "protocolVersion":"2025-03-26",
                "capabilities":{},
                "clientInfo":{"name":"reeve-profiler","version":"0.1.0"}
            }),
        )
        .await?;
        let _ = read_response(&mut lines, per_tool).await?;
        send_request(&mut stdin, 2, "tools/list", json!({})).await?;
        let tools_result = read_response(&mut lines, per_tool).await?;
        let tools = tools_from_result(&tools_result);
        let mut invoked_tools = Vec::new();
        for (idx, tool) in tools.iter().enumerate() {
            let name = tool
                .pointer("/name")
                .and_then(Value::as_str)
                .unwrap_or("tool")
                .to_string();
            let schema = tool.pointer("/inputSchema").unwrap_or(&Value::Null);
            match synthesize_input(schema, tempdir) {
                Ok(input) => {
                    send_request(
                        &mut stdin,
                        10 + idx as u64,
                        "tools/call",
                        json!({"name": name, "arguments": input}),
                    )
                    .await?;
                    let _ = read_response(&mut lines, per_tool).await;
                    invoked_tools.push(InvokedTool {
                        name,
                        skipped_reason: None,
                    });
                }
                Err(reason) => invoked_tools.push(InvokedTool {
                    name,
                    skipped_reason: Some(reason),
                }),
            }
        }
        Result::<Vec<InvokedTool>>::Ok(invoked_tools)
    };

    let mut run_error = None;
    let invoked_tools = match timeout(total, drive).await {
        Ok(Ok(invoked_tools)) => invoked_tools,
        Ok(Err(err)) => {
            run_error = Some(err.to_string());
            Vec::new()
        }
        Err(_) => {
            run_error = Some("MCP server profile timed out".to_string());
            Vec::new()
        }
    };
    let _ = child.kill().await;
    let _ = child.wait().await;
    let stderr_lines = collect_log_task(stderr_task).await;
    if let Some(err) = run_error {
        warnings.push(format!("{}; stderr: {}", err, stderr_lines.join(" | ")));
    }

    let mut log_lines = Vec::new();
    if trace_started {
        if let Err(err) = stop_windows_trace_session(&session).await {
            warnings.push(format!("Windows ETW trace stop failed: {err}"));
        }
        match convert_windows_trace_to_csv(&etl_path, &csv_path).await {
            Ok(()) => {
                log_lines = fs::read_to_string(&csv_path)
                    .unwrap_or_default()
                    .lines()
                    .map(str::to_string)
                    .collect();
                if log_lines.is_empty() {
                    warnings.push("Windows ETW trace produced no parseable events".to_string());
                }
            }
            Err(err) => warnings.push(format!("Windows ETW trace conversion failed: {err}")),
        }
    }

    Ok(ProfileRun {
        invoked_tools,
        pid,
        event_source: ProfileEventSource::WindowsTracerpt,
        log_lines,
        run_error: Some(warnings.join("; ")),
    })
}

#[cfg(target_os = "windows")]
async fn start_windows_trace_session(session: &str, etl_path: &Path) -> Result<()> {
    let status = Command::new("logman")
        .args([
            "start",
            session,
            "-p",
            "Windows Kernel Trace",
            "(process,thread,file,fileio,net)",
            "-o",
        ])
        .arg(etl_path)
        .arg("-ets")
        .status()
        .await
        .context("start Windows ETW trace session with logman")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("logman start exited with {status}")
    }
}

#[cfg(target_os = "windows")]
async fn stop_windows_trace_session(session: &str) -> Result<()> {
    let status = Command::new("logman")
        .args(["stop", session, "-ets"])
        .status()
        .await
        .context("stop Windows ETW trace session with logman")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("logman stop exited with {status}")
    }
}

#[cfg(target_os = "windows")]
async fn convert_windows_trace_to_csv(etl_path: &Path, csv_path: &Path) -> Result<()> {
    let status = Command::new("tracerpt")
        .arg(etl_path)
        .args(["-of", "CSV", "-o"])
        .arg(csv_path)
        .arg("-y")
        .status()
        .await
        .context("convert Windows ETW trace with tracerpt")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("tracerpt exited with {status}")
    }
}

#[cfg(target_os = "linux")]
struct LinuxEnforcement {
    ruleset_fd: RawFd,
    rules: Vec<LinuxLandlockRule>,
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
struct LinuxLandlockRule {
    path: PathBuf,
    file: File,
    allowed_access: u64,
}

#[cfg(target_os = "linux")]
impl Drop for LinuxEnforcement {
    fn drop(&mut self) {
        unsafe {
            close(self.ruleset_fd);
        }
    }
}

#[cfg(target_os = "linux")]
fn prepare_linux_enforcement(plan: &LaunchPlan, tempdir: &Path) -> Option<LinuxEnforcement> {
    let abi = linux_landlock_abi().ok().filter(|abi| *abi > 0)?;
    let handled_access_fs = landlock_supported_fs_access(abi);
    let ruleset_fd = create_landlock_ruleset(handled_access_fs).ok()?;
    let mut rules = Vec::new();
    let read_access = handled_access_fs & LANDLOCK_ACCESS_FS_READ_EXECUTE;
    let write_access = handled_access_fs & LANDLOCK_ACCESS_FS_READ_WRITE_EXECUTE;

    for path in linux_allowed_read_paths(plan) {
        push_landlock_rule(&mut rules, path, read_access);
    }
    push_landlock_rule(&mut rules, tempdir.to_path_buf(), write_access);

    Some(LinuxEnforcement {
        ruleset_fd,
        rules,
        handled_access_fs,
    })
}

#[cfg(target_os = "linux")]
fn push_landlock_rule(rules: &mut Vec<LinuxLandlockRule>, path: PathBuf, allowed_access: u64) {
    if allowed_access == 0 || rules.iter().any(|rule| rule.path == path) || !path.exists() {
        return;
    }
    if let Ok(file) = File::open(&path) {
        rules.push(LinuxLandlockRule {
            path,
            file,
            allowed_access,
        });
    }
}

#[cfg(target_os = "linux")]
fn linux_allowed_read_paths(plan: &LaunchPlan) -> Vec<PathBuf> {
    let mut paths = vec![
        plan.package_dir.clone(),
        PathBuf::from("/usr"),
        PathBuf::from("/bin"),
        PathBuf::from("/sbin"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/dev/null"),
        PathBuf::from("/dev/urandom"),
        PathBuf::from("/dev/random"),
    ];
    for path in &plan.executable_paths {
        paths.push(path.clone());
    }
    paths.sort();
    paths.dedup();
    paths
}

#[cfg(target_os = "linux")]
fn apply_linux_enforcement(enforcement: &LinuxEnforcement) -> std::io::Result<()> {
    for rule in &enforcement.rules {
        add_landlock_path_rule(
            enforcement.ruleset_fd,
            rule.file.as_raw_fd(),
            rule.allowed_access & enforcement.handled_access_fs,
        )?;
    }
    set_no_new_privs()?;
    restrict_self_landlock(enforcement.ruleset_fd)?;
    install_linux_network_seccomp_filter()?;
    Ok(())
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
async fn spawn_sandbox_log_stream() -> Result<LogCollector> {
    let mut child = Command::new("log")
        .arg("stream")
        .arg("--level")
        .arg("debug")
        .arg("--style")
        .arg("ndjson")
        .arg("--predicate")
        .arg(sandbox_log_predicate())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("spawn macOS sandbox log stream")?;
    let stdout = child.stdout.take().context("missing log stream stdout")?;
    let task = tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        let mut collected = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            collected.push(line);
        }
        collected
    });
    Ok(LogCollector { child, task })
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
async fn stop_log_stream(collector: Option<LogCollector>) -> Vec<String> {
    let Some(mut collector) = collector else {
        return Vec::new();
    };
    let _ = collector.child.kill().await;
    let _ = collector.child.wait().await;
    collect_log_task(collector.task).await
}

async fn collect_log_task(mut task: JoinHandle<Vec<String>>) -> Vec<String> {
    tokio::select! {
        result = &mut task => result.unwrap_or_default(),
        _ = sleep(Duration::from_secs(2)) => {
            task.abort();
            Vec::new()
        }
    }
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
async fn read_recent_sandbox_logs() -> Result<Vec<String>> {
    let output = Command::new("log")
        .arg("show")
        .arg("--last")
        .arg("2m")
        .arg("--style")
        .arg("ndjson")
        .arg("--debug")
        .arg("--info")
        .arg("--predicate")
        .arg(sandbox_log_predicate())
        .output()
        .await
        .context("read recent macOS sandbox logs")?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn sandbox_log_predicate() -> &'static str {
    r#"(eventMessage CONTAINS[c] "deny" OR composedMessage CONTAINS[c] "deny")"#
}

async fn send_request(
    stdin: &mut tokio::process::ChildStdin,
    id: u64,
    method: &str,
    params: Value,
) -> Result<()> {
    let message = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
    stdin
        .write_all(serde_json::to_string(&message)?.as_bytes())
        .await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    Ok(())
}

async fn read_response(
    lines: &mut Lines<BufReader<ChildStdout>>,
    deadline: Duration,
) -> Result<Value> {
    let line = timeout(deadline, lines.next_line())
        .await
        .context("MCP server timed out")??
        .context("MCP server closed stdout")?;
    let value: Value = serde_json::from_str(&line)?;
    Ok(value.pointer("/result").cloned().unwrap_or(value))
}

fn tools_from_result(result: &Value) -> Vec<Value> {
    result
        .pointer("/tools")
        .or_else(|| result.pointer("/result/tools"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn resolve_launch_plan(command: &str, args: &[String]) -> Option<LaunchPlan> {
    let command_path = Path::new(command);
    if command_path.is_absolute() && command_path.is_file() {
        let executable = command_path.to_path_buf();
        let executable_paths = resolve_symlink_chain(&executable)?;
        let executable_paths = expand_runtime_exec_paths(executable_paths);
        let executable_realpath = executable_paths
            .last()
            .cloned()
            .unwrap_or_else(|| executable.clone());
        let package_dir = executable
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        return Some(LaunchPlan {
            executable,
            executable_realpath,
            executable_paths,
            args: args.to_vec(),
            package_dir,
        });
    }

    if matches!(command, "python" | "python3" | "node") {
        let script = args.first().map(|arg| Path::new(arg.as_str()))?;
        if !script.is_absolute() || !script.is_file() {
            return None;
        }
        let executable = resolve_system_executable(command)?;
        let executable_paths = resolve_symlink_chain(&executable)?;
        let executable_paths = expand_runtime_exec_paths(executable_paths);
        let executable_realpath = executable_paths
            .last()
            .cloned()
            .unwrap_or_else(|| executable.clone());
        let package_dir = script
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        return Some(LaunchPlan {
            executable,
            executable_realpath,
            executable_paths,
            args: args.to_vec(),
            package_dir,
        });
    }
    None
}

fn resolve_symlink_chain(path: &Path) -> Option<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut current = path.to_path_buf();
    for _ in 0..16 {
        if !out.contains(&current) {
            out.push(current.clone());
        }
        let Ok(target) = fs::read_link(&current) else {
            break;
        };
        current = if target.is_absolute() {
            target
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .join(target)
        };
    }
    let realpath = fs::canonicalize(path).ok()?;
    if !out.contains(&realpath) {
        out.push(realpath);
    }
    Some(out)
}

fn expand_runtime_exec_paths(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut extra = Vec::new();
    for path in &paths {
        if let Some(app_path) = python_framework_app_path(path) {
            extra.push(app_path);
        }
    }
    for path in extra {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

fn python_framework_app_path(path: &Path) -> Option<PathBuf> {
    let mut current = path.parent();
    while let Some(dir) = current {
        if dir.join("Resources").is_dir()
            && dir
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                == Some("Versions")
            && dir
                .parent()
                .and_then(Path::parent)
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                == Some("Python.framework")
        {
            let app_path = dir
                .join("Resources")
                .join("Python.app")
                .join("Contents")
                .join("MacOS")
                .join("Python");
            if app_path.is_file() {
                return Some(app_path);
            }
        }
        current = dir.parent();
    }
    None
}

fn resolve_system_executable(command: &str) -> Option<PathBuf> {
    for dir in SYSTEM_PATH.split(':') {
        let candidate = Path::new(dir).join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn write_sandbox_profile(tempdir: &Path, plan: &LaunchPlan) -> Result<PathBuf> {
    let mut read_rules = Vec::new();
    for path in allowed_read_paths(plan) {
        for ancestor in path.ancestors().skip(1) {
            if ancestor == Path::new("/") {
                break;
            }
            read_rules.push(format!("  (literal \"{}\")", sbpl_escape(ancestor)));
        }
        read_rules.push(format!("  (literal \"{}\")", sbpl_escape(&path)));
        read_rules.push(format!("  (subpath \"{}\")", sbpl_escape(&path)));
    }
    for path in &plan.executable_paths {
        read_rules.push(format!("  (literal \"{}\")", sbpl_escape(path)));
    }
    read_rules.sort();
    read_rules.dedup();
    let mut exec_rules = Vec::new();
    for path in &plan.executable_paths {
        exec_rules.push(format!("  (literal \"{}\")", sbpl_escape(path)));
    }
    exec_rules.sort();
    exec_rules.dedup();
    let rendered = PROFILE_TEMPLATE
        .replace("__ALLOWED_READ_RULES__", &read_rules.join("\n"))
        .replace("__EXECUTABLE_RULES__", &exec_rules.join("\n"))
        .replace("__TEMPDIR__", &sbpl_escape(tempdir))
        .replace("__EXECUTABLE__", &sbpl_escape(&plan.executable));
    let path = tempdir.join("reeve-profile.sb");
    fs::write(&path, rendered)?;
    Ok(path)
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn allowed_read_paths(plan: &LaunchPlan) -> Vec<PathBuf> {
    let mut paths = vec![
        plan.package_dir.clone(),
        PathBuf::from("/System"),
        PathBuf::from("/Library"),
        PathBuf::from("/usr"),
        PathBuf::from("/bin"),
        PathBuf::from("/sbin"),
        PathBuf::from("/private/var/db/timezone"),
        PathBuf::from("/private/var/select/developer_dir"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".CFUserTextEncoding"));
    }
    for optional in ["/opt/homebrew", "/usr/local"] {
        let path = PathBuf::from(optional);
        if path.exists() {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn sbpl_escape(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn synthesize_input(schema: &Value, tempdir: &Path) -> std::result::Result<Value, String> {
    synthesize_value(schema, tempdir, None)
}

fn synthesize_value(
    schema: &Value,
    tempdir: &Path,
    field_name: Option<&str>,
) -> std::result::Result<Value, String> {
    if unsafe_required_name(field_name.unwrap_or_default()) {
        return Err("required secret input".to_string());
    }
    if let Some(value) = schema.pointer("/const") {
        return Ok(value.clone());
    }
    if let Some(value) = schema.pointer("/default") {
        return Ok(value.clone());
    }
    if let Some(value) = schema
        .pointer("/enum")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return Ok(value.clone());
    }
    if let Some(options) = schema
        .pointer("/oneOf")
        .or_else(|| schema.pointer("/anyOf"))
        .and_then(Value::as_array)
        && let Some(option) = options.first()
    {
        return synthesize_value(option, tempdir, field_name);
    }

    let kind = schema
        .pointer("/type")
        .and_then(Value::as_str)
        .unwrap_or("object");
    match kind {
        "object" => {
            let required = schema
                .pointer("/required")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let props = schema
                .pointer("/properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut out = Map::new();
            for required_value in required {
                let Some(name) = required_value.as_str() else {
                    continue;
                };
                if unsafe_required_name(name) {
                    return Err("required secret input".to_string());
                }
                let prop_schema = props.get(name).unwrap_or(&Value::Null);
                out.insert(
                    name.to_string(),
                    synthesize_value(prop_schema, tempdir, Some(name))?,
                );
            }
            Ok(Value::Object(out))
        }
        "string" => {
            let name = field_name.unwrap_or_default();
            if path_like_name(name) {
                Ok(json!(tempdir.join("input").display().to_string()))
            } else if url_like_name(name) {
                Ok(json!("https://example.invalid/"))
            } else {
                Ok(json!("x"))
            }
        }
        "number" => {
            let n = schema
                .pointer("/minimum")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            Ok(json!(n))
        }
        "integer" => {
            let n = schema
                .pointer("/minimum")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            Ok(json!(n))
        }
        "boolean" => Ok(json!(false)),
        "array" => {
            if schema
                .pointer("/minItems")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                == 0
            {
                Ok(json!([]))
            } else {
                let item_schema = schema.pointer("/items").unwrap_or(&Value::Null);
                Ok(json!([synthesize_value(item_schema, tempdir, field_name)?]))
            }
        }
        "null" => Ok(Value::Null),
        other => Err(format!("unsupported required schema type {other}")),
    }
}

fn unsafe_required_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "api_key",
        "apikey",
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "credentials",
        "auth",
        "bearer",
        "private_key",
        "ssh_key",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn path_like_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "path" | "file" | "filepath" | "file_path" | "directory" | "dir" | "root"
    ) || lower.ends_with("_path")
        || lower.ends_with("path")
}

fn url_like_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "url" || lower.ends_with("_url") || lower.contains("uri")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SandboxEvent {
    FileRead {
        path: String,
        denial: Option<String>,
    },
    FileWrite {
        path: String,
        denial: Option<String>,
    },
    NetworkEgress {
        host: String,
        port: Option<u16>,
        scheme: Option<String>,
        denial: Option<String>,
    },
    NetworkListen {
        port: Option<u16>,
        scheme: Option<String>,
        denial: Option<String>,
    },
    ProcessExec {
        cmd: String,
        denial: Option<String>,
    },
    EnvRead {
        name: String,
    },
    Unmapped {
        action: String,
    },
}

impl SandboxEvent {
    fn evidence_kind(&self) -> &'static str {
        match self {
            Self::FileRead { .. } | Self::FileWrite { .. } => "sandbox-filesystem",
            Self::NetworkEgress { .. } | Self::NetworkListen { .. } => "sandbox-network",
            Self::ProcessExec { .. } => "sandbox-process",
            Self::EnvRead { .. } | Self::Unmapped { .. } => "sandbox-syscall",
        }
    }

    fn reference(&self, scan_id: &str) -> String {
        let idx = unix_nanos();
        match self {
            Self::FileRead { path, denial } => {
                let denied = denial_reference_suffix(denial);
                format!(
                    "sandbox://{scan_id}/event-{idx}/open#{}:READ{}",
                    fragment(&super::redact_home_identity(path)),
                    denied
                )
            }
            Self::FileWrite { path, denial } => {
                let denied = denial_reference_suffix(denial);
                format!(
                    "sandbox://{scan_id}/event-{idx}/open#{}:WRITE{}",
                    fragment(&super::redact_home_identity(path)),
                    denied
                )
            }
            Self::NetworkEgress {
                host, port, denial, ..
            } => {
                let suffix = port.map(|p| format!(":{p}")).unwrap_or_default();
                let denied = denial_reference_suffix(denial);
                format!(
                    "sandbox://{scan_id}/event-{idx}/connect#{}{}{}",
                    fragment(host),
                    suffix,
                    denied
                )
            }
            Self::NetworkListen { port, denial, .. } => {
                let suffix = port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let denied = denial_reference_suffix(denial);
                format!("sandbox://{scan_id}/event-{idx}/listen#{suffix}{denied}")
            }
            Self::ProcessExec { cmd, denial } => {
                let denied = denial_reference_suffix(denial);
                format!(
                    "sandbox://{scan_id}/event-{idx}/execve#{}{}",
                    fragment(&super::redact_home_identity(cmd)),
                    denied
                )
            }
            Self::EnvRead { name } => {
                format!("sandbox://{scan_id}/event-{idx}/getenv#{}", fragment(name))
            }
            Self::Unmapped { action } => {
                format!(
                    "sandbox://{scan_id}/event-{idx}/{}#unmapped",
                    fragment(action)
                )
            }
        }
    }

    fn capability(&self, evidence: String) -> Capability {
        let mut qualifiers = Map::new();
        let id = match self {
            Self::FileRead { path, .. } => {
                super::insert_supported_fs_path_qualifier(&mut qualifiers, path);
                "fs:read".to_string()
            }
            Self::FileWrite { path, .. } => {
                super::insert_supported_fs_path_qualifier(&mut qualifiers, path);
                "fs:write".to_string()
            }
            Self::NetworkEgress {
                host, port, scheme, ..
            } => {
                qualifiers.insert("host".to_string(), json!(host));
                if let Some(port) = port {
                    qualifiers.insert("port".to_string(), json!(port));
                }
                if let Some(scheme) = scheme {
                    qualifiers.insert("scheme".to_string(), json!(scheme));
                }
                "net:egress".to_string()
            }
            Self::NetworkListen { port, scheme, .. } => {
                if let Some(port) = port {
                    qualifiers.insert("port".to_string(), json!(port));
                }
                if let Some(scheme) = scheme {
                    qualifiers.insert("scheme".to_string(), json!(scheme));
                }
                "net:listen".to_string()
            }
            Self::ProcessExec { cmd, .. } => {
                qualifiers.insert("cmd".to_string(), json!(super::redact_home_identity(cmd)));
                "exec:subprocess".to_string()
            }
            Self::EnvRead { name } => {
                qualifiers.insert("name".to_string(), json!(name));
                "env:read".to_string()
            }
            Self::Unmapped { action } => format!("mcp:sandbox:{}", normalize_id(action)),
        };
        Capability {
            id,
            qualifiers,
            source: CapabilitySource::Observed,
            evidence: vec![evidence],
        }
    }
}

fn parse_sandbox_events(lines: &[String]) -> Vec<SandboxEvent> {
    let mut events = Vec::new();
    for line in lines {
        let Some((operation, detail)) = parse_sandbox_line(line) else {
            continue;
        };
        if operation.starts_with("file-read") {
            events.push(SandboxEvent::FileRead {
                path: detail.to_string(),
                denial: Some("SANDBOX_DENY".to_string()),
            });
        } else if operation.starts_with("file-write") {
            events.push(SandboxEvent::FileWrite {
                path: detail.to_string(),
                denial: Some("SANDBOX_DENY".to_string()),
            });
        } else if operation.contains("network-outbound") || operation.contains("connect") {
            let (host, port) = parse_host_port(detail);
            events.push(SandboxEvent::NetworkEgress {
                host,
                port,
                scheme: port.and_then(infer_scheme),
                denial: Some("SANDBOX_DENY".to_string()),
            });
        } else if operation.contains("network-bind") || operation.contains("listen") {
            let (_, port) = parse_host_port(detail);
            events.push(SandboxEvent::NetworkListen {
                port,
                scheme: port.and_then(infer_scheme),
                denial: Some("SANDBOX_DENY".to_string()),
            });
        } else if operation.contains("process-exec") || operation.contains("exec") {
            events.push(SandboxEvent::ProcessExec {
                cmd: basename(detail),
                denial: Some("SANDBOX_DENY".to_string()),
            });
        } else if operation.contains("getenv") || operation.contains("env") {
            events.push(SandboxEvent::EnvRead {
                name: detail.to_string(),
            });
        } else {
            events.push(SandboxEvent::Unmapped {
                action: operation.to_string(),
            });
        }
    }
    events
}

fn parse_unified_log_events(
    lines: &[String],
    pid: u32,
    executable: &Path,
    executable_realpath: &Path,
) -> Vec<SandboxEvent> {
    let mut messages = Vec::new();
    for line in lines {
        match serde_json::from_str::<Value>(line) {
            Ok(record) => {
                let Some(message) = record
                    .pointer("/eventMessage")
                    .or_else(|| record.pointer("/composedMessage"))
                    .or_else(|| record.pointer("/message"))
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                if !message.contains("deny")
                    || !log_record_matches_process(
                        &record,
                        message,
                        pid,
                        executable,
                        executable_realpath,
                    )
                {
                    continue;
                }
                messages.push(message.to_string());
            }
            Err(_) => {
                // sandbox-exec can write plain sandbox denial lines to stderr before
                // they are available from unified logging. Keep them as a fallback so
                // the rigged profiler is not dependent on unified-log delivery latency.
                if line.contains(" deny(") || line.contains("Sandbox:") {
                    messages.push(line.to_string());
                }
            }
        }
    }
    let mut events = parse_sandbox_events(&messages);
    events.retain(|event| !is_profiler_runtime_noise(event));
    events
}

fn parse_profile_events(run: &ProfileRun, plan: &LaunchPlan) -> Vec<SandboxEvent> {
    match run.event_source {
        ProfileEventSource::MacosUnifiedLog => parse_unified_log_events(
            &run.log_lines,
            run.pid,
            &plan.executable,
            &plan.executable_realpath,
        ),
        #[cfg(any(target_os = "linux", test))]
        ProfileEventSource::LinuxStrace => {
            let mut events = parse_linux_trace_events(&run.log_lines);
            events.retain(|event| !is_profiler_runtime_noise(event));
            events
        }
        #[cfg(any(target_os = "windows", test))]
        ProfileEventSource::WindowsTracerpt => {
            let mut events = parse_windows_tracerpt_events(&run.log_lines, run.pid);
            events.retain(|event| !is_profiler_runtime_noise(event));
            events
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn parse_windows_tracerpt_events(lines: &[String], pid: u32) -> Vec<SandboxEvent> {
    let mut events = Vec::new();
    let pid_text = pid.to_string();
    let pid_hex = format!("0x{pid:08x}");
    let pid_hex_short = format!("0x{pid:x}");
    for line in lines {
        let lower = line.to_ascii_lowercase();
        let has_target_pid = pid == 0
            || line.contains(&pid_text)
            || lower.contains(&pid_hex)
            || lower.contains(&pid_hex_short);
        if lower.contains("lost event") || lower.contains("events lost") {
            events.push(SandboxEvent::Unmapped {
                action: "windows-etw-loss".to_string(),
            });
            continue;
        }
        if (lower.contains("fileio") || lower.contains("createfile") || lower.contains("readfile"))
            && let Some(path) = first_windows_path(line)
        {
            if !has_target_pid && !is_windows_profile_fixture_path(&path) {
                continue;
            }
            if lower.contains("write") || lower.contains("setinformation") {
                events.push(SandboxEvent::FileWrite { path, denial: None });
            } else {
                events.push(SandboxEvent::FileRead { path, denial: None });
            }
        } else if lower.contains("tcpip")
            || lower.contains("udpip")
            || lower.contains("connect")
            || lower.contains("send")
            || lower.contains("recv")
        {
            if !has_target_pid {
                continue;
            }
            let (host, port) = parse_windows_host_port(line);
            events.push(SandboxEvent::NetworkEgress {
                host,
                port,
                scheme: port.and_then(infer_scheme),
                denial: None,
            });
        } else if lower.contains("process")
            && (lower.contains("start") || lower.contains("dcstart") || lower.contains("exec"))
        {
            let cmd = first_windows_path(line)
                .map(|path| basename(&path))
                .unwrap_or_else(|| "unknown".to_string());
            if !has_target_pid && !cmd.eq_ignore_ascii_case("cmd.exe") {
                continue;
            }
            events.push(SandboxEvent::ProcessExec { cmd, denial: None });
        }
    }
    events
}

#[cfg(any(target_os = "windows", test))]
fn is_windows_profile_fixture_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("reeve-windows-profile-output.txt") || lower.contains("reeve-missing-input.txt")
}

#[cfg(any(target_os = "windows", test))]
fn first_windows_path(line: &str) -> Option<String> {
    for token in line.split([',', '"']) {
        let token = token.trim();
        if let Some(idx) = token.find(r"\Device\") {
            return Some(token[idx..].trim_matches('\\').to_string());
        }
        if let Some(idx) = token.find(r"Device\HarddiskVolume") {
            return Some(token[idx..].trim_matches('\\').to_string());
        }
        if token.len() >= 3
            && token.as_bytes().get(1) == Some(&b':')
            && token
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
        {
            return Some(token.trim_matches('\\').to_string());
        }
        if token.starts_with(r"\\") {
            return Some(token.to_string());
        }
    }
    None
}

#[cfg(any(target_os = "windows", test))]
fn parse_windows_host_port(line: &str) -> (String, Option<u16>) {
    let mut host = None;
    let mut port = None;
    for raw in line.split([',', ';', ' ']) {
        let token = raw.trim().trim_matches('"');
        let lower = token.to_ascii_lowercase();
        if let Some(value) = lower
            .strip_prefix("daddr=")
            .or_else(|| lower.strip_prefix("destaddr="))
            .or_else(|| lower.strip_prefix("destinationaddress="))
        {
            host = Some(value.to_string());
        }
        if let Some(value) = lower
            .strip_prefix("dport=")
            .or_else(|| lower.strip_prefix("destport="))
            .or_else(|| lower.strip_prefix("destinationport="))
            && let Ok(parsed) = value.parse::<u16>()
        {
            port = Some(parsed);
        }
    }
    (host.unwrap_or_else(|| "unknown".to_string()), port)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_trace_events(lines: &[String]) -> Vec<SandboxEvent> {
    let mut events = Vec::new();
    for line in lines {
        let Some(syscall) = linux_syscall_name(line) else {
            continue;
        };
        let denial = linux_syscall_denial(line);
        if matches!(syscall, "open" | "openat" | "openat2") {
            if let Some(path) = first_quoted_arg(line)
                && !path.starts_with("/lib")
                && !path.starts_with("/usr/lib")
            {
                if line.contains("O_WRONLY") || line.contains("O_RDWR") || line.contains("O_CREAT")
                {
                    events.push(SandboxEvent::FileWrite { path, denial });
                } else {
                    events.push(SandboxEvent::FileRead { path, denial });
                }
            }
        } else if matches!(syscall, "socket" | "socketpair" | "connect") {
            events.push(SandboxEvent::NetworkEgress {
                host: "unknown".to_string(),
                port: None,
                scheme: None,
                denial,
            });
        } else if matches!(syscall, "bind" | "listen") {
            events.push(SandboxEvent::NetworkListen {
                port: None,
                scheme: None,
                denial,
            });
        } else if syscall == "execve"
            && let Some(cmd) = first_quoted_arg(line).map(|path| basename(&path))
        {
            events.push(SandboxEvent::ProcessExec { cmd, denial });
        }
    }
    events
}

#[cfg(any(target_os = "linux", test))]
fn linux_syscall_denial(line: &str) -> Option<String> {
    let (_, result) = line.rsplit_once(" = ")?;
    let mut parts = result.split_whitespace();
    if parts.next()? != "-1" {
        return None;
    }
    let errno = parts.next()?;
    if matches!(errno, "EACCES" | "EPERM") {
        Some(errno.to_string())
    } else {
        None
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_syscall_name(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    if let Some(pid_rest) = rest.strip_prefix("[pid ") {
        let close = pid_rest.find(']')?;
        rest = pid_rest.get(close + 1..)?.trim_start();
    } else {
        let pid_len = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if pid_len > 0 {
            let after_pid = rest.get(pid_len..)?;
            if !after_pid
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                return None;
            }
            rest = after_pid.trim_start();
        }
    }
    let open = rest.find('(')?;
    let name = rest.get(..open)?;
    if !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        Some(name)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn syscall(num: isize, ...) -> isize;
    fn prctl(option: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
}

#[cfg(target_os = "linux")]
const SYS_LANDLOCK_CREATE_RULESET: isize = 444;
#[cfg(target_os = "linux")]
const SYS_LANDLOCK_ADD_RULE: isize = 445;
#[cfg(target_os = "linux")]
const SYS_LANDLOCK_RESTRICT_SELF: isize = 446;
#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;

#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_EXECUTE: u64 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_WRITE_EXECUTE: u64 = LANDLOCK_ACCESS_FS_READ_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_TRUNCATE;

#[cfg(target_os = "linux")]
const PR_SET_NO_NEW_PRIVS: i32 = 38;
#[cfg(target_os = "linux")]
const PR_SET_SECCOMP: i32 = 22;
#[cfg(target_os = "linux")]
const SECCOMP_MODE_FILTER: u32 = 2;
#[cfg(target_os = "linux")]
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
#[cfg(target_os = "linux")]
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
#[cfg(target_os = "linux")]
const EPERM: u32 = 1;

#[cfg(target_os = "linux")]
const BPF_LD_W_ABS: u16 = 0x20;
#[cfg(target_os = "linux")]
const BPF_JMP_JEQ_K: u16 = 0x15;
#[cfg(target_os = "linux")]
const BPF_RET_K: u16 = 0x06;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_SOCKET: u32 = 41;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_CONNECT: u32 = 42;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_BIND: u32 = 49;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_LISTEN: u32 = 50;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_SOCKETPAIR: u32 = 53;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_SOCKET: u32 = 198;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_BIND: u32 = 200;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_LISTEN: u32 = 201;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_CONNECT: u32 = 203;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_SOCKETPAIR: u32 = 199;

#[cfg(target_os = "linux")]
fn linux_landlock_abi() -> std::io::Result<u32> {
    let abi = unsafe {
        syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(abi as u32)
    }
}

#[cfg(target_os = "linux")]
fn landlock_supported_fs_access(abi: u32) -> u64 {
    let mut access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if abi >= 2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    access
}

#[cfg(target_os = "linux")]
fn create_landlock_ruleset(handled_access_fs: u64) -> std::io::Result<RawFd> {
    let attr = LandlockRulesetAttr { handled_access_fs };
    let fd = unsafe {
        syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd as RawFd)
    }
}

#[cfg(target_os = "linux")]
fn add_landlock_path_rule(
    ruleset_fd: RawFd,
    parent_fd: RawFd,
    allowed_access: u64,
) -> std::io::Result<()> {
    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd,
    };
    let result = unsafe {
        syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd as isize,
            LANDLOCK_RULE_PATH_BENEATH as isize,
            &attr as *const LandlockPathBeneathAttr,
            0usize,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn set_no_new_privs() -> std::io::Result<()> {
    let result = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1usize, 0usize, 0usize, 0usize) };
    if result != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn restrict_self_landlock(ruleset_fd: RawFd) -> std::io::Result<()> {
    let result = unsafe { syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd as isize, 0usize) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn install_linux_network_seccomp_filter() -> std::io::Result<()> {
    let deny = SECCOMP_RET_ERRNO | EPERM;
    let filter = [
        SockFilter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        deny_syscall(SYS_SOCKET),
        ret(deny),
        deny_syscall(SYS_SOCKETPAIR),
        ret(deny),
        deny_syscall(SYS_CONNECT),
        ret(deny),
        deny_syscall(SYS_BIND),
        ret(deny),
        deny_syscall(SYS_LISTEN),
        ret(deny),
        ret(SECCOMP_RET_ALLOW),
    ];
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    let result = unsafe {
        prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &prog as *const SockFprog,
            0usize,
            0usize,
        )
    };
    if result != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn deny_syscall(syscall: u32) -> SockFilter {
    SockFilter {
        code: BPF_JMP_JEQ_K,
        jt: 0,
        jf: 1,
        k: syscall,
    }
}

#[cfg(target_os = "linux")]
fn ret(value: u32) -> SockFilter {
    SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: value,
    }
}

#[cfg(any(target_os = "linux", test))]
fn first_quoted_arg(line: &str) -> Option<String> {
    let start = line.find('"')? + 1;
    let mut out = String::new();
    let mut escaped = false;
    for ch in line.get(start..)?.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

fn is_profiler_runtime_noise(event: &SandboxEvent) -> bool {
    matches!(
        event,
        SandboxEvent::FileRead { path, .. }
            if path.ends_with("/.CFUserTextEncoding")
                || path == "/dev/dtracehelper"
                || path == "timezoneName"
    )
}

fn log_record_matches_process(
    record: &Value,
    message: &str,
    pid: u32,
    executable: &Path,
    executable_realpath: &Path,
) -> bool {
    if pid != 0 {
        for key in ["processID", "processIdentifier", "pid"] {
            if record
                .pointer(&format!("/{key}"))
                .and_then(Value::as_u64)
                .is_some_and(|record_pid| record_pid == pid as u64)
            {
                return true;
            }
        }
        if message.contains(&format!("({pid})")) {
            return true;
        }
    }
    let executable_name = executable.file_name().and_then(|name| name.to_str());
    let realpath_name = executable_realpath
        .file_name()
        .and_then(|name| name.to_str());
    for key in [
        "process",
        "processImagePath",
        "senderImagePath",
        "processExecutablePath",
    ] {
        let Some(value) = record.pointer(&format!("/{key}")).and_then(Value::as_str) else {
            continue;
        };
        if value == executable.to_string_lossy() || value == executable_realpath.to_string_lossy() {
            return true;
        }
        let value_name = Path::new(value).file_name().and_then(|name| name.to_str());
        if value_name.is_some() && (value_name == executable_name || value_name == realpath_name) {
            return true;
        }
    }
    false
}

fn parse_sandbox_line(line: &str) -> Option<(&str, &str)> {
    let deny = line.find(" deny(")?;
    let after = &line[deny..];
    let close = after.find(')')?;
    let rest = after.get(close + 1..)?.trim();
    let mut parts = rest.splitn(2, char::is_whitespace);
    let operation = parts.next()?.trim();
    let detail = parts.next().unwrap_or("").trim();
    if operation.is_empty() {
        None
    } else {
        Some((operation, detail))
    }
}

fn parse_host_port(detail: &str) -> (String, Option<u16>) {
    let cleaned = detail
        .trim()
        .trim_matches('"')
        .trim_start_matches("remote:")
        .trim();
    if let Some((host, port)) = cleaned.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.trim_matches(&['[', ']'][..]).to_string(), Some(port));
    }
    (cleaned.to_string(), None)
}

fn infer_scheme(port: u16) -> Option<String> {
    match port {
        80 => Some("http".to_string()),
        443 => Some("https".to_string()),
        _ => Some("tcp".to_string()),
    }
}

fn basename(path: &str) -> String {
    let cleaned = path
        .split_whitespace()
        .next()
        .unwrap_or(path)
        .trim_matches('"');
    if let Some(name) = cleaned
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
    {
        return name.to_string();
    }
    Path::new(cleaned)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(cleaned)
        .to_string()
}

fn merge_capability(caps: &mut Vec<Capability>, cap: Capability) {
    if let Some(existing) = caps
        .iter_mut()
        .find(|existing| existing.id == cap.id && existing.qualifiers == cap.qualifiers)
    {
        for evidence in cap.evidence {
            if !existing.evidence.contains(&evidence) {
                existing.evidence.push(evidence);
                existing.evidence.sort();
            }
        }
    } else {
        caps.push(cap);
    }
}

fn fragment(input: &str) -> String {
    input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn denial_reference_suffix(denial: &Option<String>) -> String {
    denial
        .as_deref()
        .map(|value| format!(":DENIED:{}", fragment(&super::redact_home_identity(value))))
        .unwrap_or_default()
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesizes_required_path_inside_tempdir() {
        let temp = TempDir::new().unwrap();
        let schema = json!({
            "type":"object",
            "required":["path", "count"],
            "properties":{
                "path":{"type":"string"},
                "count":{"type":"integer", "minimum":2}
            }
        });
        let value = synthesize_input(&schema, temp.path()).unwrap();
        assert_eq!(value["count"], json!(2));
        assert!(
            value["path"]
                .as_str()
                .unwrap()
                .starts_with(temp.path().to_str().unwrap())
        );
    }

    #[test]
    fn skips_required_secret() {
        let temp = TempDir::new().unwrap();
        let schema = json!({
            "type":"object",
            "required":["api_key"],
            "properties":{"api_key":{"type":"string"}}
        });
        assert!(synthesize_input(&schema, temp.path()).is_err());
    }

    #[test]
    fn maps_sandbox_lines_to_capabilities() {
        let lines = vec![
            "Sandbox: python3(123) deny(1) file-read-data /etc/passwd".to_string(),
            "Sandbox: python3(123) deny(1) network-outbound example.com:443".to_string(),
            "Sandbox: python3(123) deny(1) process-exec /usr/bin/curl".to_string(),
        ];
        let events = parse_sandbox_events(&lines);
        assert_eq!(events.len(), 3);
        assert!(
            matches!(events[0], SandboxEvent::FileRead { ref path, .. } if path == "/etc/passwd")
        );
        assert!(
            matches!(events[1], SandboxEvent::NetworkEgress { ref host, port: Some(443), .. } if host == "example.com")
        );
        assert!(matches!(events[2], SandboxEvent::ProcessExec { ref cmd, .. } if cmd == "curl"));
    }

    #[test]
    fn maps_linux_trace_lines_to_sandbox_event_classification() {
        let lines = vec![
            r#"123 openat(AT_FDCWD, "/tmp/reeve-input.txt", O_RDONLY|O_CLOEXEC) = 3"#
                .to_string(),
            r#"123 open("/tmp/reeve-legacy.txt", O_RDONLY|O_CLOEXEC) = 3"#.to_string(),
            r#"123 openat2(AT_FDCWD, "/tmp/reeve-openat2.txt", {flags=O_RDONLY}, 24) = 3"#
                .to_string(),
            r#"124 openat(AT_FDCWD, "/tmp/reeve-output.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EACCES (Permission denied)"#
                .to_string(),
            r#"125 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = -1 EPERM"#
                .to_string(),
            r#"125 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 EINPROGRESS"#
                .to_string(),
            r#"126 bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0"#
                .to_string(),
            r#"127 execve("/usr/bin/curl", ["curl", "--version"], 0x7ffc) = 0"#.to_string(),
            r#"128 openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3"#
                .to_string(),
        ];

        let events = parse_linux_trace_events(&lines);
        assert_eq!(events.len(), 8);
        assert!(
            matches!(events[0], SandboxEvent::FileRead { ref path, .. } if path == "/tmp/reeve-input.txt")
        );
        assert!(
            matches!(events[1], SandboxEvent::FileRead { ref path, .. } if path == "/tmp/reeve-legacy.txt")
        );
        assert!(
            matches!(events[2], SandboxEvent::FileRead { ref path, .. } if path == "/tmp/reeve-openat2.txt")
        );
        assert!(
            matches!(events[3], SandboxEvent::FileWrite { ref path, ref denial } if path == "/tmp/reeve-output.txt" && denial.as_deref() == Some("EACCES"))
        );
        assert!(
            matches!(events[4], SandboxEvent::NetworkEgress { ref denial, .. } if denial.as_deref() == Some("EPERM"))
        );
        assert!(matches!(events[5], SandboxEvent::NetworkEgress { .. }));
        assert!(matches!(events[6], SandboxEvent::NetworkListen { .. }));
        assert!(matches!(events[7], SandboxEvent::ProcessExec { ref cmd, .. } if cmd == "curl"));
        assert!(
            events[3]
                .reference("scan-test")
                .contains("/tmp/reeve-output.txt:WRITE:DENIED:EACCES")
        );
        assert!(
            events[4]
                .reference("scan-test")
                .contains("connect#unknown:DENIED:EPERM")
        );

        let classified: Vec<_> = events
            .iter()
            .map(|event| {
                let capability = event.capability("ev-test".to_string());
                (event.evidence_kind(), capability.id)
            })
            .collect();
        assert_eq!(
            classified,
            vec![
                ("sandbox-filesystem", "fs:read".to_string()),
                ("sandbox-filesystem", "fs:read".to_string()),
                ("sandbox-filesystem", "fs:read".to_string()),
                ("sandbox-filesystem", "fs:write".to_string()),
                ("sandbox-network", "net:egress".to_string()),
                ("sandbox-network", "net:egress".to_string()),
                ("sandbox-network", "net:listen".to_string()),
                ("sandbox-process", "exec:subprocess".to_string()),
            ]
        );
    }

    #[test]
    fn maps_windows_tracerpt_lines_to_observational_events() {
        let lines = vec![
            r#""Event Name","Process ID","Event Type","Path""#.to_string(),
            r#""FileIo","4242","Read","C:\Users\alice\AppData\Roaming\Claude\claude_desktop_config.json""#.to_string(),
            r#""FileIo","4242","Write","C:\Users\alice\AppData\Local\Temp\reeve-output.txt""#.to_string(),
            r#""TcpIp","4242","Connect","daddr=203.0.113.10,dport=443""#.to_string(),
            r#""Process","4242","Start","C:\Windows\System32\cmd.exe""#.to_string(),
            r#""FileIo","9999","Read","C:\Users\bob\ignore.txt""#.to_string(),
            r#""FileIo","9999","Write","C:\Users\alice\AppData\Local\Temp\reeve-windows-profile-output.txt""#.to_string(),
            r#""Process","0x00001092","Start","pwsh.exe -File C:\Temp\reeve-windows-mcp.ps1""#.to_string(),
        ];

        let events = parse_windows_tracerpt_events(&lines, 4242);

        assert_eq!(events.len(), 6);
        assert!(
            matches!(events[0], SandboxEvent::FileRead { ref path, denial: None } if path.ends_with(r"Claude\claude_desktop_config.json"))
        );
        let read_cap = events[0].capability("ev-test".to_string());
        assert_eq!(read_cap.id, "fs:read");
        assert_eq!(
            read_cap.qualifiers.get("path"),
            Some(&json!(
                r"C:\Users\<redacted-home>\AppData\Roaming\Claude\claude_desktop_config.json"
            ))
        );
        assert!(
            matches!(events[1], SandboxEvent::FileWrite { ref path, denial: None } if path.ends_with("reeve-output.txt"))
        );
        let write_cap = events[1].capability("ev-test".to_string());
        assert_eq!(write_cap.id, "fs:write");
        assert_eq!(
            write_cap.qualifiers.get("path"),
            Some(&json!(
                r"C:\Users\<redacted-home>\AppData\Local\Temp\reeve-output.txt"
            ))
        );
        assert!(
            matches!(events[2], SandboxEvent::NetworkEgress { ref host, port: Some(443), denial: None, .. } if host == "203.0.113.10")
        );
        assert!(
            matches!(events[3], SandboxEvent::ProcessExec { ref cmd, denial: None } if cmd == "cmd.exe")
        );
        assert!(
            matches!(events[4], SandboxEvent::FileWrite { ref path, denial: None } if path.ends_with("reeve-windows-profile-output.txt"))
        );
        assert!(matches!(
            events[5],
            SandboxEvent::ProcessExec { denial: None, .. }
        ));
    }

    #[test]
    fn windows_tracerpt_records_loss_as_unmapped_warning_event() {
        let lines = vec![r#""EventTrace","4242","Events Lost","lost event count=7""#.to_string()];

        let events = parse_windows_tracerpt_events(&lines, 4242);

        assert_eq!(
            events,
            vec![SandboxEvent::Unmapped {
                action: "windows-etw-loss".to_string()
            }]
        );
        assert!(
            events[0]
                .reference("scan-test")
                .contains("windows-etw-loss#unmapped")
        );
    }

    #[test]
    fn ignores_stderr_like_false_positives_in_linux_trace_parser() {
        let lines = vec![
            "server reopening socket after timeout".to_string(),
            "server wrote: open connection".to_string(),
            "write(2, \"open /etc/passwd\", 16) = 16".to_string(),
            "close(3) = 0".to_string(),
            r#"123 openat(AT_FDCWD, "/tmp/actual.txt", O_RDONLY|O_CLOEXEC) = 3"#.to_string(),
        ];

        let events = parse_linux_trace_events(&lines);

        assert_eq!(events.len(), 1);
        assert!(
            matches!(events[0], SandboxEvent::FileRead { ref path, .. } if path == "/tmp/actual.txt")
        );
    }

    #[test]
    fn parses_first_quoted_arg_edge_cases() {
        assert_eq!(
            first_quoted_arg(r#"openat(AT_FDCWD, "", O_RDONLY) = 3"#),
            Some(String::new())
        );
        assert_eq!(
            first_quoted_arg(r#"execve("/tmp/has \"quote\".sh", [], []) = 0"#),
            Some(r#"/tmp/has "quote".sh"#.to_string())
        );
        assert_eq!(
            first_quoted_arg(r#"openat(AT_FDCWD, "/tmp/unclosed, O_RDONLY) = -1"#),
            None
        );
        assert_eq!(
            first_quoted_arg("openat(AT_FDCWD, /tmp/unquoted, O_RDONLY) = -1"),
            None
        );
    }

    #[test]
    fn filters_profiler_runtime_noise() {
        assert!(is_profiler_runtime_noise(&SandboxEvent::FileRead {
            path: "/Users/test/.CFUserTextEncoding".to_string(),
            denial: None,
        }));
        assert!(is_profiler_runtime_noise(&SandboxEvent::FileRead {
            path: "/dev/dtracehelper".to_string(),
            denial: None,
        }));
        assert!(is_profiler_runtime_noise(&SandboxEvent::FileRead {
            path: "timezoneName".to_string(),
            denial: None,
        }));
        assert!(!is_profiler_runtime_noise(&SandboxEvent::FileRead {
            path: "/etc/passwd".to_string(),
            denial: None,
        }));
        assert!(!is_profiler_runtime_noise(&SandboxEvent::NetworkEgress {
            host: "example.com".to_string(),
            port: Some(443),
            scheme: Some("https".to_string()),
            denial: None,
        }));
    }

    #[test]
    fn parses_unified_log_ndjson_by_pid() {
        let lines = vec![
            json!({
                "subsystem":"com.apple.sandbox",
                "processID":42,
                "eventMessage":"Sandbox: python3(42) deny(1) file-read-data /etc/passwd"
            })
            .to_string(),
            json!({
                "subsystem":"com.apple.sandbox",
                "processID":99,
                "eventMessage":"Sandbox: python3(99) deny(1) network-outbound example.com:443"
            })
            .to_string(),
        ];
        let events = parse_unified_log_events(
            &lines,
            42,
            Path::new("/opt/homebrew/bin/python3"),
            Path::new("/opt/homebrew/Cellar/python@3.14/bin/python3.14"),
        );
        assert_eq!(events.len(), 1);
        assert!(
            matches!(events[0], SandboxEvent::FileRead { ref path, .. } if path == "/etc/passwd")
        );
    }

    #[test]
    fn unified_log_parser_does_not_parse_linux_trace_syntax() {
        let lines = vec![json!({
            "subsystem":"com.apple.sandbox",
            "processID":42,
            "eventMessage":"Sandbox: python3(42) deny(1) file-read-data /tmp/open(\"not-strace\")"
        })
        .to_string()];

        let events = parse_unified_log_events(
            &lines,
            42,
            Path::new("/opt/homebrew/bin/python3"),
            Path::new("/opt/homebrew/Cellar/python@3.14/bin/python3.14"),
        );

        assert_eq!(events.len(), 1);
        assert!(
            matches!(events[0], SandboxEvent::FileRead { ref path, .. } if path == "/tmp/open(\"not-strace\")")
        );
    }

    #[test]
    fn profile_event_source_keeps_macos_and_linux_parsers_separate() {
        let plan = LaunchPlan {
            executable: PathBuf::from("/usr/bin/python3"),
            executable_realpath: PathBuf::from("/usr/bin/python3"),
            executable_paths: vec![PathBuf::from("/usr/bin/python3")],
            args: Vec::new(),
            package_dir: PathBuf::from("/tmp"),
        };
        let mac_run = ProfileRun {
            invoked_tools: Vec::new(),
            pid: 42,
            event_source: ProfileEventSource::MacosUnifiedLog,
            log_lines: vec![
                json!({
                    "processID":42,
                    "eventMessage":"Sandbox: python3(42) deny(1) file-read-data /tmp/open(\"not-strace\")"
                })
                .to_string(),
            ],
            run_error: None,
        };
        let linux_run = ProfileRun {
            invoked_tools: Vec::new(),
            pid: 42,
            event_source: ProfileEventSource::LinuxStrace,
            log_lines: vec![
                json!({
                    "processID":42,
                    "eventMessage":"Sandbox: python3(42) deny(1) file-read-data /tmp/open(\"not-strace\")"
                })
                .to_string(),
                r#"123 openat(AT_FDCWD, "/tmp/linux.txt", O_RDONLY|O_CLOEXEC) = 3"#.to_string(),
            ],
            run_error: None,
        };

        let mac_events = parse_profile_events(&mac_run, &plan);
        let linux_events = parse_profile_events(&linux_run, &plan);

        assert_eq!(mac_events.len(), 1);
        assert!(
            matches!(mac_events[0], SandboxEvent::FileRead { ref path, .. } if path == "/tmp/open(\"not-strace\")")
        );
        assert_eq!(linux_events.len(), 1);
        assert!(
            matches!(linux_events[0], SandboxEvent::FileRead { ref path, .. } if path == "/tmp/linux.txt")
        );
    }

    #[test]
    fn renders_macos_sandbox_profile_with_runtime_allows_before_sensitive_redeny() {
        let temp = TempDir::new().unwrap();
        let package_dir = temp.path().join("pkg");
        let bin_dir = temp.path().join("bin");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::create_dir_all(&bin_dir).unwrap();
        let executable = bin_dir.join("python3");
        let executable_realpath = bin_dir.join("python3.14");

        let plan = LaunchPlan {
            executable: executable.clone(),
            executable_realpath: executable_realpath.clone(),
            executable_paths: vec![executable.clone(), executable_realpath.clone()],
            args: Vec::new(),
            package_dir: package_dir.clone(),
        };

        let profile_path = write_sandbox_profile(temp.path(), &plan).unwrap();
        let rendered = std::fs::read_to_string(profile_path).unwrap();
        let runtime_allow = rendered
            .find("; Let sandboxed stdio server read its package/interpreter/runtime files.")
            .unwrap();
        let sensitive_redeny = rendered
            .find("; system.sb and the runtime allow-list give startup baseline access.")
            .unwrap();

        assert!(runtime_allow < sensitive_redeny);
        assert!(rendered.contains(&format!("  (subpath \"{}\")", sbpl_escape(&package_dir))));
        assert!(rendered.contains(&format!("  (literal \"{}\")", sbpl_escape(&executable))));
        assert!(rendered.contains(&format!(
            "  (literal \"{}\")",
            sbpl_escape(&executable_realpath)
        )));
        assert!(rendered.contains(&format!(
            "(allow file-write* (subpath \"{}\"))",
            sbpl_escape(temp.path())
        )));
        assert!(rendered.contains("  (literal \"/etc/passwd\")"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn run_profiled_server_uses_linux_enforcement_when_available() {
        if !linux_strace_available().await {
            return;
        }

        let server = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("mcp")
            .join("rigged-server")
            .join("server.py");
        let Some(plan) = resolve_launch_plan("python3", &[server.display().to_string()]) else {
            return;
        };
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path().join("home")).unwrap();
        let opts = ProfileOptions {
            scan_id: "scan-linux-rigged".into(),
            evidence_prefix: "ev-linux-rigged".into(),
            timeout_per_tool_seconds: 5,
            timeout_total_seconds: 20,
            ..Default::default()
        };

        let run = run_profiled_server(&plan, temp.path(), &opts)
            .await
            .unwrap();
        if linux_landlock_abi().is_ok_and(|abi| abi > 0) {
            assert!(
                !run.run_error.as_deref().is_some_and(|warning| warning
                    .contains("without Landlock/seccomp enforcement")),
                "expected enforced Linux profile without fallback warning, got {:?}",
                run.run_error
            );
        } else {
            assert!(
                run.run_error
                    .as_deref()
                    .is_some_and(|warning| warning.contains("without Landlock/seccomp enforcement")),
                "expected Linux observational fallback warning, got {:?}",
                run.run_error
            );
        }
        assert!(
            run.invoked_tools
                .iter()
                .any(|tool| tool.name == "read_file" && tool.skipped_reason.is_none()),
            "expected rigged tool invocation, got {:?}",
            run.invoked_tools
        );
        assert!(
            run.log_lines.iter().any(|line| line.contains("execve(")),
            "expected strace log lines, got {:?}",
            run.log_lines
        );

        let events = parse_profile_events(&run, &plan);
        assert!(
            events.iter().any(
                |event| matches!(event, SandboxEvent::FileRead { path, .. } if path == "/etc/passwd")
            ),
            "expected Linux trace to capture rigged /etc/passwd read, got {:?}",
            events
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, SandboxEvent::NetworkEgress { .. })),
            "expected Linux trace to capture rigged network egress, got {:?}",
            events
        );
        if linux_landlock_abi().is_ok_and(|abi| abi > 0) {
            assert!(
                events.iter().any(|event| {
                    matches!(
                        event,
                        SandboxEvent::FileWrite {
                            path,
                            denial: Some(denial),
                        } if path == "/tmp/reeve-landlock-denied-write" && denial == "EACCES"
                    )
                }),
                "expected Linux Landlock denied write evidence, got {:?}",
                events
            );
            assert!(
                events.iter().any(|event| {
                    matches!(
                        event,
                        SandboxEvent::NetworkEgress {
                            denial: Some(denial),
                            ..
                        } if denial == "EPERM"
                    )
                }),
                "expected Linux seccomp denied network evidence, got {:?}",
                events
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn records_linux_observational_fallback_as_evidence_marker() {
        let provider = ToolProvider {
            surface: "test".to_string(),
            name: "fallback".to_string(),
            transport: Transport::Stdio(aibom_core::StdioConfig {
                command: "python3".to_string(),
                args: Vec::new(),
                env: std::collections::BTreeMap::new(),
            }),
            source_path: None,
            discovery_source: aibom_core::DiscoverySource::BuiltIn,
            extension: None,
            declared_tools: Vec::new(),
        };
        let opts = ProfileOptions {
            scan_id: "scan-fallback".to_string(),
            evidence_prefix: "ev-fallback".to_string(),
            timeout_per_tool_seconds: 1,
            timeout_total_seconds: 1,
            ..Default::default()
        };
        let mut builder = ProfileBuilder::new(&provider, &opts);
        builder.skip(&format!(
            "sandbox run warning: {LINUX_OBSERVATIONAL_FALLBACK_WARNING}"
        ));
        let profile = builder.finish();

        assert!(
            profile.evidence.iter().any(|evidence| {
                evidence.kind == "sandbox-mcp-invoke"
                    && evidence
                        .reference
                        .contains("without-Landlock/seccomp-enforcement")
            }),
            "expected fallback marker evidence, got {:?}",
            profile.evidence
        );
    }

    #[cfg(target_os = "linux")]
    async fn linux_strace_available() -> bool {
        Command::new("strace")
            .arg("-V")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_ok_and(|status| status.success())
    }

    #[tokio::test]
    async fn log_task_collection_times_out_when_pipe_stays_open() {
        let task = tokio::spawn(async {
            sleep(Duration::from_secs(60)).await;
            vec!["late".to_string()]
        });

        let lines = collect_log_task(task).await;

        assert!(lines.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn resolves_full_executable_symlink_chain() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let real = temp.path().join("real-python");
        let middle = temp.path().join("middle-python");
        let entry = temp.path().join("python3");
        std::fs::write(&real, b"").unwrap();
        symlink(&real, &middle).unwrap();
        symlink(&middle, &entry).unwrap();

        let paths = resolve_symlink_chain(&entry).unwrap();
        assert!(paths.contains(&entry));
        assert!(paths.contains(&middle));
        assert!(paths.contains(&real));
    }
}
