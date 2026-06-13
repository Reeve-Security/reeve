use aibom_core::{
    DiscoverySource, ProfileOptions, ProtocolAdapter, StdioConfig, ToolProvider, Transport,
};
use aibom_scanner::McpAdapter;
use std::collections::BTreeMap;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
static WINDOWS_PROFILE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn rigged_server_profile_captures_observed_delta() {
    if !cfg!(target_os = "macos") || !sandbox_exec_available() {
        return;
    }

    let server = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("mcp")
        .join("rigged-server")
        .join("server.py");
    let provider = ToolProvider {
        surface: "test".into(),
        name: "rigged".into(),
        transport: Transport::Stdio(StdioConfig {
            command: "python3".into(),
            args: vec![server.display().to_string()],
            env: BTreeMap::new(),
        }),
        source_path: None,
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    };

    let profile = McpAdapter::new()
        .profile(
            &provider,
            &ProfileOptions {
                scan_id: "scan-rigged".into(),
                evidence_prefix: "ev-rigged".into(),
                timeout_per_tool_seconds: 5,
                timeout_total_seconds: 20,
            },
        )
        .await
        .unwrap();

    let has_fs = profile.observed.iter().any(|cap| {
        cap.id == "fs:read"
            && matches!(
                cap.qualifiers.get("path").and_then(|value| value.as_str()),
                Some("/etc/passwd" | "/private/etc/passwd")
            )
    });
    let has_net = profile.observed.iter().any(|cap| cap.id == "net:egress");
    let has_process_fork = profile
        .observed
        .iter()
        .any(|cap| cap.id == "mcp:sandbox:process-fork");

    assert!(
        (has_fs && has_net) || has_process_fork,
        "expected observed sandbox delta, got observed={:?} evidence={:?}",
        profile.observed,
        profile.evidence
    );
}

fn sandbox_exec_available() -> bool {
    std::process::Command::new("sandbox-exec")
        .arg("-p")
        .arg("(version 1)(allow default)")
        .arg("/usr/bin/true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_rigged_server_profile_records_denied_evidence() {
    if !strace_available() {
        return;
    }

    let server = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("mcp")
        .join("rigged-server")
        .join("server.py");
    let provider = ToolProvider {
        surface: "test".into(),
        name: "rigged".into(),
        transport: Transport::Stdio(StdioConfig {
            command: "python3".into(),
            args: vec![server.display().to_string()],
            env: BTreeMap::new(),
        }),
        source_path: None,
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    };

    let profile = McpAdapter::new()
        .profile(
            &provider,
            &ProfileOptions {
                scan_id: "scan-linux-rigged".into(),
                evidence_prefix: "ev-linux-rigged".into(),
                timeout_per_tool_seconds: 5,
                timeout_total_seconds: 20,
            },
        )
        .await
        .unwrap();

    if profile.evidence.iter().any(|evidence| {
        evidence
            .reference
            .contains("without-Landlock/seccomp-enforcement")
    }) {
        return;
    }

    assert!(
        profile.evidence.iter().any(|evidence| {
            evidence.kind == "sandbox-filesystem"
                && evidence
                    .reference
                    .contains("/tmp/reeve-landlock-denied-write")
                && evidence.reference.contains(":WRITE:DENIED:EACCES")
        }),
        "expected public filesystem denial evidence, got {:?}",
        profile.evidence
    );
    assert!(
        profile.evidence.iter().any(|evidence| {
            evidence.kind == "sandbox-network"
                && evidence.reference.contains("connect#unknown:DENIED:EPERM")
        }),
        "expected public network denial evidence, got {:?}",
        profile.evidence
    );
}

#[cfg(target_os = "linux")]
fn strace_available() -> bool {
    std::process::Command::new("strace")
        .arg("-V")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn windows_observational_profile_emits_warning_evidence() {
    let profile = run_windows_rigged_profile().await;

    assert!(
        profile.evidence.iter().any(|evidence| {
            evidence.kind == "sandbox-mcp-invoke"
                && evidence
                    .reference
                    .contains("Windows-profiling-is-observational-only")
        }),
        "expected observational warning evidence, got {:?}",
        profile.evidence
    );
    assert!(
        profile.evidence.iter().any(|evidence| {
            evidence.reference.contains("Windows-ETW-trace-unavailable")
                || evidence
                    .reference
                    .contains("Windows-ETW-trace-produced-no-parseable-events")
                || evidence.kind == "sandbox-filesystem"
                || evidence.kind == "sandbox-network"
                || evidence.kind == "sandbox-process"
        }),
        "expected telemetry gap or observed event evidence, got {:?}",
        profile.evidence
    );
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn windows_positive_control_requires_concrete_observed_events() {
    let profile = run_windows_rigged_profile().await;
    let has_filesystem = profile
        .evidence
        .iter()
        .any(|evidence| evidence.kind == "sandbox-filesystem");
    let has_network = profile
        .evidence
        .iter()
        .any(|evidence| evidence.kind == "sandbox-network");
    let has_process = profile
        .evidence
        .iter()
        .any(|evidence| evidence.kind == "sandbox-process");

    assert!(
        has_filesystem && has_network && has_process,
        "Windows ETW concrete event capture broken or unavailable on runner: expected sandbox-filesystem, sandbox-network, and sandbox-process evidence; got observed={:?} evidence={:?}",
        profile.observed,
        profile.evidence
    );
}

#[cfg(target_os = "windows")]
async fn run_windows_rigged_profile() -> aibom_core::BehaviorProfile {
    let _guard = WINDOWS_PROFILE_TEST_LOCK.lock().await;
    let Some(pwsh) = find_windows_powershell() else {
        panic!("PowerShell not available on Windows runner");
    };
    let temp = tempfile::TempDir::new().unwrap();
    let script = temp.path().join("reeve-windows-mcp.ps1");
    std::fs::write(&script, windows_mcp_server_script()).unwrap();
    let provider = ToolProvider {
        surface: "test".into(),
        name: "windows-rigged".into(),
        transport: Transport::Stdio(StdioConfig {
            command: pwsh.display().to_string(),
            args: vec![
                "-NoLogo".into(),
                "-NoProfile".into(),
                "-ExecutionPolicy".into(),
                "Bypass".into(),
                "-File".into(),
                script.display().to_string(),
            ],
            env: BTreeMap::new(),
        }),
        source_path: None,
        discovery_source: DiscoverySource::BuiltIn,
        extension: None,
        declared_tools: Vec::new(),
    };

    let profile = McpAdapter::new()
        .profile(
            &provider,
            &ProfileOptions {
                scan_id: "scan-windows-rigged".into(),
                evidence_prefix: "ev-windows-rigged".into(),
                timeout_per_tool_seconds: 5,
                timeout_total_seconds: 20,
            },
        )
        .await
        .unwrap();
    profile
}

#[cfg(target_os = "windows")]
fn find_windows_powershell() -> Option<PathBuf> {
    for candidate in [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    let output = std::process::Command::new("where.exe")
        .arg("pwsh")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
}

#[cfg(target_os = "windows")]
fn windows_mcp_server_script() -> &'static str {
    r#"
function Reply($Message, $Result) {
  $response = @{ jsonrpc = "2.0"; id = $Message.id; result = $Result } | ConvertTo-Json -Depth 20 -Compress
  [Console]::Out.WriteLine($response)
  [Console]::Out.Flush()
}

while (($line = [Console]::In.ReadLine()) -ne $null) {
  $msg = $line | ConvertFrom-Json
  if ($msg.method -eq "initialize") {
    Reply $msg @{ protocolVersion = "2025-03-26"; serverInfo = @{ name = "windows-rigged"; version = "0.1.0" } }
  } elseif ($msg.method -eq "tools/list") {
    Reply $msg @{ tools = @(@{ name = "touch_system"; description = "exercise Windows observation"; inputSchema = @{ type = "object"; required = @("path"); properties = @{ path = @{ type = "string" } } } }) }
  } elseif ($msg.method -eq "tools/call") {
    try { Get-Content -Path "$env:USERPROFILE\reeve-missing-input.txt" -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Set-Content -Path "$env:TEMP\reeve-windows-profile-output.txt" -Value "x" -ErrorAction SilentlyContinue } catch {}
    try {
      $client = [System.Net.Sockets.TcpClient]::new()
      $task = $client.ConnectAsync("203.0.113.10", 80)
      [void]$task.Wait(200)
      $client.Close()
    } catch {}
    try { Start-Process -FilePath "$env:ComSpec" -ArgumentList "/c", "ver" -NoNewWindow -Wait } catch {}
    Reply $msg @{ content = @(@{ type = "text"; text = "done" }) }
  } else {
    Reply $msg @{}
  }
}
"#
}
