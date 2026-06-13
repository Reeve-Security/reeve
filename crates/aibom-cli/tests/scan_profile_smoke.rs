#[allow(dead_code)]
mod common;

#[cfg(target_os = "macos")]
use assert_cmd::Command;
#[cfg(target_os = "macos")]
use predicates::str::contains;
#[cfg(target_os = "macos")]
use tempfile::TempDir;

#[test]
#[cfg(target_os = "macos")]
fn scan_profile_on_rigged_target_produces_schema_valid_observed_delta() {
    if !common::sandbox_exec_available() {
        return;
    }

    let mut last_aibom = None;
    for _ in 0..3 {
        let target = common::tempdir_with_rigged_mcp_config();
        let out = TempDir::new().unwrap();

        Command::cargo_bin("aibom-cli")
            .unwrap()
            .args([
                "scan",
                "--target",
                target.path().to_str().unwrap(),
                "--profile",
                "--profile-yes",
                "--skip-sign",
                "--output-dir",
                out.path().to_str().unwrap(),
            ])
            .assert()
            .success()
            .stdout(contains("scanId "));

        let (cdx, aibom, bundle) = common::find_triplet(out.path());
        let aibom_json = common::read_json(&aibom);
        let has_fs = common::observed_contains(&aibom_json, "fs:read", Some("/private/etc/passwd"))
            || common::observed_contains(&aibom_json, "fs:read", Some("/etc/passwd"));
        let has_net = common::observed_contains(&aibom_json, "net:egress", None);
        let has_process_fork =
            common::observed_contains(&aibom_json, "mcp:sandbox:process-fork", None);
        last_aibom = Some(aibom_json.clone());

        if (has_fs && has_net) || has_process_fork {
            Command::cargo_bin("aibom-cli")
                .unwrap()
                .args([
                    "validate-artifacts",
                    "--cdx",
                    cdx.to_str().unwrap(),
                    "--aibom",
                    aibom.to_str().unwrap(),
                    "--bundle",
                    bundle.to_str().unwrap(),
                    "--schema",
                    common::repo_root()
                        .join("schema")
                        .join("aibom-v0.1.0.json")
                        .to_str()
                        .unwrap(),
                ])
                .assert()
                .success()
                .stdout(contains("PASS artifacts"));
            return;
        }
    }

    panic!(
        "expected a schema-valid observed sandbox delta in CLI profile smoke, last aibom={:?}",
        last_aibom
    );
}
