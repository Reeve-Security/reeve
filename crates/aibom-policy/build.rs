use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::Digest;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bundle_dir = manifest_dir.join("bundles");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Copy the committed pre-built WASM policy bundle into OUT_DIR so that
    // the crate can embed it at compile time.
    //
    // Rationale: aibom-policy uses OPA (`opa build -t wasm`) which is a Go
    // binary not available in many CI / cross-compilation environments. By
    // committing the compiled policy.wasm we remove a native build dependency
    // from the release pipeline and make the build deterministic.
    //
    // To regenerate the bundle after editing Rego files:
    //   scripts/build-policy-bundle.sh --write
    //
    // The version string below must match the crate version and committed
    // bundle filenames. Hashes come from the committed provenance file because
    // OPA can emit byte-distinct policy.wasm for identical Rego sources.
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let wasm_src = bundle_dir.join(format!("{}.wasm", version));
    let data_src = bundle_dir.join(format!("{}.json", version));
    let provenance_src = bundle_dir.join(format!("{}.provenance.json", version));

    if !wasm_src.exists() {
        panic!(
            "committed policy bundle missing: {}\n\
             Regenerate with: scripts/build-policy-bundle.sh --write",
            wasm_src.display(),
        );
    }

    let hashes = policy_bundle_hashes(&provenance_src, &version);
    println!("cargo:rerun-if-changed={}", wasm_src.display());
    println!("cargo:rerun-if-changed={}", data_src.display());
    println!("cargo:rerun-if-changed={}", provenance_src.display());

    verify_hash(&wasm_src, &hashes.policy_wasm);
    verify_hash(&data_src, &hashes.data_json);

    copy_file(&wasm_src, &out_dir.join("policy.wasm"));
    copy_file(&data_src, &out_dir.join("data.json"));
}

struct PolicyBundleHashes {
    policy_wasm: String,
    data_json: String,
}

fn policy_bundle_hashes(path: &Path, version: &str) -> PolicyBundleHashes {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "failed to read policy bundle provenance {}: {}",
            path.display(),
            e
        )
    });
    let provenance: Value = serde_json::from_str(&raw).unwrap_or_else(|e| {
        panic!(
            "failed to parse policy bundle provenance {}: {}",
            path.display(),
            e
        )
    });
    expect_string(&provenance, "/bundleVersion", path, version);

    let wasm_path = format!("crates/aibom-policy/bundles/{version}.wasm");
    let data_path = format!("crates/aibom-policy/bundles/{version}.json");
    expect_string(&provenance, "/outputs/policyWasm/path", path, &wasm_path);
    expect_string(&provenance, "/outputs/dataJson/path", path, &data_path);

    PolicyBundleHashes {
        policy_wasm: expected_sha256(&provenance, "/outputs/policyWasm/sha256", path),
        data_json: expected_sha256(&provenance, "/outputs/dataJson/sha256", path),
    }
}

fn expect_string(provenance: &Value, pointer: &str, path: &Path, expected: &str) {
    let actual = provenance
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "policy bundle provenance {} missing string at {}",
                path.display(),
                pointer
            )
        });
    if actual != expected {
        panic!(
            "policy bundle provenance {} mismatch at {}: expected {}, got {}",
            path.display(),
            pointer,
            expected,
            actual
        );
    }
}

fn expected_sha256(provenance: &Value, pointer: &str, path: &Path) -> String {
    let value = provenance
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "policy bundle provenance {} missing string at {}",
                path.display(),
                pointer
            )
        });
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        panic!(
            "policy bundle provenance {} has invalid sha256 at {}: {}",
            path.display(),
            pointer,
            value
        );
    }
    value.to_string()
}

fn verify_hash(path: &Path, expected: &str) {
    let mut file = fs::File::open(path).unwrap_or_else(|e| {
        panic!(
            "failed to open policy bundle artifact {}: {}",
            path.display(),
            e
        )
    });
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer).unwrap_or_else(|e| {
            panic!(
                "failed to read policy bundle artifact {}: {}",
                path.display(),
                e
            )
        });
        if read == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        panic!(
            "policy bundle hash mismatch for {}: expected {}, got {}. Run scripts/build-policy-bundle.sh --write and commit the regenerated bundle/provenance together.",
            path.display(),
            expected,
            actual
        );
    }
}

fn copy_file(src: &Path, dst: &Path) {
    fs::copy(src, dst).unwrap_or_else(|e| {
        panic!(
            "failed to copy {} to {}: {}",
            src.display(),
            dst.display(),
            e
        )
    });
}
