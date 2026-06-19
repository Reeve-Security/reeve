use aibom_signer::{Allowlist, ArtifactPair, OnlineSigstoreSigner, verify_crypto};
use base64::prelude::*;
use serde_json::Value;

/// Live Sigstore acceptance smoke. Ignored by default because it requires
/// ambient OIDC (GitHub Actions `id-token: write` or an interactive browser),
/// a working `cosign` binary, and network reachability to Fulcio / Rekor /
/// the Sigstore TUF mirror. The live-sigstore-acceptance workflow sets
/// `REEVE_ONLINE_SIGSTORE=1` and runs this under `--ignored` as the
/// online acceptance gate.
#[test]
#[ignore = "requires REEVE_ONLINE_SIGSTORE=1, cosign, OIDC, Fulcio, Rekor, TUF"]
fn online_sigstore_smoke() {
    if std::env::var("REEVE_ONLINE_SIGSTORE").ok().as_deref() != Some("1") {
        panic!("set REEVE_ONLINE_SIGSTORE=1 to run online Sigstore smoke");
    }
    let dir = tempfile::tempdir().unwrap();
    let bundle_path = dir.path().join("bundle.json");
    let pair = ArtifactPair {
        cdx_name: "smoke.cdx.json",
        cdx_bytes: br#"{"bomFormat":"CycloneDX"}"#,
        aibom_name: "smoke.aibom.json",
        aibom_bytes: br#"{"aibom":{"schemaVersion":"0.1.0"}}"#,
    };
    OnlineSigstoreSigner::from_env()
        .expect("resolve cosign binary")
        .sign_pair_to_bundle(&pair, &bundle_path)
        .expect("cosign attest-blob produced no bundle");
    assert!(bundle_path.is_file(), "bundle file was not written");

    let bundle_bytes = std::fs::read(&bundle_path).expect("read bundle");
    let bundle: Value = serde_json::from_slice(&bundle_bytes).expect("bundle is JSON");

    // The fixture bundle carries `_fixture_note` markers; a live bundle
    // must not. Guards against accidental silent downgrade to fixture.
    assert!(
        bundle
            .pointer("/verificationMaterial/_fixture_note")
            .is_none(),
        "live bundle leaked a fixture marker: {bundle:#}"
    );

    let cert_b64 = bundle
        .pointer("/verificationMaterial/certificate/rawBytes")
        .and_then(Value::as_str)
        .expect("certificate.rawBytes missing");
    assert_ne!(
        cert_b64, "FIXTURE_PLACEHOLDER_CERT_BYTES",
        "live bundle carries the fixture placeholder cert",
    );
    let cert_der = BASE64_STANDARD
        .decode(cert_b64)
        .expect("certificate.rawBytes base64 decodes");
    assert!(
        cert_der.len() > 200,
        "Fulcio cert should be a full DER X.509; got {} bytes",
        cert_der.len()
    );

    let tlog = bundle
        .pointer("/verificationMaterial/tlogEntries/0")
        .expect("tlogEntries[0] missing");
    assert!(
        tlog.pointer("/_fixture_note").is_none(),
        "live tlog entry leaked a fixture marker"
    );
    assert!(
        tlog.pointer("/logIndex").is_some(),
        "tlogEntries[0].logIndex missing — Rekor did not return an inclusion receipt"
    );
    assert!(
        tlog.pointer("/canonicalizedBody").is_some(),
        "tlogEntries[0].canonicalizedBody missing"
    );

    let dsse_sig = bundle
        .pointer("/dsseEnvelope/signatures/0/sig")
        .and_then(Value::as_str)
        .expect("dsseEnvelope.signatures[0].sig missing");
    assert_ne!(
        dsse_sig, "FIXTURE_PLACEHOLDER_SIGNATURE",
        "live bundle carries the fixture placeholder signature",
    );

    // The validator's crypto-verification path must accept this live bundle.
    // (Per  the validator's verify_crypto is the structural crypto
    // gate that release-time tooling chains together with cosign verify; the
    // end-to-end `aibom verify --verify-crypto` wiring is proven on the CLI
    // in the live-sigstore-acceptance workflow.)
    verify_crypto(&bundle, &Allowlist::default()).expect("validator rejected a live bundle");
}
