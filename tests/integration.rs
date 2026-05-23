#![forbid(unsafe_code)]

use std::path::Path;
use std::process::Command;

use acdi::detect::{detect_in_bytes_pem_der, detect_in_file};
use acdi::model::{QuantumSafety, Risk};

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

// ── Certificate detection ─────────────────────────────────────────────────────

#[test]
fn detects_rsa2048_cert_as_vulnerable() {
    let path = fixture("pems/rsa2048.crt.pem");
    let assets = detect_in_file(&path).expect("detect should succeed");
    assert!(!assets.is_empty(), "should find at least one asset");

    let asset = &assets[0];
    assert_eq!(
        asset.quantum_safe,
        QuantumSafety::Vulnerable,
        "RSA-2048 must be VULNERABLE"
    );
    assert!(
        asset.hndl_risk >= Risk::High,
        "RSA-2048 HNDL risk must be HIGH or CRITICAL"
    );
}

#[test]
fn detects_ec_p256_cert_as_vulnerable() {
    let path = fixture("pems/ec_p256.crt.pem");
    let assets = detect_in_file(&path).expect("detect should succeed");
    assert!(!assets.is_empty(), "should find at least one asset");

    let asset = &assets[0];
    assert_eq!(
        asset.quantum_safe,
        QuantumSafety::Vulnerable,
        "ECDSA P-256 must be VULNERABLE"
    );
    assert!(
        asset.hndl_risk >= Risk::High,
        "ECDSA P-256 HNDL risk must be HIGH or CRITICAL"
    );
}

#[test]
fn detects_ec_p384_cert_as_vulnerable() {
    let path = fixture("pems/ec_p384.crt.pem");
    let assets = detect_in_file(&path).expect("detect should succeed");
    assert!(!assets.is_empty(), "should find at least one asset");

    let asset = &assets[0];
    assert_eq!(
        asset.quantum_safe,
        QuantumSafety::Vulnerable,
        "ECDSA P-384 must be VULNERABLE"
    );
}

#[test]
fn detects_rsa4096_cert() {
    let path = fixture("pems/rsa4096.crt.pem");
    let assets = detect_in_file(&path).expect("detect should succeed");
    assert!(!assets.is_empty(), "should find at least one asset");
    assert_eq!(assets[0].quantum_safe, QuantumSafety::Vulnerable);
}

#[test]
fn returns_empty_for_non_crypto_file() {
    let path = fixture("configs/not_crypto.txt");
    // File doesn't exist — detect_in_file should return empty, not error
    if !path.exists() {
        // Create a dummy non-crypto file for the test
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(&path, "Hello, world!\n").unwrap();
    }
    let assets = detect_in_file(&path).expect("should not error on non-crypto file");
    assert!(assets.is_empty(), "plain text file should yield no assets");
}

// ── Private key detection ─────────────────────────────────────────────────────

#[test]
fn detects_rsa_private_key() {
    let path = fixture("keys/rsa2048.key.pem");
    let assets = detect_in_file(&path).expect("detect should succeed");
    assert!(!assets.is_empty(), "should detect RSA private key");
    assert_eq!(assets[0].quantum_safe, QuantumSafety::Vulnerable);
    assert!(assets[0].hndl_risk >= Risk::High);
}

#[test]
fn detects_ec_private_key() {
    let path = fixture("keys/ec_p256.key.pem");
    let assets = detect_in_file(&path).expect("detect should succeed");
    assert!(!assets.is_empty(), "should detect EC private key");
    assert_eq!(assets[0].quantum_safe, QuantumSafety::Vulnerable);
}

// ── CBOM output ───────────────────────────────────────────────────────────────

#[test]
fn cbom_output_is_valid_json_with_correct_spec_version() {
    let path = fixture("pems/rsa2048.crt.pem");
    let assets = detect_in_file(&path).expect("detect should succeed");
    let cbom = acdi::output::emit_cbom(&assets);

    let parsed: serde_json::Value =
        serde_json::from_str(&cbom).expect("CBOM output must be valid JSON");

    assert_eq!(parsed["specVersion"], "1.7", "specVersion must be 1.7");
    assert_eq!(parsed["bomFormat"], "CycloneDX");
    assert!(
        parsed["components"].as_array().is_some(),
        "components must be an array"
    );
}

#[test]
fn cbom_components_have_crypto_properties() {
    let path = fixture("pems/rsa2048.crt.pem");
    let assets = detect_in_file(&path).expect("detect should succeed");
    let cbom = acdi::output::emit_cbom(&assets);
    let parsed: serde_json::Value = serde_json::from_str(&cbom).unwrap();

    let components = parsed["components"].as_array().unwrap();
    assert!(!components.is_empty());

    for comp in components {
        assert!(
            comp["cryptoProperties"].is_object(),
            "every component must have cryptoProperties"
        );
        assert!(
            comp["cryptoProperties"]["assetType"].is_string(),
            "cryptoProperties.assetType must be a string"
        );
    }
}

// ── OID catalog ───────────────────────────────────────────────────────────────

#[test]
fn oid_catalog_maps_rsa_oid() {
    use acdi::catalog::oids::oid_to_algorithm;
    assert_eq!(
        oid_to_algorithm("1.2.840.113549.1.1.1"),
        Some("RSA")
    );
}

#[test]
fn oid_catalog_maps_sha256_oid() {
    use acdi::catalog::oids::oid_to_algorithm;
    assert_eq!(
        oid_to_algorithm("2.16.840.1.101.3.4.2.1"),
        Some("SHA-256")
    );
}

#[test]
fn oid_catalog_returns_none_for_unknown() {
    use acdi::catalog::oids::oid_to_algorithm;
    assert_eq!(oid_to_algorithm("9.9.9.9.9.9"), None);
}

// ── Classification correctness ────────────────────────────────────────────────

#[test]
fn rsa2048_cert_has_correct_name_and_risk() {
    let path = fixture("pems/rsa2048.crt.pem");
    let assets = detect_in_file(&path).unwrap();
    let asset = &assets[0];
    assert_eq!(asset.name, "RSA-2048", "cert name must include key size");
    assert_eq!(asset.hndl_risk, Risk::Critical);
    assert_eq!(asset.nist_quantum_security, 0);
}

#[test]
fn rsa4096_cert_has_high_not_critical_risk() {
    let path = fixture("pems/rsa4096.crt.pem");
    let assets = detect_in_file(&path).unwrap();
    let asset = &assets[0];
    assert_eq!(asset.name, "RSA-4096", "cert name must include key size");
    // RSA-4096 is High (not Critical) per NIST IR 8547 — larger key, lower HNDL urgency
    assert_eq!(asset.hndl_risk, Risk::High);
}

#[test]
fn ec_p256_cert_has_correct_name_and_curve() {
    let path = fixture("pems/ec_p256.crt.pem");
    let assets = detect_in_file(&path).unwrap();
    let asset = &assets[0];
    assert_eq!(asset.name, "ECDSA-P-256", "EC cert must include named curve");
    assert_eq!(asset.parameter_set.as_deref(), Some("P-256"));
    assert_eq!(asset.quantum_safe, QuantumSafety::Vulnerable);
    assert_eq!(asset.hndl_risk, Risk::Critical);
}

#[test]
fn ec_p384_cert_has_correct_name_and_curve() {
    let path = fixture("pems/ec_p384.crt.pem");
    let assets = detect_in_file(&path).unwrap();
    let asset = &assets[0];
    assert_eq!(asset.name, "ECDSA-P-384", "EC cert must include named curve");
    assert_eq!(asset.parameter_set.as_deref(), Some("P-384"));
}

// ── CBOM diff command ─────────────────────────────────────────────────────────

#[test]
fn diff_identical_cboms_shows_no_changes() {
    let path = fixture("pems/rsa2048.crt.pem");
    let assets = detect_in_file(&path).unwrap();
    let cbom = acdi::output::emit_cbom(&assets);

    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(&before, &cbom).unwrap();
    std::fs::write(&after, &cbom).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .output()
        .expect("failed to run acdi diff");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("0 added"));
    assert!(stdout.contains("0 removed"));
}

#[test]
fn diff_reports_added_and_removed_assets() {
    let path_a = fixture("pems/rsa2048.crt.pem");
    let path_b = fixture("pems/ec_p256.crt.pem");
    let assets_a = detect_in_file(&path_a).unwrap();
    let assets_b = detect_in_file(&path_b).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(&before, acdi::output::emit_cbom(&assets_a)).unwrap();
    std::fs::write(&after, acdi::output::emit_cbom(&assets_b)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .output()
        .expect("failed to run acdi diff");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    // RSA-2048 removed, ECDSA-P-256 added
    assert!(stdout.contains("1 added"), "expected 1 added, got: {stdout}");
    assert!(stdout.contains("1 removed"), "expected 1 removed, got: {stdout}");
}

// ── Phase 2: CBOM properties ──────────────────────────────────────────────────

#[test]
fn cbom_components_have_acdi_properties() {
    let path = fixture("pems/rsa2048.crt.pem");
    let assets = detect_in_file(&path).unwrap();
    let cbom = acdi::output::emit_cbom(&assets);
    let parsed: serde_json::Value = serde_json::from_str(&cbom).unwrap();

    let comp = &parsed["components"][0];
    let props = comp["properties"].as_array().expect("properties must be an array");

    let names: Vec<&str> = props
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert!(names.contains(&"acdi:quantum_safe"), "must have acdi:quantum_safe");
    assert!(names.contains(&"acdi:hndl_risk"), "must have acdi:hndl_risk");
    assert!(names.contains(&"acdi:nist_level"), "must have acdi:nist_level");

    let qs_val = props
        .iter()
        .find(|p| p["name"] == "acdi:quantum_safe")
        .and_then(|p| p["value"].as_str())
        .unwrap();
    assert_eq!(qs_val, "VULNERABLE", "RSA-2048 must be VULNERABLE in properties");
}

#[test]
fn diff_detects_changed_quantum_safety() {
    // Simulate an RSA-2048 cert "migrating" to RSA-4096 by changing the property value directly.
    // This exercises the changed-asset code path in diff.rs.
    let path = fixture("pems/rsa2048.crt.pem");
    let assets = detect_in_file(&path).unwrap();
    let before_cbom = acdi::output::emit_cbom(&assets);

    // Patch the CBOM to show RSA-2048 as if it were quantum-safe (simulates a future state)
    let patched = before_cbom.replace("\"VULNERABLE\"", "\"SAFE\"");

    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(&before, &before_cbom).unwrap();
    std::fs::write(&after, &patched).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .output()
        .expect("failed to run acdi diff");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("1 changed"), "patched quantum_safe must show as changed: {stdout}");
    assert!(stdout.contains("0 added"), "no new assets: {stdout}");
    assert!(stdout.contains("0 removed"), "no removed assets: {stdout}");
}

// ── Phase 2: detect_in_bytes_pem_der ─────────────────────────────────────────

#[test]
fn detect_in_bytes_pem_der_handles_der_cert() {
    use base64::Engine;

    let path = fixture("pems/rsa2048.crt.pem");
    let pem_data = std::fs::read_to_string(&path).unwrap();

    // Extract raw DER from the PEM
    let b64: String = pem_data
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64.trim()).unwrap();

    let assets = detect_in_bytes_pem_der(&der, "test:443", "certificate")
        .expect("detect from DER bytes should succeed");

    assert!(!assets.is_empty(), "should find an asset in DER bytes");
    assert_eq!(assets[0].name, "RSA-2048");
    assert_eq!(assets[0].locations[0].source, "test:443");
}

#[test]
fn detect_in_bytes_pem_der_handles_pem_bytes() {
    let path = fixture("pems/ec_p256.crt.pem");
    let pem_bytes = std::fs::read(&path).unwrap();

    // PEM path: bytes start with "-----BEGIN"
    let assets = detect_in_bytes_pem_der(&pem_bytes, "endpoint:443", "certificate")
        .expect("detect from PEM bytes should succeed");

    assert!(!assets.is_empty(), "should find an asset in PEM bytes");
    assert_eq!(assets[0].name, "ECDSA-P-256");
    assert_eq!(assets[0].locations[0].source, "endpoint:443");
}

// ── Phase 2: TLS edge cases ───────────────────────────────────────────────────

#[test]
fn tls_unreachable_host_exits_ok_with_warning() {
    // 127.0.0.1:9999 is always closed — must not crash, must exit 0 with warn to stderr.
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["tls", "127.0.0.1:9999"])
        .output()
        .expect("failed to run acdi tls");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "unreachable host must exit 0");
    assert!(
        stderr.contains("warn:"),
        "must emit a warning to stderr, got: {stderr}"
    );
}

#[test]
fn tls_invalid_hostname_does_not_panic() {
    // Hostile hostname with shell metacharacters must be rejected cleanly.
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["tls", "$(evil):443"])
        .output()
        .expect("failed to run acdi tls");

    // Either exits non-zero with an error, or exits 0 with a warn — must not panic.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stderr.contains("panicked") && !stdout.contains("panicked"),
        "must not panic on malformed hostname"
    );
}

#[test]
fn tls_hosts_file_ignores_comments_and_blank_lines() {
    let dir = tempfile::tempdir().unwrap();
    let hosts_file = dir.path().join("hosts.txt");
    // Only the comment and blank line — no real hosts
    std::fs::write(&hosts_file, "# just a comment\n\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["tls", "--hosts", hosts_file.to_str().unwrap()])
        .output()
        .expect("failed to run acdi tls");

    // No targets → should fail with a clear error, not panic
    assert!(!output.status.success(), "empty hosts file must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no targets"),
        "must report no targets, got: {stderr}"
    );
}

// ── Phase 3: Source code scanning ─────────────────────────────────────────────

#[test]
fn source_c_detects_openssl_rsa_and_aes() {
    let path = fixture("source/openssl_c.c");
    let assets = detect_in_file(&path).expect("should scan C source");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"RSA-2048"),
        "must detect RSA-2048 from RSA_generate_key_ex(..., 2048, ...), got: {names:?}"
    );
    assert!(
        names.contains(&"AES-256"),
        "must detect AES-256 from EVP_aes_256_cbc(), got: {names:?}"
    );
    assert!(
        names.contains(&"SHA-1"),
        "must detect SHA-1 from EVP_sha1(), got: {names:?}"
    );
    assert!(
        names.contains(&"ECDSA-P-256"),
        "must detect ECDSA-P-256 from EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), got: {names:?}"
    );
}

#[test]
fn source_c_findings_have_line_numbers() {
    let path = fixture("source/openssl_c.c");
    let assets = detect_in_file(&path).expect("should scan C source");
    assert!(!assets.is_empty(), "should find at least one asset");
    for asset in &assets {
        assert!(
            asset.locations[0].line.is_some(),
            "source findings must include line number, missing for: {}",
            asset.name
        );
    }
}

#[test]
fn source_python_detects_crypto_lib_and_hashlib() {
    let path = fixture("source/python_crypto.py");
    let assets = detect_in_file(&path).expect("should scan Python source");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"RSA-2048"),
        "must detect RSA-2048 from rsa.generate_private_key(key_size=2048), got: {names:?}"
    );
    assert!(
        names.contains(&"ECDSA-P-256"),
        "must detect ECDSA-P-256 from ec.SECP256R1(), got: {names:?}"
    );
    assert!(
        names.contains(&"SHA-1"),
        "must detect SHA-1 from hashes.SHA1(), got: {names:?}"
    );
    assert!(
        names.contains(&"MD5"),
        "must detect MD5 from hashlib.md5(), got: {names:?}"
    );
}

#[test]
fn source_java_detects_jca_apis() {
    let path = fixture("source/java_crypto.java");
    let assets = detect_in_file(&path).expect("should scan Java source");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"RSA"),
        "must detect RSA from KeyPairGenerator.getInstance(\"RSA\"), got: {names:?}"
    );
    assert!(
        names.contains(&"SHA-1"),
        "must detect SHA-1 from MessageDigest.getInstance(\"SHA-1\"), got: {names:?}"
    );
    assert!(
        names.contains(&"AES"),
        "must detect AES from Cipher.getInstance(\"AES/CBC/...\"), got: {names:?}"
    );
}

#[test]
fn source_go_detects_crypto_apis() {
    let path = fixture("source/go_crypto.go");
    let assets = detect_in_file(&path).expect("should scan Go source");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"RSA-2048"),
        "must detect RSA-2048 from rsa.GenerateKey(rand.Reader, 2048), got: {names:?}"
    );
    assert!(
        names.contains(&"ECDSA-P-256"),
        "must detect ECDSA-P-256 from ecdsa.GenerateKey(elliptic.P256()), got: {names:?}"
    );
    assert!(
        names.contains(&"SHA-1"),
        "must detect SHA-1 from sha1.New(), got: {names:?}"
    );
    assert!(
        names.contains(&"MD5"),
        "must detect MD5 from md5.New(), got: {names:?}"
    );
}

#[test]
fn source_scan_uses_correct_evidence_type() {
    use acdi::model::asset::Evidence;
    let path = fixture("source/openssl_c.c");
    let assets = detect_in_file(&path).expect("should scan C source");
    for asset in &assets {
        assert_eq!(
            asset.evidence,
            Evidence::SourceCodePattern,
            "source findings must have SourceCodePattern evidence"
        );
    }
}

#[test]
fn source_vulnerable_algo_marked_correctly() {
    let path = fixture("source/openssl_c.c");
    let assets = detect_in_file(&path).expect("should scan C source");
    let sha1 = assets.iter().find(|a| a.name == "SHA-1").expect("SHA-1 must be found");
    assert_eq!(sha1.quantum_safe, QuantumSafety::Vulnerable, "SHA-1 must be VULNERABLE");
    assert!(sha1.hndl_risk >= Risk::Low, "SHA-1 must have non-None risk");
}

// ── Phase 3: Binary scanning ───────────────────────────────────────────────────

#[test]
fn binary_detects_algo_strings_and_oids() {
    let path = fixture("binaries/crypto_strings.bin");
    let assets = acdi::detect::binary::scan_binary(&path).expect("should scan binary");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"RSA-2048") || names.contains(&"RSA"),
        "must detect RSA-2048 string or RSA OID, got: {names:?}"
    );
    assert!(
        names.contains(&"SHA-1"),
        "must detect SHA-1 string, got: {names:?}"
    );
    assert!(
        names.contains(&"SHA-256") || names.contains(&"AES-256"),
        "must detect SHA-256 OID or AES-256 string, got: {names:?}"
    );
}

#[test]
fn binary_deduplicates_repeated_algo_name() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("dup.bin");
    // "RSA-2048" appears 5 times as null-separated strings
    let content = b"RSA-2048\x00RSA-2048\x00RSA-2048\x00RSA-2048\x00RSA-2048\x00";
    std::fs::write(&bin, content).unwrap();

    let assets = acdi::detect::binary::scan_binary(&bin).expect("should scan");
    let rsa_count = assets.iter().filter(|a| a.name == "RSA-2048").count();
    assert_eq!(rsa_count, 1, "must deduplicate: RSA-2048 should appear exactly once");
}

#[test]
fn binary_large_file_returns_empty_not_error() {
    let dir = tempfile::tempdir().unwrap();
    let large = dir.path().join("huge.bin");

    // Create a sparse 101 MB file (no actual disk allocation on most filesystems)
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&large)
        .unwrap();
    f.set_len(101 * 1024 * 1024).unwrap();

    let assets = acdi::detect::binary::scan_binary(&large).expect("large file must not error");
    assert!(assets.is_empty(), "large file must return empty, not scan");
}

#[test]
fn binary_scan_uses_correct_evidence_type() {
    use acdi::model::asset::Evidence;
    let path = fixture("binaries/crypto_strings.bin");
    let assets = acdi::detect::binary::scan_binary(&path).expect("should scan");
    for asset in &assets {
        assert_eq!(
            asset.evidence,
            Evidence::BinaryStringSearch,
            "binary findings must have BinaryStringSearch evidence"
        );
    }
}

#[test]
fn binary_oid_scan_finds_rsa_oid_in_crafted_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("oid_only.bin");
    // Pure OID byte sequence with no readable strings
    let rsa_oid: &[u8] = &[
        0x00, 0x00, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x00, 0x00,
    ];
    std::fs::write(&bin, rsa_oid).unwrap();

    let assets = acdi::detect::binary::scan_binary(&bin).expect("should scan");
    assert!(
        assets.iter().any(|a| a.name == "RSA"),
        "must find RSA from OID bytes, got: {:?}",
        assets.iter().map(|a| &a.name).collect::<Vec<_>>()
    );
}

#[test]
fn cli_scan_source_dir_finds_vulnerable_algos() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["scan", fixture("source").to_str().unwrap(), "--quiet"])
        .output()
        .expect("failed to run acdi scan");

    assert!(output.status.success());
    let cbom: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    let components = cbom["components"].as_array().unwrap();
    assert!(
        !components.is_empty(),
        "scanning source fixtures must yield at least one component"
    );
    // RSA-2048 must be present from at least one of the source fixtures
    let names: Vec<&str> = components
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(
        names.contains(&"RSA-2048"),
        "must find RSA-2048 in source fixtures, got: {names:?}"
    );
}

// ── CLI: --output flag ────────────────────────────────────────────────────────

#[test]
fn scan_output_flag_writes_valid_cbom_file() {
    let dir = tempfile::tempdir().unwrap();
    let out_file = dir.path().join("cbom.json");

    let status = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--output",
            out_file.to_str().unwrap(),
            "--quiet",
        ])
        .status()
        .expect("failed to run acdi scan");

    assert!(status.success());
    assert!(out_file.exists(), "CBOM output file must be created");

    let content = std::fs::read_to_string(&out_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["specVersion"], "1.7");
    assert!(!parsed["components"].as_array().unwrap().is_empty());
}

// ── CLI: --fail-on exit codes ─────────────────────────────────────────────────

#[test]
fn fail_on_critical_exits_1_when_critical_assets_present() {
    let status = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--fail-on",
            "critical",
            "--quiet",
        ])
        .status()
        .expect("failed to run acdi scan");

    assert_eq!(status.code(), Some(1), "must exit 1 when critical assets present");
}

#[test]
fn fail_on_high_exits_1_when_high_or_worse_present() {
    let status = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--fail-on",
            "high",
            "--quiet",
        ])
        .status()
        .expect("failed to run acdi scan");

    assert_eq!(status.code(), Some(1), "must exit 1 for high+ risk");
}

// ── CLI: edge cases ───────────────────────────────────────────────────────────

#[test]
fn scan_nonexistent_path_exits_1() {
    let status = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["scan", "/nonexistent/path/that/does/not/exist", "--quiet"])
        .status()
        .expect("failed to run acdi");

    assert_ne!(status.code(), Some(0), "must fail on missing path");
}

#[test]
fn scan_single_file_finds_one_asset() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems/rsa2048.crt.pem").to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan");

    assert!(output.status.success());
    let cbom: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    assert_eq!(
        cbom["components"].as_array().unwrap().len(),
        1,
        "scanning a single cert file must yield exactly one component"
    );
}

#[test]
fn scan_empty_directory_exits_ok() {
    let dir = tempfile::tempdir().unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["scan", dir.path().to_str().unwrap(), "--quiet"])
        .status()
        .expect("failed to run acdi scan");

    // Empty dir is not an error — just no findings
    assert!(status.success(), "empty directory scan must exit 0");
}

#[test]
fn scan_malformed_pem_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let bad_pem = dir.path().join("bad.pem");
    std::fs::write(
        &bad_pem,
        b"-----BEGIN CERTIFICATE-----\nthis is not valid base64!!!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["scan", dir.path().to_str().unwrap(), "--quiet"])
        .output()
        .expect("failed to run acdi scan");

    // Must not crash — malformed PEMs are silently skipped
    assert!(output.status.success());
    let cbom: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        cbom["components"].as_array().unwrap().len(),
        0,
        "malformed PEM must yield zero components, not a panic"
    );
}

// ── Phase 4: Config file scanning ────────────────────────────────────────────

#[test]
fn config_yaml_detects_jwt_and_cipher_algorithms() {
    let path = fixture("config/app.yaml");
    let assets = detect_in_file(&path).expect("should scan yaml");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    // RS256 → RSA-2048 from jwt.algorithm
    assert!(
        names.contains(&"RSA-2048"),
        "yaml: must find RSA-2048 from RS256, got: {names:?}"
    );
    // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 → RSA
    assert!(
        names.contains(&"RSA"),
        "yaml: must find RSA from TLS cipher suite, got: {names:?}"
    );
}

#[test]
fn config_yaml_detects_sha1_as_vulnerable() {
    use acdi::model::QuantumSafety;
    let path = fixture("config/app.yaml");
    let assets = detect_in_file(&path).expect("should scan yaml");

    let sha1 = assets.iter().find(|a| a.name == "SHA-1");
    assert!(sha1.is_some(), "must detect SHA-1 from hash_algorithm");
    assert_eq!(
        sha1.unwrap().quantum_safe,
        QuantumSafety::Vulnerable,
        "SHA-1 must be VULNERABLE"
    );
}

#[test]
fn config_toml_detects_rsa_and_aes() {
    let path = fixture("config/app.toml");
    let assets = detect_in_file(&path).expect("should scan toml");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"RSA-2048") || names.contains(&"RSA"),
        "toml: must find RSA from RS256 alg, got: {names:?}"
    );
    assert!(
        names.contains(&"AES-128"),
        "toml: must find AES-128 from encryption_algorithm, got: {names:?}"
    );
}

#[test]
fn config_json_detects_jwt_es256() {
    let path = fixture("config/app.json");
    let assets = detect_in_file(&path).expect("should scan json");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    // ES256 → ECDSA-P-256
    assert!(
        names.contains(&"ECDSA-P-256"),
        "json: must find ECDSA-P-256 from ES256 alg field, got: {names:?}"
    );
}

#[test]
fn config_properties_detects_algorithms() {
    let path = fixture("config/app.properties");
    let assets = detect_in_file(&path).expect("should scan properties");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"RSA-2048") || names.contains(&"RSA"),
        "properties: must find RSA from RS256, got: {names:?}"
    );
    assert!(
        names.contains(&"AES-256"),
        "properties: must find AES-256, got: {names:?}"
    );
}

#[test]
fn config_scan_uses_correct_evidence_type() {
    use acdi::model::asset::Evidence;
    let path = fixture("config/app.yaml");
    let assets = detect_in_file(&path).expect("should scan yaml");
    assert!(!assets.is_empty(), "must find at least one asset");
    for asset in &assets {
        assert_eq!(
            asset.evidence,
            Evidence::ConfigFileRule,
            "config findings must have ConfigFileRule evidence"
        );
    }
}

#[test]
fn config_findings_have_line_numbers() {
    let path = fixture("config/app.yaml");
    let assets = detect_in_file(&path).expect("should scan yaml");
    for asset in &assets {
        assert!(
            asset.locations[0].line.is_some(),
            "config findings must have line numbers"
        );
    }
}

#[test]
fn config_large_file_returns_empty_not_error() {
    let dir = tempfile::tempdir().unwrap();
    let large = dir.path().join("huge.yaml");
    // Write 5 MB of spaces — exceeds MAX_CONFIG_BYTES (4 MB)
    let data: Vec<u8> = vec![b' '; 5 * 1024 * 1024];
    std::fs::write(&large, &data).unwrap();

    let assets =
        acdi::detect::config::scan_config(&large).expect("large config must not error");
    assert!(assets.is_empty(), "large config must return empty, not scan");
}

#[test]
fn cli_scan_config_dir_finds_vulnerable_algos() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["scan", fixture("config").to_str().unwrap(), "--quiet"])
        .output()
        .expect("failed to run acdi scan");

    assert!(output.status.success());
    let cbom: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    let components = cbom["components"].as_array().unwrap();
    assert!(
        !components.is_empty(),
        "scanning config fixtures must yield at least one component"
    );
}

// ── Phase 4: SARIF output ─────────────────────────────────────────────────────

#[test]
fn sarif_output_is_valid_json_with_correct_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format",
            "sarif",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan --format sarif");

    assert!(output.status.success());
    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("sarif stdout must be valid JSON");
    assert_eq!(sarif["version"], "2.1.0", "SARIF version must be 2.1.0");
    assert!(
        sarif["runs"].as_array().map(|r| !r.is_empty()).unwrap_or(false),
        "SARIF must have at least one run"
    );
}

#[test]
fn sarif_results_contain_correct_rule_ids() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format",
            "sarif",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan");

    assert!(output.status.success());
    let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(
        !results.is_empty(),
        "SARIF results must not be empty for pems fixtures"
    );

    // All results must have ruleId starting with "ACDI-"
    for result in results {
        let rule_id = result["ruleId"].as_str().unwrap_or("");
        assert!(
            rule_id.starts_with("ACDI-"),
            "ruleId must start with ACDI-, got: {rule_id}"
        );
    }
}

#[test]
fn sarif_results_have_physical_locations() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format",
            "sarif",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan");

    let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    for result in results {
        let loc = &result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"];
        assert!(loc.is_string(), "each SARIF result must have a URI location");
        assert!(
            !loc.as_str().unwrap().is_empty(),
            "SARIF location URI must not be empty"
        );
    }
}

#[test]
fn sarif_output_file_is_written_by_output_flag() {
    let dir = tempfile::tempdir().unwrap();
    let out_file = dir.path().join("results.sarif");

    let status = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format",
            "sarif",
            "--output",
            out_file.to_str().unwrap(),
            "--quiet",
        ])
        .status()
        .expect("failed to run acdi scan");

    assert!(status.success());
    assert!(out_file.exists(), "SARIF output file must be created");
    let content = std::fs::read_to_string(&out_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
}

// ── Phase 5: Package manifest scanning ───────────────────────────────────────

#[test]
fn manifest_cargo_detects_crypto_crates() {
    let path = fixture("manifests/Cargo.toml");
    let assets = detect_in_file(&path).expect("should scan Cargo.toml");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"openssl"),
        "must detect openssl crate, got: {names:?}"
    );
    assert!(
        names.contains(&"rsa"),
        "must detect rsa crate, got: {names:?}"
    );
    assert!(
        names.contains(&"ring"),
        "must detect ring crate, got: {names:?}"
    );
    assert!(
        names.contains(&"md5"),
        "must detect md5 crate, got: {names:?}"
    );
}

#[test]
fn manifest_cargo_dev_dependencies_are_scanned() {
    let path = fixture("manifests/Cargo.toml");
    let assets = detect_in_file(&path).expect("should scan Cargo.toml");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"sha1"),
        "dev-dependencies must be scanned, got: {names:?}"
    );
}

#[test]
fn manifest_cargo_library_assets_have_correct_type() {
    use acdi::model::asset::{AssetType, Evidence};
    let path = fixture("manifests/Cargo.toml");
    let assets = detect_in_file(&path).expect("should scan Cargo.toml");
    assert!(!assets.is_empty());
    for asset in &assets {
        assert_eq!(
            asset.asset_type,
            AssetType::Library,
            "manifest findings must be Library type"
        );
        assert_eq!(
            asset.evidence,
            Evidence::ManifestDependency,
            "manifest findings must have ManifestDependency evidence"
        );
    }
}

#[test]
fn manifest_cargo_vulnerable_crate_marked_correctly() {
    use acdi::model::QuantumSafety;
    let path = fixture("manifests/Cargo.toml");
    let assets = detect_in_file(&path).expect("should scan Cargo.toml");

    let rsa_crate = assets.iter().find(|a| a.name == "rsa");
    assert!(rsa_crate.is_some(), "must find rsa crate");
    assert_eq!(
        rsa_crate.unwrap().quantum_safe,
        QuantumSafety::Vulnerable,
        "rsa crate must be marked VULNERABLE"
    );
}

#[test]
fn manifest_cargo_findings_have_line_numbers() {
    let path = fixture("manifests/Cargo.toml");
    let assets = detect_in_file(&path).expect("should scan Cargo.toml");
    for asset in &assets {
        assert!(
            asset.locations[0].line.is_some(),
            "manifest findings must have line numbers"
        );
    }
}

#[test]
fn manifest_cargo_parameter_set_contains_algorithm() {
    let path = fixture("manifests/Cargo.toml");
    let assets = detect_in_file(&path).expect("should scan Cargo.toml");

    let openssl = assets.iter().find(|a| a.name == "openssl").unwrap();
    assert!(
        openssl.parameter_set.is_some(),
        "library asset must have parameter_set with primary algorithm"
    );
    assert_eq!(
        openssl.parameter_set.as_deref(),
        Some("RSA"),
        "openssl primary algorithm must be RSA"
    );
}

#[test]
fn manifest_npm_detects_crypto_packages() {
    let path = fixture("manifests/package.json");
    let assets = detect_in_file(&path).expect("should scan package.json");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"node-forge"),
        "must detect node-forge, got: {names:?}"
    );
    assert!(
        names.contains(&"jsonwebtoken"),
        "must detect jsonwebtoken, got: {names:?}"
    );
    assert!(
        names.contains(&"elliptic"),
        "must detect elliptic, got: {names:?}"
    );
}

#[test]
fn manifest_python_detects_crypto_packages() {
    let path = fixture("manifests/requirements.txt");
    let assets = detect_in_file(&path).expect("should scan requirements.txt");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"cryptography"),
        "must detect cryptography package, got: {names:?}"
    );
    assert!(
        names.contains(&"paramiko"),
        "must detect paramiko package, got: {names:?}"
    );
    assert!(
        names.contains(&"pycryptodome"),
        "must detect pycryptodome (tilde-eq specifier), got: {names:?}"
    );
    // requests is NOT a crypto library — must not be in results
    assert!(
        !names.contains(&"requests"),
        "non-crypto packages must not appear, got: {names:?}"
    );
}

#[test]
fn manifest_go_detects_crypto_modules() {
    let path = fixture("manifests/go.mod");
    let assets = detect_in_file(&path).expect("should scan go.mod");
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"golang.org/x/crypto"),
        "must detect x/crypto module, got: {names:?}"
    );
    assert!(
        names.contains(&"github.com/golang-jwt/jwt"),
        "must detect jwt module, got: {names:?}"
    );
}

#[test]
fn manifest_go_detects_pqc_library_as_safe() {
    use acdi::model::QuantumSafety;
    let path = fixture("manifests/go.mod");
    let assets = detect_in_file(&path).expect("should scan go.mod");

    let circl = assets
        .iter()
        .find(|a| a.name == "github.com/cloudflare/circl");
    assert!(circl.is_some(), "must detect cloudflare/circl (PQC library)");
    assert_eq!(
        circl.unwrap().quantum_safe,
        QuantumSafety::Safe,
        "cloudflare/circl maps to ML-KEM-768 which must be SAFE"
    );
}

#[test]
fn manifest_cargo_toml_not_scanned_as_config() {
    // Cargo.toml must go to manifest scanner, NOT config scanner.
    // Config scanner would see 'edition = "2021"' etc. and produce false positives.
    use acdi::model::asset::Evidence;
    let path = fixture("manifests/Cargo.toml");
    let assets = detect_in_file(&path).expect("should scan Cargo.toml");

    for asset in &assets {
        assert_eq!(
            asset.evidence,
            Evidence::ManifestDependency,
            "Cargo.toml must produce ManifestDependency evidence, not ConfigFileRule"
        );
    }
}

#[test]
fn cli_scan_manifest_dir_finds_library_assets() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["scan", fixture("manifests").to_str().unwrap(), "--quiet"])
        .output()
        .expect("failed to run acdi scan");

    assert!(output.status.success());
    let cbom: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout must be valid JSON");
    let components = cbom["components"].as_array().unwrap();

    assert!(
        !components.is_empty(),
        "scanning manifests must yield library components"
    );
    // At least one library component
    let has_library = components
        .iter()
        .any(|c| c["type"].as_str() == Some("library"));
    assert!(has_library, "CBOM must contain library-type components");
}

// ── Phase 6: .acdignore suppression ─────────────────────────────────────────

#[test]
fn ignore_list_parses_algorithm_rule() {
    let rules = acdi::ignore::IgnoreList::parse("algorithm:RSA-2048\n");
    assert_eq!(rules.len(), 1);
}

#[test]
fn ignore_list_parses_path_rule() {
    let rules = acdi::ignore::IgnoreList::parse("path:tests/**\n");
    assert_eq!(rules.len(), 1);
}

#[test]
fn ignore_list_skips_comments_and_blank_lines() {
    let text = "# this is a comment\n\nalgorithm:SHA-1\n# another\n";
    let list = acdi::ignore::IgnoreList::parse(text);
    assert_eq!(list.len(), 1, "only one real rule");
}

#[test]
fn ignore_list_suppresses_algorithm_match() {
    use acdi::model::asset::{AssetType, Evidence, Location};
    use acdi::model::{CryptoAsset, Primitive, QuantumSafety, Risk};

    let asset = CryptoAsset {
        asset_type: AssetType::Algorithm,
        name: "RSA-2048".to_string(),
        oid: None,
        primitive: Primitive::PublicKeyEncryption,
        parameter_set: None,
        nist_quantum_security: 0,
        quantum_safe: QuantumSafety::Vulnerable,
        hndl_risk: Risk::Critical,
        locations: vec![Location { source: "test.pem".to_string(), line: None, column: None }],
        evidence: Evidence::CertificateParsing,
    };

    let list = acdi::ignore::IgnoreList::parse("algorithm:RSA-2048\n");
    assert!(list.suppresses(&asset), "RSA-2048 must be suppressed");

    // Case-insensitive
    let list2 = acdi::ignore::IgnoreList::parse("algorithm:rsa-2048\n");
    assert!(list2.suppresses(&asset), "algorithm match must be case-insensitive");

    // Different algorithm — must NOT be suppressed
    let list3 = acdi::ignore::IgnoreList::parse("algorithm:ECDSA-P-256\n");
    assert!(!list3.suppresses(&asset), "non-matching algorithm must not be suppressed");
}

#[test]
fn ignore_list_suppresses_path_glob() {
    use acdi::model::asset::{AssetType, Evidence, Location};
    use acdi::model::{CryptoAsset, Primitive, QuantumSafety, Risk};

    let make = |source: &str| CryptoAsset {
        asset_type: AssetType::Algorithm,
        name: "RSA-2048".to_string(),
        oid: None,
        primitive: Primitive::PublicKeyEncryption,
        parameter_set: None,
        nist_quantum_security: 0,
        quantum_safe: QuantumSafety::Vulnerable,
        hndl_risk: Risk::Critical,
        locations: vec![Location { source: source.to_string(), line: None, column: None }],
        evidence: Evidence::CertificateParsing,
    };

    let list = acdi::ignore::IgnoreList::parse("path:tests/**\n");
    assert!(list.suppresses(&make("tests/pems/rsa2048.crt.pem")), "** glob must match subdirectories");
    assert!(!list.suppresses(&make("/other/path/cert.pem")), "non-matching path must not be suppressed");
}

#[test]
fn ignore_list_suppresses_evidence_type() {
    use acdi::model::asset::{AssetType, Evidence, Location};
    use acdi::model::{CryptoAsset, Primitive, QuantumSafety, Risk};

    let binary_asset = CryptoAsset {
        asset_type: AssetType::Algorithm,
        name: "RSA".to_string(),
        oid: None,
        primitive: Primitive::PublicKeyEncryption,
        parameter_set: None,
        nist_quantum_security: 0,
        quantum_safe: QuantumSafety::Vulnerable,
        hndl_risk: Risk::Critical,
        locations: vec![Location { source: "lib.so".to_string(), line: None, column: None }],
        evidence: Evidence::BinaryStringSearch,
    };

    let list = acdi::ignore::IgnoreList::parse("evidence:binary-string-search\n");
    assert!(list.suppresses(&binary_asset), "binary evidence must be suppressed");

    let list2 = acdi::ignore::IgnoreList::parse("evidence:certificate-parsing\n");
    assert!(!list2.suppresses(&binary_asset), "other evidence must not be suppressed");
}

#[test]
fn cli_acdignore_suppresses_rsa4096_from_pems() {
    // tests/fixtures/pems/.acdignore contains `algorithm:RSA-4096`
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["scan", fixture("pems").to_str().unwrap(), "--quiet"])
        .output()
        .expect("failed to run acdi scan");

    assert!(output.status.success());
    let cbom: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let names: Vec<&str> = cbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();

    assert!(
        !names.contains(&"RSA-4096"),
        ".acdignore must suppress RSA-4096, got: {names:?}"
    );
    assert!(
        names.contains(&"RSA-2048"),
        "RSA-2048 must still appear (not ignored), got: {names:?}"
    );
}

#[test]
fn cli_no_ignore_flag_bypasses_acdignore() {
    // With --no-ignore, RSA-4096 must reappear even though .acdignore suppresses it
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args(["scan", fixture("pems").to_str().unwrap(), "--quiet", "--no-ignore"])
        .output()
        .expect("failed to run acdi scan");

    assert!(output.status.success());
    let cbom: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let names: Vec<&str> = cbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();

    assert!(
        names.contains(&"RSA-4096"),
        "--no-ignore must restore RSA-4096, got: {names:?}"
    );
}

// ── Phase 6: HTML report ─────────────────────────────────────────────────────

#[test]
fn html_output_is_valid_html_with_doctype() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format", "html",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan --format html");

    assert!(output.status.success());
    let html = String::from_utf8_lossy(&output.stdout);
    assert!(html.starts_with("<!DOCTYPE html>"), "HTML must start with DOCTYPE");
    assert!(html.contains("<html"), "must contain <html> tag");
    assert!(html.contains("</html>"), "must be closed HTML");
}

#[test]
fn html_output_contains_summary_and_findings() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format", "html",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan");

    let html = String::from_utf8_lossy(&output.stdout);
    assert!(html.contains("Executive Summary"), "must have Executive Summary section");
    assert!(html.contains("NIST IR 8547"), "must reference NIST IR 8547 timeline");
    assert!(html.contains("Remediation Guide"), "must have Remediation Guide section");
    assert!(html.contains("RSA-2048"), "must mention RSA-2048 in findings");
}

#[test]
fn html_output_file_written_by_output_flag() {
    let dir = tempfile::tempdir().unwrap();
    let out_file = dir.path().join("report.html");

    let status = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format", "html",
            "--output", out_file.to_str().unwrap(),
            "--quiet",
        ])
        .status()
        .expect("failed to run acdi scan");

    assert!(status.success());
    assert!(out_file.exists(), "HTML report file must be created");
    let content = std::fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("<!DOCTYPE html>"), "output file must be valid HTML");
    assert!(content.len() > 1024, "HTML report must be non-trivial in size");
}

#[test]
fn html_report_includes_remediation_for_vulnerable_algos() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("source").to_str().unwrap(),
            "--format", "html",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan");

    let html = String::from_utf8_lossy(&output.stdout);
    // RSA-2048 findings should produce remediation advice mentioning ML-KEM
    assert!(
        html.contains("ML-KEM") || html.contains("ML-DSA"),
        "HTML report must include post-quantum migration advice"
    );
}

#[test]
fn html_report_scan_stats_section_present() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("source").to_str().unwrap(),
            "--format", "html",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan");

    let html = String::from_utf8_lossy(&output.stdout);
    assert!(html.contains("Scan Statistics"), "must have Scan Statistics section");
    assert!(html.contains("Source code"), "stats must include source code row");
}

// ── Maven pom.xml ─────────────────────────────────────────────────────────────

#[test]
fn manifest_maven_pom_detects_bouncy_castle() {
    let assets = detect_in_file(&fixture("manifests/pom.xml")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"bcprov-jdk18on"),
        "should detect BouncyCastle provider; got {names:?}"
    );
}

#[test]
fn manifest_maven_pom_detects_jwt_library() {
    let assets = detect_in_file(&fixture("manifests/pom.xml")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"java-jwt"),
        "should detect Auth0 java-jwt; got {names:?}"
    );
}

#[test]
fn manifest_maven_pom_detects_nimbus() {
    let assets = detect_in_file(&fixture("manifests/pom.xml")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"nimbus-jose-jwt"),
        "should detect Nimbus JOSE+JWT; got {names:?}"
    );
}

#[test]
fn manifest_maven_pom_ignores_non_crypto_deps() {
    let assets = detect_in_file(&fixture("manifests/pom.xml")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        !names.contains(&"junit-jupiter"),
        "should NOT detect junit-jupiter"
    );
}

#[test]
fn manifest_maven_pom_assets_have_library_type() {
    let assets = detect_in_file(&fixture("manifests/pom.xml")).unwrap();
    for a in &assets {
        assert_eq!(
            a.asset_type,
            acdi::model::asset::AssetType::Library,
            "pom.xml findings must be AssetType::Library"
        );
    }
}

// ── Gradle build.gradle ───────────────────────────────────────────────────────

#[test]
fn manifest_gradle_detects_bouncy_castle() {
    let assets = detect_in_file(&fixture("manifests/build.gradle")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"bcprov-jdk18on"),
        "should detect BouncyCastle in build.gradle; got {names:?}"
    );
}

#[test]
fn manifest_gradle_detects_jjwt() {
    let assets = detect_in_file(&fixture("manifests/build.gradle")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.starts_with("jjwt")),
        "should detect jjwt in build.gradle; got {names:?}"
    );
}

#[test]
fn manifest_gradle_ignores_non_crypto_deps() {
    let assets = detect_in_file(&fixture("manifests/build.gradle")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(!names.contains(&"guava"), "should not detect guava");
    assert!(!names.contains(&"junit-jupiter"), "should not detect junit-jupiter");
}

// ── Ruby source ───────────────────────────────────────────────────────────────

#[test]
fn source_ruby_detects_openssl_rsa() {
    let assets = detect_in_file(&fixture("source/ruby_crypto.rb")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.starts_with("RSA")),
        "should detect RSA from OpenSSL::PKey::RSA; got {names:?}"
    );
}

#[test]
fn source_ruby_detects_sha1_digest() {
    let assets = detect_in_file(&fixture("source/ruby_crypto.rb")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"SHA-1"),
        "should detect SHA-1 from OpenSSL::Digest::SHA1; got {names:?}"
    );
}

#[test]
fn source_ruby_detects_jwt_rsa() {
    let assets = detect_in_file(&fixture("source/ruby_crypto.rb")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"RSA-2048"),
        "should detect RSA-2048 from JWT.encode with RS256; got {names:?}"
    );
}

#[test]
fn source_ruby_uses_source_code_evidence() {
    let assets = detect_in_file(&fixture("source/ruby_crypto.rb")).unwrap();
    for a in &assets {
        assert_eq!(
            a.evidence,
            acdi::model::asset::Evidence::SourceCodePattern,
            "Ruby findings must use SourceCodePattern evidence"
        );
    }
}

// ── PHP source ────────────────────────────────────────────────────────────────

#[test]
fn source_php_detects_openssl_rsa() {
    let assets = detect_in_file(&fixture("source/php_crypto.php")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.starts_with("RSA")),
        "should detect RSA from openssl_pkey_new; got {names:?}"
    );
}

#[test]
fn source_php_detects_aes_encryption() {
    let assets = detect_in_file(&fixture("source/php_crypto.php")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.starts_with("AES")),
        "should detect AES from openssl_encrypt; got {names:?}"
    );
}

#[test]
fn source_php_detects_md5() {
    let assets = detect_in_file(&fixture("source/php_crypto.php")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"MD5"),
        "should detect MD5 from md5() call; got {names:?}"
    );
}

#[test]
fn source_php_detects_sha1_hash() {
    let assets = detect_in_file(&fixture("source/php_crypto.php")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"SHA-1"),
        "should detect SHA-1 from hash('sha1',...); got {names:?}"
    );
}

// ── Swift source ──────────────────────────────────────────────────────────────

#[test]
fn source_swift_detects_p256_key() {
    let assets = detect_in_file(&fixture("source/swift_crypto.swift")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"ECDSA-P-256"),
        "should detect ECDSA-P-256 from P256.Signing.PrivateKey; got {names:?}"
    );
}

#[test]
fn source_swift_detects_sha256() {
    let assets = detect_in_file(&fixture("source/swift_crypto.swift")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"SHA-256"),
        "should detect SHA-256 from SHA256.hash; got {names:?}"
    );
}

#[test]
fn source_swift_detects_insecure_sha1() {
    let assets = detect_in_file(&fixture("source/swift_crypto.swift")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"SHA-1"),
        "should detect SHA-1 from Insecure.SHA1.hash; got {names:?}"
    );
}

#[test]
fn source_swift_detects_rsa_security_framework() {
    let assets = detect_in_file(&fixture("source/swift_crypto.swift")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.starts_with("RSA")),
        "should detect RSA from kSecAttrKeyTypeRSA; got {names:?}"
    );
}

// ── CSV output ────────────────────────────────────────────────────────────────

#[test]
fn csv_output_has_header_row() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format", "csv",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan");

    assert!(output.status.success());
    let csv = String::from_utf8_lossy(&output.stdout);
    let first_line = csv.lines().next().unwrap_or("");
    assert_eq!(
        first_line,
        "Algorithm,AssetType,QuantumSafety,HNDLRisk,NISTLevel,File,Line,Evidence",
        "CSV must start with the correct header"
    );
}

#[test]
fn csv_output_contains_findings() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format", "csv",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan");

    let csv = String::from_utf8_lossy(&output.stdout);
    assert!(csv.contains("RSA-2048"), "CSV must contain RSA-2048");
    assert!(csv.contains("CRITICAL"), "CSV must contain CRITICAL risk");
    assert!(csv.contains("certificate-parsing"), "CSV must contain evidence type");
}

#[test]
fn csv_output_file_written_by_output_flag() {
    let dir = tempfile::tempdir().unwrap();
    let out_file = dir.path().join("findings.csv");

    let status = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("source").to_str().unwrap(),
            "--format", "csv",
            "--output", out_file.to_str().unwrap(),
            "--quiet",
        ])
        .status()
        .expect("failed to run acdi scan");

    assert!(status.success());
    assert!(out_file.exists(), "CSV file must be created");
    let content = std::fs::read_to_string(&out_file).unwrap();
    assert!(content.starts_with("Algorithm,"), "file must start with CSV header");
    assert!(content.lines().count() > 1, "CSV must have data rows");
}

#[test]
fn csv_output_correct_column_count() {
    let output = Command::new(env!("CARGO_BIN_EXE_acdi"))
        .args([
            "scan",
            fixture("pems").to_str().unwrap(),
            "--format", "csv",
            "--quiet",
        ])
        .output()
        .expect("failed to run acdi scan");

    let csv = String::from_utf8_lossy(&output.stdout);
    for line in csv.lines() {
        assert_eq!(
            line.split(',').count(), 8,
            "every CSV row must have 8 columns; got: {line}"
        );
    }
}

// ── Kotlin — Android Keystore ─────────────────────────────────────────────────

#[test]
fn source_kotlin_detects_android_keystore_rsa() {
    let assets = detect_in_file(&fixture("source/kotlin_crypto.kt")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.starts_with("RSA")),
        "should detect RSA from KeyProperties.KEY_ALGORITHM_RSA; got {names:?}"
    );
}

#[test]
fn source_kotlin_detects_android_keystore_ec() {
    let assets = detect_in_file(&fixture("source/kotlin_crypto.kt")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.starts_with("ECDSA")),
        "should detect ECDSA from KeyProperties.KEY_ALGORITHM_EC; got {names:?}"
    );
}

#[test]
fn source_kotlin_detects_keyproperties_digest_sha1() {
    let assets = detect_in_file(&fixture("source/kotlin_crypto.kt")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"SHA-1"),
        "should detect SHA-1 from KeyProperties.DIGEST_SHA1; got {names:?}"
    );
}

#[test]
fn source_kotlin_detects_hmac_sha256() {
    let assets = detect_in_file(&fixture("source/kotlin_crypto.kt")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"SHA-256"),
        "should detect SHA-256 from HmacSHA256 SecretKeySpec; got {names:?}"
    );
}

#[test]
fn source_kotlin_uses_source_code_evidence() {
    use acdi::model::asset::Evidence;
    let assets = detect_in_file(&fixture("source/kotlin_crypto.kt")).unwrap();
    assert!(
        assets.iter().all(|a| a.evidence == Evidence::SourceCodePattern),
        "all Kotlin findings should use SourceCodePattern evidence"
    );
}

// ── C# — System.Security.Cryptography ────────────────────────────────────────

#[test]
fn source_csharp_detects_rsa_create() {
    let assets = detect_in_file(&fixture("source/csharp_crypto.cs")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"RSA-2048"),
        "should detect RSA-2048 from RSA.Create(2048); got {names:?}"
    );
}

#[test]
fn source_csharp_detects_rsacng_key_size() {
    let assets = detect_in_file(&fixture("source/csharp_crypto.cs")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"RSA-4096"),
        "should detect RSA-4096 from new RSACng(4096); got {names:?}"
    );
}

#[test]
fn source_csharp_detects_ecdsa_nist_curve() {
    let assets = detect_in_file(&fixture("source/csharp_crypto.cs")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"ECDSA-P-256"),
        "should detect ECDSA-P-256 from ECCurve.NamedCurves.nistP256; got {names:?}"
    );
}

#[test]
fn source_csharp_detects_ecdsa_p384() {
    let assets = detect_in_file(&fixture("source/csharp_crypto.cs")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"ECDSA-P-384"),
        "should detect ECDSA-P-384 from ECDsa.Create(nistP384); got {names:?}"
    );
}

#[test]
fn source_csharp_detects_aes_create() {
    let assets = detect_in_file(&fixture("source/csharp_crypto.cs")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"AES"),
        "should detect AES from Aes.Create(); got {names:?}"
    );
}

#[test]
fn source_csharp_detects_tripledes() {
    let assets = detect_in_file(&fixture("source/csharp_crypto.cs")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"3DES"),
        "should detect 3DES from TripleDES.Create(); got {names:?}"
    );
}

#[test]
fn source_csharp_detects_md5_create() {
    let assets = detect_in_file(&fixture("source/csharp_crypto.cs")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"MD5"),
        "should detect MD5 from MD5.Create(); got {names:?}"
    );
}

#[test]
fn source_csharp_detects_sha_create() {
    let assets = detect_in_file(&fixture("source/csharp_crypto.cs")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"SHA-1") && names.contains(&"SHA-256"),
        "should detect SHA-1 and SHA-256 from SHA1/SHA256.Create(); got {names:?}"
    );
}

#[test]
fn source_csharp_detects_hmacsha256() {
    let assets = detect_in_file(&fixture("source/csharp_crypto.cs")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"SHA-256"),
        "should detect SHA-256 from new HMACSHA256(); got {names:?}"
    );
}

// ── Terraform HCL ─────────────────────────────────────────────────────────────

#[test]
fn config_terraform_detects_rsa_algorithm() {
    let assets = detect_in_file(&fixture("config/terraform.tf")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.starts_with("RSA")),
        "should detect RSA from algorithm = \"RSA\"; got {names:?}"
    );
}

#[test]
fn config_terraform_detects_rsa_bits() {
    let assets = detect_in_file(&fixture("config/terraform.tf")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"RSA-2048"),
        "should detect RSA-2048 from rsa_bits = 2048; got {names:?}"
    );
}

#[test]
fn config_terraform_detects_ecdsa_curve() {
    let assets = detect_in_file(&fixture("config/terraform.tf")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"ECDSA-P-256"),
        "should detect ECDSA-P-256 from ecdsa_curve = \"P256\"; got {names:?}"
    );
}

#[test]
fn config_terraform_detects_aws_kms_rsa() {
    let assets = detect_in_file(&fixture("config/terraform.tf")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"RSA-2048"),
        "should detect RSA-2048 from customer_master_key_spec = \"RSA_2048\"; got {names:?}"
    );
}

#[test]
fn config_terraform_detects_aws_kms_ecc() {
    let assets = detect_in_file(&fixture("config/terraform.tf")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"ECDSA-P-256"),
        "should detect ECDSA-P-256 from customer_master_key_spec = \"ECC_NIST_P256\"; got {names:?}"
    );
}

#[test]
fn config_terraform_detects_symmetric_default_aes() {
    let assets = detect_in_file(&fixture("config/terraform.tf")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"AES-256"),
        "should detect AES-256 from SYMMETRIC_DEFAULT; got {names:?}"
    );
}

// ── Kubernetes cert-manager ───────────────────────────────────────────────────

#[test]
fn config_k8s_certmanager_detects_rsa_algorithm() {
    let assets = detect_in_file(&fixture("config/k8s_certmanager.yaml")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.starts_with("RSA")),
        "should detect RSA from algorithm: RSA; got {names:?}"
    );
}

#[test]
fn config_k8s_certmanager_detects_ecdsa_curve_p256() {
    let assets = detect_in_file(&fixture("config/k8s_certmanager.yaml")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"ECDSA-P-256"),
        "should detect ECDSA-P-256 from curve: P256; got {names:?}"
    );
}

#[test]
fn config_k8s_certmanager_detects_ecdsa_curve_p384() {
    let assets = detect_in_file(&fixture("config/k8s_certmanager.yaml")).unwrap();
    let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
    assert!(
        names.contains(&"ECDSA-P-384"),
        "should detect ECDSA-P-384 from curve: P384; got {names:?}"
    );
}
