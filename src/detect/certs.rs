#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{Context, Result};
use x509_parser::prelude::*;

use crate::catalog::oids::oid_to_algorithm;
use crate::model::{
    asset::{AssetType, Evidence, Location, Primitive},
    classify::QuantumSafety,
    risk::Risk,
    CryptoAsset,
};

// PEM block type labels we recognise
const PEM_CERT_TAGS: &[&str] = &["CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"];
const PEM_KEY_TAGS: &[&str] = &[
    "PRIVATE KEY",         // PKCS#8 unencrypted
    "ENCRYPTED PRIVATE KEY", // PKCS#8 encrypted
    "RSA PRIVATE KEY",     // PKCS#1
    "EC PRIVATE KEY",      // SEC1
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
];
const PEM_PUBKEY_TAGS: &[&str] = &["PUBLIC KEY", "RSA PUBLIC KEY"];

/// Detect crypto assets in raw bytes (DER certificate or PEM blob).
///
/// `source` is used as the location label (e.g., a TLS endpoint string).
/// `hint` accepts "certificate", "key", or "" to auto-detect from content.
pub fn detect_in_bytes_pem_der(
    bytes: &[u8],
    source: &str,
    hint: &str,
) -> Result<Vec<CryptoAsset>> {
    let location = Location {
        source: source.to_string(),
        line: None,
        column: None,
    };

    // Try PEM first (starts with "-----BEGIN")
    if bytes.starts_with(b"-----BEGIN") {
        let mut assets = Vec::new();
        for pem in Pem::iter_from_buffer(bytes) {
            let pem = match pem {
                Ok(p) => p,
                Err(_) => continue,
            };
            let tag = pem.label.to_uppercase();
            if PEM_CERT_TAGS.iter().any(|t| tag.contains(t)) {
                let dummy_path = std::path::Path::new(source);
                if let Some(asset) = parse_x509_der(&pem.contents, location.clone(), dummy_path) {
                    assets.push(asset);
                }
            }
        }
        return Ok(assets);
    }

    // Otherwise assume DER
    if hint == "certificate" || hint.is_empty() {
        let dummy_path = std::path::Path::new(source);
        let assets = parse_x509_der(bytes, location, dummy_path)
            .map(|a| vec![a])
            .unwrap_or_default();
        return Ok(assets);
    }

    Ok(vec![])
}

/// Detect all crypto assets in a single file.
/// Returns an empty vec (not an error) if the file type is not recognised.
pub fn detect_in_file(path: &Path) -> Result<Vec<CryptoAsset>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "pem" | "crt" | "cer" | "key" | "pub" | "p7b" | "p7c" => parse_pem_file(path),
        "der" => parse_der_file(path),
        _ => {
            // Try PEM magic-byte sniff for extension-less files
            if looks_like_pem_pub(path)? {
                parse_pem_file(path)
            } else {
                Ok(vec![])
            }
        }
    }
}

// ── PEM parsing ───────────────────────────────────────────────────────────────

fn parse_pem_file(path: &Path) -> Result<Vec<CryptoAsset>> {
    let data = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let mut assets = Vec::new();

    for pem in Pem::iter_from_buffer(&data) {
        let pem = match pem {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("PEM parse error in {}: {}", path.display(), e);
                continue;
            }
        };

        let tag = pem.label.to_uppercase();
        let location = location_from_path(path);

        if PEM_CERT_TAGS.iter().any(|t| tag.contains(t)) {
            if let Some(asset) = parse_x509_der(&pem.contents, location, path) {
                assets.push(asset);
            }
        } else if PEM_KEY_TAGS.iter().any(|t| tag.contains(t)) {
            assets.push(private_key_asset_from_der(&tag, &pem.contents, location, path));
        } else if PEM_PUBKEY_TAGS.iter().any(|t| tag.contains(t)) {
            assets.push(public_key_asset_from_tag(&tag, location, path));
        }
    }

    Ok(assets)
}

fn parse_der_file(path: &Path) -> Result<Vec<CryptoAsset>> {
    let data = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let location = location_from_path(path);
    let assets = parse_x509_der(&data, location, path)
        .map(|a| vec![a])
        .unwrap_or_default();
    Ok(assets)
}

// ── X.509 DER parsing ─────────────────────────────────────────────────────────

fn parse_x509_der(der: &[u8], location: Location, path: &Path) -> Option<CryptoAsset> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| {
            tracing::debug!("X.509 DER parse error in {}: {}", path.display(), e);
            e
        })
        .ok()?;

    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    let spki_oid = cert.public_key().algorithm.algorithm.to_id_string();

    // Determine the base algorithm name from the public key OID
    let base_algo = oid_to_algorithm(&spki_oid)
        .or_else(|| oid_to_algorithm(&sig_oid))
        .unwrap_or("Unknown");

    // Extract parameter set BEFORE classification so the catalog lookup is precise.
    // For RSA this is key size ("2048"), for EC it's the named curve ("P-256").
    let parameter_set = extract_key_parameter(&cert);

    // Build the full canonical name used for catalog lookup, e.g. "RSA-2048", "ECDSA-P-256"
    let full_name = format_cert_name(base_algo, parameter_set.as_deref());

    let (quantum_safe, hndl_risk, nist_level, primitive) = classify_by_name(&full_name);

    Some(CryptoAsset {
        asset_type: AssetType::Certificate,
        name: full_name,
        oid: Some(spki_oid),
        primitive,
        parameter_set,
        nist_quantum_security: nist_level,
        quantum_safe,
        hndl_risk,
        locations: vec![location],
        evidence: Evidence::CertificateParsing,
    })
}

/// Extract the key size or named curve from a parsed certificate's SubjectPublicKeyInfo.
fn extract_key_parameter(cert: &X509Certificate<'_>) -> Option<String> {
    let spki = cert.public_key();
    let oid = spki.algorithm.algorithm.to_id_string();

    match oid.as_str() {
        // RSA — derive key size from the modulus byte length in the BITSTRING payload.
        // The BITSTRING starts with a 0x00 padding byte, then the DER SEQUENCE for RSAPublicKey.
        "1.2.840.113549.1.1.1" => {
            // x509-parser stores the BITSTRING value bytes (unused_bits field is separate),
            // so data starts directly with the RSAPublicKey SEQUENCE tag (0x30).
            let modulus_bits = rsa_modulus_bits(&spki.subject_public_key.data)?;
            let rounded = round_rsa_bits(modulus_bits);
            Some(rounded.to_string())
        }
        // EC public key (id-ecPublicKey) — named curve is in the AlgorithmIdentifier parameters,
        // NOT in the algorithm OID itself.
        "1.2.840.10045.2.1" => ec_named_curve_from_params(spki),
        // Edwards / Diffie-Hellman keys carry their parameter set in the OID directly
        "1.3.101.112" => Some("Ed25519".to_string()),
        "1.3.101.113" => Some("Ed448".to_string()),
        "1.3.101.110" => Some("X25519".to_string()),
        "1.3.101.111" => Some("X448".to_string()),
        _ => None,
    }
}

/// Parse the named curve from an EC SubjectPublicKeyInfo's AlgorithmIdentifier parameters.
///
/// EC SPKI structure:
///   AlgorithmIdentifier { algorithm: id-ecPublicKey, parameters: namedCurve OID }
///
/// The `parameters` Any holds just the VALUE bytes of the DER OID (no tag/length header).
/// We match on the known OID encodings directly.
fn ec_named_curve_from_params(spki: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> Option<String> {
    let params = spki.algorithm.parameters.as_ref()?;

    // OID tag is 0x06; skip if parameters is some other type (e.g. NULL for implicit curve)
    if params.header.tag().0 != 6 {
        return None;
    }

    // Match on the OID VALUE bytes (the content after tag and length)
    match params.data as &[u8] {
        // P-256 / prime256v1: OID 1.2.840.10045.3.1.7
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Some("P-256".to_string()),
        // P-384 / secp384r1: OID 1.3.132.0.34
        [0x2b, 0x81, 0x04, 0x00, 0x22] => Some("P-384".to_string()),
        // P-521 / secp521r1: OID 1.3.132.0.35
        [0x2b, 0x81, 0x04, 0x00, 0x23] => Some("P-521".to_string()),
        // secp256k1: OID 1.3.132.0.10
        [0x2b, 0x81, 0x04, 0x00, 0x0a] => Some("secp256k1".to_string()),
        _ => None,
    }
}

/// Parse the RSA modulus bit-length from SubjectPublicKeyInfo.subject_public_key.data.
///
/// x509-parser separates the unused_bits byte from the BITSTRING content, so data starts
/// directly with the DER-encoded RSAPublicKey SEQUENCE (0x30 tag):
///   RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
fn rsa_modulus_bits(key_data: &[u8]) -> Option<usize> {
    // Must start with SEQUENCE tag
    if key_data.first() != Some(&0x30) {
        return None;
    }

    // Parse SEQUENCE length
    let (seq_extra, _seq_len) = parse_der_length(key_data.get(1..)?)?;
    // Content starts at: 1 (SEQUENCE tag) + 1 (first len byte) + seq_extra
    let content = key_data.get(2 + seq_extra..)?;

    // First element must be modulus INTEGER
    if content.first() != Some(&0x02) {
        return None;
    }

    let (int_extra, int_len) = parse_der_length(content.get(1..)?)?;
    let modulus_bytes = content.get(2 + int_extra..2 + int_extra + int_len)?;

    // Strip the DER positive-integer leading 0x00 sign byte if present
    let meaningful = if modulus_bytes.first() == Some(&0x00) {
        modulus_bytes.get(1..)?
    } else {
        modulus_bytes
    };

    Some(meaningful.len() * 8)
}

/// Parse a DER length field. Returns (extra_bytes_consumed, length_value).
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        Some((0, first as usize))
    } else {
        let n_bytes = (first & 0x7f) as usize;
        if n_bytes == 0 || n_bytes > 4 {
            return None;
        }
        let len_bytes = data.get(1..1 + n_bytes)?;
        let mut len: usize = 0;
        for &b in len_bytes {
            len = len.checked_shl(8)?.checked_add(b as usize)?;
        }
        Some((n_bytes, len))
    }
}

fn round_rsa_bits(bits: usize) -> usize {
    // Round to the nearest standard RSA key size
    for &size in &[512usize, 1024, 2048, 3072, 4096, 8192] {
        if bits <= size + 8 {
            return size;
        }
    }
    bits
}

// ── Private / public key stubs (content not parsed without private key) ───────

fn private_key_asset_from_der(tag: &str, der: &[u8], location: Location, _path: &Path) -> CryptoAsset {
    // For PKCS#8 ("PRIVATE KEY") we extract the algorithm OID from the DER structure.
    // For legacy formats ("RSA PRIVATE KEY", "EC PRIVATE KEY") the tag itself tells us.
    let (algo, quantum_safe, hndl_risk, nist_level, primitive) = if tag.contains("PRIVATE KEY")
        && !tag.contains("RSA")
        && !tag.contains("EC")
        && !tag.contains("DSA")
        && !tag.contains("OPENSSH")
    {
        // PKCS#8 generic — read algorithm OID from DER
        classify_pkcs8_der(der)
    } else {
        classify_key_tag(tag)
    };

    CryptoAsset {
        asset_type: AssetType::PrivateKey,
        name: algo.to_string(),
        oid: None,
        primitive,
        parameter_set: None,
        nist_quantum_security: nist_level,
        quantum_safe,
        hndl_risk,
        locations: vec![location],
        evidence: Evidence::CertificateParsing,
    }
}

/// Identify the algorithm from a PKCS#8 PrivateKeyInfo DER blob by scanning for
/// known algorithm OID byte sequences. Only the first 64 bytes are scanned —
/// the AlgorithmIdentifier is always near the beginning of the structure.
fn classify_pkcs8_der(der: &[u8]) -> (&'static str, QuantumSafety, Risk, u8, Primitive) {
    let scan = &der[..der.len().min(64)];

    // RSA  — OID 1.2.840.113549.1.1.1 encodes as: 2a 86 48 86 f7 0d 01 01 01
    if scan.windows(9).any(|w| w == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) {
        return ("RSA", QuantumSafety::Vulnerable, Risk::Critical, 0, Primitive::PublicKeyEncryption);
    }
    // EC   — OID 1.2.840.10045.2.1 encodes as: 2a 86 48 ce 3d 02 01
    if scan.windows(7).any(|w| w == [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]) {
        return ("ECDSA", QuantumSafety::Vulnerable, Risk::Critical, 0, Primitive::DigitalSignature);
    }
    // DSA  — OID 1.2.840.10040.4.1 encodes as: 2a 86 48 ce 38 04 01
    if scan.windows(7).any(|w| w == [0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01]) {
        return ("DSA", QuantumSafety::Vulnerable, Risk::High, 0, Primitive::DigitalSignature);
    }
    // Ed25519 — OID 1.3.101.112 encodes as: 2b 65 70
    if scan.windows(3).any(|w| w == [0x2b, 0x65, 0x70]) {
        return ("Ed25519", QuantumSafety::Vulnerable, Risk::High, 0, Primitive::DigitalSignature);
    }
    // Ed448 — OID 1.3.101.113 encodes as: 2b 65 71
    if scan.windows(3).any(|w| w == [0x2b, 0x65, 0x71]) {
        return ("Ed448", QuantumSafety::Vulnerable, Risk::High, 0, Primitive::DigitalSignature);
    }
    // X25519 — OID 1.3.101.110 encodes as: 2b 65 6e
    if scan.windows(3).any(|w| w == [0x2b, 0x65, 0x6e]) {
        return ("X25519", QuantumSafety::Vulnerable, Risk::High, 0, Primitive::KeyAgreement);
    }

    ("Unknown", QuantumSafety::Unknown, Risk::Medium, 0, Primitive::Other)
}

fn public_key_asset_from_tag(tag: &str, location: Location, _path: &Path) -> CryptoAsset {
    let (algo, quantum_safe, hndl_risk, nist_level, primitive) = classify_key_tag(tag);
    CryptoAsset {
        asset_type: AssetType::PublicKey,
        name: algo.to_string(),
        oid: None,
        primitive,
        parameter_set: None,
        nist_quantum_security: nist_level,
        quantum_safe,
        hndl_risk,
        locations: vec![location],
        evidence: Evidence::CertificateParsing,
    }
}

fn classify_key_tag(tag: &str) -> (&'static str, QuantumSafety, Risk, u8, Primitive) {
    let tag_up = tag.to_uppercase();
    if tag_up.contains("RSA") {
        ("RSA", QuantumSafety::Vulnerable, Risk::Critical, 0, Primitive::PublicKeyEncryption)
    } else if tag_up.contains("EC") {
        ("ECDSA", QuantumSafety::Vulnerable, Risk::Critical, 0, Primitive::DigitalSignature)
    } else if tag_up.contains("DSA") {
        ("DSA", QuantumSafety::Vulnerable, Risk::High, 0, Primitive::DigitalSignature)
    } else if tag_up.contains("OPENSSH") {
        ("OpenSSH", QuantumSafety::Unknown, Risk::High, 0, Primitive::Other)
    } else {
        ("Unknown", QuantumSafety::Unknown, Risk::Medium, 0, Primitive::Other)
    }
}

// ── Classification helpers ────────────────────────────────────────────────────

pub(crate) fn classify_by_name(name: &str) -> (QuantumSafety, Risk, u8, Primitive) {
    use crate::catalog::algorithms::lookup_by_name;

    if let Some(info) = lookup_by_name(name) {
        return (
            info.quantum_safe.clone(),
            info.hndl_risk.clone(),
            info.nist_quantum_security,
            info.primitive.clone(),
        );
    }

    let lower = name.to_lowercase();
    // Heuristic fallback for names not in catalog
    if lower.contains("rsa") {
        (QuantumSafety::Vulnerable, Risk::Critical, 0, Primitive::PublicKeyEncryption)
    } else if lower.contains("ecdsa") || lower.contains("ec") {
        (QuantumSafety::Vulnerable, Risk::Critical, 0, Primitive::DigitalSignature)
    } else if lower.contains("dsa") {
        (QuantumSafety::Vulnerable, Risk::High, 0, Primitive::DigitalSignature)
    } else if lower.contains("ml-kem") || lower.contains("kyber") {
        (QuantumSafety::Safe, Risk::None, 3, Primitive::PostQuantumKem)
    } else if lower.contains("ml-dsa") || lower.contains("dilithium") {
        (QuantumSafety::Safe, Risk::None, 3, Primitive::PostQuantumSignature)
    } else if lower.contains("aes-256") {
        (QuantumSafety::ClassicallyAdequate, Risk::None, 5, Primitive::BlockCipher)
    } else if lower.contains("aes-128") {
        (QuantumSafety::ClassicallyAdequate, Risk::Medium, 1, Primitive::BlockCipher)
    } else {
        (QuantumSafety::Unknown, Risk::Medium, 0, Primitive::Other)
    }
}

fn format_cert_name(algo: &str, param: Option<&str>) -> String {
    match param {
        Some(p) => format!("{}-{}", algo, p),
        None => algo.to_string(),
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn location_from_path(path: &Path) -> Location {
    Location {
        source: path.to_string_lossy().into_owned(),
        line: None,
        column: None,
    }
}

/// Peek at the first 27 bytes to detect a PEM header without relying on extension.
pub(crate) fn looks_like_pem_pub(path: &Path) -> Result<bool> {
    use std::io::Read;
    let mut buf = [0u8; 27];
    let n = std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .read(&mut buf)
        .with_context(|| format!("reading header of {}", path.display()))?;
    Ok(&buf[..n] == b"-----BEGIN " || buf.starts_with(b"-----BEGIN "))
}
