#![forbid(unsafe_code)]

//! Binary file crypto scanner.
//!
//! Two detection strategies:
//! 1. Extract printable ASCII strings (≥ MIN_STRING_LEN chars) and match against known
//!    algorithm names and common variants.
//! 2. Scan raw bytes for DER-encoded OID sequences from the algorithm catalog.
//!
//! Results are deduplicated by algorithm name — one asset per unique algorithm per file.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::detect::certs::classify_by_name;
use crate::model::{
    asset::{AssetType, Evidence, Location},
    CryptoAsset,
};

const MAX_BINARY_BYTES: u64 = 100 * 1024 * 1024;
const MIN_STRING_LEN: usize = 4;

// ── OID byte sequences ────────────────────────────────────────────────────────

/// Known DER-encoded OID VALUE bytes (content after tag and length).
static OID_PATTERNS: &[(&[u8], &str)] = &[
    // RSA: 1.2.840.113549.1.1.1
    (&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01], "RSA"),
    // id-ecPublicKey: 1.2.840.10045.2.1
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], "ECDSA"),
    // DSA: 1.2.840.10040.4.1
    (&[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01], "DSA"),
    // AES-128-CBC: 2.16.840.1.101.3.4.1.2
    (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02], "AES-128"),
    // AES-128-GCM: 2.16.840.1.101.3.4.1.6
    (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06], "AES-128"),
    // AES-256-CBC: 2.16.840.1.101.3.4.1.42
    (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a], "AES-256"),
    // AES-256-GCM: 2.16.840.1.101.3.4.1.46
    (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e], "AES-256"),
    // SHA-256: 2.16.840.1.101.3.4.2.1
    (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01], "SHA-256"),
    // SHA-384: 2.16.840.1.101.3.4.2.2
    (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02], "SHA-384"),
    // SHA-512: 2.16.840.1.101.3.4.2.3
    (&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03], "SHA-512"),
    // SHA-1: 1.3.14.3.2.26
    (&[0x2b, 0x0e, 0x03, 0x02, 0x1a], "SHA-1"),
    // MD5: 1.2.840.113549.2.5
    (&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05], "MD5"),
    // Ed25519: 1.3.101.112
    (&[0x2b, 0x65, 0x70], "Ed25519"),
    // X25519: 1.3.101.110
    (&[0x2b, 0x65, 0x6e], "X25519"),
];

// ── String-based name matching ────────────────────────────────────────────────

/// Known lowercase string variants → canonical algorithm name.
static STRING_ALIASES: &[(&str, &str)] = &[
    ("rsa-2048", "RSA-2048"),
    ("rsa-4096", "RSA-4096"),
    ("rsa-3072", "RSA-3072"),
    ("rsa-1024", "RSA-1024"),
    ("rsa2048", "RSA-2048"),
    ("rsa4096", "RSA-4096"),
    ("rsa", "RSA"),
    ("aes-128-cbc", "AES-128"),
    ("aes-128-gcm", "AES-128"),
    ("aes-256-cbc", "AES-256"),
    ("aes-256-gcm", "AES-256"),
    ("aes-192-cbc", "AES-192"),
    ("aes-128", "AES-128"),
    ("aes-192", "AES-192"),
    ("aes-256", "AES-256"),
    ("aes128", "AES-128"),
    ("aes192", "AES-192"),
    ("aes256", "AES-256"),
    ("3des", "3DES"),
    ("des3", "3DES"),
    ("des-ede3", "3DES"),
    ("triple-des", "3DES"),
    ("des", "DES"),
    ("rc4", "RC4"),
    ("rc2", "RC2"),
    ("ecdsa-p256", "ECDSA-P-256"),
    ("ecdsa-p384", "ECDSA-P-384"),
    ("ecdsa-p521", "ECDSA-P-521"),
    ("ecdsa-p-256", "ECDSA-P-256"),
    ("ecdsa-p-384", "ECDSA-P-384"),
    ("ecdsa-p-521", "ECDSA-P-521"),
    ("ecdsa", "ECDSA"),
    ("prime256v1", "ECDSA-P-256"),
    ("secp256r1", "ECDSA-P-256"),
    ("secp384r1", "ECDSA-P-384"),
    ("secp521r1", "ECDSA-P-521"),
    ("p-256", "ECDSA-P-256"),
    ("p-384", "ECDSA-P-384"),
    ("p-521", "ECDSA-P-521"),
    ("x25519", "X25519"),
    ("ed25519", "Ed25519"),
    ("sha-512", "SHA-512"),
    ("sha-384", "SHA-384"),
    ("sha-256", "SHA-256"),
    ("sha-224", "SHA-224"),
    ("sha-1", "SHA-1"),
    ("sha512", "SHA-512"),
    ("sha384", "SHA-384"),
    ("sha256", "SHA-256"),
    ("sha224", "SHA-224"),
    ("sha1", "SHA-1"),
    ("md5", "MD5"),
    ("md4", "MD4"),
    ("ml-kem-512", "ML-KEM-512"),
    ("ml-kem-768", "ML-KEM-768"),
    ("ml-kem-1024", "ML-KEM-1024"),
    ("ml-dsa-44", "ML-DSA-44"),
    ("ml-dsa-65", "ML-DSA-65"),
    ("ml-dsa-87", "ML-DSA-87"),
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan a binary file for embedded algorithm names and OID byte sequences.
/// Returns an empty vec for files exceeding the size limit.
pub fn scan_binary(path: &Path) -> Result<Vec<CryptoAsset>> {
    let size = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if size > MAX_BINARY_BYTES {
        tracing::debug!("binary file too large, skipping: {}", path.display());
        return Ok(vec![]);
    }

    let data = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let source = path.to_string_lossy().into_owned();
    let mut seen: HashSet<String> = HashSet::new();
    let mut assets: Vec<CryptoAsset> = Vec::new();

    // Strategy 1: OID byte sequences
    for (oid_bytes, algo_name) in OID_PATTERNS {
        if data.windows(oid_bytes.len()).any(|w| w == *oid_bytes) {
            push_unique(&mut seen, &mut assets, algo_name, &source);
        }
    }

    // Strategy 2: printable ASCII string extraction
    for s in extract_printable_strings(&data) {
        let lower = s.to_lowercase();
        let trimmed = lower.trim();

        // Direct alias lookup
        if let Some(&canonical) = STRING_ALIASES.iter().find_map(|(k, v)| {
            if *k == trimmed { Some(v) } else { None }
        }) {
            push_unique(&mut seen, &mut assets, canonical, &source);
        }
    }

    Ok(assets)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn push_unique(
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
    name: &str,
    source: &str,
) {
    if seen.contains(name) {
        return;
    }
    seen.insert(name.to_string());

    let (qs, risk, nist, primitive) = classify_by_name(name);

    assets.push(CryptoAsset {
        asset_type: AssetType::Algorithm,
        name: name.to_string(),
        oid: None,
        primitive,
        parameter_set: None,
        nist_quantum_security: nist,
        quantum_safe: qs,
        hndl_risk: risk,
        locations: vec![Location {
            source: source.to_string(),
            line: None,
            column: None,
        }],
        evidence: Evidence::BinaryStringSearch,
    });
}

/// Extract runs of printable ASCII bytes (0x20–0x7e) of at least MIN_STRING_LEN chars.
fn extract_printable_strings(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut run: Vec<u8> = Vec::new();

    for &b in data {
        if (0x20..=0x7e).contains(&b) {
            run.push(b);
        } else {
            if run.len() >= MIN_STRING_LEN {
                if let Ok(s) = std::str::from_utf8(&run) {
                    result.push(s.to_string());
                }
            }
            run.clear();
        }
    }
    if run.len() >= MIN_STRING_LEN {
        if let Ok(s) = std::str::from_utf8(&run) {
            result.push(s.to_string());
        }
    }
    result
}

/// Peek at the first 4 bytes to detect ELF, PE (MZ), or Mach-O magic.
pub fn has_binary_magic(path: &Path) -> Result<bool> {
    use std::io::Read;
    let mut buf = [0u8; 4];
    let n = std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .read(&mut buf)
        .with_context(|| format!("reading header of {}", path.display()))?;
    if n < 4 {
        return Ok(false);
    }
    Ok(matches!(
        buf,
        // ELF
        [0x7f, b'E', b'L', b'F']
        // PE (MZ)
        | [b'M', b'Z', _, _]
        // Mach-O little-endian 32/64
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xcf, 0xfa, 0xed, 0xfe]
        // Mach-O big-endian 32/64
        | [0xfe, 0xed, 0xfa, 0xce]
        | [0xfe, 0xed, 0xfa, 0xcf]
    ))
}
