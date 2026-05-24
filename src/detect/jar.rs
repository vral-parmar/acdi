#![forbid(unsafe_code)]

//! JAR / Java class-file crypto scanner.
//!
//! Two entry points:
//! - `scan_jar`   — treats the file as a ZIP archive; finds and scans every `.class` inside.
//! - `scan_class` — parses the Java class-file constant pool and extracts Utf8 strings.
//!
//! Both strategies produce findings via `Evidence::JarClassFile`.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use zip::ZipArchive;

use crate::detect::certs::classify_by_name;
use crate::model::{
    asset::{AssetType, Evidence, Location},
    CryptoAsset,
};

const MAX_JAR_BYTES: u64 = 100 * 1024 * 1024;
const CLASS_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

// ── Crypto API string catalog ─────────────────────────────────────────────────

/// Fragments found in Java class constant-pool strings → canonical algorithm name.
/// Keys are lowercase; match is substring-based.
static CLASS_STRING_MAP: &[(&str, &str)] = &[
    // JCA / JCE fully-qualified class names
    ("javax/crypto/cipher",                 "AES-256"),  // generic cipher; most common = AES
    ("javax/crypto/keygenerator",           "AES-128"),
    ("java/security/keyfactory",            "RSA"),
    ("java/security/keypairgenerator",      "RSA"),
    ("java/security/messagedigest",         "SHA-256"),
    ("java/security/signature",             "RSA"),
    // Algorithm-name string literals used with getInstance()
    ("aes/cbc/pkcs5padding",                "AES-128"),
    ("aes/gcm/nopadding",                   "AES-256"),
    ("aes/ecb/nopadding",                   "AES-128"),
    ("rsa/ecb/oaepwithsha-256",             "RSA-2048"),
    ("rsa/ecb/pkcs1padding",                "RSA-2048"),
    ("sha256withrsa",                       "RSA-2048"),
    ("sha384withrsa",                       "RSA-2048"),
    ("sha512withrsa",                       "RSA-2048"),
    ("sha256withecdsa",                     "ECDSA-P-256"),
    ("sha384withecdsa",                     "ECDSA-P-384"),
    ("sha1withrsa",                         "RSA-2048"),
    // Message-digest algorithm names
    ("sha-256",                             "SHA-256"),
    ("sha-384",                             "SHA-384"),
    ("sha-512",                             "SHA-512"),
    ("sha-1",                               "SHA-1"),
    // Raw algorithm names
    ("hmacsha256",                          "SHA-256"),
    ("hmacsha384",                          "SHA-384"),
    ("hmacsha512",                          "SHA-512"),
    ("hmacsha1",                            "SHA-1"),
    ("hmacmd5",                             "MD5"),
    // BouncyCastle class names
    ("org/bouncycastle/crypto/engines/rsaengine",  "RSA"),
    ("org/bouncycastle/crypto/engines/aesengine",  "AES-256"),
    // Post-quantum (liboqs-java / Bouncy Castle PQC)
    ("mlkem",                               "ML-KEM-768"),
    ("kyber",                               "ML-KEM-768"),
    ("mldsa",                               "ML-DSA-65"),
    ("dilithium",                           "ML-DSA-65"),
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan a JAR/WAR/AAR/EAR file by iterating its ZIP entries and scanning every
/// `.class` file found.
pub fn scan_jar(path: &Path) -> Result<Vec<CryptoAsset>> {
    let size = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if size > MAX_JAR_BYTES {
        tracing::debug!("JAR file too large, skipping: {}", path.display());
        return Ok(vec![]);
    }

    let file = std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?;

    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!("ZIP parse error in {}: {e}", path.display());
            return Ok(vec![]);
        }
    };

    let source = path.to_string_lossy().into_owned();
    let mut seen: HashSet<String> = HashSet::new();
    let mut assets: Vec<CryptoAsset> = Vec::new();

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let entry_name = entry.name().to_lowercase();
        if !entry_name.ends_with(".class") {
            continue;
        }

        let mut buf = Vec::new();
        if entry.read_to_end(&mut buf).is_err() {
            continue;
        }

        scan_class_bytes(&buf, &source, &mut seen, &mut assets);
    }

    Ok(assets)
}

/// Scan a standalone `.class` file.
pub fn scan_class_file(path: &Path) -> Result<Vec<CryptoAsset>> {
    let data = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let source = path.to_string_lossy().into_owned();
    let mut seen = HashSet::new();
    let mut assets = Vec::new();
    scan_class_bytes(&data, &source, &mut seen, &mut assets);
    Ok(assets)
}

/// Return true if the first 4 bytes are the ZIP local-file magic (PK\x03\x04).
/// Used for extension-less JAR detection.
pub fn has_jar_magic(path: &Path) -> Result<bool> {
    use std::io::Read as _;
    let mut buf = [0u8; 4];
    let n = std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .read(&mut buf)
        .with_context(|| format!("reading header of {}", path.display()))?;
    Ok(n >= 4 && buf == [0x50, 0x4B, 0x03, 0x04])
}

// ── Class-file constant pool parser ──────────────────────────────────────────

/// Parse the constant pool of a Java class file from raw bytes and
/// match Utf8 entries against the crypto catalog.
fn scan_class_bytes(
    data: &[u8],
    source: &str,
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
) {
    // Validate magic
    if data.get(..4) != Some(&CLASS_MAGIC) {
        return;
    }

    // Skip magic (4) + minor (2) + major (2) = 8 bytes; read cp_count
    let cp_count = match data.get(8..10) {
        Some(b) => u16::from_be_bytes([b[0], b[1]]) as usize,
        None => return,
    };

    let mut pos = 10usize;
    let mut i = 1usize;

    while i < cp_count {
        let tag = match data.get(pos) {
            Some(&t) => t,
            None => return,
        };
        pos += 1;

        match tag {
            1 => {
                // CONSTANT_Utf8: 2-byte length + bytes
                let len = match data.get(pos..pos + 2) {
                    Some(b) => u16::from_be_bytes([b[0], b[1]]) as usize,
                    None => return,
                };
                pos += 2;
                if let Some(bytes) = data.get(pos..pos + len) {
                    if let Ok(s) = std::str::from_utf8(bytes) {
                        match_class_string(s, source, seen, assets);
                    }
                }
                pos += len;
                i += 1;
            }
            3 | 4 => { pos += 4; i += 1; }  // Integer / Float
            5 | 6 => { pos += 8; i += 2; }  // Long / Double (takes 2 slots)
            7 | 8 | 16 | 19 | 20 => { pos += 2; i += 1; }  // Class / String / MethodType / Module / Package
            9..=12 => { pos += 4; i += 1; }  // Fieldref / Methodref / InterfaceMethodref / NameAndType
            15 => { pos += 3; i += 1; }  // MethodHandle
            17 | 18 => { pos += 4; i += 1; }  // Dynamic / InvokeDynamic
            _ => { return; }  // Unknown tag — stop parsing
        }
    }
}

fn match_class_string(
    s: &str,
    source: &str,
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
) {
    let lower = s.to_lowercase();
    for (fragment, canonical) in CLASS_STRING_MAP {
        if lower.contains(fragment) {
            push_unique(seen, assets, canonical, source);
            return;  // one match per string is enough
        }
    }
}

fn push_unique(seen: &mut HashSet<String>, assets: &mut Vec<CryptoAsset>, name: &str, source: &str) {
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
        evidence: Evidence::JarClassFile,
    });
}
