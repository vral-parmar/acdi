#![forbid(unsafe_code)]

//! Configuration file crypto scanner.
//!
//! Scans YAML, TOML, JSON, INI, .properties, .env, and similar config files for
//! key-value patterns that name cryptographic algorithms. Detects JWT `alg` fields,
//! TLS cipher-suite settings, SSH key-type declarations, and generic
//! `algorithm = <value>` style keys.

use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use regex::Regex;

use crate::detect::certs::classify_by_name;
use crate::model::{
    asset::{AssetType, Evidence, Location},
    CryptoAsset,
};

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

// ── Value alias table ─────────────────────────────────────────────────────────

/// Lowercase config values → canonical algorithm name.
static CONFIG_VALUE_ALIASES: &[(&str, &str)] = &[
    // JWT algorithm identifiers (RFC 7518)
    ("rs256", "RSA-2048"),
    ("rs384", "RSA-2048"),
    ("rs512", "RSA-2048"),
    ("ps256", "RSA-2048"),
    ("ps384", "RSA-2048"),
    ("ps512", "RSA-2048"),
    ("es256", "ECDSA-P-256"),
    ("es384", "ECDSA-P-384"),
    ("es512", "ECDSA-P-521"),
    ("eddsa", "Ed25519"),
    ("hs256", "SHA-256"),
    ("hs384", "SHA-384"),
    ("hs512", "SHA-512"),
    // RSA key sizes
    ("rsa-1024", "RSA-1024"),
    ("rsa-2048", "RSA-2048"),
    ("rsa-3072", "RSA-3072"),
    ("rsa-4096", "RSA-4096"),
    ("rsa1024", "RSA-1024"),
    ("rsa2048", "RSA-2048"),
    ("rsa3072", "RSA-3072"),
    ("rsa4096", "RSA-4096"),
    ("rsa", "RSA"),
    // EC / ECDSA
    ("ecdsa-p256", "ECDSA-P-256"),
    ("ecdsa-p384", "ECDSA-P-384"),
    ("ecdsa-p521", "ECDSA-P-521"),
    ("ecdsa-p-256", "ECDSA-P-256"),
    ("ecdsa-p-384", "ECDSA-P-384"),
    ("ecdsa-p-521", "ECDSA-P-521"),
    ("ecdsa", "ECDSA"),
    ("ec", "ECDSA"),
    ("prime256v1", "ECDSA-P-256"),
    ("secp256r1", "ECDSA-P-256"),
    ("secp384r1", "ECDSA-P-384"),
    ("secp521r1", "ECDSA-P-521"),
    ("p-256", "ECDSA-P-256"),
    ("p-384", "ECDSA-P-384"),
    ("p-521", "ECDSA-P-521"),
    ("p256", "ECDSA-P-256"),
    ("p384", "ECDSA-P-384"),
    ("p521", "ECDSA-P-521"),
    ("ed25519", "Ed25519"),
    ("x25519", "X25519"),
    // Symmetric
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
    // Hash functions
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
    // Post-quantum
    ("ml-kem-512", "ML-KEM-512"),
    ("ml-kem-768", "ML-KEM-768"),
    ("ml-kem-1024", "ML-KEM-1024"),
    ("ml-dsa-44", "ML-DSA-44"),
    ("ml-dsa-65", "ML-DSA-65"),
    ("ml-dsa-87", "ML-DSA-87"),
];

fn value_to_canonical(val: &str) -> Option<&'static str> {
    let lower = val.to_lowercase();
    if let Some(canonical) = CONFIG_VALUE_ALIASES
        .iter()
        .find_map(|(k, v)| if *k == lower.as_str() { Some(*v) } else { None })
    {
        return Some(canonical);
    }
    // TLS cipher suite names contain the auth algorithm in the prefix
    if lower.starts_with("tls_") {
        return tls_cipher_to_canonical(val);
    }
    None
}

/// Extract the authentication algorithm from a TLS cipher suite name.
/// e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 → "RSA"
fn tls_cipher_to_canonical(suite: &str) -> Option<&'static str> {
    let u = suite.to_uppercase();
    if u.contains("_ECDSA_") {
        Some("ECDSA")
    } else if u.contains("_RSA_") || u.starts_with("TLS_RSA_") {
        Some("RSA")
    } else if u.contains("_DSS_") || u.contains("_DSA_") {
        Some("DSA-2048")
    } else {
        None
    }
}

// ── Pattern rules ─────────────────────────────────────────────────────────────

struct ConfigRule {
    /// Full-line regex; named group `val` captures the raw algorithm value.
    regex_str: &'static str,
    /// Restrict to these extensions (empty = all config extensions).
    extensions: &'static [&'static str],
}

static RULES: &[ConfigRule] = &[
    // Generic "algorithm / cipher / hash" key → value lookup
    ConfigRule {
        regex_str: r#"(?i)(?:algorithm|cipher|digest|hash|signing|encryption|signature)[_\-]?(?:algorithm|type|suite|method|function)?\s*[=:]\s*["']?(?P<val>[A-Za-z0-9][A-Za-z0-9_\-\.]*)"#,
        extensions: &[],
    },
    // JWT "alg" field — short key, needs surrounding context to avoid false positives
    ConfigRule {
        regex_str: r#"(?i)(?:^|[{,\s\[])["']?alg["']?\s*[=:]\s*["']?(?P<val>[A-Za-z][A-Za-z0-9]+)"#,
        extensions: &["json", "yaml", "yml", "toml", "properties", "env"],
    },
    // SSH / TLS key-type declarations
    ConfigRule {
        regex_str: r#"(?i)(?:key[_\-]type|ssh[_\-]?key[_\-]?type|HostKeyAlgorithms?|public[_\-]key[_\-]algorithm)\s*[=:\s]\s*["']?(?P<val>[A-Za-z0-9][A-Za-z0-9_\-\.]*)"#,
        extensions: &[],
    },
    // TLS cipher suite names (IANA format TLS_*_WITH_*)
    ConfigRule {
        regex_str: r#"(?P<val>TLS_(?:RSA|DHE_RSA|ECDHE_RSA|ECDHE_ECDSA|DHE_DSS|ECDHE_PSK)_WITH_[A-Z0-9_]+)"#,
        extensions: &[],
    },
];

// ── Compiled cache ────────────────────────────────────────────────────────────

type CompiledRules = Vec<(Regex, &'static ConfigRule)>;
static COMPILED: OnceLock<CompiledRules> = OnceLock::new();

fn compiled_rules() -> &'static CompiledRules {
    COMPILED.get_or_init(|| {
        RULES
            .iter()
            .filter_map(|rule| match Regex::new(rule.regex_str) {
                Ok(re) => Some((re, rule)),
                Err(e) => {
                    tracing::error!("config rule compile error: {e}");
                    None
                }
            })
            .collect()
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan a configuration file for algorithm references.
/// Returns an empty vec for files exceeding the size limit or that cannot be read as UTF-8.
pub fn scan_config(path: &Path) -> Result<Vec<CryptoAsset>> {
    let size = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if size > MAX_CONFIG_BYTES {
        tracing::debug!("config file too large, skipping: {}", path.display());
        return Ok(vec![]);
    }

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let rules = compiled_rules();
    let source = path.to_string_lossy().into_owned();
    let mut seen: HashSet<String> = HashSet::new();
    let mut assets: Vec<CryptoAsset> = Vec::new();

    for (idx, line) in text.lines().enumerate() {
        let line_no = (idx + 1) as u32;

        // Skip pure comment lines
        let trimmed = line.trim();
        if trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with("<!--")
            || trimmed.starts_with('*')
        {
            continue;
        }

        for (re, rule) in rules {
            if !rule.extensions.is_empty() && !rule.extensions.contains(&ext.as_str()) {
                continue;
            }

            for caps in re.captures_iter(line) {
                if let Some(raw) = caps.name("val") {
                    if let Some(canonical) = value_to_canonical(raw.as_str()) {
                        push_unique(&mut seen, &mut assets, canonical, &source, line_no);
                    }
                }
            }
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
    line: u32,
) {
    let key = format!("{name}:{line}");
    if seen.contains(&key) {
        return;
    }
    seen.insert(key);

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
            line: Some(line),
            column: None,
        }],
        evidence: Evidence::ConfigFileRule,
    });
}
