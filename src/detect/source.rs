#![forbid(unsafe_code)]

//! Source-code crypto-API pattern scanner.
//!
//! Scans text source files line-by-line with pre-compiled regexes.
//! Covers C/C++ OpenSSL, Python cryptography, Java JCA, Go crypto/*, Rust ring,
//! and generic config patterns.

use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use regex::Regex;

use crate::catalog::algorithms::lookup_by_name;
use crate::detect::certs::classify_by_name;
use crate::model::{
    asset::{AssetType, Evidence, Location},
    CryptoAsset,
};

const MAX_SOURCE_BYTES: u64 = 10 * 1024 * 1024; // skip files > 10 MB

// ── Pattern table ─────────────────────────────────────────────────────────────

/// A single source-code pattern rule.
///
/// `algo_base` is the algorithm family ("RSA", "AES", "SHA", etc.).
/// When empty, the named capture group `param` is itself the full/canonical name.
///
/// `extensions` restricts the rule to specific file types; empty means all source files.
struct PatternRule {
    algo_base: &'static str,
    regex_str: &'static str,
    extensions: &'static [&'static str],
}

static RULES: &[PatternRule] = &[
    // ── C / C++ — OpenSSL / BoringSSL ─────────────────────────────────────────
    PatternRule {
        algo_base: "RSA",
        regex_str: r"RSA_generate_key(?:_ex)?\s*\([^,)]*,\s*(?P<param>\d+)",
        extensions: &["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"],
    },
    PatternRule {
        algo_base: "AES",
        regex_str: r"\bEVP_aes_(?P<param>128|192|256)_",
        extensions: &["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"],
    },
    PatternRule {
        algo_base: "3DES",
        regex_str: r"\bEVP_des_ede3\b",
        extensions: &["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"],
    },
    PatternRule {
        algo_base: "DES",
        regex_str: r"\bEVP_des_(?:cbc|ecb|cfb|ofb|ctr)\b",
        extensions: &["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"],
    },
    PatternRule {
        algo_base: "RC4",
        regex_str: r"\bEVP_rc4\b",
        extensions: &["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"],
    },
    PatternRule {
        algo_base: "SHA",
        regex_str: r"\bEVP_sha(?P<param>1|224|256|384|512)\b",
        extensions: &["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"],
    },
    PatternRule {
        algo_base: "MD5",
        regex_str: r"\bEVP_md5\b",
        extensions: &["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"],
    },
    PatternRule {
        algo_base: "MD4",
        regex_str: r"\bEVP_md4\b",
        extensions: &["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"],
    },
    PatternRule {
        algo_base: "ECDSA",
        regex_str: r"\bEC_KEY_new_by_curve_name\s*\(\s*(?P<param>\w+)",
        extensions: &["c", "cpp", "cc", "cxx", "h", "hpp", "hxx"],
    },
    // ── Python — cryptography library ─────────────────────────────────────────
    PatternRule {
        algo_base: "RSA",
        regex_str: r"\brsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(?P<param>\d+)",
        extensions: &["py", "pyw"],
    },
    PatternRule {
        algo_base: "ECDSA",
        regex_str: r"\bec\.(?P<param>SECP256R1|SECP384R1|SECP521R1|SECP256K1|BrainpoolP256R1)\s*\(",
        extensions: &["py", "pyw"],
    },
    PatternRule {
        algo_base: "SHA",
        regex_str: r"\bhashes\.(?P<param>SHA1|SHA224|SHA256|SHA384|SHA512|MD5)\s*\(",
        extensions: &["py", "pyw"],
    },
    // ── Python — hashlib ──────────────────────────────────────────────────────
    PatternRule {
        algo_base: "SHA",
        regex_str: r"\bhashlib\.(?P<param>sha1|sha224|sha256|sha384|sha512|md5)\s*\(",
        extensions: &["py", "pyw"],
    },
    // ── Java / Kotlin — JCA ───────────────────────────────────────────────────
    PatternRule {
        algo_base: "",
        regex_str: r#"\bKeyPairGenerator\.getInstance\s*\(\s*"(?P<param>RSA|EC|DSA|DH)""#,
        extensions: &["java", "kt", "kts"],
    },
    PatternRule {
        algo_base: "",
        regex_str: r#"\bMessageDigest\.getInstance\s*\(\s*"(?P<param>SHA-?1|SHA-?256|SHA-?384|SHA-?512|MD5|MD4)""#,
        extensions: &["java", "kt", "kts"],
    },
    PatternRule {
        algo_base: "",
        regex_str: r#"\bCipher\.getInstance\s*\(\s*"(?P<param>AES|DES(?:ede)?|RC4|RC2|RSA)(?:[^"]*)?""#,
        extensions: &["java", "kt", "kts"],
    },
    PatternRule {
        algo_base: "",
        regex_str: r#"\bKeyGenerator\.getInstance\s*\(\s*"(?P<param>AES|DES(?:ede)?|Blowfish|RC4)""#,
        extensions: &["java", "kt", "kts"],
    },
    // ── Go — crypto/* ─────────────────────────────────────────────────────────
    PatternRule {
        algo_base: "RSA",
        regex_str: r"\brsa\.GenerateKey\s*\([^,]+,\s*(?P<param>\d+)",
        extensions: &["go"],
    },
    PatternRule {
        algo_base: "ECDSA",
        regex_str: r"\becdsa\.GenerateKey\s*\(\s*elliptic\.(?P<param>P256|P384|P521)\s*\(",
        extensions: &["go"],
    },
    PatternRule {
        algo_base: "SHA",
        regex_str: r"\b(?P<param>sha1|sha256|sha512|sha3_256|sha3_512)\.New\s*\(",
        extensions: &["go"],
    },
    PatternRule {
        algo_base: "MD5",
        regex_str: r"\bmd5\.New\s*\(",
        extensions: &["go"],
    },
    PatternRule {
        algo_base: "AES",
        regex_str: r"\baes\.NewCipher\s*\(",
        extensions: &["go"],
    },
    PatternRule {
        algo_base: "3DES",
        regex_str: r"\bdes\.NewTripleDESCipher\s*\(",
        extensions: &["go"],
    },
    PatternRule {
        algo_base: "DES",
        regex_str: r"\bdes\.NewCipher\s*\([^)]*\)",
        extensions: &["go"],
    },
    // ── Rust — ring ───────────────────────────────────────────────────────────
    PatternRule {
        algo_base: "ring",
        regex_str: r"\bring::(?:signature|agreement|hmac|aead|digest)::(?P<param>[A-Z][A-Z0-9_]+)",
        extensions: &["rs"],
    },
    // ── Generic — config / YAML / JSON / TOML (all source files) ─────────────
    PatternRule {
        algo_base: "",
        regex_str: r#"(?i)["']?(?:algorithm|cipher|digest|signature_algo)["']?\s*[:=]\s*["']?(?P<param>RSA-\d+|AES-\d+-\w+|AES-\d+|SHA-?1|SHA-?256|SHA-?384|SHA-?512|MD5|3DES|DES|RC4)["']?"#,
        extensions: &[],
    },
];

// ── Compiled regex cache ──────────────────────────────────────────────────────

static COMPILED: OnceLock<Vec<(Regex, &'static PatternRule)>> = OnceLock::new();

fn compiled_rules() -> &'static [(Regex, &'static PatternRule)] {
    COMPILED.get_or_init(|| {
        RULES
            .iter()
            .filter_map(|rule| {
                match Regex::new(rule.regex_str) {
                    Ok(re) => Some((re, rule)),
                    Err(e) => {
                        tracing::warn!("source pattern compile error: {e}");
                        None
                    }
                }
            })
            .collect()
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan a source-code file for cryptographic API calls.
/// Returns an empty vec for files exceeding the size limit.
pub fn scan_source(path: &Path) -> Result<Vec<CryptoAsset>> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;
    if meta.len() > MAX_SOURCE_BYTES {
        tracing::debug!("source file too large, skipping: {}", path.display());
        return Ok(vec![]);
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let raw = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let text = String::from_utf8_lossy(&raw);
    let source = path.to_string_lossy().into_owned();
    let rules = compiled_rules();

    // Deduplicate: (normalized_name, line_number)
    let mut seen: HashSet<(String, u32)> = HashSet::new();
    let mut assets: Vec<CryptoAsset> = Vec::new();

    for (idx, line) in text.lines().enumerate() {
        let line_no = (idx + 1) as u32;

        for (re, rule) in rules {
            if !rule.extensions.is_empty()
                && !rule.extensions.contains(&ext.as_str())
            {
                continue;
            }

            for caps in re.captures_iter(line) {
                let param = caps.name("param").map(|m| m.as_str());
                let full_name = build_name(rule.algo_base, param);

                if full_name.is_empty() || full_name == "Unknown" {
                    continue;
                }
                if seen.contains(&(full_name.clone(), line_no)) {
                    continue;
                }
                seen.insert((full_name.clone(), line_no));

                let col = caps.get(0).map(|m| (m.start() + 1) as u32);
                let (qs, risk, nist, primitive) = lookup_by_name(&full_name)
                    .map(|i| (i.quantum_safe.clone(), i.hndl_risk.clone(), i.nist_quantum_security, i.primitive.clone()))
                    .unwrap_or_else(|| classify_by_name(&full_name));

                assets.push(CryptoAsset {
                    asset_type: AssetType::Algorithm,
                    name: full_name,
                    oid: None,
                    primitive,
                    parameter_set: None,
                    nist_quantum_security: nist,
                    quantum_safe: qs,
                    hndl_risk: risk,
                    locations: vec![Location {
                        source: source.clone(),
                        line: Some(line_no),
                        column: col,
                    }],
                    evidence: Evidence::SourceCodePattern,
                });
            }
        }
    }

    Ok(assets)
}

// ── Name building and normalization ──────────────────────────────────────────

/// Build and normalize the full canonical algorithm name from a rule and captured param.
fn build_name(algo_base: &str, param: Option<&str>) -> String {
    match (algo_base, param) {
        // Empty base: param IS the full name (Java/generic rules)
        ("", Some(p)) => normalize_generic(p),
        ("", None) => String::new(),

        // SHA family: EVP_sha256 → SHA-256, hashes.SHA1 → SHA-1, sha256.New → SHA-256
        ("SHA", Some(p)) => normalize_sha(p),

        // ECDSA: curve name from param
        ("ECDSA", Some(p)) => {
            let curve = normalize_ec_curve(p);
            format!("ECDSA-{curve}")
        }
        ("ECDSA", None) => "ECDSA".to_string(),

        // RSA/DSA: key size from param
        ("RSA", Some(p)) => format!("RSA-{p}"),
        ("RSA", None) => "RSA".to_string(),
        ("DSA", Some(p)) => format!("DSA-{p}"),
        ("DSA", None) => "DSA".to_string(),

        // AES: key size from param
        ("AES", Some(p)) => format!("AES-{p}"),
        ("AES", None) => "AES".to_string(),

        // Ring constants: map constant name to canonical algo
        ("ring", Some(p)) => normalize_ring_const(p),
        ("ring", None) => String::new(),

        // Everything else: base (no param expected)
        (base, _) => base.to_string(),
    }
}

fn normalize_sha(s: &str) -> String {
    match s.to_uppercase().as_str() {
        "1" | "SHA1" | "SHA-1" => "SHA-1".to_string(),
        "224" | "SHA224" | "SHA-224" => "SHA-224".to_string(),
        "256" | "SHA256" | "SHA-256" | "SHA2" | "SHA2_256" => "SHA-256".to_string(),
        "384" | "SHA384" | "SHA-384" => "SHA-384".to_string(),
        "512" | "SHA512" | "SHA-512" | "SHA2_512" => "SHA-512".to_string(),
        "3_256" | "SHA3_256" | "SHA3-256" => "SHA3-256".to_string(),
        "3_512" | "SHA3_512" | "SHA3-512" => "SHA3-512".to_string(),
        "MD5" => "MD5".to_string(),
        _ => format!("SHA-{s}"),
    }
}

fn normalize_ec_curve(s: &str) -> String {
    match s.to_uppercase().as_str() {
        "SECP256R1" | "P256" | "P_256" | "PRIME256V1" | "NID_X9_62_PRIME256V1" => {
            "P-256".to_string()
        }
        "SECP384R1" | "P384" | "P_384" => "P-384".to_string(),
        "SECP521R1" | "P521" | "P_521" => "P-521".to_string(),
        "SECP256K1" | "NID_SECP256K1" => "secp256k1".to_string(),
        _ => s.to_string(),
    }
}

fn normalize_ring_const(s: &str) -> String {
    let u = s.to_uppercase();
    if u.contains("ECDSA_P256") {
        return "ECDSA-P-256".to_string();
    }
    if u.contains("ECDSA_P384") {
        return "ECDSA-P-384".to_string();
    }
    if u.contains("ECDH_P256") || u.contains("X25519_ECDH_P256") {
        return "ECDH-P-256".to_string();
    }
    if u.contains("ECDH_P384") {
        return "ECDH-P-384".to_string();
    }
    if u.contains("X25519") {
        return "X25519".to_string();
    }
    if u.contains("ED25519") {
        return "Ed25519".to_string();
    }
    if u.contains("RSA") {
        return "RSA".to_string();
    }
    if u.contains("SHA256") || u.contains("SHA_256") {
        return "SHA-256".to_string();
    }
    if u.contains("SHA384") || u.contains("SHA_384") {
        return "SHA-384".to_string();
    }
    if u.contains("SHA512") || u.contains("SHA_512") {
        return "SHA-512".to_string();
    }
    String::new()
}

fn normalize_generic(s: &str) -> String {
    match s.to_uppercase().trim() {
        "RSA" => "RSA".to_string(),
        "EC" => "ECDSA".to_string(),
        "DSA" => "DSA".to_string(),
        "DH" => "DH-2048".to_string(),
        "AES" => "AES".to_string(),
        "DES" => "DES".to_string(),
        "DESEDE" | "3DES" | "DESEDE3" => "3DES".to_string(),
        "RC4" => "RC4".to_string(),
        "RC2" => "RC2".to_string(),
        "SHA-1" | "SHA1" => "SHA-1".to_string(),
        "SHA-256" | "SHA256" => "SHA-256".to_string(),
        "SHA-384" | "SHA384" => "SHA-384".to_string(),
        "SHA-512" | "SHA512" => "SHA-512".to_string(),
        "MD5" => "MD5".to_string(),
        "MD4" => "MD4".to_string(),
        other => other.to_string(),
    }
}
