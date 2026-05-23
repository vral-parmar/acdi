#![forbid(unsafe_code)]

//! Package manifest dependency scanner.
//!
//! Detects crypto library dependencies declared in:
//!   - `Cargo.toml`           (Rust)
//!   - `package.json`         (Node.js / npm)
//!   - `requirements.txt` / `Pipfile` (Python)
//!   - `go.mod`               (Go)
//!   - `pom.xml`              (Maven)
//!   - `build.gradle` / `build.gradle.kts` (Gradle)
//!
//! Each matched library emits an `AssetType::Library` finding whose quantum risk
//! is derived from the algorithm the library primarily implements.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::detect::certs::classify_by_name;
use crate::model::{
    asset::{AssetType, Evidence, Location},
    CryptoAsset,
};

const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

// ── Library catalog ───────────────────────────────────────────────────────────

/// (lowercase library name, primary algorithm for risk classification)
static LIBRARY_CATALOG: &[(&str, &str)] = &[
    // ── Rust crates ───────────────────────────────────────────────────────────
    ("openssl",            "RSA"),          // classic OpenSSL bindings
    ("native-tls",         "RSA"),          // system TLS (OpenSSL/SChannel)
    ("ring",               "ECDSA"),        // BoringSSL-derived: ECDSA, RSA-PSS, AES
    ("boring",             "ECDSA"),        // BoringSSL Rust bindings
    ("rustls",             "ECDSA"),        // rustls 0.23: ring backend, no ML-KEM by default
    ("rsa",                "RSA-2048"),     // pure-Rust RSA
    ("dsa",                "DSA-2048"),     // pure-Rust DSA
    ("ecdsa",              "ECDSA"),        // RustCrypto ECDSA
    ("ed25519-dalek",      "Ed25519"),      // Ed25519 signatures
    ("x25519-dalek",       "X25519"),       // X25519 key agreement
    ("p256",               "ECDSA-P-256"),  // RustCrypto P-256
    ("p384",               "ECDSA-P-384"),  // RustCrypto P-384
    ("k256",               "ECDSA"),        // secp256k1 (Bitcoin)
    ("sha1",               "SHA-1"),        // SHA-1 hash crate
    ("md5",                "MD5"),          // MD5 hash crate
    ("des",                "DES"),          // DES block cipher
    ("rc4",                "RC4"),          // RC4 stream cipher
    ("aes",                "AES-256"),      // AES block cipher (quantum-adequate)
    ("sha2",               "SHA-256"),      // SHA-2 family (quantum-adequate)
    ("sha3",               "SHA3-256"),     // SHA-3 family
    ("hmac",               "SHA-256"),      // HMAC (hash-based MAC)
    ("pqcrypto-kyber",     "ML-KEM-768"),   // PQC: ML-KEM (Kyber)
    ("pqcrypto-dilithium", "ML-DSA-65"),    // PQC: ML-DSA (Dilithium)
    ("ml-kem",             "ML-KEM-768"),   // NIST FIPS 203
    ("ml-dsa",             "ML-DSA-65"),    // NIST FIPS 204
    // ── npm packages ─────────────────────────────────────────────────────────
    ("node-forge",     "RSA"),          // full crypto suite for Node.js
    ("jsonwebtoken",   "RSA-2048"),     // JWT signing — defaults to RS256
    ("jose",           "ECDSA-P-256"),  // JavaScript Object Signing (JOSE)
    ("node-rsa",       "RSA-2048"),     // pure RSA for Node.js
    ("elliptic",       "ECDSA"),        // EC for Node.js
    ("crypto-js",      "AES-256"),      // symmetric crypto for browsers
    ("jsrsasign",      "RSA"),          // RSA/ECDSA for JavaScript
    ("bcrypt",         "SHA-256"),      // bcrypt (hash-based KDF)
    ("bcryptjs",       "SHA-256"),
    // ── Python packages ───────────────────────────────────────────────────────
    ("cryptography",    "RSA"),         // pyca/cryptography — full suite
    ("paramiko",        "RSA"),         // SSH client/server
    ("pycryptodome",    "RSA"),         // PyCryptodome suite
    ("pycryptodomex",   "RSA"),
    ("pyopenssl",       "RSA"),         // pyOpenSSL bindings
    ("pyjwt",           "RSA-2048"),    // JWT for Python (RS/ES/PS)
    ("python-jose",     "ECDSA-P-256"), // JOSE for Python
    ("rsa",             "RSA-2048"),    // pure-Python RSA
    ("ecdsa",           "ECDSA"),       // pure-Python ECDSA
    // ── Go modules ───────────────────────────────────────────────────────────
    ("golang.org/x/crypto",             "Ed25519"),      // standard Go crypto extensions
    ("github.com/cloudflare/circl",     "ML-KEM-768"),   // Cloudflare CIRCL (PQC!)
    ("gopkg.in/square/go-jose.v2",      "ECDSA-P-256"),
    ("gopkg.in/go-jose/go-jose.v3",     "ECDSA-P-256"),
    ("github.com/golang-jwt/jwt",       "RSA-2048"),
    ("github.com/dgrijalva/jwt-go",     "RSA-2048"),     // deprecated JWT library
    ("github.com/lestrrat-go/jwx",      "ECDSA-P-256"),
    ("github.com/lestrrat-go/jwx/v2",   "ECDSA-P-256"),
    // ── Maven / Gradle artifacts (Java ecosystem) ─────────────────────────────
    ("bcprov-jdk15on",         "RSA-2048"),  // BouncyCastle Provider (Java 8–14)
    ("bcprov-jdk18on",         "RSA-2048"),  // BouncyCastle Provider (Java 11+)
    ("bcpkix-jdk15on",         "RSA-2048"),  // BouncyCastle PKIX/CMS
    ("bcpkix-jdk18on",         "RSA-2048"),
    ("bctls-jdk15on",          "RSA-2048"),  // BouncyCastle TLS
    ("bctls-jdk18on",          "RSA-2048"),
    ("java-jwt",               "RSA-2048"),  // Auth0 Java JWT
    ("jjwt",                   "RSA-2048"),  // io.jsonwebtoken JJWT
    ("jjwt-api",               "RSA-2048"),
    ("jjwt-impl",              "RSA-2048"),
    ("nimbus-jose-jwt",        "ECDSA-P-256"), // Nimbus JOSE+JWT
    ("spring-security-crypto", "RSA-2048"),  // Spring Security crypto module
    ("spring-security-core",   "RSA-2048"),
    ("commons-codec",          "SHA-1"),     // Apache Commons Codec (MD5/SHA-1 helpers)
    ("commons-crypto",         "AES-128"),   // Apache Commons Crypto (AES)
    ("jose4j",                 "RSA-2048"),  // jose4j JOSE library
    ("conscrypt-openjdk-uber", "ECDSA-P-256"), // Google Conscrypt
    ("tink",                   "AES-256"),   // Google Tink (modern safe crypto)
    ("jasypt",                 "SHA-1"),     // Jasypt simplified encryption
    ("jasypt-spring-boot",     "SHA-1"),
    ("shiro-crypto-hash",      "SHA-1"),     // Apache Shiro crypto
    ("shiro-crypto-core",      "SHA-1"),
    ("jbcrypt",                "SHA-256"),   // jBCrypt password hashing
    ("pac4j-core",             "RSA-2048"),  // pac4j security framework
    ("keycloak-core",          "RSA-2048"),  // Keycloak identity
];

fn lookup_library(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    LIBRARY_CATALOG
        .iter()
        .find_map(|(lib, algo)| if *lib == lower.as_str() { Some(*algo) } else { None })
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn scan_manifest(path: &Path) -> Result<Vec<CryptoAsset>> {
    let size = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if size > MAX_MANIFEST_BYTES {
        tracing::debug!("manifest too large, skipping: {}", path.display());
        return Ok(vec![]);
    }

    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let source = path.to_string_lossy().into_owned();
    let mut seen: HashSet<String> = HashSet::new();
    let mut assets: Vec<CryptoAsset> = Vec::new();

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    match file_name {
        "Cargo.toml" => parse_cargo_toml(&text, &source, &mut seen, &mut assets),
        "package.json" => parse_package_json(&text, &source, &mut seen, &mut assets),
        "requirements.txt" | "Pipfile" => {
            parse_requirements(&text, &source, &mut seen, &mut assets)
        }
        "go.mod" => parse_go_mod(&text, &source, &mut seen, &mut assets),
        "pom.xml" => parse_pom_xml(&text, &source, &mut seen, &mut assets),
        "build.gradle" | "build.gradle.kts" => {
            parse_build_gradle(&text, &source, &mut seen, &mut assets)
        }
        _ => {}
    }

    Ok(assets)
}

// ── Per-ecosystem parsers ─────────────────────────────────────────────────────

/// Cargo.toml: scan lines inside [dependencies] / [dev-dependencies] sections.
fn parse_cargo_toml(
    text: &str,
    source: &str,
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
) {
    let mut in_deps = false;

    for (idx, line) in text.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            in_deps = matches!(
                trimmed,
                "[dependencies]"
                    | "[dev-dependencies]"
                    | "[build-dependencies]"
                    | "[workspace.dependencies]"
            );
            continue;
        }

        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Extract the crate name: the key before `=`
        if let Some(name) = trimmed.split('=').next() {
            let crate_name = name.trim().trim_matches('"');
            if let Some(algo) = lookup_library(crate_name) {
                push_unique(seen, assets, crate_name, algo, source, line_no);
            }
        }
    }
}

/// package.json: find `"<name>": "<version>"` lines inside dependency objects.
fn parse_package_json(
    text: &str,
    source: &str,
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
) {
    for (idx, line) in text.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = line.trim();

        // Match  "package-name": "version-string"
        if !trimmed.starts_with('"') {
            continue;
        }
        if let Some(close) = trimmed[1..].find('"') {
            let pkg_name = &trimmed[1..close + 1];
            if let Some(algo) = lookup_library(pkg_name) {
                push_unique(seen, assets, pkg_name, algo, source, line_no);
            }
        }
    }
}

/// requirements.txt / Pipfile: one package name per line (before `==`, `>=`, `[`, etc.).
fn parse_requirements(
    text: &str,
    source: &str,
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
) {
    for (idx, line) in text.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        // Extract name before any version specifier
        let pkg_name = trimmed
            .split(['=', '<', '>', '!', '~', '[', ';', ' ', '\t'])
            .next()
            .unwrap_or("")
            .trim();

        if !pkg_name.is_empty() {
            if let Some(algo) = lookup_library(pkg_name) {
                push_unique(seen, assets, pkg_name, algo, source, line_no);
            }
        }
    }
}

/// go.mod: extract module paths from `require (...)` blocks and single-line requires.
fn parse_go_mod(
    text: &str,
    source: &str,
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
) {
    let mut in_require = false;

    for (idx, line) in text.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = line.trim();

        if trimmed == "require (" {
            in_require = true;
            continue;
        }
        if trimmed == ")" && in_require {
            in_require = false;
            continue;
        }

        // Single-line require: `require golang.org/x/crypto v0.x`
        if let Some(rest) = trimmed.strip_prefix("require ") {
            let module = rest.split_whitespace().next().unwrap_or("").trim();
            if let Some(algo) = lookup_library(module) {
                push_unique(seen, assets, module, algo, source, line_no);
            }
            continue;
        }

        if in_require && !trimmed.is_empty() && !trimmed.starts_with("//") {
            let module = trimmed.split_whitespace().next().unwrap_or("").trim();
            if let Some(algo) = lookup_library(module) {
                push_unique(seen, assets, module, algo, source, line_no);
            }
        }
    }
}

/// pom.xml: state-machine parser — tracks groupId per <dependency> block.
fn parse_pom_xml(
    text: &str,
    source: &str,
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
) {
    let mut in_dependency = false;
    let mut dep_line: u32 = 1;
    let mut current_group: Option<String> = None;

    for (idx, line) in text.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = line.trim();

        if trimmed.contains("<dependency>") && !trimmed.contains("<!--") {
            in_dependency = true;
            dep_line = line_no;
            current_group = None;
            continue;
        }
        if trimmed.contains("</dependency>") {
            in_dependency = false;
            current_group = None;
            continue;
        }

        if !in_dependency {
            continue;
        }

        if let Some(group) = extract_xml_tag(trimmed, "groupId") {
            current_group = Some(group);
            continue;
        }

        if let Some(artifact) = extract_xml_tag(trimmed, "artifactId") {
            // Try groupId:artifactId first for disambiguation, then bare artifactId
            let algo = current_group
                .as_ref()
                .and_then(|g| lookup_library(&format!("{g}:{artifact}")))
                .or_else(|| lookup_library(&artifact));

            if let Some(algo) = algo {
                push_unique(seen, assets, &artifact, algo, source, dep_line);
            }
        }
    }
}

/// build.gradle / build.gradle.kts: find `'group:artifact:version'` dependency strings.
fn parse_build_gradle(
    text: &str,
    source: &str,
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
) {
    for (idx, line) in text.lines().enumerate() {
        let line_no = (idx + 1) as u32;
        let trimmed = line.trim();

        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }

        // Try both quote styles
        for &quote in &['"', '\''] {
            if let Some(dep_str) = extract_quoted_gav(trimmed, quote) {
                let parts: Vec<&str> = dep_str.splitn(3, ':').collect();
                if parts.len() >= 2 {
                    let group = parts[0];
                    let artifact = parts[1];
                    let full_key = format!("{group}:{artifact}");

                    let algo = lookup_library(&full_key)
                        .or_else(|| lookup_library(artifact));

                    if let Some(algo) = algo {
                        push_unique(seen, assets, artifact, algo, source, line_no);
                    }
                }
                break; // only one quote style per line
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract text content from `<tag>content</tag>` on a single line.
fn extract_xml_tag(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = line.find(&open)? + open.len();
    let rest = &line[start..];
    let end = rest.find(&close)?;
    Some(rest[..end].trim().to_string())
}

/// Extract a `group:artifact:version` string delimited by `quote` from a Gradle dep line.
/// Only returns strings that contain exactly 2 colons (i.e., group:artifact:version).
fn extract_quoted_gav(line: &str, quote: char) -> Option<&str> {
    let start = line.find(quote)? + 1;
    let rest = &line[start..];
    let end = rest.find(quote)?;
    let content = &rest[..end];
    if content.chars().filter(|&c| c == ':').count() == 2 {
        Some(content)
    } else {
        None
    }
}

fn push_unique(
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
    lib_name: &str,
    primary_algo: &str,
    source: &str,
    line: u32,
) {
    let key = format!("{lib_name}:{line}");
    if seen.contains(&key) {
        return;
    }
    seen.insert(key);

    let (qs, risk, nist, primitive) = classify_by_name(primary_algo);

    assets.push(CryptoAsset {
        asset_type: AssetType::Library,
        name: lib_name.to_string(),
        oid: None,
        primitive,
        parameter_set: Some(primary_algo.to_string()),
        nist_quantum_security: nist,
        quantum_safe: qs,
        hndl_risk: risk,
        locations: vec![Location {
            source: source.to_string(),
            line: Some(line),
            column: None,
        }],
        evidence: Evidence::ManifestDependency,
    });
}
