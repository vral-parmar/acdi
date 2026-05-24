#![forbid(unsafe_code)]

//! Symbol-table scanner for ELF, PE, and Mach-O binaries.
//!
//! Extracts imported and exported function symbol names and matches them
//! against a catalog of known cryptographic API function names.
//! Complements the string-extraction approach in binary.rs with structured
//! symbol information that survives stripping of printable strings.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use goblin::Object;

use crate::detect::certs::classify_by_name;
use crate::model::{
    asset::{AssetType, Evidence, Location},
    CryptoAsset,
};

// ── Crypto symbol catalog ─────────────────────────────────────────────────────

/// Exact function symbol name → canonical algorithm.
/// Covers OpenSSL/BoringSSL, Windows CNG/CAPI, PKCS#11, and libsodium.
static SYMBOL_MAP: &[(&str, &str)] = &[
    // ── RSA ──────────────────────────────────────────────────────────────────
    ("RSA_generate_key",                    "RSA"),
    ("RSA_generate_key_ex",                 "RSA"),
    ("RSA_sign",                            "RSA"),
    ("RSA_verify",                          "RSA"),
    ("RSA_public_encrypt",                  "RSA"),
    ("RSA_private_decrypt",                 "RSA"),
    ("EVP_PKEY_CTX_set_rsa_keygen_bits",    "RSA"),
    ("BCryptGenerateKeyPair",               "RSA"),  // Windows CNG (RSA context)
    // ── ECDSA / EC ───────────────────────────────────────────────────────────
    ("EC_KEY_new_by_curve_name",            "ECDSA"),
    ("EC_GROUP_new_by_curve_name",          "ECDSA"),
    ("ECDSA_sign",                          "ECDSA"),
    ("ECDSA_verify",                        "ECDSA"),
    ("ECDSA_do_sign",                       "ECDSA"),
    ("ECDSA_do_verify",                     "ECDSA"),
    // ── AES ──────────────────────────────────────────────────────────────────
    ("EVP_aes_128_cbc",                     "AES-128"),
    ("EVP_aes_128_ecb",                     "AES-128"),
    ("EVP_aes_128_gcm",                     "AES-128"),
    ("EVP_aes_128_ctr",                     "AES-128"),
    ("EVP_aes_256_cbc",                     "AES-256"),
    ("EVP_aes_256_ecb",                     "AES-256"),
    ("EVP_aes_256_gcm",                     "AES-256"),
    ("EVP_aes_256_ctr",                     "AES-256"),
    ("EVP_aes_192_cbc",                     "AES-192"),
    ("EVP_aes_192_gcm",                     "AES-192"),
    // ── Hash / digest ─────────────────────────────────────────────────────────
    ("EVP_sha1",                            "SHA-1"),
    ("EVP_sha256",                          "SHA-256"),
    ("EVP_sha384",                          "SHA-384"),
    ("EVP_sha512",                          "SHA-512"),
    ("EVP_md5",                             "MD5"),
    ("EVP_md4",                             "MD4"),
    ("SHA1",                                "SHA-1"),
    ("SHA256",                              "SHA-256"),
    ("SHA384",                              "SHA-384"),
    ("SHA512",                              "SHA-512"),
    ("MD5",                                 "MD5"),
    // ── 3DES ─────────────────────────────────────────────────────────────────
    ("EVP_des_ede3_cbc",                    "3DES"),
    ("EVP_des_ede3",                        "3DES"),
    // ── Ed25519 / X25519 ─────────────────────────────────────────────────────
    ("crypto_sign_ed25519",                 "Ed25519"),
    ("crypto_sign_ed25519_keypair",         "Ed25519"),
    ("EVP_PKEY_CTX_new_id",                 "Ed25519"),  // may be Ed25519 context
    ("crypto_box_curve25519xsalsa20poly1305", "X25519"),
    // ── Windows CNG / CAPI ────────────────────────────────────────────────────
    ("CryptGenKey",                         "RSA"),
    ("CryptSignHash",                       "RSA"),
    ("NCryptCreatePersistedKey",            "RSA"),
    // ── PKCS#11 ───────────────────────────────────────────────────────────────
    ("C_GenerateKeyPair",                   "RSA"),
    ("C_SignInit",                          "RSA"),
    ("C_DecryptInit",                       "RSA"),
    // ── ML-KEM / post-quantum ─────────────────────────────────────────────────
    ("PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair", "ML-KEM-768"),
    ("OQS_KEM_ml_kem_768_keypair",          "ML-KEM-768"),
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan a binary's symbol table (ELF/PE/Mach-O) for known crypto function names.
/// Returns an empty vec on parse errors — symbol scanning is best-effort.
pub fn scan_symbols(path: &Path) -> Result<Vec<CryptoAsset>> {
    let data = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;

    let source = path.to_string_lossy().into_owned();
    let mut seen: HashSet<String> = HashSet::new();
    let mut assets: Vec<CryptoAsset> = Vec::new();

    match Object::parse(&data) {
        Ok(Object::Elf(elf)) => {
            for sym in elf.dynsyms.iter() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    check_symbol(name, &mut seen, &mut assets, &source);
                }
            }
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        check_symbol(name, &mut seen, &mut assets, &source);
                    }
                }
            }
        }
        Ok(Object::PE(pe)) => {
            for import in &pe.imports {
                check_symbol(&import.name, &mut seen, &mut assets, &source);
            }
            for export in &pe.exports {
                if let Some(name) = export.name {
                    check_symbol(name, &mut seen, &mut assets, &source);
                }
            }
        }
        Ok(Object::Mach(goblin::mach::Mach::Binary(mach))) => {
            scan_macho_symbols(&mach, &mut seen, &mut assets, &source);
        }
        Ok(Object::Mach(goblin::mach::Mach::Fat(fat))) => {
            // Use into_iter() (consuming) so the MachO slice has full lifetime access
            // to the data buffer — borrowed iteration yields partial MachO objects.
            for maybe_arch in fat.into_iter() {
                if let Ok(goblin::mach::SingleArch::MachO(mach)) = maybe_arch {
                    scan_macho_symbols(&mach, &mut seen, &mut assets, &source);
                    break; // first slice is sufficient for symbol detection
                }
            }
        }
        _ => {}
    }

    Ok(assets)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Scan a Mach-O binary's symbol table.
/// Uses `mach.symbols` (the raw symbol table) because `mach.imports()` does not
/// work on modern macOS binaries that use chained fixups instead of binding info.
fn scan_macho_symbols(
    mach: &goblin::mach::MachO<'_>,
    seen: &mut std::collections::HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
    source: &str,
) {
    if let Some(syms) = &mach.symbols {
        for sym in syms.iter() {
            if let Ok((raw_name, _)) = sym {
                // Strip leading underscore (Mach-O ABI convention)
                let name = raw_name.trim_start_matches('_');
                if !name.is_empty() {
                    check_symbol(name, seen, assets, source);
                }
            }
        }
    }
    // Fallback: try imports() for older binaries that use traditional binding
    if let Ok(imports) = mach.imports() {
        for import in imports {
            let name = import.name.trim_start_matches('_');
            check_symbol(name, seen, assets, source);
        }
    }
}

fn check_symbol(
    sym: &str,
    seen: &mut HashSet<String>,
    assets: &mut Vec<CryptoAsset>,
    source: &str,
) {
    if let Some(&algo) = SYMBOL_MAP.iter().find_map(|(name, algo)| {
        if *name == sym { Some(algo) } else { None }
    }) {
        push_unique(seen, assets, algo, source);
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
        evidence: Evidence::ElfSymbol,
    });
}
