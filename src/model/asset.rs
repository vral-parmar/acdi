#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use super::{QuantumSafety, Risk};

/// A single detected cryptographic asset — algorithm, certificate, key, protocol, or library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAsset {
    pub asset_type: AssetType,
    /// Human-readable name, e.g. "RSA-2048", "ML-KEM-768", "TLS_AES_256_GCM_SHA384"
    pub name: String,
    /// ASN.1 OID if applicable, e.g. "1.2.840.113549.1.1.11"
    pub oid: Option<String>,
    pub primitive: Primitive,
    /// Key size, curve name, or NIST parameter set, e.g. "2048", "P-256", "768"
    pub parameter_set: Option<String>,
    /// NIST quantum security level (0 = broken classically, 1–5 = post-quantum levels)
    pub nist_quantum_security: u8,
    pub quantum_safe: QuantumSafety,
    pub hndl_risk: Risk,
    pub locations: Vec<Location>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AssetType {
    Algorithm,
    Certificate,
    PrivateKey,
    PublicKey,
    Protocol,
    Library,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Primitive {
    PublicKeyEncryption,
    KeyEncapsulationMechanism,
    DigitalSignature,
    KeyDerivation,
    KeyAgreement,
    BlockCipher,
    StreamCipher,
    Hash,
    Mac,
    /// Post-quantum KEM (ML-KEM / Kyber)
    PostQuantumKem,
    /// Post-quantum signature (ML-DSA / Dilithium, SLH-DSA / SPHINCS+)
    PostQuantumSignature,
    Other,
}

/// Where in the filesystem or network this asset was found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Canonicalized file path or TLS endpoint string
    pub source: String,
    /// Line number inside the file (None for binary/cert parsing)
    pub line: Option<u32>,
    /// Column number (for source-code findings)
    pub column: Option<u32>,
}

/// How the asset was detected — used for audit trail in the CBOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Evidence {
    /// Parsed directly from a certificate or key file
    CertificateParsing,
    /// Found by probing a TLS endpoint handshake
    TlsHandshake,
    /// Matched a regex pattern in source code
    SourceCodePattern,
    /// Found in binary string search (OID or algorithm name string)
    BinaryStringSearch,
    /// Matched a rule against a configuration file
    ConfigFileRule,
    /// Found as a declared dependency in a package manifest (Cargo.toml, package.json, etc.)
    ManifestDependency,
    /// Found by parsing the symbol table of an ELF, PE, or Mach-O binary
    ElfSymbol,
    /// Found in the constant pool of a Java class file (direct or inside a JAR)
    JarClassFile,
}
