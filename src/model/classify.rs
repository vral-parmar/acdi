#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Quantum safety classification per NIST IR 8547.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuantumSafety {
    /// Broken by Shor's algorithm (RSA, ECC, DSA, DH, ECDH, ECDSA)
    Vulnerable,
    /// Post-quantum standardized (ML-KEM, ML-DSA, SLH-DSA, HQC)
    Safe,
    /// Classical algorithm with sufficient key size to resist Grover's (AES-256, SHA-384+)
    ClassicallyAdequate,
    /// Hybrid: classical + PQC (e.g. X25519MLKEM768)
    HybridSafe,
    /// Algorithm not in catalog or insufficient information
    Unknown,
}

impl std::fmt::Display for QuantumSafety {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuantumSafety::Vulnerable => write!(f, "VULNERABLE"),
            QuantumSafety::Safe => write!(f, "SAFE"),
            QuantumSafety::ClassicallyAdequate => write!(f, "CLASSICALLY ADEQUATE"),
            QuantumSafety::HybridSafe => write!(f, "HYBRID SAFE"),
            QuantumSafety::Unknown => write!(f, "UNKNOWN"),
        }
    }
}
