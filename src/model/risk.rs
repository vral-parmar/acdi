#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Harvest-Now-Decrypt-Later (HNDL) risk level.
///
/// Critical = long-lived data protected by classical asymmetric crypto, interceptable today.
/// High     = quantum-vulnerable, medium data lifetime.
/// Medium   = symmetric crypto with marginal key size (AES-128) or deprecated hash.
/// Low      = deprecated but unlikely to be exploited classically (SHA-1 with no collision path).
/// None     = post-quantum algorithm, no known risk.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Risk {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Risk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Risk::None => write!(f, "NONE"),
            Risk::Low => write!(f, "LOW"),
            Risk::Medium => write!(f, "MEDIUM"),
            Risk::High => write!(f, "HIGH"),
            Risk::Critical => write!(f, "CRITICAL"),
        }
    }
}
