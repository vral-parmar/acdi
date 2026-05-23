#![forbid(unsafe_code)]

//! PQC hybrid detection via `openssl s_client`.
//!
//! OpenSSL 3.5+ supports X25519MLKEM768 and P256MLKEM768 groups.
//! We shell out to `openssl s_client` and inspect the output for evidence
//! of PQC hybrid key exchange. The probe degrades gracefully on LibreSSL
//! or older OpenSSL versions.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;
use tokio::time::timeout;

/// Result of the PQC hybrid detection probe.
#[derive(Debug, Clone, Default)]
pub struct PqcProbeResult {
    /// Whether any PQC hybrid group was detected in the handshake.
    pub hybrid_detected: bool,
    /// The negotiated KEM group name if detectable (e.g. "X25519MLKEM768").
    pub group_name: Option<String>,
    /// Raw openssl version string for diagnostics.
    pub openssl_version: Option<String>,
    /// Non-fatal notes about why detection was skipped.
    pub note: Option<String>,
}

/// Attempt PQC hybrid detection against `host:port`.
///
/// Returns `Ok(PqcProbeResult)` even on soft failures (unsupported openssl,
/// timeout). Hard errors (I/O, argument injection) bubble up as `Err`.
pub async fn detect_pqc_hybrid(host: &str, port: u16, timeout_secs: u64) -> PqcProbeResult {
    match detect_inner(host, port, timeout_secs).await {
        Ok(r) => r,
        Err(e) => PqcProbeResult {
            note: Some(format!("PQC probe failed: {e}")),
            ..Default::default()
        },
    }
}

async fn detect_inner(
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<PqcProbeResult> {
    // Reject any characters that could escape the argument list.
    if !host
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        anyhow::bail!("invalid hostname: '{host}'");
    }

    let version = openssl_version().await?;

    // LibreSSL and old OpenSSL don't support PQC groups.
    if version.starts_with("LibreSSL") || !supports_mlkem(&version) {
        return Ok(PqcProbeResult {
            openssl_version: Some(version.clone()),
            note: Some(format!("{version} does not support ML-KEM groups; skipping PQC probe")),
            ..Default::default()
        });
    }

    let output = timeout(
        Duration::from_secs(timeout_secs + 2),
        Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &format!("{host}:{port}"),
                "-groups",
                "X25519MLKEM768:P256MLKEM768:X25519:P-256:P-384",
                "-brief",
            ])
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await
    .context("openssl s_client timed out")?
    .context("openssl s_client spawn failed")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    let (hybrid_detected, group_name) = parse_kem_group(&combined);

    Ok(PqcProbeResult {
        hybrid_detected,
        group_name,
        openssl_version: Some(version),
        note: None,
    })
}

/// Parse `openssl version` output, returning the version string.
async fn openssl_version() -> Result<String> {
    let output = Command::new("openssl")
        .arg("version")
        .output()
        .await
        .context("failed to run `openssl version`")?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Determine whether the openssl version string indicates >= 3.5 with ML-KEM support.
fn supports_mlkem(version: &str) -> bool {
    // e.g. "OpenSSL 3.5.0 ..."
    if let Some(ver_part) = version.strip_prefix("OpenSSL ") {
        let parts: Vec<&str> = ver_part.split(' ').next().unwrap_or("").split('.').collect();
        if parts.len() >= 2 {
            let major: u32 = parts[0].parse().unwrap_or(0);
            let minor: u32 = parts[1].parse().unwrap_or(0);
            return major > 3 || (major == 3 && minor >= 5);
        }
    }
    false
}

/// Look for PQC KEM group names in openssl s_client output.
fn parse_kem_group(output: &str) -> (bool, Option<String>) {
    for line in output.lines() {
        let lower = line.to_lowercase();
        // openssl -brief shows "Server Temp Key: X25519MLKEM768, ..."
        if lower.contains("x25519mlkem768") {
            return (true, Some("X25519MLKEM768".to_string()));
        }
        if lower.contains("p256mlkem768") {
            return (true, Some("P256MLKEM768".to_string()));
        }
        // Also check generic "group" line
        if lower.contains("mlkem") {
            let group = line
                .split_whitespace()
                .find(|t| t.to_lowercase().contains("mlkem"))
                .unwrap_or("ML-KEM (unknown)")
                .to_string();
            return (true, Some(group));
        }
    }
    (false, None)
}
