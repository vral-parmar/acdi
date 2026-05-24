#![forbid(unsafe_code)]

//! SARIF 2.1.0 output emitter.
//!
//! Static Analysis Results Interchange Format — used by GitHub Code Scanning,
//! VS Code SARIF viewer, and most CI security dashboards.
//! Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use std::collections::HashMap;

use serde::Serialize;

use crate::model::{asset::Evidence, CryptoAsset, Risk};

// ── SARIF document types ──────────────────────────────────────────────────────

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: &'static str,
    information_uri: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifText,
    full_description: SarifText,
    default_configuration: SarifConfiguration,
    help: SarifText,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    tags: Vec<&'static str>,
    precision: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: &'static str,
    message: SarifText,
    locations: Vec<SarifLocation>,
    properties: SarifResultProperties,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResultProperties {
    quantum_safe: String,
    hndl_risk: String,
    nist_level: u8,
    evidence: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
}

#[derive(Serialize)]
struct SarifText {
    text: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn emit_sarif(assets: &[CryptoAsset]) -> anyhow::Result<String> {
    // Build deduplicated rule list (one rule per unique algorithm name)
    let mut rule_order: Vec<String> = Vec::new();
    let mut rules_map: HashMap<String, SarifRule> = HashMap::new();

    for asset in assets {
        let rule_id = rule_id_for(&asset.name);
        if rules_map.contains_key(&rule_id) {
            continue;
        }
        rule_order.push(rule_id.clone());
        rules_map.insert(
            rule_id.clone(),
            SarifRule {
                id: rule_id,
                name: sanitize_id(&asset.name),
                short_description: SarifText {
                    text: format!(
                        "{} — quantum safety: {}",
                        asset.name,
                        format_qs(&asset.quantum_safe)
                    ),
                },
                full_description: SarifText {
                    text: format!(
                        "{} has HNDL risk {} and NIST quantum security level {}. \
                         Deprecated by NIST IR 8547 by 2030: {}. Removed by 2035: {}.",
                        asset.name,
                        format_risk(&asset.hndl_risk),
                        asset.nist_quantum_security,
                        asset.nist_quantum_security == 0,
                        asset.nist_quantum_security == 0,
                    ),
                },
                default_configuration: SarifConfiguration {
                    level: risk_to_level(&asset.hndl_risk),
                },
                help: SarifText {
                    text: format!(
                        "Replace {} with a NIST-approved post-quantum algorithm \
                         (ML-KEM-768 for key encapsulation, ML-DSA-65 for signatures).",
                        asset.name
                    ),
                },
                properties: SarifRuleProperties {
                    tags: rule_tags(&asset.hndl_risk),
                    precision: "high",
                },
            },
        );
    }

    let rules: Vec<SarifRule> = rule_order
        .into_iter()
        .filter_map(|id| rules_map.remove(&id))
        .collect();

    // Build results — one per (asset, location) pair
    let results: Vec<SarifResult> = assets
        .iter()
        .flat_map(|asset| {
            let rule_id = rule_id_for(&asset.name);
            let level = risk_to_level(&asset.hndl_risk);
            asset.locations.iter().map(move |loc| SarifResult {
                rule_id: rule_id.clone(),
                level,
                message: SarifText {
                    text: format!(
                        "{} is {} (HNDL risk: {}, NIST level: {}). \
                         Consider migrating to a post-quantum alternative.",
                        asset.name,
                        format_qs(&asset.quantum_safe),
                        format_risk(&asset.hndl_risk),
                        asset.nist_quantum_security,
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: loc.source.clone(),
                        },
                        region: loc.line.map(|l| SarifRegion {
                            start_line: l,
                            start_column: loc.column,
                        }),
                    },
                }],
                properties: SarifResultProperties {
                    quantum_safe: format!("{:?}", asset.quantum_safe),
                    hndl_risk: format!("{:?}", asset.hndl_risk),
                    nist_level: asset.nist_quantum_security,
                    evidence: format_evidence(&asset.evidence),
                },
            })
        })
        .collect();

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "acdi",
                    information_uri: "https://github.com/acdi-tool/acdi",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results,
        }],
    };

    Ok(serde_json::to_string_pretty(&log)?)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rule_id_for(algo_name: &str) -> String {
    format!("ACDI-{}", sanitize_id(algo_name))
}

fn sanitize_id(name: &str) -> String {
    name.replace(' ', "-")
}

fn risk_to_level(risk: &Risk) -> &'static str {
    match risk {
        Risk::Critical | Risk::High => "error",
        Risk::Medium => "warning",
        Risk::Low => "note",
        Risk::None => "none",
    }
}

fn rule_tags(risk: &Risk) -> Vec<&'static str> {
    match risk {
        Risk::Critical => vec!["security", "cryptography", "pqc", "critical"],
        Risk::High => vec!["security", "cryptography", "pqc", "high"],
        Risk::Medium => vec!["security", "cryptography", "pqc"],
        _ => vec!["cryptography", "pqc"],
    }
}

fn format_qs(qs: &crate::model::QuantumSafety) -> &'static str {
    match qs {
        crate::model::QuantumSafety::Safe => "SAFE",
        crate::model::QuantumSafety::HybridSafe => "HYBRID-SAFE",
        crate::model::QuantumSafety::ClassicallyAdequate => "ADEQUATE",
        crate::model::QuantumSafety::Vulnerable => "VULNERABLE",
        crate::model::QuantumSafety::Unknown => "UNKNOWN",
    }
}

fn format_risk(risk: &Risk) -> &'static str {
    match risk {
        Risk::Critical => "CRITICAL",
        Risk::High => "HIGH",
        Risk::Medium => "MEDIUM",
        Risk::Low => "LOW",
        Risk::None => "NONE",
    }
}

fn format_evidence(ev: &Evidence) -> String {
    match ev {
        Evidence::CertificateParsing => "certificate-parsing".to_string(),
        Evidence::TlsHandshake => "tls-handshake".to_string(),
        Evidence::SourceCodePattern => "source-code-pattern".to_string(),
        Evidence::BinaryStringSearch => "binary-string-search".to_string(),
        Evidence::ConfigFileRule => "config-file-rule".to_string(),
        Evidence::ManifestDependency => "manifest-dependency".to_string(),
        Evidence::ElfSymbol => "elf-symbol".to_string(),
        Evidence::JarClassFile => "jar-class-file".to_string(),
    }
}
