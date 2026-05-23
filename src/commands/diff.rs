#![forbid(unsafe_code)]

//! `acdi diff` — compare two CBOM files and show the cryptographic delta.

use std::collections::HashMap;

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::Value;

use crate::cli::{DiffArgs, DiffFormat};

#[derive(Debug)]
struct AssetSummary {
    name: String,
    quantum_safe: String,
    hndl_risk: String,
    nist_level: String,
    asset_type: String,
}

impl AssetSummary {
    fn from_component(comp: &Value) -> Self {
        let props = prop_map(comp);
        AssetSummary {
            name: comp["name"].as_str().unwrap_or("unknown").to_string(),
            quantum_safe: props
                .get("acdi:quantum_safe")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            hndl_risk: props
                .get("acdi:hndl_risk")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            nist_level: props
                .get("acdi:nist_level")
                .cloned()
                .unwrap_or_else(|| "0".to_string()),
            asset_type: comp["cryptoProperties"]["assetType"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
        }
    }

    fn is_vulnerable(&self) -> bool {
        self.quantum_safe.eq_ignore_ascii_case("vulnerable")
    }
}

// ── JSON output types ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct DiffOutput<'a> {
    before: &'a str,
    after: &'a str,
    summary: DiffSummary,
    added: Vec<AssetEntry>,
    removed: Vec<AssetEntry>,
    changed: Vec<ChangedEntry>,
}

#[derive(Serialize)]
struct DiffSummary {
    added: usize,
    removed: usize,
    changed: usize,
    unchanged: usize,
    vulnerable_before: usize,
    vulnerable_after: usize,
}

#[derive(Serialize)]
struct AssetEntry {
    name: String,
    asset_type: String,
    hndl_risk: String,
    quantum_safe: String,
    nist_level: String,
}

#[derive(Serialize)]
struct ChangedEntry {
    name: String,
    asset_type: String,
    before: FieldDelta,
    after: FieldDelta,
}

#[derive(Serialize)]
struct FieldDelta {
    quantum_safe: String,
    hndl_risk: String,
    nist_level: String,
}

impl AssetEntry {
    fn from(a: &AssetSummary) -> Self {
        AssetEntry {
            name: a.name.clone(),
            asset_type: a.asset_type.clone(),
            hndl_risk: a.hndl_risk.clone(),
            quantum_safe: a.quantum_safe.clone(),
            nist_level: a.nist_level.clone(),
        }
    }
}

// ── Command entry point ───────────────────────────────────────────────────────

pub fn run(args: DiffArgs) -> Result<()> {
    let before_raw = std::fs::read_to_string(&args.before)
        .with_context(|| format!("reading {}", args.before.display()))?;
    let after_raw = std::fs::read_to_string(&args.after)
        .with_context(|| format!("reading {}", args.after.display()))?;

    let before: Value = serde_json::from_str(&before_raw)
        .with_context(|| format!("parsing {}", args.before.display()))?;
    let after: Value = serde_json::from_str(&after_raw)
        .with_context(|| format!("parsing {}", args.after.display()))?;

    let before_map = component_map(&before);
    let after_map = component_map(&after);

    let mut added: Vec<&AssetSummary> = Vec::new();
    let mut removed: Vec<&AssetSummary> = Vec::new();
    let mut changed: Vec<(&AssetSummary, &AssetSummary)> = Vec::new();
    let mut unchanged_count = 0usize;

    for (name, after_asset) in &after_map {
        match before_map.get(name) {
            None => added.push(after_asset),
            Some(before_asset) => {
                if before_asset.quantum_safe != after_asset.quantum_safe
                    || before_asset.hndl_risk != after_asset.hndl_risk
                    || before_asset.nist_level != after_asset.nist_level
                {
                    changed.push((before_asset, after_asset));
                } else {
                    unchanged_count += 1;
                }
            }
        }
    }
    for (name, asset) in &before_map {
        if !after_map.contains_key(name) {
            removed.push(asset);
        }
    }

    added.sort_by(|a, b| a.name.cmp(&b.name));
    removed.sort_by(|a, b| a.name.cmp(&b.name));
    changed.sort_by(|a, b| a.0.name.cmp(&b.0.name));

    let before_vuln = before_map.values().filter(|a| a.is_vulnerable()).count();
    let after_vuln = after_map.values().filter(|a| a.is_vulnerable()).count();

    match args.format {
        DiffFormat::Json => {
            let out = DiffOutput {
                before: args.before.to_str().unwrap_or(""),
                after: args.after.to_str().unwrap_or(""),
                summary: DiffSummary {
                    added: added.len(),
                    removed: removed.len(),
                    changed: changed.len(),
                    unchanged: unchanged_count,
                    vulnerable_before: before_vuln,
                    vulnerable_after: after_vuln,
                },
                added: added.iter().map(|a| AssetEntry::from(a)).collect(),
                removed: removed.iter().map(|a| AssetEntry::from(a)).collect(),
                changed: changed
                    .iter()
                    .map(|(b, a)| ChangedEntry {
                        name: b.name.clone(),
                        asset_type: b.asset_type.clone(),
                        before: FieldDelta {
                            quantum_safe: b.quantum_safe.clone(),
                            hndl_risk: b.hndl_risk.clone(),
                            nist_level: b.nist_level.clone(),
                        },
                        after: FieldDelta {
                            quantum_safe: a.quantum_safe.clone(),
                            hndl_risk: a.hndl_risk.clone(),
                            nist_level: a.nist_level.clone(),
                        },
                    })
                    .collect(),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }

        DiffFormat::Text => {
            println!(
                "CBOM diff: {} → {}",
                args.before.display(),
                args.after.display()
            );
            println!(
                "  {} added   {} removed   {} changed   {} unchanged\n",
                added.len(),
                removed.len(),
                changed.len(),
                unchanged_count,
            );

            for a in &added {
                println!(
                    "  {} {} [{}] risk={} nist={}",
                    "+".green().bold(),
                    a.name.green(),
                    a.asset_type,
                    risk_colored(&a.hndl_risk),
                    a.nist_level
                );
            }

            for r in &removed {
                println!(
                    "  {} {} [{}] risk={} nist={}",
                    "-".red().bold(),
                    r.name.red(),
                    r.asset_type,
                    risk_colored(&r.hndl_risk),
                    r.nist_level
                );
            }

            for (before_a, after_a) in &changed {
                println!(
                    "  {} {} [{}]",
                    "~".yellow().bold(),
                    before_a.name.yellow(),
                    before_a.asset_type
                );
                if before_a.quantum_safe != after_a.quantum_safe {
                    println!(
                        "      quantum_safe: {} → {}",
                        qs_colored(&before_a.quantum_safe),
                        qs_colored(&after_a.quantum_safe)
                    );
                }
                if before_a.hndl_risk != after_a.hndl_risk {
                    println!(
                        "      hndl_risk:    {} → {}",
                        risk_colored(&before_a.hndl_risk),
                        risk_colored(&after_a.hndl_risk)
                    );
                }
                if before_a.nist_level != after_a.nist_level {
                    println!(
                        "      nist_level:   {} → {}",
                        before_a.nist_level, after_a.nist_level
                    );
                }
            }

            if before_vuln != after_vuln {
                println!();
                let delta = after_vuln as i64 - before_vuln as i64;
                let arrow = if delta > 0 {
                    format!("▲ {delta}").red().to_string()
                } else {
                    format!("▼ {}", delta.unsigned_abs()).green().to_string()
                };
                println!(
                    "  Quantum-vulnerable assets: {} → {} ({})",
                    before_vuln, after_vuln, arrow
                );
            }
        }
    }

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn component_map(bom: &Value) -> HashMap<String, AssetSummary> {
    bom["components"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let name = c["name"].as_str()?.to_string();
                    Some((name, AssetSummary::from_component(c)))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn prop_map(comp: &Value) -> HashMap<String, String> {
    comp["properties"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let k = p["name"].as_str()?.to_string();
                    let v = p["value"].as_str()?.to_string();
                    Some((k, v))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn risk_colored(risk: &str) -> String {
    match risk.to_lowercase().as_str() {
        "critical" => risk.red().bold().to_string(),
        "high" => risk.yellow().to_string(),
        "medium" => risk.bright_yellow().to_string(),
        "low" => risk.cyan().to_string(),
        _ => risk.to_string(),
    }
}

fn qs_colored(qs: &str) -> String {
    match qs.to_lowercase().as_str() {
        "vulnerable" => qs.red().bold().to_string(),
        "safe" => qs.green().to_string(),
        _ => qs.to_string(),
    }
}
