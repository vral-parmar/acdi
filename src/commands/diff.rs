#![forbid(unsafe_code)]

//! `acdi diff` — compare two CBOM files and show the cryptographic delta.

use std::collections::HashMap;

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use serde_json::Value;

use crate::cli::DiffArgs;

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
        let risk_label = risk_colored(&a.hndl_risk);
        println!(
            "  {} {} [{}] risk={} nist={}",
            "+".green().bold(),
            a.name.green(),
            a.asset_type,
            risk_label,
            a.nist_level
        );
    }

    for r in &removed {
        let risk_label = risk_colored(&r.hndl_risk);
        println!(
            "  {} {} [{}] risk={} nist={}",
            "-".red().bold(),
            r.name.red(),
            r.asset_type,
            risk_label,
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

    // Quantum-safety delta summary
    let before_vuln = before_map.values().filter(|a| a.is_vulnerable()).count();
    let after_vuln = after_map.values().filter(|a| a.is_vulnerable()).count();
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

    Ok(())
}

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
