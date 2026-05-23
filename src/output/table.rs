#![forbid(unsafe_code)]

use comfy_table::{Cell, CellAlignment, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;

use crate::model::{CryptoAsset, QuantumSafety, Risk};

/// Print a human-readable summary table to stdout.
pub fn print_table(assets: &[CryptoAsset], path: &str) {
    if assets.is_empty() {
        println!(
            "{}",
            "No cryptographic assets found.".yellow()
        );
        return;
    }

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Asset").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("Type").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("Quantum Safety").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("HNDL Risk").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("NIST Lvl").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("Location").add_attribute(comfy_table::Attribute::Bold),
        ]);

    for asset in assets {
        let (qs_cell, risk_cell) = styled_cells(&asset.quantum_safe, &asset.hndl_risk);

        let location = asset
            .locations
            .first()
            .map(|l| shorten_path(&l.source, path))
            .unwrap_or_default();

        table.add_row(vec![
            Cell::new(&asset.name),
            Cell::new(format!("{:?}", asset.asset_type)),
            qs_cell,
            risk_cell,
            Cell::new(asset.nist_quantum_security.to_string())
                .set_alignment(CellAlignment::Center),
            Cell::new(location),
        ]);
    }

    println!("\n{table}\n");
    print_summary(assets);
}

fn styled_cells(qs: &QuantumSafety, risk: &Risk) -> (Cell, Cell) {
    let qs_cell = match qs {
        QuantumSafety::Vulnerable => {
            Cell::new("VULNERABLE").fg(Color::Red)
        }
        QuantumSafety::Safe => {
            Cell::new("SAFE").fg(Color::Green)
        }
        QuantumSafety::ClassicallyAdequate => {
            Cell::new("ADEQUATE").fg(Color::Yellow)
        }
        QuantumSafety::HybridSafe => {
            Cell::new("HYBRID SAFE").fg(Color::Cyan)
        }
        QuantumSafety::Unknown => {
            Cell::new("UNKNOWN").fg(Color::Grey)
        }
    };

    let risk_cell = match risk {
        Risk::Critical => Cell::new("CRITICAL").fg(Color::Red),
        Risk::High => Cell::new("HIGH").fg(Color::Red),
        Risk::Medium => Cell::new("MEDIUM").fg(Color::Yellow),
        Risk::Low => Cell::new("LOW").fg(Color::Cyan),
        Risk::None => Cell::new("NONE").fg(Color::Green),
    };

    (qs_cell, risk_cell)
}

fn print_summary(assets: &[CryptoAsset]) {
    let critical = assets.iter().filter(|a| a.hndl_risk == Risk::Critical).count();
    let high = assets.iter().filter(|a| a.hndl_risk == Risk::High).count();
    let medium = assets.iter().filter(|a| a.hndl_risk == Risk::Medium).count();
    let low = assets.iter().filter(|a| a.hndl_risk == Risk::Low).count();
    let safe = assets.iter().filter(|a| a.hndl_risk == Risk::None).count();
    let vulnerable = assets
        .iter()
        .filter(|a| a.quantum_safe == QuantumSafety::Vulnerable)
        .count();

    println!(
        "Found {} asset(s) — {} quantum-vulnerable",
        assets.len(),
        vulnerable
    );

    if critical > 0 {
        println!("  {} CRITICAL", critical.to_string().red());
    }
    if high > 0 {
        println!("  {} HIGH", high.to_string().red());
    }
    if medium > 0 {
        println!("  {} MEDIUM", medium.to_string().yellow());
    }
    if low > 0 {
        println!("  {} LOW", low.to_string().cyan());
    }
    if safe > 0 {
        println!("  {} NONE/SAFE", safe.to_string().green());
    }
    println!();
}

/// Shorten an absolute path relative to the scan root for compact display.
fn shorten_path(source: &str, root: &str) -> String {
    if let Some(rel) = source.strip_prefix(root) {
        rel.trim_start_matches('/').trim_start_matches('\\').to_string()
    } else {
        source.to_string()
    }
}
