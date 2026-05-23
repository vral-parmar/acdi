#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{bail, Result};
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

use crate::cli::{FailOn, OutputFormat, ScanArgs};
use crate::detect::detect_in_file;
use crate::ignore::IgnoreList;
use crate::model::{CryptoAsset, Risk};
use crate::output::{emit_cbom, emit_csv, emit_html, emit_sarif, print_table};

pub fn run(args: ScanArgs) -> Result<()> {
    let scan_root = args
        .path
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("Cannot access path '{}': {}", args.path.display(), e))?;

    tracing::debug!("Scanning {}", scan_root.display());

    let files = collect_files(&scan_root, args.follow_links);

    if files.is_empty() {
        eprintln!("No files to scan in '{}'.", scan_root.display());
        return Ok(());
    }

    let pb = if !args.quiet {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        Some(pb)
    } else {
        None
    };

    // Parallel scan across all files
    let results: Vec<Vec<CryptoAsset>> = files
        .par_iter()
        .map(|path| {
            if let Some(pb) = &pb {
                pb.set_message(
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string(),
                );
                pb.inc(1);
            }
            match detect_in_file(path) {
                Ok(assets) => assets,
                Err(e) => {
                    tracing::warn!("Error scanning {}: {}", path.display(), e);
                    vec![]
                }
            }
        })
        .collect();

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    let mut assets: Vec<CryptoAsset> = results.into_iter().flatten().collect();

    // Apply .acdignore suppression
    let ignore = load_ignore(&scan_root, &args);
    if !ignore.is_empty() {
        let before = assets.len();
        assets.retain(|a| !ignore.suppresses(a));
        let suppressed = before - assets.len();
        if suppressed > 0 {
            tracing::debug!("Suppressed {suppressed} finding(s) via ignore rules");
        }
    }

    // Sort by severity descending for display
    assets.sort_by(|a, b| b.hndl_risk.cmp(&a.hndl_risk));

    // Emit output
    let scan_root_str = scan_root.to_string_lossy();
    let output_str = match args.format {
        OutputFormat::Sarif       => emit_sarif(&assets)?,
        OutputFormat::Html        => emit_html(&assets, &scan_root_str)?,
        OutputFormat::CycloneDx17 => emit_cbom(&assets),
        OutputFormat::Csv         => emit_csv(&assets),
    };

    // Output routing:
    //   --quiet             → output to stdout (pipe-friendly)
    //   --output file       → write to file; human table to stdout
    //   default             → human table to stdout; hint to use --output
    let label = match args.format {
        OutputFormat::Sarif       => "SARIF",
        OutputFormat::Html        => "HTML report",
        OutputFormat::CycloneDx17 => "CBOM",
        OutputFormat::Csv         => "CSV",
    };

    match (&args.output, args.quiet) {
        (_, true) => {
            if let Some(out_path) = &args.output {
                std::fs::write(out_path, output_str.as_bytes()).map_err(|e| {
                    anyhow::anyhow!("Writing {} to '{}': {}", label, out_path.display(), e)
                })?;
            } else {
                // Avoid double newline when the format already ends with \n (CSV, HTML)
                let s = output_str.trim_end_matches('\n');
                println!("{s}");
            }
        }
        (Some(out_path), false) => {
            std::fs::write(out_path, output_str.as_bytes()).map_err(|e| {
                anyhow::anyhow!("Writing {} to '{}': {}", label, out_path.display(), e)
            })?;
            print_table(&assets, &scan_root_str);
            println!("✓ {label} written → {}", out_path.display());
        }
        (None, false) => {
            print_table(&assets, &scan_root_str);
            println!(
                "  💡 Use --output report.html --format html for the migration report."
            );
        }
    }

    // --fail-on exit code
    if let Some(threshold) = args.fail_on {
        let threshold_risk = fail_on_to_risk(&threshold);
        let exceeded = assets.iter().any(|a| a.hndl_risk >= threshold_risk);
        if exceeded {
            bail!(
                "Failing: one or more assets meet or exceed risk threshold {:?}",
                threshold
            );
        }
    }

    Ok(())
}

fn collect_files(root: &Path, follow_links: bool) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let walk = WalkBuilder::new(root)
        .follow_links(follow_links)
        .hidden(false)
        .build();

    for entry in walk.flatten() {
        let path = entry.path().to_path_buf();
        if path.is_file() {
            files.push(path);
        }
    }

    files
}

fn fail_on_to_risk(fail_on: &FailOn) -> Risk {
    match fail_on {
        FailOn::Low => Risk::Low,
        FailOn::Medium => Risk::Medium,
        FailOn::High => Risk::High,
        FailOn::Critical => Risk::Critical,
    }
}

fn load_ignore(scan_root: &Path, args: &crate::cli::ScanArgs) -> IgnoreList {
    if args.no_ignore {
        return IgnoreList::empty();
    }
    let path = args
        .ignore_file
        .clone()
        .unwrap_or_else(|| scan_root.join(".acdignore"));
    if path.exists() {
        match IgnoreList::load(&path) {
            Ok(list) => {
                tracing::debug!("Loaded {} ignore rule(s) from {}", list.len(), path.display());
                list
            }
            Err(e) => {
                tracing::warn!("Failed to load ignore file {}: {}", path.display(), e);
                IgnoreList::empty()
            }
        }
    } else {
        IgnoreList::empty()
    }
}
