#![forbid(unsafe_code)]

//! `acdi tls` — probe TLS endpoints and emit crypto-asset CBOMs.

use std::sync::Arc;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::cli::TlsArgs;
use crate::detect::detect_in_bytes_pem_der;
use crate::model::CryptoAsset;
use crate::output::{emit_cbom, print_table};
use crate::probe::pqc::detect_pqc_hybrid;
use crate::probe::tls::{parse_target, probe, TlsHandshakeResult};

pub async fn run(args: TlsArgs) -> Result<()> {
    let targets = collect_targets(&args)?;
    if targets.is_empty() {
        anyhow::bail!("no targets supplied — use <target> or --hosts <file>");
    }

    let sem = Arc::new(Semaphore::new(args.concurrency));
    let timeout = args.timeout;

    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} {msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=>-"),
    );

    let mut join_set: JoinSet<(TlsHandshakeResult, Vec<CryptoAsset>)> = JoinSet::new();

    for target in targets {
        let sem = Arc::clone(&sem);
        let pb = pb.clone();

        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore closed");
            let (host, port) = parse_target(&target).unwrap_or_else(|_| (target.clone(), 443));
            pb.set_message(format!("{host}:{port}"));

            let mut result = probe(&host, port, timeout).await;

            // PQC hybrid detection (best-effort, non-fatal)
            let pqc = detect_pqc_hybrid(&host, port, timeout).await;
            result.pqc_hybrid = pqc.hybrid_detected;
            if let Some(group) = &pqc.group_name {
                tracing::debug!("{host}:{port} PQC hybrid group: {group}");
            }
            if let Some(note) = &pqc.note {
                tracing::debug!("{note}");
            }

            let assets = extract_assets_from_result(&result, &host, port);
            pb.inc(1);
            (result, assets)
        });
    }

    let mut all_assets: Vec<CryptoAsset> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    while let Some(join_result) = join_set.join_next().await {
        match join_result {
            Ok((result, mut assets)) => {
                if let Some(err) = result.error {
                    errors.push(format!("{}:{} — {err}", result.host, result.port));
                } else {
                    // Inject TLS-specific fields as a synthetic asset if PQC hybrid detected
                    if result.pqc_hybrid {
                        if let Some(hybrid_asset) = pqc_hybrid_asset(&result) {
                            assets.push(hybrid_asset);
                        }
                    }
                    all_assets.append(&mut assets);
                }
            }
            Err(e) => errors.push(format!("task panic: {e}")),
        }
    }

    pb.finish_and_clear();

    for err in &errors {
        eprintln!("warn: {err}");
    }

    let cbom = emit_cbom(&all_assets);

    if let Some(out_path) = &args.output {
        std::fs::write(out_path, &cbom)
            .with_context(|| format!("writing CBOM to {}", out_path.display()))?;
        print_table(&all_assets, "TLS endpoints");
        eprintln!("Wrote CBOM to {}", out_path.display());
    } else {
        print_table(&all_assets, "TLS endpoints");
        println!("{cbom}");
    }

    Ok(())
}

fn collect_targets(args: &TlsArgs) -> Result<Vec<String>> {
    let mut targets = Vec::new();

    if let Some(t) = &args.target {
        targets.push(t.clone());
    }

    if let Some(hosts_file) = &args.hosts {
        let content = std::fs::read_to_string(hosts_file)
            .with_context(|| format!("reading hosts file {}", hosts_file.display()))?;
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                targets.push(trimmed.to_string());
            }
        }
    }

    Ok(targets)
}

fn extract_assets_from_result(
    result: &TlsHandshakeResult,
    host: &str,
    port: u16,
) -> Vec<CryptoAsset> {
    let mut assets = Vec::new();
    let source = format!("{host}:{port}");

    for cert_der in &result.peer_certs {
        match detect_in_bytes_pem_der(cert_der, &source, "certificate") {
            Ok(mut cert_assets) => assets.append(&mut cert_assets),
            Err(e) => tracing::debug!("cert parse error for {source}: {e}"),
        }
    }

    assets
}

fn pqc_hybrid_asset(result: &TlsHandshakeResult) -> Option<CryptoAsset> {
    use crate::model::{
        asset::{AssetType, Location},
        QuantumSafety, Risk,
    };
    use crate::catalog::algorithms::lookup_by_name;
    use crate::model::Primitive;

    let group = result
        .pqc_hybrid
        .then(|| "X25519MLKEM768".to_string())?;

    let source = format!("{}:{}", result.host, result.port);
    let info = lookup_by_name(&group);

    Some(CryptoAsset {
        asset_type: AssetType::Protocol,
        name: group.clone(),
        oid: None,
        primitive: Primitive::KeyAgreement,
        parameter_set: None,
        nist_quantum_security: info.map(|i| i.nist_quantum_security).unwrap_or(5),
        quantum_safe: QuantumSafety::HybridSafe,
        hndl_risk: Risk::Low,
        locations: vec![Location {
            source,
            line: None,
            column: None,
        }],
        evidence: crate::model::asset::Evidence::TlsHandshake,
    })
}
