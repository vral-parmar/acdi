#![forbid(unsafe_code)]

//! CSV output emitter — one row per occurrence, RFC 4180 compliant.

use crate::model::{
    asset::{AssetType, Evidence},
    CryptoAsset,
};

const HEADER: &str =
    "Algorithm,AssetType,QuantumSafety,HNDLRisk,NISTLevel,File,Line,Evidence\n";

pub fn emit_csv(assets: &[CryptoAsset]) -> String {
    let mut out = String::with_capacity(assets.len() * 120 + HEADER.len());
    out.push_str(HEADER);

    for asset in assets {
        if asset.locations.is_empty() {
            write_row(
                &mut out,
                &asset.name,
                format_asset_type(&asset.asset_type),
                format!("{:?}", asset.quantum_safe).to_uppercase(),
                format!("{:?}", asset.hndl_risk).to_uppercase(),
                asset.nist_quantum_security,
                "",
                None,
                format_evidence(&asset.evidence),
            );
        } else {
            for loc in &asset.locations {
                write_row(
                    &mut out,
                    &asset.name,
                    format_asset_type(&asset.asset_type),
                    format!("{:?}", asset.quantum_safe).to_uppercase(),
                    format!("{:?}", asset.hndl_risk).to_uppercase(),
                    asset.nist_quantum_security,
                    &loc.source,
                    loc.line,
                    format_evidence(&asset.evidence),
                );
            }
        }
    }

    out
}

#[allow(clippy::too_many_arguments)]
fn write_row(
    out: &mut String,
    algorithm: &str,
    asset_type: &str,
    quantum_safe: String,
    hndl_risk: String,
    nist_level: u8,
    file: &str,
    line: Option<u32>,
    evidence: &str,
) {
    out.push_str(&csv_field(algorithm));
    out.push(',');
    out.push_str(asset_type);
    out.push(',');
    out.push_str(&quantum_safe);
    out.push(',');
    out.push_str(&hndl_risk);
    out.push(',');
    out.push_str(&nist_level.to_string());
    out.push(',');
    out.push_str(&csv_field(file));
    out.push(',');
    if let Some(l) = line {
        out.push_str(&l.to_string());
    }
    out.push(',');
    out.push_str(evidence);
    out.push('\n');
}

/// RFC 4180: wrap in double-quotes if the field contains comma, quote, or newline.
/// Existing double-quotes are escaped by doubling them.
fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn format_asset_type(t: &AssetType) -> &'static str {
    match t {
        AssetType::Algorithm   => "algorithm",
        AssetType::Certificate => "certificate",
        AssetType::PrivateKey  => "private-key",
        AssetType::PublicKey   => "public-key",
        AssetType::Protocol    => "protocol",
        AssetType::Library     => "library",
    }
}

fn format_evidence(e: &Evidence) -> &'static str {
    match e {
        Evidence::CertificateParsing  => "certificate-parsing",
        Evidence::TlsHandshake        => "tls-handshake",
        Evidence::SourceCodePattern   => "source-code-pattern",
        Evidence::BinaryStringSearch  => "binary-string-search",
        Evidence::ConfigFileRule      => "config-file-rule",
        Evidence::ManifestDependency  => "manifest-dependency",
        Evidence::ElfSymbol           => "elf-symbol",
        Evidence::JarClassFile        => "jar-class-file",
    }
}
