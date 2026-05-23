#![forbid(unsafe_code)]

//! .acdignore suppression rule loader.
//!
//! Format (one rule per line, `#` for comments):
//!
//!   algorithm:<name>                       — suppress all findings for this algorithm
//!   path:<glob>                            — suppress findings from matching file paths
//!   path:<glob> algorithm:<name>           — suppress specific combination
//!   evidence:<type>                        — suppress by evidence type
//!
//! Glob patterns: `*` matches any non-`/` sequence; `**` matches anything.

use std::path::Path;

use anyhow::{Context, Result};

use crate::model::{asset::Evidence, CryptoAsset};

// ── Rule types ────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct IgnoreRule {
    /// Glob pattern against asset location paths (None = any path).
    path_glob: Option<String>,
    /// Algorithm name to match (None = any algorithm, case-insensitive).
    algorithm: Option<String>,
    /// Evidence type to match (None = any evidence).
    evidence: Option<String>,
}

impl IgnoreRule {
    fn matches(&self, asset: &CryptoAsset) -> bool {
        // All specified conditions must match
        if let Some(algo) = &self.algorithm {
            if !algo.eq_ignore_ascii_case(&asset.name) {
                return false;
            }
        }
        if let Some(ev) = &self.evidence {
            if !evidence_matches(ev, &asset.evidence) {
                return false;
            }
        }
        if let Some(glob) = &self.path_glob {
            let matched = asset.locations.iter().any(|loc| {
                path_glob_matches(&loc.source, glob)
            });
            if !matched {
                return false;
            }
        }
        true
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Loaded set of ignore rules. Created via `IgnoreList::load` or `IgnoreList::empty`.
pub struct IgnoreList {
    rules: Vec<IgnoreRule>,
}

impl IgnoreList {
    pub fn empty() -> Self {
        Self { rules: vec![] }
    }

    /// Load rules from an `.acdignore`-formatted file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading ignore file {}", path.display()))?;
        Ok(Self::parse(&text))
    }

    /// Parse rule text without I/O (exposed for testing).
    pub fn parse(text: &str) -> Self {
        let rules = text
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return None;
                }
                Some(parse_rule(trimmed))
            })
            .flatten()
            .collect();
        Self { rules }
    }

    /// Returns `true` if the asset should be suppressed.
    pub fn suppresses(&self, asset: &CryptoAsset) -> bool {
        self.rules.iter().any(|r| r.matches(asset))
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

// ── Rule parsing ──────────────────────────────────────────────────────────────

fn parse_rule(line: &str) -> Option<IgnoreRule> {
    let mut path_glob: Option<String> = None;
    let mut algorithm: Option<String> = None;
    let mut evidence: Option<String> = None;

    for token in line.split_whitespace() {
        if let Some(val) = token.strip_prefix("algorithm:") {
            algorithm = Some(val.to_string());
        } else if let Some(val) = token.strip_prefix("path:") {
            path_glob = Some(val.to_string());
        } else if let Some(val) = token.strip_prefix("evidence:") {
            evidence = Some(val.to_lowercase());
        } else {
            tracing::warn!("acdignore: unrecognised token '{token}' — skipping rule");
            return None;
        }
    }

    if path_glob.is_none() && algorithm.is_none() && evidence.is_none() {
        return None;
    }

    Some(IgnoreRule { path_glob, algorithm, evidence })
}

// ── Glob matching ─────────────────────────────────────────────────────────────

fn path_glob_matches(path: &str, glob: &str) -> bool {
    let path = path.replace('\\', "/");
    let glob = glob.replace('\\', "/");
    glob_match(path.as_bytes(), glob.as_bytes())
}

fn glob_match(text: &[u8], pattern: &[u8]) -> bool {
    match (text.first(), pattern.first()) {
        (_, None) => text.is_empty(),
        (_, Some(b'*')) => {
            if pattern.get(1) == Some(&b'*') {
                // `**` — match any sequence including `/`
                let rest = pattern.get(2..).unwrap_or(&[]);
                let rest = rest.strip_prefix(b"/").unwrap_or(rest);
                (0..=text.len()).any(|i| glob_match(&text[i..], rest))
            } else {
                // `*` — match any sequence except `/`
                let slash = text.iter().position(|&b| b == b'/').unwrap_or(text.len());
                let rest = &pattern[1..];
                (0..=slash).any(|i| glob_match(&text[i..], rest))
            }
        }
        (None, _) => false,
        (Some(tc), Some(pc)) => tc == pc && glob_match(&text[1..], &pattern[1..]),
    }
}

// ── Evidence matching ─────────────────────────────────────────────────────────

fn evidence_matches(spec: &str, ev: &Evidence) -> bool {
    let canonical = match ev {
        Evidence::CertificateParsing => "certificate-parsing",
        Evidence::TlsHandshake => "tls-handshake",
        Evidence::SourceCodePattern => "source-code-pattern",
        Evidence::BinaryStringSearch => "binary-string-search",
        Evidence::ConfigFileRule => "config-file-rule",
        Evidence::ManifestDependency => "manifest-dependency",
    };
    spec.eq_ignore_ascii_case(canonical)
}
