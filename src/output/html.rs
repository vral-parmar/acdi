#![forbid(unsafe_code)]

//! HTML migration report emitter.
//!
//! Produces a self-contained single-file HTML report with:
//! - Executive summary cards
//! - NIST IR 8547 compliance timeline
//! - Sortable/filterable findings table
//! - Per-algorithm remediation guide
//! - Scan statistics breakdown

use chrono::Utc;

use crate::model::{asset::{AssetType, Evidence}, CryptoAsset, QuantumSafety, Risk};

// ── Remediation advice table ──────────────────────────────────────────────────

/// (algorithm name prefix, replacement recommendation, NIST reference)
static REMEDIATION: &[(&str, &str, &str)] = &[
    ("RSA", "ML-KEM-768 (FIPS 203) for key encapsulation · ML-DSA-65 (FIPS 204) for signatures", "NIST IR 8547 · NSA CNSA 2.0"),
    ("ECDSA", "ML-DSA-65 (FIPS 204) for digital signatures", "NIST IR 8547"),
    ("ECDH", "ML-KEM-768 (FIPS 203) for key encapsulation", "NIST IR 8547"),
    ("Ed25519", "ML-DSA-65 (FIPS 204) for digital signatures", "NIST IR 8547"),
    ("X25519", "ML-KEM-768 (FIPS 203) for key agreement", "NIST IR 8547"),
    ("DSA", "ML-DSA-65 (FIPS 204) for digital signatures", "NIST IR 8547"),
    ("DH-", "ML-KEM-768 (FIPS 203) for key encapsulation", "NIST IR 8547"),
    ("SHA-1", "SHA-256 or SHA-3-256 (already adequate against quantum)", "NIST SP 800-131A"),
    ("MD5", "SHA-256 · immediate replacement required — classically broken", "NIST SP 800-131A"),
    ("MD4", "SHA-256 · immediate replacement required — classically broken", "NIST SP 800-131A"),
    ("DES", "AES-256-GCM · immediate replacement required — classically broken", "NIST SP 800-131A rev.2"),
    ("3DES", "AES-256-GCM · replace during next maintenance cycle", "NIST SP 800-131A rev.2"),
    ("RC4", "AES-256-GCM · immediate replacement required — classically broken", "NIST SP 800-131A"),
    ("RC2", "AES-256-GCM · immediate replacement required — classically broken", "NIST SP 800-131A"),
    ("AES-128", "AES-256 for full CNSA 2.0 compliance (Grover halves key length)", "NSA CNSA 2.0"),
    ("AES-192", "AES-256 recommended for CNSA 2.0 compliance", "NSA CNSA 2.0"),
];

fn remediation_for(algo: &str) -> Option<(&'static str, &'static str)> {
    REMEDIATION.iter().find_map(|(prefix, repl, reference)| {
        if algo.starts_with(prefix) { Some((*repl, *reference)) } else { None }
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn emit_html(assets: &[CryptoAsset], scan_path: &str) -> anyhow::Result<String> {
    let now = Utc::now();
    let timestamp = now.format("%Y-%m-%d %H:%M UTC").to_string();
    let current_year: u32 = now.format("%Y").to_string().parse().unwrap_or(2026);
    let version = env!("CARGO_PKG_VERSION");

    let total = assets.len();
    let critical = count(assets, Risk::Critical);
    let high     = count(assets, Risk::High);
    let medium   = count(assets, Risk::Medium);
    let low      = count(assets, Risk::Low);
    let safe     = count(assets, Risk::None);
    let vulnerable = assets.iter().filter(|a| a.quantum_safe == QuantumSafety::Vulnerable).count();

    let mut out = String::with_capacity(128 * 1024);

    // ── Document head ──────────────────────────────────────────────────────
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"UTF-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    out.push_str("<title>acdi \u{2014} Crypto Migration Report</title>\n");
    out.push_str("<style>\n");
    out.push_str(CSS);
    out.push_str("</style>\n</head>\n<body>\n");

    // ── Header ─────────────────────────────────────────────────────────────
    out.push_str("<header><div class=\"container\">\n");
    out.push_str("<h1>&#x1F512; Cryptographic Asset Migration Report</h1>\n");
    out.push_str(&format!(
        "<p class=\"meta\">Scan path: <code>{}</code> &nbsp;&bull;&nbsp; \
         Generated: {} &nbsp;&bull;&nbsp; Tool: acdi v{}</p>\n",
        he(scan_path), timestamp, version
    ));
    out.push_str("</div></header>\n<main class=\"container\">\n");

    // ── Summary cards ──────────────────────────────────────────────────────
    out.push_str("<section>\n<h2>Executive Summary</h2>\n<div class=\"cards\">\n");
    out.push_str(&card("total", &total.to_string(), "Total Findings"));
    out.push_str(&card("vuln",  &vulnerable.to_string(), "Quantum-Vulnerable"));
    out.push_str(&card("critical", &critical.to_string(), "CRITICAL"));
    out.push_str(&card("high",     &high.to_string(),     "HIGH"));
    out.push_str(&card("medium",   &medium.to_string(),   "MEDIUM"));
    out.push_str(&card("low",      &low.to_string(),      "LOW"));
    out.push_str(&card("safe",     &safe.to_string(),     "NONE / SAFE"));
    out.push_str("</div>\n</section>\n");

    // ── NIST IR 8547 timeline ──────────────────────────────────────────────
    out.push_str("<section>\n<h2>NIST IR 8547 Compliance Timeline</h2>\n");
    out.push_str(&build_timeline(current_year, assets));
    out.push_str("</section>\n");

    // ── Findings table ─────────────────────────────────────────────────────
    out.push_str("<section>\n<h2>All Findings</h2>\n");
    out.push_str("<div class=\"filter-bar\">\n");
    out.push_str("<input id=\"fs\" type=\"search\" placeholder=\"Filter findings\u{2026}\">\n");
    out.push_str("<span style=\"color:#6b7280;font-size:.8rem\">Risk:</span>\n");
    for r in &["critical", "high", "medium", "low", "none"] {
        out.push_str(&format!("<button class=\"fbtn\" data-risk=\"{r}\">{}</button>\n", r.to_uppercase()));
    }
    out.push_str("</div>\n");
    out.push_str("<div class=\"table-wrap\">\n");
    out.push_str("<table id=\"ft\">\n<thead><tr>\n");
    for (i, h) in ["Asset / Library","Type","Quantum Safety","HNDL Risk","NIST Lvl","Evidence","File","Line"].iter().enumerate() {
        out.push_str(&format!("<th data-col=\"{i}\">{h}</th>\n"));
    }
    out.push_str("</tr></thead>\n<tbody id=\"ftb\">\n");
    for asset in assets {
        out.push_str(&findings_row(asset));
    }
    out.push_str("</tbody>\n</table>\n</div>\n</section>\n");

    // ── Remediation guide ──────────────────────────────────────────────────
    out.push_str("<section>\n<h2>Remediation Guide</h2>\n");
    out.push_str("<p style=\"color:#6b7280;margin-bottom:16px\">Unique vulnerable algorithms found, with migration recommendations.</p>\n");
    out.push_str(&build_remediation(assets));
    out.push_str("</section>\n");

    // ── Scan statistics ────────────────────────────────────────────────────
    out.push_str("<section>\n<h2>Scan Statistics</h2>\n");
    out.push_str("<div class=\"stat-grid\">\n");
    for (label, ev) in [
        ("Certificate parsing", Evidence::CertificateParsing),
        ("TLS handshake",       Evidence::TlsHandshake),
        ("Source code",         Evidence::SourceCodePattern),
        ("Binary scan",         Evidence::BinaryStringSearch),
        ("Config file",         Evidence::ConfigFileRule),
        ("Manifest dependency", Evidence::ManifestDependency),
    ] {
        let n = assets.iter().filter(|a| a.evidence == ev).count();
        out.push_str(&format!(
            "<div class=\"stat-item\"><span class=\"sv\">{n}</span><span class=\"sk\">{label}</span></div>\n"
        ));
    }
    out.push_str("</div>\n</section>\n");

    out.push_str("</main>\n<script>\n");
    out.push_str(JS);
    out.push_str("</script>\n</body>\n</html>");

    Ok(out)
}

// ── Section builders ──────────────────────────────────────────────────────────

fn build_timeline(current_year: u32, assets: &[CryptoAsset]) -> String {
    let start = 2024u32;
    let end   = 2036u32;
    let span  = (end - start) as f64;

    let pct_now  = ((current_year.max(start).min(end) - start) as f64 / span * 100.0) as u32;
    let pct_2030 = ((2030 - start) as f64 / span * 100.0) as u32; // 50%
    let pct_2035 = ((2035 - start) as f64 / span * 100.0) as u32; // ~91%

    let deprecated = assets.iter().filter(|a| a.nist_quantum_security == 0 && a.quantum_safe == QuantumSafety::Vulnerable).count();
    let disallowed = deprecated; // same set for now

    let mut s = String::new();
    s.push_str("<div class=\"timeline\">\n");
    s.push_str("<div class=\"tl-bar\">\n");
    s.push_str(&format!("<div class=\"tl-fill\" style=\"width:{pct_now}%\"></div>\n"));
    // markers
    s.push_str(&marker(pct_2030, "2030", "RSA/ECC<br>deprecated", "above"));
    s.push_str(&marker(pct_2035, "2035", "RSA/ECC<br>disallowed", "above"));
    s.push_str(&format!("<div class=\"tl-now\" style=\"left:{pct_now}%\"><span class=\"tl-now-label\">Today<br>{current_year}</span></div>\n"));
    s.push_str("</div>\n");
    s.push_str(&format!("<div class=\"tl-labels\"><span>{start}</span><span>{end}</span></div>\n"));
    s.push_str(&format!(
        "<p style=\"margin-top:16px;font-size:.875rem;color:#6b7280\">\
         <strong>{deprecated}</strong> assets will be deprecated by 2030 &nbsp;&bull;&nbsp;\
         <strong>{disallowed}</strong> assets will be disallowed by 2035\
         </p>\n"
    ));
    s.push_str("</div>\n");
    s
}

fn marker(pct: u32, year: &str, label: &str, _pos: &str) -> String {
    format!(
        "<div class=\"tl-m\" style=\"left:{pct}%\"><span class=\"tl-ml\">{label}</span><span class=\"tl-my\">{year}</span></div>\n"
    )
}

fn findings_row(asset: &CryptoAsset) -> String {
    let risk_key = risk_key(&asset.hndl_risk);
    let loc = asset.locations.first();
    let file = loc.map(|l| {
        let normalized = l.source.replace('\\', "/");
        let parts: Vec<&str> = normalized.split('/').collect();
        if parts.len() > 2 {
            format!("\u{2026}/{}/{}", parts[parts.len()-2], parts[parts.len()-1])
        } else {
            l.source.clone()
        }
    }).unwrap_or_default();
    let full_path = loc.map(|l| l.source.as_str()).unwrap_or("");
    let line = loc.and_then(|l| l.line).map(|n| n.to_string()).unwrap_or_default();

    let asset_type = match asset.asset_type {
        AssetType::Algorithm => "Algorithm",
        AssetType::Certificate => "Certificate",
        AssetType::PrivateKey => "Private Key",
        AssetType::PublicKey => "Public Key",
        AssetType::Protocol => "Protocol",
        AssetType::Library => "Library",
    };
    let ev = match asset.evidence {
        Evidence::CertificateParsing  => "Certificate",
        Evidence::TlsHandshake        => "TLS",
        Evidence::SourceCodePattern   => "Source",
        Evidence::BinaryStringSearch  => "Binary",
        Evidence::ConfigFileRule      => "Config",
        Evidence::ManifestDependency  => "Manifest",
    };
    let qs_class = match asset.quantum_safe {
        QuantumSafety::Vulnerable          => "critical",
        QuantumSafety::ClassicallyAdequate => "adequate",
        QuantumSafety::Safe                => "safe",
        QuantumSafety::HybridSafe          => "safe",
        QuantumSafety::Unknown             => "unknown",
    };
    let qs_label = match asset.quantum_safe {
        QuantumSafety::Vulnerable          => "VULNERABLE",
        QuantumSafety::ClassicallyAdequate => "ADEQUATE",
        QuantumSafety::Safe                => "SAFE",
        QuantumSafety::HybridSafe          => "HYBRID-SAFE",
        QuantumSafety::Unknown             => "UNKNOWN",
    };

    format!(
        "<tr data-risk=\"{risk_key}\">\
         <td><strong>{name}</strong></td>\
         <td>{asset_type}</td>\
         <td><span class=\"badge {qs_class}\">{qs_label}</span></td>\
         <td><span class=\"badge {risk_key}\">{risk}</span></td>\
         <td style=\"text-align:center\">{nist}</td>\
         <td>{ev}</td>\
         <td title=\"{full_path}\">{file}</td>\
         <td style=\"text-align:center\">{line}</td>\
         </tr>\n",
        name      = he(&asset.name),
        risk      = risk_label(&asset.hndl_risk),
        nist      = asset.nist_quantum_security,
        full_path = he(full_path),
        file      = he(&file),
    )
}

fn build_remediation(assets: &[CryptoAsset]) -> String {
    // Collect unique vulnerable algorithm names in severity order
    let mut seen = std::collections::HashSet::new();
    let mut algos: Vec<&CryptoAsset> = Vec::new();
    for a in assets {
        if a.quantum_safe == QuantumSafety::Vulnerable && seen.insert(&a.name) {
            algos.push(a);
        }
    }

    if algos.is_empty() {
        return "<p style=\"color:#16a34a;font-weight:600\">\u{2705} No quantum-vulnerable algorithms detected.</p>\n".to_string();
    }

    let mut s = String::new();
    for asset in algos {
        let count = assets.iter().filter(|a| a.name == asset.name).count();
        let risk_key = risk_key(&asset.hndl_risk);
        let (repl, reference) = remediation_for(&asset.name).unwrap_or((
            "Evaluate for replacement with a NIST-approved post-quantum algorithm",
            "NIST IR 8547",
        ));

        s.push_str(&format!(
            "<div class=\"rc\">\
             <div class=\"rc-head\">\
             <span class=\"badge {risk_key}\" style=\"font-size:.875rem;padding:3px 10px\">{risk}</span>\
             &nbsp;<code class=\"algo\">{name}</code>\
             <span class=\"rc-count\">{count} finding{pl}</span>\
             </div>\
             <div class=\"rc-body\">\
             <span class=\"rc-arrow\">\u{2192}</span>\
             <span class=\"rc-repl\">{repl}</span>\
             </div>\
             <div class=\"rc-ref\">Reference: {reference}</div>\
             </div>\n",
            risk      = risk_label(&asset.hndl_risk),
            name      = he(&asset.name),
            count     = count,
            pl        = if count == 1 { "" } else { "s" },
            repl      = he(repl),
            reference = he(reference),
        ));
    }
    s
}

// ── Small helpers ─────────────────────────────────────────────────────────────

fn card(cls: &str, val: &str, label: &str) -> String {
    format!("<div class=\"card {cls}\"><span class=\"cv\">{val}</span><span class=\"cl\">{label}</span></div>\n")
}

fn count(assets: &[CryptoAsset], risk: Risk) -> usize {
    assets.iter().filter(|a| a.hndl_risk == risk).count()
}

fn risk_key(r: &Risk) -> &'static str {
    match r {
        Risk::Critical => "critical",
        Risk::High     => "high",
        Risk::Medium   => "medium",
        Risk::Low      => "low",
        Risk::None     => "none",
    }
}

fn risk_label(r: &Risk) -> &'static str {
    match r {
        Risk::Critical => "CRITICAL",
        Risk::High     => "HIGH",
        Risk::Medium   => "MEDIUM",
        Risk::Low      => "LOW",
        Risk::None     => "NONE",
    }
}

/// HTML-escape user data to prevent injection in the output file.
fn he(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

// ── Embedded CSS ──────────────────────────────────────────────────────────────

static CSS: &str = r#"
:root{--cr:#dc2626;--hi:#ea580c;--me:#d97706;--lo:#2563eb;--sa:#16a34a;--bg:#f8fafc;--card:#fff;--bd:#e2e8f0;--tx:#0f172a;--mu:#64748b}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--tx);line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:0 24px}
header{background:#0f172a;color:#f1f5f9;padding:20px 0}
header h1{font-size:1.375rem;font-weight:700}
.meta{font-size:.8rem;color:#94a3b8;margin-top:4px}
.meta code{background:#1e293b;padding:1px 6px;border-radius:4px;font-size:.75rem}
main{padding:28px 0}
section{margin-bottom:36px}
h2{font-size:1.1rem;font-weight:600;color:#1e293b;margin-bottom:14px;padding-bottom:8px;border-bottom:2px solid var(--bd)}
.cards{display:flex;gap:12px;flex-wrap:wrap}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:16px 20px;min-width:110px;flex:1}
.cv{display:block;font-size:2rem;font-weight:700;line-height:1.1}
.cl{display:block;font-size:.75rem;color:var(--mu);margin-top:2px}
.card.total .cv{color:#0f172a}.card.vuln .cv{color:var(--cr)}
.card.critical .cv{color:var(--cr)}.card.high .cv{color:var(--hi)}
.card.medium .cv{color:var(--me)}.card.low .cv{color:var(--lo)}.card.safe .cv{color:var(--sa)}
.timeline{padding:8px 0}
.tl-bar{height:10px;background:#e2e8f0;border-radius:5px;position:relative;margin:40px 0 18px}
.tl-fill{height:100%;border-radius:5px;background:linear-gradient(90deg,var(--cr),var(--hi),var(--me))}
.tl-m{position:absolute;top:-30px;transform:translateX(-50%);text-align:center;pointer-events:none}
.tl-ml{display:block;font-size:.65rem;color:var(--mu);line-height:1.2}
.tl-my{display:block;font-size:.7rem;font-weight:600;color:#1e293b;border-top:1px solid var(--bd);margin-top:2px;padding-top:2px}
.tl-now{position:absolute;top:-12px;bottom:-12px;width:2px;background:#0f172a;transform:translateX(-50%)}
.tl-now-label{position:absolute;top:-32px;left:6px;font-size:.65rem;font-weight:700;white-space:nowrap;color:#0f172a}
.tl-labels{display:flex;justify-content:space-between;font-size:.75rem;color:var(--mu)}
.filter-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
#fs{padding:6px 12px;border:1px solid var(--bd);border-radius:6px;font-size:.875rem;width:220px}
.fbtn{padding:4px 10px;border:1px solid var(--bd);border-radius:5px;background:var(--card);cursor:pointer;font-size:.75rem;font-weight:600;transition:all .15s}
.fbtn.active{background:#0f172a;color:#fff;border-color:#0f172a}
.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--bd)}
table{width:100%;border-collapse:collapse;background:var(--card);font-size:.8rem}
thead th{background:#1e293b;color:#f1f5f9;padding:10px 14px;text-align:left;cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover{background:#334155}
thead th::after{content:' \2195';opacity:.35;font-size:.7rem}
tbody tr:nth-child(even){background:#f8fafc}
tbody tr:hover{background:#eff6ff}
tbody td{padding:8px 14px;border-bottom:1px solid var(--bd);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.7rem;font-weight:700;letter-spacing:.3px}
.badge.critical{background:#fee2e2;color:var(--cr)}
.badge.high{background:#ffedd5;color:var(--hi)}
.badge.medium{background:#fef3c7;color:var(--me)}
.badge.low{background:#dbeafe;color:var(--lo)}
.badge.none,.badge.safe{background:#dcfce7;color:var(--sa)}
.badge.adequate{background:#fef9c3;color:#854d0e}
.badge.unknown{background:#f1f5f9;color:var(--mu)}
.rc{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px 18px;margin-bottom:10px}
.rc-head{display:flex;align-items:center;gap:10px;margin-bottom:8px}
code.algo{font-size:.9rem;background:#f1f5f9;padding:2px 8px;border-radius:4px;color:#0f172a}
.rc-count{margin-left:auto;font-size:.75rem;color:var(--mu)}
.rc-body{display:flex;align-items:baseline;gap:8px;font-size:.875rem}
.rc-arrow{color:var(--sa);font-size:1.1rem;font-weight:700}
.rc-repl{color:#0f172a}
.rc-ref{font-size:.75rem;color:var(--mu);margin-top:6px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}
.stat-item{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px 16px}
.sv{display:block;font-size:1.75rem;font-weight:700;color:#0f172a}
.sk{display:block;font-size:.75rem;color:var(--mu)}
"#;

// ── Embedded JavaScript ───────────────────────────────────────────────────────

static JS: &str = r#"
(function(){
  // Table sorting
  document.querySelectorAll('#ft thead th[data-col]').forEach(function(th){
    th.addEventListener('click',function(){
      var col=parseInt(th.dataset.col);
      var asc=th.dataset.dir!=='asc';
      document.querySelectorAll('#ft thead th').forEach(function(h){delete h.dataset.dir;});
      th.dataset.dir=asc?'asc':'desc';
      var tbody=document.getElementById('ftb');
      var rows=[].slice.call(tbody.querySelectorAll('tr'));
      rows.sort(function(a,b){
        var av=(a.cells[col]||{}).textContent||'';
        var bv=(b.cells[col]||{}).textContent||'';
        return asc?av.localeCompare(bv,undefined,{numeric:true}):bv.localeCompare(av,undefined,{numeric:true});
      });
      rows.forEach(function(r){tbody.appendChild(r);});
    });
  });

  // Filter bar
  var activeRisks={};
  document.querySelectorAll('.fbtn[data-risk]').forEach(function(btn){
    btn.addEventListener('click',function(){
      btn.classList.toggle('active');
      activeRisks[btn.dataset.risk]=btn.classList.contains('active');
      applyFilter();
    });
  });
  var searchEl=document.getElementById('fs');
  if(searchEl)searchEl.addEventListener('input',applyFilter);

  function applyFilter(){
    var q=(searchEl?searchEl.value:'').toLowerCase();
    var hasActive=Object.values(activeRisks).some(Boolean);
    document.querySelectorAll('#ftb tr').forEach(function(row){
      var matchQ=!q||row.textContent.toLowerCase().includes(q);
      var matchR=!hasActive||activeRisks[row.dataset.risk];
      row.style.display=(matchQ&&matchR)?'':'none';
    });
  }
})();
"#;
