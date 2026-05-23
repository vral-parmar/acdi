# HTML Migration Report

The HTML report is a self-contained single file — no JavaScript CDN, no external fonts, no internet connection required. Open it in any browser, share it by email, or attach it to a ticket.

## Generate

```bash
acdi scan ./project --format html --output report.html
open report.html
```

---

## Sections

### Summary cards

Seven cards at the top of the page:

| Card | Content |
|---|---|
| Total findings | Count of all crypto assets found |
| Critical | Count of CRITICAL-risk findings |
| High | Count of HIGH-risk findings |
| Medium | Count of MEDIUM-risk findings |
| Algorithms | Count of distinct algorithm names |
| Vulnerable | Count of VULNERABLE quantum safety findings |
| Files scanned | Total files examined |

### NIST IR 8547 Timeline

An interactive visual strip spanning 2024–2036 with three markers:

- **Today** — current date
- **2030** — RSA/ECDSA/ECDH deprecated (no new uses)
- **2035** — RSA/ECDSA/ECDH removed (all uses must cease)

Each finding appears on the timeline relative to its risk urgency.

### Findings table

Sortable and filterable table with columns:

| Column | Description |
|---|---|
| Algorithm | Canonical algorithm name |
| Type | Asset type (algorithm, certificate, library, …) |
| Quantum Safety | VULNERABLE / ADEQUATE / QUANTUM_SAFE / UNKNOWN |
| HNDL Risk | CRITICAL / HIGH / MEDIUM / LOW / NONE |
| NIST Level | 0–5 |
| Location | Source file path (shortened to last two path components) |
| Evidence | How it was found (certificate, source code, binary, config, manifest, TLS) |

Filter by risk level, algorithm name, or free-text search. Sort by any column.

### Remediation guide

Per-algorithm migration recommendations:

| Vulnerable algorithm | Recommended replacement |
|---|---|
| RSA (key exchange) | ML-KEM-768 (FIPS 203) |
| ECDSA / RSA (signatures) | ML-DSA-65 (FIPS 204) |
| SHA-1 | SHA-256 or SHA-384 |
| MD5 | SHA-256 |
| 3DES / RC4 | AES-256-GCM |
| ECDH | ML-KEM-768 or X25519+ML-KEM (hybrid) |

### Scan statistics

Breakdown of findings by evidence type — how many were found in certificates, source code, binaries, config files, manifests, and TLS handshakes.

---

## Sharing

The file is fully self-contained — CSS, JavaScript, and all data are inlined. Attach it to a Jira ticket, send by email, or host it on an internal wiki.

```bash
# Scan a production repo and send the report
acdi scan /opt/app --format html --output /tmp/acdi-$(date +%Y%m%d).html --quiet
```
