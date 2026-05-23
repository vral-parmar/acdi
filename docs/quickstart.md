# Quick Start

This page gets you from zero to your first cryptography inventory in under two minutes.

---

## 1. Scan a directory

```bash
acdi scan ./my-project
```

`acdi` walks the directory recursively, scans every file it recognises, and prints a colour-coded findings table:

```
+-------------+-----------+----------------+-----------+----------+--------------------+
| Asset       | Type      | Quantum Safety | HNDL Risk | NIST Lvl | Location           |
+=======================================================================================+
| RSA-2048    | Algorithm | VULNERABLE     | CRITICAL  |     0    | src/auth/jwt.go    |
| ECDSA-P-256 | Algorithm | VULNERABLE     | CRITICAL  |     0    | certs/server.crt   |
| SHA-1       | Algorithm | VULNERABLE     | MEDIUM    |     0    | src/legacy/hash.py |
| AES-256-GCM | Algorithm | ADEQUATE       | NONE      |     5    | src/crypto/enc.rs  |
+-------------+-----------+----------------+-----------+----------+--------------------+

Found 4 asset(s) — 3 quantum-vulnerable
  2 CRITICAL
  1 MEDIUM
  1 NONE/SAFE

  💡 Use --output report.html --format html for the migration report.
```

---

## 2. Generate a migration report

```bash
acdi scan ./my-project --format html --output report.html
open report.html          # macOS
xdg-open report.html      # Linux
start report.html         # Windows
```

The HTML report is a self-contained single file — no internet connection required. It includes:

- Summary cards with risk counts
- An interactive NIST IR 8547 timeline (2024–2036)
- A sortable, filterable findings table
- A per-algorithm remediation guide

---

## 3. Export a CBOM for your SBOM toolchain

```bash
acdi scan ./my-project --quiet > cbom.json
```

The `--quiet` flag suppresses the table and prints only the CycloneDX 1.7 JSON to stdout, making it pipe-friendly.

---

## 4. Probe a live TLS endpoint

```bash
acdi tls api.example.com:443
```

---

## 5. Add a CI gate

Fail your pipeline if any **CRITICAL** finding is present:

```bash
acdi scan . --fail-on critical --quiet > /dev/null
```

Exit code is `0` if no findings meet the threshold, `1` if they do.

---

## Next steps

- [Full command reference → `acdi scan`](commands/scan.md)
- [Suppress known findings with `.acdignore`](reference/acdignore.md)
- [CI/CD integration examples](guides/ci-cd.md)
- [Understanding the risk model](reference/risk-model.md)
