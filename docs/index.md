# acdi — Automated Cryptography Discovery & Inventory

**Find every quantum-vulnerable algorithm in your codebase, certificates, and TLS endpoints — in seconds.**

`acdi` is a single-binary CLI that scans filesystems, source code, package manifests, config files, PEM/DER certificates, compiled binaries, and live TLS endpoints for cryptographic assets. It emits a [CycloneDX 1.7 CBOM](https://cyclonedx.org/capabilities/cbom/), SARIF 2.1, or an interactive HTML migration report — ready for your PQC migration programme.

```bash
acdi scan ./my-project
```

```
+-------------+-----------+----------------+-----------+----------+--------------------+
| Asset       | Type      | Quantum Safety | HNDL Risk | NIST Lvl | Location           |
+=======================================================================================+
| RSA-2048    | Algorithm | VULNERABLE     | CRITICAL  |     0    | src/auth/jwt.go    |
| ECDSA-P-256 | Algorithm | VULNERABLE     | CRITICAL  |     0    | certs/server.crt   |
| RSA-4096    | Algorithm | VULNERABLE     | HIGH      |     0    | config/tls.yaml    |
| SHA-1       | Algorithm | VULNERABLE     | MEDIUM    |     0    | src/legacy/hash.py |
| AES-256-GCM | Algorithm | ADEQUATE       | NONE      |     5    | src/crypto/enc.rs  |
+-------------+-----------+----------------+-----------+----------+--------------------+
```

---

## Why acdi?

Quantum computers running Shor's algorithm will break RSA, ECDSA, and ECDH. [NIST IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf) deprecates these algorithms by **2030** and removes them by **2035**. The [Harvest Now, Decrypt Later (HNDL)](https://en.wikipedia.org/wiki/Harvest_now%2C_decrypt_later) threat means encrypted traffic captured *today* can be decrypted once quantum computers arrive.

Before you migrate, you need to know *what* you have. `acdi` automates that discovery step.

---

## Feature overview

| Capability | Details |
|---|---|
| **Certificate scanning** | PEM & DER — RSA, ECDSA, Ed25519; key size, curve, OID |
| **Certificate scanning** | PEM & DER — RSA, ECDSA, Ed25519; key size, curve, OID |
| **Source code scanning** | C/C++, Go, Java, Kotlin, Python, Rust, JS/TS, Ruby, PHP, Swift, C# |
| **Binary scanning** | String extraction — algorithm names and OIDs in compiled binaries |
| **Config file scanning** | YAML, TOML, JSON, .env, .ini — JWT `alg` fields, TLS cipher suites |
| **Package manifests** | Cargo.toml, package.json, requirements.txt, go.mod, pom.xml, build.gradle — maps libraries to algorithms |
| **Terraform / Kubernetes** | `.tf` HCL — `rsa_bits`, `ecdsa_curve`, AWS/GCP KMS keys; cert-manager `curve:` in YAML |
| **TLS endpoint probing** | Live handshake — negotiated cipher suite, certificate chain |
| **CBOM output** | CycloneDX 1.7 with `cryptoProperties` |
| **SARIF output** | Import into GitHub Advanced Security or VS Code |
| **HTML report** | Self-contained interactive report with NIST timeline and remediation guide |
| **CSV output** | RFC 4180 CSV — pipe to Excel, pandas, or BI tools |
| **`.acdignore`** | Suppress known-acceptable findings |
| **CBOM diff** | Compare two CBOMs — see what changed |
| **Risk scoring** | CRITICAL / HIGH / MEDIUM / LOW / NONE |

---

## Quick links

<div class="grid cards" markdown>

- :material-download: **[Installation](installation.md)** — pre-built binaries, cargo install, build from source
- :material-rocket-launch: **[Quick Start](quickstart.md)** — be scanning in 2 minutes
- :material-console: **[Commands](commands/scan.md)** — full CLI reference
- :material-file-code: **[Output Formats](formats/cbom.md)** — CBOM, SARIF, HTML
- :material-filter: **[.acdignore](reference/acdignore.md)** — suppress false positives
- :material-shield-check: **[Risk Model](reference/risk-model.md)** — how risk is scored
- :material-pipe: **[CI/CD Integration](guides/ci-cd.md)** — GitHub Actions, GitLab CI

</div>
