# acdi — Automated Cryptography Discovery & Inventory

[![Crates.io Version](https://img.shields.io/crates/v/acdi.svg)](https://crates.io/crates/acdi)
[![Crates.io Downloads](https://img.shields.io/crates/d/acdi.svg)](https://crates.io/crates/acdi)
[![Documentation](https://img.shields.io/badge/docs-docs.rs-blue)](https://vral-parmar.github.io/acdi/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

**Find every quantum-vulnerable algorithm in your codebase, certificates, and TLS endpoints in seconds.**

`acdi` is a single-binary CLI that scans filesystems, source code, package manifests, config files, PEM/DER certificates, compiled binaries, and live TLS endpoints for cryptographic assets. It emits a [CycloneDX 1.7 CBOM](https://cyclonedx.org/capabilities/cbom/), SARIF 2.1, or an interactive HTML migration report — ready for your PQC migration programme.

```
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

Quantum computers running Shor's algorithm will break RSA, ECDSA, and ECDH. NIST IR 8547 deprecates these algorithms by **2030** and removes them by **2035**. The [Harvest Now, Decrypt Later](https://en.wikipedia.org/wiki/Harvest_now%2C_decrypt_later) (HNDL) threat means encrypted traffic captured *today* can be decrypted once quantum computers arrive.

Before you migrate, you need to know *what* you have. `acdi` automates that discovery step.

---

## Features

| Capability | Details |
|---|---|
| **Certificate scanning** | PEM & DER RSA, ECDSA, Ed25519; key size, curve, OID |
| **Source code scanning** | C/C++, Go, Java, Python, Rust, JS/TS, **Ruby, PHP, Swift** — OpenSSL, JCA, hashlib, CryptoKit, jwt… |
| **Binary scanning** | String extraction — finds algorithm names and OIDs in compiled binaries |
| **Config file scanning** | YAML, TOML, JSON, .env, .ini JWT `alg` fields, TLS cipher suites, SSH key types |
| **Package manifests** | Cargo.toml, package.json, requirements.txt, go.mod, Pipfile, **pom.xml, build.gradle** — maps libraries to algorithms |
| **TLS endpoint probing** | Live handshake — negotiated cipher suite, certificate chain |
| **CBOM output** | CycloneDX 1.7 with `cryptoProperties`, `assetType`, `algorithmProperties` |
| **SARIF output** | Import directly into GitHub Advanced Security, VS Code, or any SAST platform |
| **HTML report** | Self-contained interactive report with NIST timeline, sortable findings, remediation guide |
| **CSV output** | RFC 4180 CSV — pipe to Excel, pandas, or any analytics tool |
| **`.acdignore`** | Suppress known-acceptable findings by algorithm, file path glob, or evidence type |
| **CBOM diff** | Compare two CBOMs see what changed between scans |
| **Risk scoring** | CRITICAL / HIGH / MEDIUM / LOW / NONE based on HNDL threat and NIST IR 8547 |

---

## Installation

### Pre-built binaries (recommended)

Download the latest release from the [GitHub Releases](../../releases) page. Statically linked no runtime dependencies.

```bash
# macOS (Apple Silicon)
curl -Lo acdi https://github.com/vral-parmar/acdi/releases/latest/download/acdi-aarch64-apple-darwin
chmod +x acdi && sudo mv acdi /usr/local/bin/

# macOS (Intel)
curl -Lo acdi https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-apple-darwin
chmod +x acdi && sudo mv acdi /usr/local/bin/

# Linux (x86_64, static musl)
curl -Lo acdi https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-unknown-linux-musl
chmod +x acdi && sudo mv acdi /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-pc-windows-msvc.exe -OutFile acdi.exe
```

### Build from source

Requires Rust 1.75+ (`rustup` recommended).

```bash
git clone https://github.com/vral-parmar/acdi
cd acdi
cargo build --release
# Binary at: ./target/release/acdi
```

### Cargo install

```bash
cargo install acdi
```

---

## Quick Start

```bash
# Scan a directory — prints a human table + hint
acdi scan ./my-project

# Emit CycloneDX 1.7 CBOM JSON
acdi scan ./my-project --quiet > cbom.json

# Write CBOM to file; table still goes to stdout
acdi scan ./my-project --output cbom.json

# Generate an interactive HTML migration report
acdi scan ./my-project --format html --output report.html

# Generate SARIF (for GitHub Advanced Security / VS Code)
acdi scan ./my-project --format sarif --output results.sarif

# Export CSV for spreadsheet / data analysis
acdi scan ./my-project --format csv --quiet > findings.csv

# Probe a live TLS endpoint
acdi tls api.example.com:443

# Diff two CBOMs — show what changed
acdi diff cbom-before.json cbom-after.json

# CI gate — fail if any HIGH-or-worse finding
acdi scan ./my-project --fail-on high --quiet > /dev/null
```

---

## Commands

### `acdi scan`

```
acdi scan <PATH> [OPTIONS]

Arguments:
  <PATH>   File or directory to scan

Options:
  -o, --output <FILE>       Write output to file instead of stdout
      --format <FORMAT>     Output format [default: cyclonedx-1.7]
                            Values: cyclonedx-1.7 | sarif | html | csv
      --fail-on <LEVEL>     Exit 1 if any finding meets or exceeds this risk
                            Values: low | medium | high | critical
  -q, --quiet               Suppress table; print structured output only
      --follow-links        Follow symbolic links when walking directories
      --ignore-file <FILE>  Use a custom ignore file (default: <PATH>/.acdignore)
      --no-ignore           Disable all .acdignore suppression
  -v, --verbose             Increase log verbosity (-v = debug, -vv = trace)
  -h, --help                Print help
```

**Examples:**

```bash
# Scan and write HTML report
acdi scan ./src --format html --output report.html

# Scan a single certificate
acdi scan ./certs/server.crt.pem --quiet

# CI gate — fail pipeline on any critical finding
acdi scan . --fail-on critical --quiet > /dev/null

# Scan with verbose logging
acdi scan ./project -v
```

---

### `acdi tls`

Probe one or more TLS endpoints and inventory the negotiated cipher suite and certificate chain.

```
acdi tls [TARGET] [OPTIONS]

Arguments:
  [TARGET]   Host:port to probe (e.g. api.example.com:443)

Options:
  --hosts <FILE>         File with one host:port per line (# comments supported)
  -o, --output <FILE>    Write CBOM JSON to file
      --concurrency <N>  Max concurrent connections [default: 50]
      --timeout <SECS>   Per-host timeout [default: 10]
  -h, --help             Print help
```

**Examples:**

```bash
# Probe a single endpoint
acdi tls api.example.com:443

# Probe many endpoints from a file
acdi tls --hosts endpoints.txt --output tls-cbom.json

# endpoints.txt format:
# api.example.com:443
# db.internal:5432
# # this line is a comment
```

---

### `acdi diff`

Compare two CBOM files and report what cryptographic assets were added, removed, or changed between scans.

```
acdi diff <BEFORE> <AFTER> [OPTIONS]

Arguments:
  <BEFORE>   Path to the older CBOM JSON file
  <AFTER>    Path to the newer CBOM JSON file

Options:
      --format <FORMAT>   Output format [default: text]
                          Values: text | json
  -h, --help              Print help
```

**Examples:**

```bash
# Show changes between two scans
acdi diff cbom-v1.json cbom-v2.json

# Machine-readable diff
acdi diff cbom-v1.json cbom-v2.json --format json
```

---

## Output Formats

### CycloneDX 1.7 CBOM (default)

Fully compliant CycloneDX 1.7 Cryptography Bill of Materials. Each component includes:

- `cryptoProperties.assetType` — `algorithm`, `certificate`, `private-key`, `public-key`, `protocol`, `library`
- `cryptoProperties.algorithmProperties` — primitive, parameter set, NIST quantum security level
- `cryptoProperties.oid` — algorithm OID where applicable
- `properties` — `acdi:quantum_safe`, `acdi:hndl_risk`, `acdi:nist_level`

```bash
acdi scan ./project --quiet > cbom.json
# or
acdi scan ./project --output cbom.json
```

### SARIF 2.1.0

Import into GitHub Advanced Security, VS Code with the SARIF Viewer extension, or any SAST dashboard.

Each algorithm family becomes a rule (`acdi/RSA`, `acdi/ECDSA`, etc.). Each occurrence is a result with a physical location, risk level, and remediation message.

```bash
acdi scan ./project --format sarif --output results.sarif
```

**GitHub Actions integration:**

```yaml
- name: Scan for vulnerable cryptography
  run: acdi scan . --format sarif --output acdi.sarif --quiet

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: acdi.sarif
```

### CSV

RFC 4180 CSV with one row per finding occurrence. Eight columns: `Algorithm`, `AssetType`, `QuantumSafety`, `HNDLRisk`, `NISTLevel`, `File`, `Line`, `Evidence`.

```bash
acdi scan ./project --format csv --quiet > findings.csv
```

Pipe to pandas, Excel, or any BI tool.

---

### HTML Migration Report

Self-contained single-file HTML — no external dependencies, works offline.

Contains:
- **Summary cards** — total findings, CRITICAL/HIGH/MEDIUM/LOW/NONE counts, unique algorithms, files scanned
- **NIST IR 8547 timeline** — visual 2024–2036 strip with today, 2030 deprecation, and 2035 removal markers
- **Findings table** — sortable and filterable by algorithm, risk, file, evidence type
- **Remediation guide** — per-algorithm migration path (RSA→ML-KEM, ECDSA→ML-DSA, etc.)
- **Scan statistics** — breakdown by evidence type (certificate, source code, binary, config, manifest, TLS)

```bash
acdi scan ./project --format html --output report.html
open report.html
```

---

## `.acdignore` — Suppressing Findings

Place a `.acdignore` file at the root of the directory you scan (or pass `--ignore-file`) to suppress known-acceptable findings. Syntax is one rule per line; `#` starts a comment.

### Rule types

```
# Suppress by algorithm name (case-insensitive)
algorithm:RSA-4096

# Suppress by file path glob (* matches within a directory, ** matches across directories)
path:vendor/**

# Suppress by evidence type
evidence:binary-string-search

# Combine filters — ALL conditions must match
algorithm:SHA-256
path:tests/**
```

### Available evidence types

| Value | Meaning |
|---|---|
| `certificate-parsing` | X.509 certificate or private key file |
| `source-code-pattern` | Pattern match in source code |
| `binary-string-search` | String extraction from compiled binary |
| `config-file-rule` | Key/value in config or secrets file |
| `manifest-dependency` | Library in package manifest |
| `tls-handshake` | Live TLS endpoint probe |

### Example `.acdignore`

```
# RSA-4096 is acceptable in our HSM configurations
algorithm:RSA-4096
path:infra/hsm/**

# Third-party vendor code — not our responsibility
path:vendor/**

# Binary scan findings are too noisy in legacy blobs
evidence:binary-string-search
path:legacy/blobs/**

# Suppress all SHA-1 findings in test fixtures
algorithm:SHA-1
path:tests/fixtures/**
```

**Override at runtime:**

```bash
# Use a custom ignore file
acdi scan ./project --ignore-file ./security/exceptions.acdignore

# Bypass all ignore rules (e.g., for a full audit)
acdi scan ./project --no-ignore
```

---

## Risk Model

acdi assigns each finding an **HNDL risk** level based on the Harvest Now, Decrypt Later threat model and NIST IR 8547 guidance.

| Risk | Algorithms | Meaning |
|---|---|---|
| **CRITICAL** | RSA (any key size), ECDSA-P-256, ECDH-P-256 | Immediately vulnerable; captured ciphertext is at risk today |
| **HIGH** | RSA-4096, ECDSA-P-384, ECDSA-P-521 | Quantum-vulnerable; larger keys only delay the timeline |
| **MEDIUM** | SHA-1, MD5, 3DES, RC4 | Classically weak; not quantum-related but should be replaced |
| **LOW** | SHA-256, AES-128 | Classical security adequate; quantum security marginal |
| **NONE** | AES-256, SHA-384, SHA-512, ML-KEM, ML-DSA | Quantum-safe or quantum-resistant |

**NIST IR 8547 schedule:**
- **2030** — RSA, ECDSA, ECDH deprecated (no new uses)
- **2035** — RSA, ECDSA, ECDH removed (all uses must cease)

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Cryptography Inventory

on: [push, pull_request]

jobs:
  acdi-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download acdi
        run: |
          curl -Lo acdi https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-unknown-linux-musl
          chmod +x acdi

      - name: Scan for vulnerable cryptography
        run: ./acdi scan . --format sarif --output acdi.sarif --quiet

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: acdi.sarif

      - name: Fail on critical findings
        run: ./acdi scan . --fail-on critical --quiet > /dev/null
```

### GitLab CI

```yaml
acdi-scan:
  stage: security
  script:
    - curl -Lo acdi https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-unknown-linux-musl
    - chmod +x acdi
    - ./acdi scan . --format sarif --output gl-sast-report.json --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Pre-commit hook

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
acdi scan . --fail-on critical --quiet > /dev/null
```

---

## Supported Languages & Ecosystems

### Source code

| Language | Detected patterns |
|---|---|
| C / C++ | `RSA_generate_key`, `EVP_*`, `AES_*`, `SHA*`, `MD5_*`, `EC_KEY_*` (OpenSSL) |
| Go | `crypto/rsa`, `crypto/ecdsa`, `crypto/md5`, `crypto/sha1`, `golang.org/x/crypto` |
| Java | `KeyPairGenerator.getInstance`, `MessageDigest.getInstance`, `Cipher.getInstance` (JCA) |
| Python | `hashlib.*`, `Crypto.*`, `cryptography.*`, `jwt.encode` |
| Rust | `RsaPrivateKey`, `p256::`, `sha1::`, `md5::`, `ring::` |
| JavaScript / TypeScript | `crypto.createHash`, `jose.`, `jsonwebtoken.sign` |
| Ruby | `OpenSSL::PKey::RSA`, `OpenSSL::Digest::SHA1`, `OpenSSL::Cipher::AES`, `JWT.encode` |
| PHP | `openssl_pkey_new`, `openssl_encrypt`, `hash('sha1',…)`, `md5()`, `sha1()` |
| Swift | `P256/P384/P521.Signing`, `SHA256.hash`, `Insecure.SHA1`, `AES.GCM`, `kSecAttrKeyTypeRSA` |

### Package manifests

| File | Detected libraries |
|---|---|
| `Cargo.toml` | openssl, ring, rsa, ecdsa, ed25519-dalek, sha1, sha2, md5, aes, pqcrypto-*, ml-kem |
| `package.json` | node-forge, jsonwebtoken, elliptic, crypto-js, bcryptjs, noble-curves |
| `requirements.txt` / `Pipfile` | cryptography, paramiko, pycryptodome, PyJWT, pyOpenSSL |
| `go.mod` | golang.org/x/crypto, golang-jwt/jwt, cloudflare/circl |
| `pom.xml` | bcprov-jdk18on, java-jwt, nimbus-jose-jwt, jjwt-api, spring-security-crypto, tink |
| `build.gradle` / `build.gradle.kts` | same Java library catalog as pom.xml |

### Config files

| File type | Detected patterns |
|---|---|
| YAML / TOML / JSON | JWT `alg:` fields (RS256, ES256, PS512, ...), `algorithm:`, `cipher:`, `hash:` keys |
| `.env` / `.properties` | `SSL_CIPHER`, `JWT_ALGORITHM`, `HASH_ALGORITHM` |
| `.ini` / `.cfg` / `.conf` | `cipher_suite =`, `key_type =`, `digest =` |

---

## Architecture

```
acdi/
├── src/
│   ├── main.rs              # Entry point
│   ├── cli.rs               # clap argument definitions
│   ├── lib.rs               # Public API surface
│   ├── catalog/
│   │   ├── algorithms.rs    # Algorithm metadata (risk, quantum safety, OID)
│   │   └── oids.rs          # OID → algorithm name lookup
│   ├── detect/
│   │   ├── mod.rs           # Router: dispatches files to correct scanner
│   │   ├── certs.rs         # PEM / DER certificate & key parsing (x509-parser)
│   │   ├── source.rs        # Source code regex scanner (rayon parallel)
│   │   ├── binary.rs        # Binary string extraction
│   │   ├── config.rs        # Config file value scanner
│   │   └── manifest.rs      # Package manifest library catalog
│   ├── model/
│   │   ├── asset.rs         # CryptoAsset struct, Evidence enum, AssetType enum
│   │   ├── classify.rs      # QuantumSafety classification
│   │   └── risk.rs          # HNDL Risk scoring
│   ├── output/
│   │   ├── cbom.rs          # CycloneDX 1.7 serialization
│   │   ├── sarif.rs         # SARIF 2.1.0 serialization
│   │   ├── html.rs          # Self-contained HTML report
│   │   ├── csv.rs           # RFC 4180 CSV emitter
│   │   └── table.rs         # Terminal table (comfy-table + owo-colors)
│   ├── probe/
│   │   ├── tls.rs           # Async TLS handshake (tokio-rustls)
│   │   └── pqc.rs           # PQC algorithm detection
│   ├── commands/
│   │   ├── scan.rs          # scan subcommand logic
│   │   ├── tls.rs           # tls subcommand logic
│   │   └── diff.rs          # diff subcommand logic
│   └── ignore.rs            # .acdignore rule parsing & matching
└── tests/
    ├── integration.rs       # 107 integration tests
    └── fixtures/            # Test certificates, source files, configs, manifests
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Run the full test suite
cargo test

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt
```

---

## Security

`acdi` is a read-only scanning tool. It:
- Never writes files outside of `--output` destinations you specify
- Never makes network connections outside of `acdi tls` commands
- Uses `#![forbid(unsafe_code)]` throughout — zero `unsafe` blocks
- Canonicalizes all input paths before use

To report a security vulnerability, open a [GitHub Security Advisory](../../security/advisories/new) rather than a public issue.

---

## References

- [NIST IR 8547 — Transition to Post-Quantum Cryptography Standards](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)
- [NSA CNSA 2.0 — Commercial National Security Algorithm Suite 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [CycloneDX CBOM Specification](https://cyclonedx.org/capabilities/cbom/)
- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [NIST PQC Standardized Algorithms — ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## License

MIT — see [LICENSE](LICENSE).
