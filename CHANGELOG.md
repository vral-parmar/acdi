# Changelog

All notable changes to acdi are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [0.3.0] — 2026-05-23

### Added
- **HTML migration report** (`--format html`): self-contained single-file output with summary cards, interactive NIST IR 8547 timeline (2024–2036), sortable/filterable findings table, per-algorithm remediation guide, and scan statistics by evidence type.
- **`.acdignore` suppression**: place a `.acdignore` file at the scan root (or pass `--ignore-file`) to suppress findings by `algorithm:`, `path:` glob, or `evidence:` type. Multiple conditions on a rule all must match (AND logic). Overridable with `--no-ignore`.
- New CLI flags: `--ignore-file <FILE>`, `--no-ignore`.
- `IgnoreList::parse` / `IgnoreList::load` public API with recursive glob matching (`*` within directory, `**` across directories).

### Changed
- Default output format remains `cyclonedx-1.7`; `--format` now accepts `cyclonedx-1.7 | sarif | html`.

---

## [0.2.0] — 2026-05-20

### Added
- **Package manifest scanning**: Cargo.toml, package.json, requirements.txt, Pipfile, go.mod. Maps 55+ library names to primary cryptographic algorithms. Emits `AssetType::Library` findings with `Evidence::ManifestDependency`.
- **Config file scanning**: YAML, TOML, JSON, .env, .properties, .ini, .cfg, .conf. Detects JWT `alg` fields (RS256 → RSA-2048, ES256 → ECDSA-P-256, etc.), TLS cipher suite auth algorithms, SSH key types, and generic `algorithm: <value>` patterns.
- **SARIF 2.1.0 output** (`--format sarif`): per-algorithm rules, per-occurrence results, risk-to-level mapping, physical locations. Importable by GitHub Advanced Security and VS Code SARIF Viewer.
- `Evidence::ConfigFileRule` and `Evidence::ManifestDependency` variants.
- `OutputFormat::Sarif` and `OutputFormat::Html` CLI values.

---

## [0.1.0] — 2026-05-15

### Added
- Initial release.
- **Certificate scanning**: PEM and DER — RSA, ECDSA (P-256, P-384, P-521), Ed25519. Key size, curve, OID extraction via `x509-parser`.
- **Source code scanning**: C/C++, Go, Java, Python, Rust, JavaScript/TypeScript. OpenSSL, JCA, hashlib, crypto/... API pattern matching via `regex`.
- **Binary scanning**: ASCII/UTF-8 string extraction from compiled binaries. Algorithm names and OIDs.
- **CycloneDX 1.7 CBOM output** (default): `cryptoProperties`, `assetType`, `algorithmProperties`, `oid`, `acdi:*` properties.
- **CBOM diff** (`acdi diff`): compare two CBOMs, report added/removed/changed assets.
- **TLS endpoint probing** (`acdi tls`): async multi-host scanning, negotiated cipher suite and certificate chain, `--hosts` file input, `--concurrency`, `--timeout`.
- HNDL risk scoring: CRITICAL / HIGH / MEDIUM / LOW / NONE.
- NIST quantum security levels (0–5).
- Terminal table output with color-coded risk levels.
- `--fail-on <level>` exit-code gate for CI integration.
- `--quiet` flag for pipe-friendly structured output.
- `--follow-links` for symlink traversal.
- `-v` / `-vv` verbosity flags (debug / trace).
- Parallel filesystem walking and scanning via `rayon`.
- `#![forbid(unsafe_code)]` throughout — zero unsafe blocks.
