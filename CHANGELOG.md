# Changelog

All notable changes to acdi are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [0.5.0] — 2026-05-23

### Added
- **Kotlin source patterns**: Android Keystore `KeyProperties.KEY_ALGORITHM_RSA/EC/AES`, `KeyProperties.DIGEST_*` constants, `SecretKeySpec("HmacSHA256")`. All existing JCA patterns (shared with Java) already covered `.kt`/`.kts` files.
- **C# / .NET source patterns** (new extension `.cs`): `RSA.Create(N)`, `new RSACryptoServiceProvider(N)`, `new RSACng(N)`, `ECDsa.Create(ECCurve.NamedCurves.nistP256/P384/P521)`, `new ECDsaCng(256/384/521)`, `Aes.Create()`, `new AesManaged/AesCsp`, `TripleDES.Create()`, `new TripleDESCryptoServiceProvider()`, `MD5.Create()`, `SHA1/SHA256/SHA384/SHA512.Create()`, `new HMACSHA1/SHA256/SHA384/SHA512/MD5()`.
- **Terraform HCL scanning** (new extension `.tf`): detects `algorithm = "RSA"/"ECDSA"`, `rsa_bits = 2048`, `ecdsa_curve = "P256"`, AWS KMS `customer_master_key_spec` (`RSA_2048`, `ECC_NIST_P256`, `SYMMETRIC_DEFAULT`), GCP KMS `algorithm` values (`EC_SIGN_P256_SHA256`, etc.).
- **Kubernetes cert-manager patterns**: `curve: P256/P384/P521` in YAML (`.yaml`/`.yml`) files.
- `val_prefix` field on `ConfigRule` enabling unambiguous alias lookup for numeric Terraform attributes (e.g., `rsa_bits = 2048` → `RSA-2048`).
- 23 new integration tests (130 total).

### Changed
- `SOURCE_EXTENSIONS`: added `cs` (C#).
- `CONFIG_EXTENSIONS`: added `tf` (Terraform HCL).
- `normalize_ec_curve`: added `"256" | "384" | "521"` mappings for C# `ECDsaCng(256)` style key sizes.

---

## [0.4.0] — 2026-05-23

### Added
- **Maven pom.xml scanning**: detects crypto libraries (BouncyCastle, java-jwt, nimbus-jose-jwt, JJWT, Spring Security Crypto, Tink, etc.) via a state-machine XML parser that extracts `<groupId>:<artifactId>` pairs.
- **Gradle build.gradle / build.gradle.kts scanning**: detects the same Java crypto library catalog via quoted `group:artifact:version` GAV string matching.
- **Ruby source patterns**: OpenSSL RSA/EC key generation, OpenSSL Digest (SHA-1, SHA-256, MD5), OpenSSL Cipher AES, JWT.encode/decode with algorithm string normalization.
- **PHP source patterns**: `openssl_pkey_new`, `openssl_encrypt` (AES-128-CBC/AES-256-GCM/3DES), `hash()` with named algorithm, `md5()`, `sha1()`, `openssl_sign`.
- **Swift source patterns**: CryptoKit P-256/P-384/P-521 signing/key-agreement, SHA256/SHA384/SHA512 hashing, `Insecure.SHA1`/`Insecure.MD5`, AES-GCM, Security framework RSA (`kSecAttrKeyTypeRSA`).
- **CSV output format** (`--format csv`): RFC 4180 compliant, 8 columns — Algorithm, AssetType, QuantumSafety, HNDLRisk, NISTLevel, File, Line, Evidence.
- JWT algorithm string normalization in source patterns: RS256/ES256/HS256 etc. → canonical algorithm names.

### Changed
- `--format` now accepts `cyclonedx-1.7 | sarif | html | csv`.
- `diff --format json` now works correctly (was accepted but ignored in 0.3.0).

### Fixed
- `scan --quiet` output no longer emits a trailing blank line when piped to CSV or HTML formats.

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
