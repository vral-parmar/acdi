# Changelog

All notable changes to acdi are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [0.5.2] — 2026-05-24

### Added
- **`acdi tls --format`**: TLS endpoint scans now support all four output formats — `cyclonedx-1.7` (default), `sarif`, `html`, and `csv`. Generate a full HTML migration report directly from a TLS probe: `acdi tls api.example.com:443 --format html --output report.html`.

---

## [0.5.1] — 2026-05-24

### Added
- **ELF / PE / Mach-O symbol scanning** (`goblin` 0.8): resolves imported/exported function symbols (OpenSSL, BoringSSL, Windows CNG/CAPI, PKCS#11, libsodium, OQS) to canonical algorithm names. Complements string-search with structured symbol information that survives printable-string stripping.
- **JAR / WAR / AAR / EAR scanning** (`zip` 2): opens Java archive files, parses every `.class` file's constant pool (CONSTANT_Utf8 entries), and maps JCA class names and algorithm strings (e.g. `javax/crypto/Cipher`, `AES/GCM/NoPadding`, `SHA256withRSA`) to canonical algorithm names.
- **Standalone `.class` file scanning**: same constant-pool parser applied to individual Java class files.
- **Private key size / curve extraction** (cert parsing overhaul):
  - PKCS#8 RSA keys now resolve to `RSA-2048` / `RSA-3072` etc. by parsing the embedded PKCS#1 RSAPrivateKey modulus.
  - PKCS#1 RSA keys resolve to `RSA-N` by reading the modulus length directly.
  - PKCS#8 / SEC1 EC keys resolve to `ECDSA-P-256` / `ECDSA-P-384` / `ECDSA-P-521` by extracting the named-curve OID from the AlgorithmIdentifier or ECPrivateKey domain parameters.
- **Ansible IaC patterns**: `type: RSA/ECDSA/ECC/DSA/Ed25519/X25519` and `size: 1024/2048/3072/4096` fields under `community.crypto.openssl_privatekey` tasks.
- **AWS CloudFormation KMS patterns**: `KeySpec: RSA_2048 / ECC_NIST_P256 / SYMMETRIC_DEFAULT` values.
- **Watch mode** (`--watch`): continuous scanning with 500 ms debounce via `notify` 6; prints `[+]` new findings and `[-]` resolved findings on each file-system event.
- **cargo-fuzz targets** (in `fuzz/`): `fuzz_certs`, `fuzz_binary`, `fuzz_config`, `fuzz_jar` — coverage-guided fuzzing for all security-critical parsers.
- 12 new integration tests (142 total).

### Changed
- MSRV bumped to **1.85** (required by `time-macros` 0.2.27 edition 2024 feature).
- New `Evidence` variants: `ElfSymbol`, `JarClassFile` — reflected in SARIF, CSV, HTML, and `.acdignore` evidence filters.

---

## [0.5.0] — 2026-05-23

### Added
- **Kotlin source patterns**: Android Keystore `KeyProperties.KEY_ALGORITHM_RSA/EC/AES`, `KeyProperties.DIGEST_*` constants, `SecretKeySpec("HmacSHA256")`. All existing JCA patterns (shared with Java) already covered `.kt`/`.kts` files.
- **C# / .NET source patterns** (new extension `.cs`): `RSA.Create(N)`, `new RSACryptoServiceProvider(N)`, `new RSACng(N)`, `ECDsa.Create(ECCurve.NamedCurves.nistP256/P384/P521)`, `new ECDsaCng(256/384/521)`, `Aes.Create()`, `new AesManaged/AesCsp`, `TripleDES.Create()`, `SHA1/SHA256/SHA384/SHA512.Create()`, `new HMACSHA1/SHA256/SHA384/SHA512/MD5()`.
- **Terraform HCL scanning** (new extension `.tf`): detects `algorithm = "RSA"/"ECDSA"`, `rsa_bits = 2048`, `ecdsa_curve = "P256"`, AWS KMS `customer_master_key_spec` (`RSA_2048`, `ECC_NIST_P256`, `SYMMETRIC_DEFAULT`), GCP KMS `algorithm` values (`EC_SIGN_P256_SHA256`, etc.).
- **Kubernetes cert-manager patterns**: `curve: P256/P384/P521` in YAML (`.yaml`/`.yml`) files.
- **Homebrew formula**: `brew tap vral-parmar/tap && brew install acdi`.
- **Docker image** (`ghcr.io/vral-parmar/acdi`): run without installing anything — `docker run --rm -v "$(pwd)":/src ghcr.io/vral-parmar/acdi scan /src`.
- **GitHub composite Action** (`vral-parmar/acdi@v0.5.0`): one-step integration for any GitHub Actions workflow.
- 23 new integration tests (130 total).

### Changed
- `SOURCE_EXTENSIONS`: added `cs` (C# / .NET).
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

---

## [0.2.0] — 2026-05-20

### Added
- **Package manifest scanning**: Cargo.toml, package.json, requirements.txt, Pipfile, go.mod. Maps 55+ library names to primary cryptographic algorithms. Emits `AssetType::Library` findings with `Evidence::ManifestDependency`.
- **Config file scanning**: YAML, TOML, JSON, .env, .properties, .ini, .cfg, .conf. Detects JWT `alg` fields, TLS cipher suite auth algorithms, SSH key types, and generic `algorithm: <value>` patterns.
- **SARIF 2.1.0 output** (`--format sarif`): per-algorithm rules, per-occurrence results, risk-to-level mapping, physical locations.
- `Evidence::ConfigFileRule` and `Evidence::ManifestDependency` variants.

---

## [0.1.0] — 2026-05-15

### Added
- Initial release.
- **Certificate scanning**: PEM and DER — RSA, ECDSA (P-256, P-384, P-521), Ed25519.
- **Source code scanning**: C/C++, Go, Java, Python, Rust, JavaScript/TypeScript.
- **Binary scanning**: ASCII/UTF-8 string extraction from compiled binaries.
- **CycloneDX 1.7 CBOM output** (default).
- **CBOM diff** (`acdi diff`).
- **TLS endpoint probing** (`acdi tls`).
- HNDL risk scoring: CRITICAL / HIGH / MEDIUM / LOW / NONE.
- Terminal table output with colour-coded risk levels.
- `--fail-on <level>` exit-code gate for CI.
- `--quiet` flag for pipe-friendly output.
- Parallel scanning via `rayon`.
- `#![forbid(unsafe_code)]` throughout.
