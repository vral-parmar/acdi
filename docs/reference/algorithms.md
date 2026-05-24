# Supported Algorithms

This page lists the cryptographic algorithms that `acdi` recognises and classifies.

**Supported source languages**: C, C++, Go, Java, Kotlin, Python, Rust, JavaScript/TypeScript, Ruby, PHP, Swift, C# (.NET)

**Supported config/IaC formats**: YAML, TOML, JSON, .env, .properties, .ini, .cfg, .conf, Terraform HCL (`.tf`), Kubernetes cert-manager YAML, Ansible playbooks (YAML), AWS CloudFormation (YAML/JSON)

**Supported binary formats**: ELF (Linux/Android), PE (Windows), Mach-O (macOS/iOS), fat Mach-O — symbol table; string + OID extraction fallback for all other binaries

**Supported Java artifact formats**: `.jar`, `.war`, `.ear`, `.aar` archives; `.class` files — Java class constant pool parsing

---

## Quantum-vulnerable (CRITICAL)

| Algorithm | OID | Key size / curve | Primitive |
|---|---|---|---|
| RSA-1024 | 1.2.840.113549.1.1.1 | 1024 | PKE |
| RSA-2048 | 1.2.840.113549.1.1.1 | 2048 | PKE |
| RSA-3072 | 1.2.840.113549.1.1.1 | 3072 | PKE |
| ECDSA-P-256 | 1.2.840.10045.2.1 | P-256 | Signature |
| ECDH-P-256 | 1.2.840.10045.2.1 | P-256 | KEM |
| DSA | 1.2.840.10040.4.1 | — | Signature |

## Quantum-vulnerable (HIGH)

| Algorithm | Key size / curve | Primitive |
|---|---|---|
| RSA-4096 | 4096 | PKE |
| ECDSA-P-384 | P-384 | Signature |
| ECDSA-P-521 | P-521 | Signature |
| ECDH-P-384 | P-384 | KEM |
| ECDH-P-521 | P-521 | KEM |

## Classically weak (MEDIUM)

| Algorithm | Issue |
|---|---|
| SHA-1 | Collision attacks (SHAttered) |
| MD5 | Collision attacks |
| 3DES | Sweet32 birthday attack; 64-bit block size |
| RC4 | Biases in keystream; deprecated in TLS |
| DES | 56-bit key; brute-forceable |

## Adequate (LOW)

| Algorithm | Notes |
|---|---|
| SHA-256 | Quantum security ≈ 128-bit (Grover) |
| AES-128 | Quantum security ≈ 64-bit (Grover) — borderline |
| SHA-224 | Truncated SHA-256; marginal |

## Quantum-safe (NONE)

| Algorithm | NIST Level | Standard |
|---|---|---|
| AES-256 | 5 | FIPS 197 |
| AES-256-GCM | 5 | NIST SP 800-38D |
| ChaCha20-Poly1305 | 5 | RFC 8439 |
| SHA-384 | 4 | FIPS 180-4 |
| SHA-512 | 5 | FIPS 180-4 |
| SHA-3-256 | 2 | FIPS 202 |
| SHA-3-512 | 5 | FIPS 202 |
| ML-KEM-512 | 1 | FIPS 203 |
| ML-KEM-768 | 3 | FIPS 203 |
| ML-KEM-1024 | 5 | FIPS 203 |
| ML-DSA-44 | 2 | FIPS 204 |
| ML-DSA-65 | 3 | FIPS 204 |
| ML-DSA-87 | 5 | FIPS 204 |
| SLH-DSA-128s | 1 | FIPS 205 |
| SLH-DSA-256s | 5 | FIPS 205 |
| Ed25519 | — | RFC 8032 (classically secure; not yet PQC) |
| X25519 | — | RFC 7748 (classically secure; not yet PQC) |

---

## Detected library mappings

Libraries detected in package manifests are mapped to their primary algorithm:

| Library | Primary algorithm |
|---|---|
**Rust (Cargo.toml)**

| Library | Primary algorithm |
|---|---|
| `openssl` | RSA-2048 |
| `ring` | ECDSA-P-256 |
| `rsa` | RSA-2048 |
| `ecdsa` | ECDSA-P-256 |
| `ed25519-dalek` | Ed25519 |
| `sha1` | SHA-1 |
| `sha2` | SHA-256 |
| `md5` | MD5 |
| `aes` | AES-128 |
| `pqcrypto-kyber` | ML-KEM-768 |
| `ml-kem` | ML-KEM-768 |

**JavaScript / Node (package.json)**

| Library | Primary algorithm |
|---|---|
| `node-forge` | RSA-2048 |
| `jsonwebtoken` | RSA-2048 |
| `elliptic` | ECDSA-P-256 |

**Python (requirements.txt / Pipfile)**

| Library | Primary algorithm |
|---|---|
| `cryptography` | RSA-2048 |
| `paramiko` | RSA-2048 |
| `pycryptodome` | RSA-2048 |

**Go (go.mod)**

| Library | Primary algorithm |
|---|---|
| `golang.org/x/crypto` | ECDH-P-256 |
| `golang-jwt/jwt` | RSA-2048 |
| `cloudflare/circl` | ML-KEM-768 |

**Ruby (Gemfile / .rb source)**

| Library | Primary algorithm |
|---|---|
| `openssl` (gem) | RSA-2048 |

**PHP (composer.json / .php source)**

| Library | Primary algorithm |
|---|---|
| `openssl` (ext) | RSA-2048 |

**Java (pom.xml / build.gradle / build.gradle.kts)**

| Library | Primary algorithm |
|---|---|
| `bcprov-jdk18on` | RSA-2048 |
| `bcpkix-jdk18on` | RSA-2048 |
| `java-jwt` | RSA-2048 |
| `jjwt-api` | RSA-2048 |
| `jjwt-impl` | RSA-2048 |
| `nimbus-jose-jwt` | ECDSA-P-256 |
| `spring-security-crypto` | RSA-2048 |
| `tink` | AES-256 |
| `conscrypt-openjdk-uber` | ECDSA-P-256 |
| `google-cloud-kms` | RSA-2048 |

Full list: 75+ entries. See `src/detect/manifest.rs` in the source code.
