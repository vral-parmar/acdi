# Binary & Java Artifact Scanning

`acdi` can extract cryptographic asset information from compiled binaries and Java archives without access to source code. This is useful for scanning dependencies, third-party libraries, Docker layers, and CI/CD build artifacts.

---

## ELF / PE / Mach-O symbol scanning

`acdi` uses structured symbol table information — not just printable strings — to identify cryptographic function calls in native binaries.

**What it covers:**

| Binary format | Where symbols are read |
|---|---|
| ELF (Linux, Android) | `.dynsym` (dynamic) + `.symtab` (full) |
| PE (Windows) | Import table + export table |
| Mach-O (macOS, iOS) | `LC_DYSYMTAB` imports (first slice of fat binaries) |

**Symbol catalog** includes functions from:

- OpenSSL / BoringSSL (`RSA_generate_key`, `EVP_aes_256_gcm`, `ECDSA_sign`, `EVP_sha256`, …)
- Windows CNG / CAPI (`BCryptGenerateKeyPair`, `CryptGenKey`, `NCryptCreatePersistedKey`)
- PKCS#11 (`C_GenerateKeyPair`, `C_SignInit`, `C_DecryptInit`)
- libsodium (`crypto_sign_ed25519`, `crypto_box_curve25519xsalsa20poly1305`)
- OQS liboqs (`OQS_KEM_ml_kem_768_keypair`, `PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair`)

**Example:**

```bash
acdi scan ./libssl.so
acdi scan ./app.exe
acdi scan /usr/lib/libcrypto.dylib
```

!!! note
    Symbol scanning is best-effort. Stripped binaries may have no symbol table — `acdi` falls back to string extraction in that case.

---

## JAR / WAR / EAR / AAR scanning

Java archives are ZIP files. `acdi` opens them and scans every `.class` entry's constant pool for JCA algorithm strings.

**What is detected:**

| Constant pool string | Detected as |
|---|---|
| `javax/crypto/Cipher` | AES-256 (generic JCA cipher) |
| `AES/GCM/NoPadding` | AES-256 |
| `AES/CBC/PKCS5Padding` | AES-128 |
| `SHA256withRSA` | RSA-2048 |
| `SHA1withRSA` | RSA-2048 |
| `SHA256withECDSA` | ECDSA |
| `java/security/MessageDigest` | SHA-256 |
| `MD5` | MD5 |

**Example:**

```bash
acdi scan ./target/myapp.jar
acdi scan ./build/libs/service.war
acdi scan ./app/build/outputs/aar/library-release.aar
```

Scan an entire Maven or Gradle build output directory:

```bash
acdi scan ./target/
acdi scan ./build/libs/
```

---

## Standalone `.class` files

The same constant pool parser runs on individual `.class` files:

```bash
acdi scan ./MyService.class
```

---

## Private key size extraction

When scanning PEM or DER private key files, `acdi` parses the key structure to extract the exact size or curve — rather than just the algorithm type:

| Key format | Example output |
|---|---|
| PKCS#8 RSA | `RSA-2048` with `parameterSet: "2048"` |
| PKCS#1 RSA | `RSA-2048` with `parameterSet: "2048"` |
| PKCS#8 EC | `ECDSA-P-256` with `parameterSet: "P-256"` |
| SEC1 EC | `ECDSA-P-256` with `parameterSet: "P-256"` |

```bash
acdi scan ./private.key
acdi scan ./keys/
```

---

## Suppressing binary noise

Symbol and string scanning can produce findings from third-party code bundled inside your binary. Use `.acdignore` to suppress:

```
# Ignore all symbol-table findings in vendored C libraries
evidence:elf-symbol
path:vendor/openssl/**

# Ignore JAR scan results for test dependencies
evidence:jar-class-file
path:target/test-classes/**
```

See [.acdignore reference](../reference/acdignore.md) for full syntax.

---

## Watch mode for build outputs

Use `--watch` to continuously re-scan a build output directory as compilation produces new artifacts:

```bash
acdi scan ./target --watch
```

On each change you'll see `[+]` for newly detected findings and `[-]` for resolved ones — useful during a migration sprint to confirm algorithms are being removed.
