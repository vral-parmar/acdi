# Risk Model

`acdi` assigns two scores to every finding: a **quantum safety** classification and an **HNDL risk** level.

---

## Quantum Safety

| Value | Meaning |
|---|---|
| `VULNERABLE` | Broken by Shor's algorithm on a cryptographically relevant quantum computer |
| `ADEQUATE` | Classically weak but not quantum-broken — still needs replacement |
| `QUANTUM_SAFE` | Resistant to both classical and quantum attacks (e.g. ML-KEM, ML-DSA) |
| `HYBRID_SAFE` | Hybrid classical+PQC scheme |
| `UNKNOWN` | Not enough information to classify |

---

## HNDL Risk

**Harvest Now, Decrypt Later (HNDL)** is the threat model where an adversary captures encrypted traffic today, stores it, and decrypts it once a quantum computer is available. Even if you don't have a quantum computer yet, data encrypted with RSA or ECDSA *today* is at risk.

| Risk | Algorithms | Rationale |
|---|---|---|
| **CRITICAL** | RSA-1024, RSA-2048, RSA-3072, ECDSA-P-256, ECDH-P-256, DH-1024 | Immediately vulnerable; small key sizes are near-term quantum targets |
| **HIGH** | RSA-4096, ECDSA-P-384, ECDSA-P-521, ECDH-P-384 | Quantum-vulnerable; larger key sizes only delay the inevitable |
| **MEDIUM** | SHA-1, MD5, 3DES, RC4, DES | Classically weak; must be replaced regardless of quantum risk |
| **LOW** | SHA-256, AES-128, SHA-224 | Classical security adequate; marginal quantum resistance |
| **NONE** | AES-256, AES-256-GCM, SHA-384, SHA-512, ML-KEM, ML-DSA, SLH-DSA, ChaCha20-Poly1305 | Quantum-safe or quantum-resistant |

---

## NIST Quantum Security Levels

NIST defines five security levels for post-quantum algorithms, based on the classical equivalent:

| Level | Classical equivalent | Example algorithms |
|---|---|---|
| 0 | None (broken) | RSA, ECDSA, SHA-1, MD5 |
| 1 | AES-128 | ML-KEM-512, ML-DSA-44 |
| 2 | SHA-256 | AES-256 (symmetric) |
| 3 | AES-192 | ML-KEM-768, ML-DSA-65 |
| 4 | SHA-384 | — |
| 5 | AES-256 | ML-KEM-1024, ML-DSA-87, SLH-DSA-256 |

---

## NIST IR 8547 Migration Schedule

| Date | Event |
|---|---|
| **2024** | FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) published |
| **2030** | RSA, ECDSA, ECDH, DH **deprecated** — no new uses permitted in federal systems |
| **2035** | RSA, ECDSA, ECDH, DH **disallowed** — all existing uses must be replaced |

Private sector is not legally bound by NIST IR 8547, but it sets the de facto industry standard.

---

## Using risk levels for prioritisation

A practical migration triage:

1. **CRITICAL** — Replace immediately. These are your highest HNDL exposure; long-lived data encrypted with RSA-2048 or ECDSA-P-256 is at real risk.
2. **HIGH** — Plan to replace before 2027. Larger RSA/ECC keys buy time but not safety.
3. **MEDIUM** — Replace as part of normal modernisation. SHA-1 and MD5 are broken classically.
4. **LOW** — Low priority. SHA-256 and AES-128 have adequate classical security.
5. **NONE** — No action needed. AES-256, SHA-512, and NIST PQC algorithms are quantum-safe.

---

## Using `--fail-on` in CI

Gate your pipeline to prevent new vulnerable algorithms from being introduced:

```bash
# Fail if any CRITICAL or HIGH finding is present
acdi scan . --fail-on high --quiet > /dev/null

# Strict mode — fail on anything Medium or worse
acdi scan . --fail-on medium --quiet > /dev/null
```
