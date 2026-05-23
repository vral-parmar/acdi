# CycloneDX 1.7 CBOM

`acdi` emits fully compliant [CycloneDX 1.7 Cryptography Bill of Materials](https://cyclonedx.org/capabilities/cbom/) (CBOM) by default.

## Generate a CBOM

```bash
# Print to stdout
acdi scan ./project --quiet

# Write to file; table still goes to terminal
acdi scan ./project --output cbom.json

# Pipe-friendly
acdi scan ./project --quiet > cbom.json
```

---

## Schema overview

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-23T16:42:12Z",
    "tools": [{ "vendor": "acdi", "name": "acdi", "version": "0.3.0" }]
  },
  "components": [ ... ]
}
```

Each finding is a `component` with `type: "cryptographic-asset"`.

---

## Component structure

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "9888b65b-c054-453b-b9dd-b02333603cc3",
  "name": "RSA-2048",
  "description": "Quantum safety: VULNERABLE | HNDL risk: CRITICAL | NIST level: 0",
  "cryptoProperties": {
    "assetType": "certificate",
    "algorithmProperties": {
      "primitive": "pke",
      "parameterSetIdentifier": "2048",
      "executionEnvironment": "unknown",
      "implementationPlatform": "unknown",
      "certificationLevel": [],
      "mode": "unknown",
      "padding": "unknown",
      "cryptoFunctions": ["encrypt"],
      "nistQuantumSecurityLevel": 0
    },
    "oid": "1.2.840.113549.1.1.1"
  },
  "evidence": {
    "occurrences": [
      {
        "location": "/path/to/server.crt.pem",
        "additionalContext": "quantum_safe=VULNERABLE hndl_risk=CRITICAL"
      }
    ]
  },
  "properties": [
    { "name": "acdi:quantum_safe", "value": "VULNERABLE" },
    { "name": "acdi:hndl_risk",    "value": "CRITICAL" },
    { "name": "acdi:nist_level",   "value": "0" }
  ]
}
```

---

## Field reference

### `cryptoProperties.assetType`

| Value | Meaning |
|---|---|
| `algorithm` | A cryptographic algorithm used in source code, config, or manifest |
| `certificate` | An X.509 certificate |
| `private-key` | A private key file |
| `public-key` | A public key file |
| `protocol` | A protocol (TLS version, SSH, etc.) |
| `library` | A cryptographic library dependency |

### `cryptoProperties.algorithmProperties.primitive`

| Value | Algorithms |
|---|---|
| `pke` | RSA, Diffie-Hellman |
| `signature` | ECDSA, Ed25519, RSA-PSS |
| `hash` | SHA-1, SHA-256, MD5 |
| `symmetric` | AES, 3DES, ChaCha20 |
| `kem` | ML-KEM, ECDH |
| `xof` | SHAKE128, SHAKE256 |

### `cryptoProperties.algorithmProperties.nistQuantumSecurityLevel`

| Level | Meaning |
|---|---|
| 0 | No quantum security (RSA, ECDSA, classical hashes) |
| 1 | ≥ AES-128 security against quantum attacks |
| 2 | ≥ SHA-256 security against quantum attacks |
| 3 | ≥ AES-192 security against quantum attacks |
| 4 | ≥ SHA-384 security against quantum attacks |
| 5 | ≥ AES-256 security against quantum attacks |

### `acdi:*` properties

| Property | Values |
|---|---|
| `acdi:quantum_safe` | `VULNERABLE`, `ADEQUATE`, `QUANTUM_SAFE`, `HYBRID_SAFE`, `UNKNOWN` |
| `acdi:hndl_risk` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `acdi:nist_level` | `0` – `5` |

---

## Integrations

The CBOM output is compatible with:

- [Dependency-Track](https://dependencytrack.org/) — import as a BOM
- [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) — validate, convert, merge
- `acdi diff` — compare two CBOMs to track migration progress
