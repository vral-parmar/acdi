# Terraform & Kubernetes Scanning

`acdi` v0.5.0 extends config scanning to Terraform HCL (`.tf`) and Kubernetes cert-manager manifests (`.yaml`/`.yml`), so infrastructure-as-code crypto choices are inventoried alongside application code.

---

## Terraform HCL

### What is detected

| Attribute | Values detected | Resolved algorithm |
|---|---|---|
| `algorithm` | `"RSA"`, `"ECDSA"` | RSA-2048, ECDSA-P-256 |
| `rsa_bits` | `2048`, `3072`, `4096` | RSA-2048, RSA-3072, RSA-4096 |
| `ecdsa_curve` | `"P256"`, `"P384"`, `"P521"` | ECDSA-P-256, ECDSA-P-384, ECDSA-P-521 |
| `customer_master_key_spec` | `"RSA_2048"`, `"ECC_NIST_P256"`, `"SYMMETRIC_DEFAULT"`, … | RSA-2048, ECDSA-P-256, AES-256 |
| `key_algorithm` | `"RSA_SIGN_PKCS1_2048_SHA256"`, `"EC_SIGN_P256_SHA256"`, … | RSA-2048, ECDSA-P-256 |

### Example — TLS private key

```hcl
resource "tls_private_key" "server" {
  algorithm   = "RSA"     # → detected: RSA-2048
  rsa_bits    = 2048      # → detected: RSA-2048
}

resource "tls_private_key" "ecdsa" {
  algorithm   = "ECDSA"   # → detected: ECDSA-P-256
  ecdsa_curve = "P256"    # → detected: ECDSA-P-256
}
```

### Example — AWS KMS key

```hcl
resource "aws_kms_key" "signing" {
  description              = "Signing key"
  customer_master_key_spec = "RSA_2048"   # → detected: RSA-2048
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_key" "aes" {
  customer_master_key_spec = "SYMMETRIC_DEFAULT"  # → detected: AES-256
}
```

### Example — GCP KMS

```hcl
resource "google_kms_crypto_key" "ec_key" {
  name     = "my-ec-key"
  key_ring = google_kms_key_ring.keyring.id

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"  # → detected: ECDSA-P-256
    protection_level = "HSM"
  }
}
```

### Run a scan

```bash
# Scan a Terraform project directory
acdi scan ./infrastructure

# Gate the pipeline: fail if any CRITICAL finding (RSA < 4096, ECDSA, …)
acdi scan ./infrastructure --fail-on critical --quiet > /dev/null

# Generate a migration report
acdi scan ./infrastructure --format html --output infra-crypto.html
```

---

## Kubernetes cert-manager

### What is detected

| Field | Values | Resolved algorithm |
|---|---|---|
| `curve` | `P256`, `P384`, `P521` | ECDSA-P-256, ECDSA-P-384, ECDSA-P-521 |
| `algorithm` (generic) | `RSA`, `ECDSA` | RSA-2048, ECDSA-P-256 |

### Example

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-cert
spec:
  secretName: example-tls
  privateKey:
    algorithm: ECDSA   # → detected: ECDSA-P-256
    curve: P256        # → detected: ECDSA-P-256
  dnsNames:
    - example.com
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
```

### Run a scan

```bash
# Scan a Kubernetes manifests directory
acdi scan ./k8s/

# Include subdirectories (default — acdi walks recursively)
acdi scan . --format sarif --output k8s-crypto.sarif
```

---

## Suppress known findings

Use `.acdignore` to suppress noise from intentional legacy entries:

```text
# .acdignore
# Suppress RSA-2048 findings in the legacy module only
algorithm: RSA-2048
path: legacy/**
```

See [`.acdignore` reference](../reference/acdignore.md) for full syntax.

---

## CI/CD integration

Terraform and Kubernetes files are picked up automatically — no extra flags needed.
See [CI/CD Integration](ci-cd.md) for complete pipeline examples.
