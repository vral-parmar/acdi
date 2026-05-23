# GitHub Advanced Security Integration

`acdi` integrates with [GitHub Advanced Security](https://docs.github.com/en/code-security/code-scanning) via SARIF upload. Findings appear in the **Security → Code scanning** tab alongside CodeQL and other tools.

---

## Setup

### 1. Add the workflow

Create `.github/workflows/acdi.yml`:

```yaml
name: Cryptography scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 4 * * 1'   # weekly, Monday 04:00 UTC

jobs:
  acdi:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - name: Download acdi
        run: |
          curl -Lo acdi \
            https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-unknown-linux-musl
          chmod +x acdi

      - name: Scan
        run: ./acdi scan . --format sarif --output acdi.sarif --quiet

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: acdi.sarif
          category: acdi-cryptography
```

### 2. Enable GitHub Advanced Security

In your repository → **Settings → Security & analysis**, enable:
- Code scanning
- Secret scanning (optional, separate feature)

### 3. View findings

Navigate to **Security → Code scanning alerts**. Filter by tool `acdi` to see only cryptography findings.

---

## What you'll see

Each finding in the Security tab includes:

- **Rule ID** — e.g. `acdi/RSA`, `acdi/ECDSA`
- **Severity** — Error (CRITICAL/HIGH), Warning (MEDIUM), Note (LOW)
- **Location** — file and line number, with inline diff annotation on PRs
- **Description** — algorithm name, HNDL risk, NIST level
- **Remediation message** — what to replace it with

---

## Pull request annotations

When a PR introduces a new vulnerable algorithm, the finding appears as an inline annotation on the diff:

```
⚠ RSA-2048 (HNDL risk: CRITICAL) — This algorithm is vulnerable to quantum
  computers via Shor's algorithm. Replace with ML-KEM-768 (FIPS 203) for
  key exchange or ML-DSA-65 (FIPS 204) for signatures.
```

---

## Suppressing findings in GitHub

You can dismiss individual findings in the Security tab with a reason:
- **False positive** — the algorithm is not used in a security context
- **Won't fix** — accepted risk (document in `.acdignore` for consistency)
- **Used in tests** — test code (add a `path:tests/**` rule to `.acdignore`)

For bulk suppression, use [`.acdignore`](../reference/acdignore.md) and re-upload the SARIF — dismissed findings in SARIF won't reappear.
