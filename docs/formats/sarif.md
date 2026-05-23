# SARIF 2.1.0

`acdi` emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) output suitable for import into GitHub Advanced Security, VS Code, and any SAST platform that supports the standard.

## Generate SARIF

```bash
acdi scan ./project --format sarif --output results.sarif
```

---

## Schema overview

### Rules

Each algorithm family becomes a SARIF rule:

```json
{
  "id": "acdi/RSA",
  "name": "WeakCryptographyRSA",
  "shortDescription": { "text": "RSA is vulnerable to quantum computers (Shor's algorithm)" },
  "fullDescription": { "text": "RSA key exchange and signatures ..." },
  "helpUri": "https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf",
  "properties": { "tags": ["security", "cryptography", "pqc"] }
}
```

### Results

Each occurrence is a result with a physical location:

```json
{
  "ruleId": "acdi/RSA",
  "level": "error",
  "message": { "text": "RSA-2048 (HNDL risk: CRITICAL) ..." },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": { "uri": "src/auth/jwt.go" },
        "region": { "startLine": 42 }
      }
    }
  ]
}
```

### Risk → SARIF level mapping

| HNDL Risk | SARIF level |
|---|---|
| CRITICAL | `error` |
| HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |
| NONE | `none` |

---

## GitHub Advanced Security integration

```yaml
# .github/workflows/acdi.yml
- name: Scan for vulnerable cryptography
  run: acdi scan . --format sarif --output acdi.sarif --quiet

- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: acdi.sarif
    category: cryptography
```

Findings appear in the **Security → Code scanning** tab. Each finding links to the source line, shows the risk level, and includes the remediation message.

---

## VS Code

Install the [SARIF Viewer extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer), then:

```bash
acdi scan ./project --format sarif --output results.sarif
code results.sarif
```

The extension shows findings inline in the editor with squiggly lines and a Problems panel entry.
