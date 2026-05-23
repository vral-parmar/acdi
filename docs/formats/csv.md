# CSV Output

`acdi` can emit findings as RFC 4180 CSV — one row per occurrence, easy to load into spreadsheets, pandas, or any BI tool.

## Generate CSV output

```bash
acdi scan ./my-project --format csv --quiet > findings.csv
```

## Schema

Eight columns, header always present:

| Column | Example | Notes |
|---|---|---|
| `Algorithm` | `RSA-2048` | Canonical algorithm name |
| `AssetType` | `algorithm` | One of: `algorithm`, `certificate`, `private-key`, `public-key`, `protocol`, `library` |
| `QuantumSafety` | `VULNERABLE` | `VULNERABLE`, `ADEQUATE`, `SAFE`, `HYBRID_SAFE`, `UNKNOWN` |
| `HNDLRisk` | `CRITICAL` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `NISTLevel` | `0` | NIST quantum security level (0 = not quantum-safe) |
| `File` | `/src/auth/jwt.go` | Absolute path to the file containing the finding |
| `Line` | `42` | Line number (blank for certificate findings or when not applicable) |
| `Evidence` | `source-code-pattern` | How the finding was detected — see below |

### Evidence values

| Value | Source |
|---|---|
| `certificate-parsing` | X.509 certificate or key file |
| `source-code-pattern` | Regex match in source code |
| `binary-string-search` | String extraction from compiled binary |
| `config-file-rule` | Key/value in config file |
| `manifest-dependency` | Library in package manifest |
| `tls-handshake` | Live TLS endpoint probe |

## RFC 4180 compliance

- Fields containing commas, double-quotes, or newlines are wrapped in double-quotes.
- Internal double-quotes are escaped by doubling (`"` → `""`).
- Lines are terminated with `\n`.

## Example rows

```
Algorithm,AssetType,QuantumSafety,HNDLRisk,NISTLevel,File,Line,Evidence
RSA-2048,algorithm,VULNERABLE,CRITICAL,0,/src/auth/jwt.go,14,source-code-pattern
ECDSA-P-256,certificate,VULNERABLE,CRITICAL,0,/certs/server.crt,,certificate-parsing
SHA-1,algorithm,VULNERABLE,MEDIUM,0,/src/legacy/hash.py,8,source-code-pattern
AES-256,algorithm,SAFE,NONE,5,/src/crypto/enc.rs,22,source-code-pattern
bcprov-jdk18on,library,VULNERABLE,CRITICAL,0,/pom.xml,9,manifest-dependency
```

## Load into pandas

```python
import pandas as pd
df = pd.read_csv("findings.csv")
critical = df[df["HNDLRisk"] == "CRITICAL"]
print(critical[["Algorithm", "File", "Line"]].to_string())
```

## Save to file

```bash
# Write to file; human table still goes to stdout
acdi scan ./project --format csv --output findings.csv

# Pipe-friendly (no table)
acdi scan ./project --format csv --quiet > findings.csv
```
