# acdi scan

Scan a file or directory for cryptographic assets.

## Synopsis

```
acdi scan <PATH> [OPTIONS]
```

## Arguments

| Argument | Description |
|---|---|
| `<PATH>` | File or directory to scan. Accepts any file type; unrecognised files are skipped. |

## Options

| Flag | Default | Description |
|---|---|---|
| `-o, --output <FILE>` | — | Write output to this file. When set, the human table still goes to stdout. |
| `--format <FORMAT>` | `cyclonedx-1.7` | Output format. See below. |
| `--fail-on <LEVEL>` | — | Exit code 1 if any finding meets or exceeds this risk level. |
| `--watch` | off | Continuous scan mode — re-scan on file-system events, printing `[+]` new findings and `[-]` resolved findings. Press Ctrl-C to stop. |
| `-q, --quiet` | off | Suppress the table; print structured output only. |
| `--follow-links` | off | Follow symbolic links when walking directories. |
| `--ignore-file <FILE>` | `<PATH>/.acdignore` | Path to a custom ignore file. |
| `--no-ignore` | off | Disable all `.acdignore` suppression. |
| `-v, --verbose` | off | Increase log verbosity (`-v` = debug, `-vv` = trace). Logs go to stderr. |

## Format values

| Value | Description |
|---|---|
| `cyclonedx-1.7` | CycloneDX 1.7 CBOM JSON (default) |
| `sarif` | SARIF 2.1.0 JSON |
| `html` | Self-contained HTML migration report |
| `csv` | RFC 4180 CSV — 8 columns per occurrence |

## Fail-on levels

| Value | Exits 1 when... |
|---|---|
| `low` | Any finding present |
| `medium` | Any MEDIUM, HIGH, or CRITICAL finding |
| `high` | Any HIGH or CRITICAL finding |
| `critical` | Any CRITICAL finding |

---

## Output routing

`acdi scan` has three output modes depending on which flags you combine:

| Flags | Structured output | Table |
|---|---|---|
| _(none)_ | hint only | stdout |
| `--output <file>` | written to file | stdout |
| `--quiet` | stdout | suppressed |
| `--quiet --output <file>` | written to file | suppressed |

---

## Examples

### Basic scan

```bash
acdi scan ./my-project
```

### Write a CBOM file; table still goes to terminal

```bash
acdi scan ./my-project --output cbom.json
```

### Pipe-friendly CBOM (no table)

```bash
acdi scan ./my-project --quiet > cbom.json
```

### HTML migration report

```bash
acdi scan ./my-project --format html --output report.html
```

### SARIF for GitHub Advanced Security

```bash
acdi scan ./my-project --format sarif --output results.sarif
```

### CSV export for data analysis

```bash
acdi scan ./my-project --format csv --quiet > findings.csv
```

### Scan a single certificate

```bash
acdi scan ./certs/server.crt.pem --quiet
```

### CI gate — fail on high or worse

```bash
acdi scan . --fail-on high --quiet > /dev/null
echo "Exit: $?"
```

### Verbose logging

```bash
acdi scan ./my-project -v 2>&1 | head -40
```

### Custom ignore file

```bash
acdi scan ./my-project --ignore-file ./security/exceptions.acdignore
```

### Bypass ignore rules (full audit)

```bash
acdi scan ./my-project --no-ignore
```

### Watch mode — live re-scan

```bash
acdi scan ./my-project --watch
```

Watches the directory for file-system events. On each change, re-runs the full scan and prints a diff:

```
[+] RSA-1024  CRITICAL  src/auth/legacy.go:42
[-] SHA-1     MEDIUM    src/hash.py:18
```

Press **Ctrl-C** to stop.

---

## What gets scanned

`acdi scan` routes each file to the appropriate scanner based on filename and extension:

| Scanner | Triggers |
|---|---|
| Certificate & key | `.pem`, `.crt`, `.cer`, `.der`, `.key`, `.p12`, `.pfx` |
| Source code | `.c`, `.cpp`, `.go`, `.java`, `.kt`, `.kts`, `.py`, `.rs`, `.js`, `.ts`, `.rb`, `.php`, `.swift`, `.cs` |
| Config / IaC | `.yaml`, `.yml`, `.toml`, `.json`, `.env`, `.ini`, `.cfg`, `.conf`, `.properties`, `.tf` |
| Package manifest | `Cargo.toml`, `package.json`, `requirements.txt`, `Pipfile`, `go.mod`, `pom.xml`, `build.gradle`, `build.gradle.kts` |
| Java archives | `.jar`, `.war`, `.ear`, `.aar` — opens archive, parses every `.class` constant pool |
| Java class file | `.class` — parses constant pool directly |
| Binary (symbols) | ELF / PE / Mach-O — resolves imported/exported function symbols to algorithm names |
| Binary (strings) | All other files — string extraction + OID scan fallback |

!!! note
    Package manifests are matched by **filename** before the extension is checked — so `Cargo.toml` is always scanned as a manifest, not a TOML config file.

!!! note
    Files without an extension are sniffed by magic bytes: ZIP magic (`PK\x03\x04`) triggers the JAR scanner; ELF/PE/Mach-O magic triggers the symbol scanner; everything else falls through to string extraction.
