# acdi diff

Compare two CBOM files and report what cryptographic assets were added, removed, or changed between scans.

## Synopsis

```
acdi diff <BEFORE> <AFTER> [OPTIONS]
```

## Arguments

| Argument | Description |
|---|---|
| `<BEFORE>` | Path to the older CBOM JSON file |
| `<AFTER>` | Path to the newer CBOM JSON file |

## Options

| Flag | Default | Description |
|---|---|---|
| `--format <FORMAT>` | `text` | Output format: `text` or `json` |

---

## Examples

### Show changes between two scans

```bash
acdi diff cbom-before.json cbom-after.json
```

```
+ ADDED   ML-KEM-768  Algorithm  src/crypto/kem.rs
- REMOVED RSA-2048    Algorithm  src/crypto/legacy.rs
~ CHANGED ECDSA-P-256 Algorithm  src/auth/sign.rs  (VULNERABLE → ADEQUATE)
```

### Machine-readable diff

```bash
acdi diff cbom-before.json cbom-after.json --format json
```

---

## Workflow: tracking migration progress

Use `acdi diff` to measure PQC migration progress sprint-over-sprint.

```bash
# Baseline scan at the start of migration
acdi scan ./project --quiet > cbom-baseline.json

# ... migration work happens ...

# Rescan after changes
acdi scan ./project --quiet > cbom-current.json

# Show what improved
acdi diff cbom-baseline.json cbom-current.json
```

---

## Change types

| Symbol | Meaning |
|---|---|
| `+` ADDED | Asset present in `AFTER` but not in `BEFORE` |
| `-` REMOVED | Asset present in `BEFORE` but not in `AFTER` |
| `~` CHANGED | Asset present in both; quantum safety or risk level changed |
