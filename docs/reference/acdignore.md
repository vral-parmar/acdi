# .acdignore

`.acdignore` lets you suppress findings that are known-acceptable — third-party vendor code, test fixtures, intentional legacy systems, or algorithms used in non-sensitive contexts.

## Placement

By default, `acdi scan` looks for `.acdignore` in the root of the scanned directory:

```
my-project/
├── .acdignore      ← loaded automatically
├── src/
└── ...
```

Override the path with `--ignore-file`, or disable it entirely with `--no-ignore`.

```bash
acdi scan ./project --ignore-file ./security/exceptions.acdignore
acdi scan ./project --no-ignore
```

---

## Syntax

One rule per line. `#` starts a comment. Blank lines are ignored.

Each line is a **set of conditions** that must ALL match (AND logic). A finding is suppressed if any rule matches.

### Condition types

| Condition | Example | Matches |
|---|---|---|
| `algorithm:<name>` | `algorithm:RSA-4096` | Algorithm name, case-insensitive |
| `path:<glob>` | `path:vendor/**` | File path glob |
| `evidence:<type>` | `evidence:binary-string-search` | How the finding was detected |

### Path glob syntax

| Pattern | Matches |
|---|---|
| `*` | Any sequence of characters **not** including `/` |
| `**` | Any sequence of characters **including** `/` |
| `?` | (not supported — use `*`) |

Examples:

| Glob | Matches |
|---|---|
| `vendor/**` | All files anywhere under `vendor/` |
| `tests/fixtures/*` | All files directly inside `tests/fixtures/` (not subdirs) |
| `*.test.ts` | All `.test.ts` files in the root |
| `src/legacy/**` | All files anywhere under `src/legacy/` |

### Evidence types

| Value | Detected by |
|---|---|
| `certificate-parsing` | PEM / DER certificate or key file |
| `source-code-pattern` | Regex match in source code |
| `binary-string-search` | String extraction from compiled binary |
| `config-file-rule` | Key/value in YAML, TOML, JSON, .env, etc. |
| `manifest-dependency` | Library in Cargo.toml, package.json, etc. |
| `tls-handshake` | Live TLS endpoint probe |

---

## Examples

### Suppress a specific algorithm globally

```
# RSA-4096 is approved for use in our HSM configurations
algorithm:RSA-4096
```

### Suppress all findings in vendor code

```
path:vendor/**
```

### Suppress SHA-1 in test fixtures only

```
algorithm:SHA-1
path:tests/fixtures/**
```

### Suppress noisy binary scan results in a specific directory

```
evidence:binary-string-search
path:legacy/blobs/**
```

### Suppress a library dependency across all manifests

```
algorithm:MD5
evidence:manifest-dependency
```

### Complex rule — all three conditions must match

```
algorithm:AES-128
path:internal/cache/**
evidence:source-code-pattern
```

---

## Full example `.acdignore`

```
# ─────────────────────────────────────────────────
# acdi ignore rules
# ─────────────────────────────────────────────────

# RSA-4096 is acceptable in HSM configurations per SEC-2024-003
algorithm:RSA-4096
path:infra/hsm/**

# Third-party vendor code — not our responsibility
path:vendor/**
path:node_modules/**

# Binary scan results in legacy blobs are too noisy
evidence:binary-string-search
path:legacy/**

# SHA-1 is only used for non-security checksums in the build tooling
algorithm:SHA-1
path:build/**

# Test fixtures are not production code
path:tests/fixtures/**
```

---

## Verification

To confirm your ignore rules are working, compare with and without `--no-ignore`:

```bash
# With suppression
acdi scan ./project --quiet | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['components']), 'findings')"

# Without suppression (full audit)
acdi scan ./project --no-ignore --quiet | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['components']), 'findings')"
```
