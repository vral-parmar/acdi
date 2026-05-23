# acdi tls

Probe one or more TLS endpoints and inventory the negotiated cipher suite and certificate chain.

## Synopsis

```
acdi tls [TARGET] [OPTIONS]
```

## Arguments

| Argument | Description |
|---|---|
| `[TARGET]` | Single `host:port` to probe (e.g. `api.example.com:443`). Omit when using `--hosts`. |

## Options

| Flag | Default | Description |
|---|---|---|
| `--hosts <FILE>` | — | File with one `host:port` per line. `#` lines are comments. |
| `-o, --output <FILE>` | — | Write CBOM JSON to this file. |
| `--concurrency <N>` | `50` | Maximum concurrent TLS connections. |
| `--timeout <SECS>` | `10` | Per-host timeout in seconds. |

---

## Examples

### Probe a single endpoint

```bash
acdi tls api.example.com:443
```

### Probe multiple endpoints from a file

```bash
acdi tls --hosts endpoints.txt --output tls-cbom.json
```

### endpoints.txt format

```
# Production APIs
api.example.com:443
auth.example.com:443

# Internal services
db.internal:5432
# cache.internal:6380  ← commented out
```

### High-concurrency bulk scan

```bash
acdi tls --hosts all-hosts.txt --concurrency 100 --timeout 5 --output tls-cbom.json
```

---

## Output

`acdi tls` emits a CycloneDX 1.7 CBOM with:

- **Negotiated cipher suite** — the algorithm family (e.g. `ECDHE-RSA-AES256-GCM-SHA384` → RSA key exchange)
- **Certificate chain** — each certificate in the chain as a `certificate` asset with key algorithm, key size, and OID

Unreachable hosts produce a `tracing::warn` log entry and are skipped — the command exits `0` as long as at least one host was reachable.

---

## Notes

- `acdi tls` validates hostnames against an allow-list of safe characters before opening any connection. Hostnames containing shell metacharacters are rejected.
- IPv6 addresses are supported: `[::1]:443`.
- TLS 1.2 and TLS 1.3 are both supported.
