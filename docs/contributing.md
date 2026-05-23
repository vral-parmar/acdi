# Contributing to acdi

Thank you for your interest in contributing. This document covers how to get set up, the conventions used in the codebase, and how to submit changes.

---

## Development setup

**Requirements:** Rust 1.75+ (install via [rustup](https://rustup.rs))

```bash
git clone https://github.com/vral-parmar/acdi
cd acdi
cargo build
cargo test
```

---

## Before you open a PR

Run all three checks — CI enforces them on every PR:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

### Code conventions

- **`#![forbid(unsafe_code)]`** — every module carries this attribute. Do not remove it or add `unsafe` blocks.
- **No `unwrap()` / `expect()` in library code** — use `anyhow::Result` and the `?` operator. `unwrap()` is acceptable in tests only.
- **No `println!` in library code** — all user-facing output goes through `src/output/`. Use `tracing::debug!` / `tracing::warn!` for diagnostics.
- **Add tests** — every new feature or bug fix should include at least one test in `tests/integration.rs`.

---

## Adding a new algorithm to the catalog

Edit `src/catalog/algorithms.rs`. Each entry needs:

- Canonical name
- `QuantumSafety` classification
- `Risk` level
- `primitive` (pke, signature, hash, symmetric, …)
- `nist_quantum_security_level` (0–5)

---

## Adding source-code detection patterns

Source-code rules live in `src/detect/source.rs`. Rules use `regex` crate syntax.

!!! warning "No negative lookahead"
    The `regex` crate does not support `(?!...)`. Use explicit alternation instead.

Add test fixtures under `tests/fixtures/source/` and a corresponding test in `tests/integration.rs`.

---

## Adding a new package manifest

1. Add a parser in `src/detect/manifest.rs`
2. Register the filename in `MANIFEST_FILENAMES` in `src/detect/mod.rs`
3. Add a test fixture under `tests/fixtures/manifests/`

---

## Adding a new config-file pattern

Extend `CONFIG_VALUE_ALIASES` in `src/detect/config.rs`. Values are lowercase-matched. Add a test fixture under `tests/fixtures/config/`.

---

## Commit style

```
feat: add ML-KEM detection in source scanner
fix: handle empty Pipfile without panic
test: add integration test for go.mod pqc libraries
docs: document .acdignore path glob syntax
chore: bump uuid to 1.9
```

---

## Reporting bugs

Open a [GitHub Issue](https://github.com/vral-parmar/acdi/issues/new?template=bug_report.md).

For security vulnerabilities, open a [Security Advisory](https://github.com/vral-parmar/acdi/security/advisories/new) instead of a public issue.

---

## License

By submitting a pull request you agree your contribution is licensed under the MIT License.
