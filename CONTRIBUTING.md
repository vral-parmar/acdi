# Contributing to acdi

Thank you for your interest in contributing. This document covers how to get set up, the conventions used in the codebase, and how to submit changes.

---

## Development setup

**Requirements:** Rust 1.75+ (install via [rustup](https://rustup.rs))

```bash
git clone https://github.com/YOUR_USERNAME/acdi
cd acdi
cargo build
cargo test
```

---

## Before you open a PR

1. **Run the test suite and clippy:**
   ```bash
   cargo test
   cargo clippy --all-targets -- -D warnings
   cargo fmt --check
   ```
   All three must pass cleanly. CI enforces this on every PR.

2. **Add tests.** Every new feature or bug fix should include at least one test in `tests/integration.rs`. Unit tests in the relevant module are also welcome.

3. **Keep `#![forbid(unsafe_code)]`.** Every module carries this attribute. Do not remove it. Do not add `unsafe` blocks.

4. **No `unwrap()` or `expect()` in library code.** Use `anyhow::Result` and the `?` operator. `unwrap()` is acceptable in tests only.

5. **No new `println!` in library code.** All user-facing output goes through the output layer (`src/output/`). Use `tracing::debug!` / `tracing::warn!` for diagnostics.

---

## Contribution areas

### Adding a new algorithm to the catalog

Edit `src/catalog/algorithms.rs`. Each entry needs:
- Canonical name (string key)
- `QuantumSafety` classification
- `Risk` level
- `primitive` (pke, signature, hash, symmetric, ...)
- `nist_quantum_security_level` (0–5)

### Adding source-code detection patterns

Detection rules live in `src/detect/`. Source-code patterns use `regex` crate syntax (no negative lookahead — use explicit alternation).

For a new language, add it to `src/detect/source.rs` and add test fixtures under `tests/fixtures/source/`.

### Adding a new package manifest

Add a parser in `src/detect/manifest.rs` and register the filename in `MANIFEST_FILENAMES` in `src/detect/mod.rs`. Add a test fixture under `tests/fixtures/manifests/`.

### Adding a new config-file pattern

Extend the value alias table in `src/detect/config.rs` (`CONFIG_VALUE_ALIASES`). Values are lowercase-matched. Add a test fixture under `tests/fixtures/config/`.

---

## Commit style

Use conventional commit prefixes:

```
feat: add ML-KEM detection in source scanner
fix: handle empty Pipfile without panic
test: add integration test for go.mod pqc libraries
docs: document .acdignore path glob syntax
chore: bump uuid to 1.9
```

---

## Reporting bugs

Open a [GitHub Issue](../../issues/new?template=bug_report.md) and include:
- `acdi --version` output
- The command you ran
- The unexpected behaviour and what you expected

For security vulnerabilities, open a [Security Advisory](../../security/advisories/new) instead of a public issue.

---

## License

By submitting a pull request you agree your contribution is licensed under the MIT License.
