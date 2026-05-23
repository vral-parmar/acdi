# Installation

`acdi` ships as a single statically-linked binary. Pick the method that fits your workflow.

---

## Homebrew (macOS / Linux) — recommended

```bash
brew tap vral-parmar/tap
brew install acdi
acdi --version
```

The tap is automatically updated on every release.

---

## Docker

```bash
# Scan the current directory — mounts it as /src inside the container
docker run --rm -v "$(pwd)":/src ghcr.io/vral-parmar/acdi scan /src

# Generate an HTML report
docker run --rm -v "$(pwd)":/src \
  ghcr.io/vral-parmar/acdi scan /src --format html --output /src/report.html --quiet

# Pin a specific version
docker run --rm -v "$(pwd)":/src ghcr.io/vral-parmar/acdi:0.5.0 scan /src
```

---

## GitHub Action

Add to any GitHub Actions workflow:

```yaml
- uses: vral-parmar/acdi@v0.5.0
  with:
    args: 'scan . --format sarif --output acdi.sarif --quiet'

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: acdi.sarif
```

See [CI/CD Integration](guides/ci-cd.md) for complete examples.

---

## Pre-built binaries

Download the latest release from the [GitHub Releases](https://github.com/vral-parmar/acdi/releases) page.

=== "macOS (Apple Silicon)"

    ```bash
    curl -Lo acdi https://github.com/vral-parmar/acdi/releases/latest/download/acdi-aarch64-apple-darwin
    chmod +x acdi
    sudo mv acdi /usr/local/bin/
    acdi --version
    ```

=== "macOS (Intel)"

    ```bash
    curl -Lo acdi https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-apple-darwin
    chmod +x acdi
    sudo mv acdi /usr/local/bin/
    acdi --version
    ```

=== "Linux (x86_64)"

    Statically linked against musl — runs on any Linux distribution without glibc version constraints.

    ```bash
    curl -Lo acdi https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-unknown-linux-musl
    chmod +x acdi
    sudo mv acdi /usr/local/bin/
    acdi --version
    ```

=== "Linux (ARM64)"

    ```bash
    curl -Lo acdi https://github.com/vral-parmar/acdi/releases/latest/download/acdi-aarch64-unknown-linux-musl
    chmod +x acdi
    sudo mv acdi /usr/local/bin/
    acdi --version
    ```

=== "Windows (x86_64)"

    ```powershell
    Invoke-WebRequest `
      -Uri https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-pc-windows-msvc.exe `
      -OutFile acdi.exe

    # Add to PATH or move to a directory already in PATH
    Move-Item acdi.exe C:\Windows\System32\acdi.exe
    acdi --version
    ```

---

## Verify checksums

Each release includes a `SHA256SUMS.txt` file.

```bash
curl -Lo SHA256SUMS https://github.com/vral-parmar/acdi/releases/latest/download/SHA256SUMS.txt
sha256sum -c SHA256SUMS --ignore-missing
```

---

## Cargo install

Requires Rust 1.75+ (install via [rustup](https://rustup.rs)).

```bash
cargo install acdi
```

---

## Build from source

```bash
git clone https://github.com/vral-parmar/acdi
cd acdi
cargo build --release
./target/release/acdi --version
```

The release profile produces a stripped, LTO-optimised binary (~3–5 MB).

---

## CI environments

For ephemeral CI runners, download the binary directly in your pipeline step — see [CI/CD Integration](guides/ci-cd.md) for complete examples.
