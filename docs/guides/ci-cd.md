# CI/CD Integration

`acdi` is designed to run in CI with no setup — download the binary, run the scan, optionally gate on risk level.

---

## GitHub Actions

### Simplest — use the official action

```yaml
name: Cryptography Inventory

on: [push, pull_request]

jobs:
  acdi:
    runs-on: ubuntu-latest
    permissions:
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - uses: vral-parmar/acdi@v0.5.0
        with:
          args: 'scan . --format sarif --output acdi.sarif --quiet'

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: acdi.sarif
          category: cryptography
```

The action automatically downloads the right binary for the runner OS/arch, caches it, and runs the scan.

### Manual binary download (when you need more control)

```yaml
    steps:
      - uses: actions/checkout@v4

      - name: Download acdi
        run: |
          curl -Lo acdi \
            https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-unknown-linux-musl
          chmod +x acdi

      - name: Scan for vulnerable cryptography
        run: ./acdi scan . --format sarif --output acdi.sarif --quiet

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: acdi.sarif
          category: cryptography
```

### Fail the build on critical findings

```yaml
      - name: Gate — fail on critical findings
        run: ./acdi scan . --fail-on critical --quiet > /dev/null
```

### Generate and upload an HTML report as an artifact

```yaml
      - name: Generate HTML report
        run: ./acdi scan . --format html --output acdi-report.html --quiet

      - name: Upload HTML report
        uses: actions/upload-artifact@v4
        with:
          name: acdi-crypto-report
          path: acdi-report.html
          retention-days: 30
```

### Cache the binary between runs

```yaml
      - name: Cache acdi binary
        uses: actions/cache@v4
        with:
          path: acdi
          key: acdi-${{ runner.os }}-latest

      - name: Download acdi (if not cached)
        run: |
          if [ ! -f acdi ]; then
            curl -Lo acdi \
              https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-unknown-linux-musl
            chmod +x acdi
          fi
```

---

## Docker

Run without installing anything:

```bash
# Scan current directory
docker run --rm -v "$(pwd)":/src ghcr.io/vral-parmar/acdi scan /src

# Generate HTML report (output written inside the mounted volume)
docker run --rm -v "$(pwd)":/src \
  ghcr.io/vral-parmar/acdi scan /src --format html --output /src/report.html --quiet

# Pin a specific version
docker run --rm -v "$(pwd)":/src ghcr.io/vral-parmar/acdi:0.5.0 scan /src
```

---

## GitLab CI

```yaml
acdi-scan:
  stage: security
  # Use the Docker image directly — no install step needed
  image: ghcr.io/vral-parmar/acdi:latest
  script:
    - acdi scan . --format sarif --output gl-sast-report.json --quiet
    - acdi scan . --fail-on critical --quiet > /dev/null
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    expire_in: 1 week
```

---

## Bitbucket Pipelines

```yaml
pipelines:
  default:
    - step:
        name: Crypto inventory
        image: alpine:latest
        script:
          - apk add --no-cache curl
          - curl -Lo acdi
              https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-unknown-linux-musl
          - chmod +x acdi
          - ./acdi scan . --format sarif --output acdi.sarif --quiet
          - ./acdi scan . --fail-on high --quiet > /dev/null
        artifacts:
          - acdi.sarif
```

---

## Jenkins

```groovy
pipeline {
    agent { label 'linux' }

    stages {
        stage('Crypto Inventory') {
            steps {
                sh '''
                    curl -Lo acdi \
                      https://github.com/vral-parmar/acdi/releases/latest/download/acdi-x86_64-unknown-linux-musl
                    chmod +x acdi
                    ./acdi scan . --format sarif --output acdi.sarif --quiet
                    ./acdi scan . --fail-on high --quiet > /dev/null
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'acdi.sarif', fingerprint: true
                }
            }
        }
    }
}
```

---

## Pre-commit hook

Gate individual commits on your machine before they reach CI:

```bash
# .git/hooks/pre-commit
#!/usr/bin/env bash
set -euo pipefail

if command -v acdi &>/dev/null; then
    echo "acdi: scanning staged files..."
    acdi scan . --fail-on critical --quiet > /dev/null
fi
```

```bash
chmod +x .git/hooks/pre-commit
```

---

## Makefile target

```makefile
.PHONY: crypto-scan

crypto-scan:
	acdi scan . --format html --output acdi-report.html
	@echo "Report: acdi-report.html"
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no findings met `--fail-on` threshold (or no threshold set) |
| `1` | A finding met or exceeded the `--fail-on` threshold, or a fatal error occurred |
