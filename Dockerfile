# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /build

# System deps needed to compile OpenSSL-based crates
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation separately from application code
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src

COPY . .
# Touch source to force re-compilation of application code only
RUN touch src/main.rs && cargo build --release --locked

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# ca-certificates required for TLS probing (acdi tls <host>)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/acdi /usr/local/bin/acdi

# Scan /src by default — mount your project there:
#   docker run --rm -v "$(pwd)":/src ghcr.io/vral-parmar/acdi scan /src
WORKDIR /src

ENTRYPOINT ["acdi"]
CMD ["--help"]
