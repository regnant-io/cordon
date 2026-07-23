# Cordon v2.0 — Multi-stage Docker build
# Stage 1: Builder
FROM rust:1.88-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies first
COPY Cargo.toml Cargo.lock ./
COPY crates/cordon-crypto/Cargo.toml crates/cordon-crypto/
COPY crates/cordon-audit/Cargo.toml crates/cordon-audit/
COPY crates/cordon-core/Cargo.toml crates/cordon-core/
COPY crates/cordon-api/Cargo.toml crates/cordon-api/
COPY crates/cordon-cli/Cargo.toml crates/cordon-cli/

# Create stub src files to cache dependencies
RUN mkdir -p crates/cordon-crypto/src crates/cordon-audit/src \
    crates/cordon-core/src crates/cordon-api/src crates/cordon-cli/src && \
    echo "fn main() {}" > crates/cordon-cli/src/main.rs && \
    echo "fn main() {}" > crates/cordon-cli/src/keygen.rs && \
    echo "fn main() {}" > crates/cordon-cli/src/verify_log.rs && \
    echo "fn main() {}" > crates/cordon-cli/src/provision.rs && \
    touch crates/cordon-crypto/src/lib.rs && \
    touch crates/cordon-audit/src/lib.rs && \
    touch crates/cordon-core/src/lib.rs && \
    touch crates/cordon-api/src/lib.rs

RUN cargo build --release 2>/dev/null || true

# Copy real source
COPY crates/ crates/
COPY tests/ tests/

# Build for real
RUN cargo build --release --bin cordon --bin cordon-keygen \
    --bin cordon-verify-log --bin cordon-provision

# Stage 2: Runtime
FROM debian:bookworm-slim AS runtime

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false -d /var/lib/cordon cordon

# Copy binaries
COPY --from=builder /build/target/release/cordon /usr/local/bin/
COPY --from=builder /build/target/release/cordon-keygen /usr/local/bin/
COPY --from=builder /build/target/release/cordon-verify-log /usr/local/bin/
COPY --from=builder /build/target/release/cordon-provision /usr/local/bin/

# Create data directory structure
RUN mkdir -p /var/lib/cordon/audit /var/lib/cordon/bundles /var/lib/cordon/tls /var/lib/cordon/keys \
    && chown -R cordon:cordon /var/lib/cordon \
    && chmod 700 /var/lib/cordon/keys

# Copy default configuration
COPY deployment/docker/cordon-light.toml /etc/cordon/cordon.toml

USER cordon
WORKDIR /var/lib/cordon

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8443/v1/health || exit 1

ENTRYPOINT ["cordon"]
CMD ["serve", "--config", "/etc/cordon/cordon.toml", "--bind", "0.0.0.0:8443", "--no-tls"]

# Labels
LABEL org.opencontainers.image.title="Cordon"
LABEL org.opencontainers.image.description="Private Inference Engine v2.0"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.licenses="Proprietary"
