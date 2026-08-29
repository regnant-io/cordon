# Cordon — container image
#
# Builds the Cordon binaries and llama.cpp's `llama-server`, so the image can
# run a model without depending on a runtime the operator provides. Cordon
# supervises that binary on loopback with its web UI unreachable; nothing but
# Cordon's own port is exposed.

# ── Stage 1: build the model runtime ────────────────────────────────────────
FROM debian:bookworm-slim AS llama

ARG LLAMA_CPP_REF=b4585

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git libcurl4-openssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch "${LLAMA_CPP_REF}" \
        https://github.com/ggml-org/llama.cpp.git . \
    && cmake -B build -DCMAKE_BUILD_TYPE=Release -DLLAMA_CURL=OFF -DLLAMA_BUILD_TESTS=OFF \
    && cmake --build build --config Release --target llama-server -j "$(nproc)"

# ── Stage 2: build Cordon ───────────────────────────────────────────────────
FROM rust:1.83-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency layer: manifests only, so a source change does not rebuild crates.
COPY Cargo.toml Cargo.lock ./
COPY crates/cordon-crypto/Cargo.toml crates/cordon-crypto/
COPY crates/cordon-audit/Cargo.toml  crates/cordon-audit/
COPY crates/cordon-core/Cargo.toml   crates/cordon-core/
COPY crates/cordon-api/Cargo.toml    crates/cordon-api/
COPY crates/cordon-cli/Cargo.toml    crates/cordon-cli/
RUN mkdir -p crates/cordon-crypto/src crates/cordon-audit/src \
             crates/cordon-core/src crates/cordon-api/src crates/cordon-cli/src \
    && touch crates/cordon-crypto/src/lib.rs \
             crates/cordon-audit/src/lib.rs \
             crates/cordon-core/src/lib.rs \
             crates/cordon-api/src/lib.rs \
    && for bin in main keygen verify_log provision; do \
         echo 'fn main() {}' > "crates/cordon-cli/src/${bin}.rs"; \
       done \
    && cargo build --release 2>/dev/null || true

# Real source. The stub artefacts are removed so cargo rebuilds them.
COPY crates/ crates/
COPY ui/ ui/
RUN find target/release -maxdepth 1 -name 'cordon*' -delete 2>/dev/null || true \
    && cargo build --release \
         --bin cordon --bin cordon-keygen \
         --bin cordon-verify-log --bin cordon-provision

# ── Stage 3: runtime image ──────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libgomp1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/cordon cordon

COPY --from=builder /build/target/release/cordon            /usr/local/bin/
COPY --from=builder /build/target/release/cordon-keygen     /usr/local/bin/
COPY --from=builder /build/target/release/cordon-verify-log /usr/local/bin/
COPY --from=builder /build/target/release/cordon-provision  /usr/local/bin/
COPY --from=llama   /build/build/bin/llama-server           /usr/local/bin/

COPY deployment/configs/cordon-light.toml /etc/cordon/cordon.toml

# The key directory is owner-only: a Client Master Key mounted here must not be
# readable by anything else in the container.
RUN mkdir -p /var/lib/cordon/audit /var/lib/cordon/bundles \
             /var/lib/cordon/models /var/lib/cordon/tls /var/lib/cordon/keys \
    && chown -R cordon:cordon /var/lib/cordon \
    && chmod 700 /var/lib/cordon/keys

USER cordon
WORKDIR /var/lib/cordon

ENV CORDON_LLAMA_SERVER=/usr/local/bin/llama-server \
    RUST_LOG=info

# Cordon's API. The model runtime is on loopback and is never published.
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -sf http://localhost:8443/v1/health || exit 1

ENTRYPOINT ["cordon"]
CMD ["serve", "--config", "/etc/cordon/cordon.toml", "--bind", "0.0.0.0:8443"]

LABEL org.opencontainers.image.title="Cordon" \
      org.opencontainers.image.description="A confidential inference control plane" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/cordon-project/cordon"
