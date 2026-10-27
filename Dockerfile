# syntax=docker/dockerfile:1
# Builder: tfhe 1.8 requires Rust >= 1.91.1 (see rust-version in Cargo.toml).
FROM rust:1.99-bookworm AS builder
WORKDIR /usr/src/heaas

# Cache dependencies: build the workspace once with stub sources, so this layer
# is reused when only our own code changes. TFHE-rs takes 10-30 min on first build.
COPY Cargo.toml Cargo.lock ./
COPY backend/Cargo.toml backend/
COPY core/Cargo.toml core/
COPY sdk/Cargo.toml sdk/
RUN mkdir -p backend/src core/src sdk/src/bin && \
    printf 'fn main(){}' > backend/src/main.rs && \
    printf 'fn main(){}' > sdk/src/bin/heaas.rs && \
    touch core/src/lib.rs sdk/src/lib.rs && \
    cargo build --release --locked -p he-backend && \
    rm -rf backend/src core/src sdk/src

COPY core/src core/src
COPY sdk/src sdk/src
COPY backend/src backend/src
COPY backend/migrations backend/migrations
RUN touch backend/src/main.rs core/src/lib.rs && cargo build --release --locked -p he-backend

FROM debian:bookworm-slim
# All TLS is rustls, so only the CA bundle is needed at runtime.
# Non-root user + healthcheck land in Phase 6 together with the named-volume
# migration (the compose bind mount ./data is root-owned on existing hosts).
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/heaas/target/release/he-backend /usr/local/bin/he-backend
EXPOSE 8080
CMD ["he-backend"]
