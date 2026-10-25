# syntax=docker/dockerfile:1
# Builder: tfhe 1.8 requires Rust >= 1.91.1 (see backend/Cargo.toml rust-version).
FROM rust:1.97-bookworm AS builder
WORKDIR /usr/src/he-backend

# Cache dependencies: compile a dummy binary first so the layer is reused
# when only src changes. TFHE-rs takes 10-30 min on first build.
COPY backend/Cargo.toml backend/Cargo.lock ./
RUN mkdir src && printf 'fn main(){}' > src/main.rs && \
    cargo build --release --locked && \
    rm -f target/release/he-backend target/release/deps/he_backend* && \
    rm -rf src

COPY backend/src ./src
COPY backend/migrations ./migrations
RUN touch src/main.rs && cargo build --release --locked

FROM debian:bookworm-slim
# All TLS is rustls, so only the CA bundle is needed at runtime.
# Non-root user + healthcheck land in Phase 6 together with the named-volume
# migration (the compose bind mount ./data is root-owned on existing hosts).
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/he-backend/target/release/he-backend /usr/local/bin/he-backend
EXPOSE 8080
CMD ["he-backend"]
