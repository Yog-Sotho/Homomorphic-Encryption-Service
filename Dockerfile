# syntax=docker/dockerfile:1
# The backend: built with cargo-chef so dependencies (TFHE-rs takes 10-30 min)
# are cached in their own layer, run as a non-root user on a distroless image.

# tfhe 1.8 requires Rust >= 1.91.1 (see rust-version in Cargo.toml).
FROM rust:1.99.1-bookworm AS chef
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /usr/src/heaas

# The recipe lists the workspace's manifests only, so it changes (and the
# dependency layer below is rebuilt) only when dependencies do.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /usr/src/heaas/recipe.json recipe.json
RUN cargo chef cook --release --locked -p he-backend --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p he-backend && \
    mkdir -p /data/keys /data/jobs

# glibc, libgcc and CA certificates, no shell or package manager. The tag's
# digest is pinned; Dependabot proposes updates.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
# A named volume mounted on /data starts with this owner (the image's nonroot user).
COPY --from=builder --chown=65532:65532 /data /data
COPY --from=builder /usr/src/heaas/target/release/he-backend /usr/local/bin/he-backend
ENV SERVER_ADDR=0.0.0.0:8080 \
    DATABASE_URL=sqlite:///data/he_saas.db?mode=rwc \
    KEY_STORE_DIR=/data/keys \
    JOB_STORE_DIR=/data/jobs \
    LOG_FORMAT=json
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
# The binary probes its own readiness endpoint (the image has no curl).
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/he-backend", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/he-backend"]
