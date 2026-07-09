FROM rust:1.89 AS builder
WORKDIR /usr/src/he-backend

# Cache dependencies: compile a dummy binary first so Docker layer is reused
# when only src changes. TFHE-rs takes 10-30 min on first build.
COPY backend/Cargo.toml backend/Cargo.lock ./
RUN mkdir src && printf 'fn main(){}' > src/main.rs && \
    cargo build --release && \
    rm -f target/release/he-backend target/release/deps/he_backend* && \
    rm -rf src

COPY backend/src ./src
COPY backend/migrations ./migrations
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/he-backend/target/release/he-backend /usr/local/bin/he-backend
EXPOSE 8080
CMD ["he-backend"]
