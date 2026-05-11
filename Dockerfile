FROM rust:1.89 as builder
WORKDIR /usr/src/he-backend
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/he-backend/target/release/he-backend /usr/local/bin/he-backend
EXPOSE 8080
CMD ["he-backend"]