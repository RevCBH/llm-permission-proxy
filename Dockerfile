# syntax=docker/dockerfile:1

# --- Build stage ---
FROM rust:1.84-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
# Cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

COPY src/ src/
RUN touch src/main.rs && cargo build --release

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/llm-permission-proxy /usr/local/bin/llm-permission-proxy

RUN mkdir -p /data
VOLUME ["/data"]

ENV BIND_ADDR=0.0.0.0:8080
ENV DATABASE_URL=sqlite:///data/proxy.db

EXPOSE 8080

ENTRYPOINT ["llm-permission-proxy"]
