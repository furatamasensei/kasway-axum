# syntax=docker/dockerfile:1
FROM rust:slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p kasway-api && \
    cp target/release/kasway-server /usr/local/bin/

# --- Runtime ---
FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Run as a non-root system user.
RUN useradd --system --uid 10001 --user-group --no-create-home kasway

COPY --from=builder /usr/local/bin/kasway-server /usr/local/bin/kasway-server

RUN chown -R kasway:kasway /app

ENV HOST_PORT=0.0.0.0:8080
EXPOSE 8080

USER kasway

CMD ["kasway-server"]
