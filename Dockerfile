# syntax=docker/dockerfile:1
FROM rust:slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# BuildKit cache mounts keep the cargo registry and target/ dir warm across
# builds, so a source-only change recompiles just this workspace instead of
# every dependency. The binary must be copied out of the cached target/ within
# the same RUN, since the cache mount is not part of the image layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release -p kasway-api && \
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
