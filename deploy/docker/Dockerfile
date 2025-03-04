FROM rust:1.75-bookworm AS builder
WORKDIR /app

COPY Cargo.toml ./
COPY crates ./crates
RUN cargo build --release -p chameleon-bridge -p chameleon-client

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/chameleon-bridge /usr/local/bin/chameleon-bridge
COPY --from=builder /app/target/release/chameleon-client /usr/local/bin/chameleon-client

ENTRYPOINT ["/usr/local/bin/chameleon-bridge"]
