FROM rust:1.99.0-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --locked --release -p epistle-server
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --create-home epistle && mkdir -p /home/epistle/data && chown epistle:epistle /home/epistle/data
COPY --from=builder /app/target/release/epistle-server /usr/local/bin/epistle
USER epistle
WORKDIR /home/epistle
ENV DATA_DIR=/home/epistle/data BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["epistle"]
