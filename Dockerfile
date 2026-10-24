FROM rust:1.99.0-bookworm AS chef
ARG CARGO_CHEF_VERSION=0.1.78
RUN apt-get update && apt-get install -y --no-install-recommends cmake musl-tools pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --version "${CARGO_CHEF_VERSION}" --locked
WORKDIR /app
# Build natively for the selected Docker platform (amd64 or arm64), linking musl.
RUN rustc -vV | sed -n 's/^host: \(.*\)-gnu$/\1-musl/p' > /rust-target \
    && test -s /rust-target && rustup target add "$(cat /rust-target)" \
    && mkdir -p .cargo \
    && printf '[target.%s]\nlinker = "musl-gcc"\n' "$(cat /rust-target)" > .cargo/config.toml
# The image already supplies this toolchain; do not install dev-only rustfmt/clippy
# from rust-toolchain.toml independently in both planner and builder.
ENV RUSTUP_TOOLCHAIN=1.99.0 CARGO_PROFILE_RELEASE_STRIP=symbols

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# This layer survives application-source changes; cook and build use identical flags.
RUN cargo chef cook --locked --release --target "$(cat /rust-target)" \
    --package epistle-server --recipe-path recipe.json
COPY . .
RUN cargo build --locked --release --target "$(cat /rust-target)" -p epistle-server \
    && cp "target/$(cat /rust-target)/release/epistle-server" /epistle \
    && readelf -l /epistle > /tmp/program-headers \
    && readelf -d /epistle > /tmp/dynamic-section \
    && ! grep -q INTERP /tmp/program-headers \
    && ! grep -q NEEDED /tmp/dynamic-section \
    && mkdir -p /runtime/home/epistle/data \
    && chmod 0700 /runtime/home/epistle/data

FROM gcr.io/distroless/static-debian13:nonroot AS runtime
COPY --from=builder /epistle /usr/local/bin/epistle
COPY --from=builder --chown=10001:10001 /runtime/home/epistle /home/epistle
# Preserve ownership compatibility with existing Epistle data volumes.
USER 10001:10001
WORKDIR /home/epistle
ENV DATA_DIR=/home/epistle/data BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/epistle"]
