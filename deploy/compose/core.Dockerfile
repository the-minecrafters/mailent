FROM rust:1.94-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY apps/core apps/core
COPY apps/sensor apps/sensor
COPY apps/probe apps/probe
COPY crates crates
COPY schemas schemas
COPY policies policies
COPY fixtures fixtures
RUN cargo build --locked --release -p mailent-core

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/mailent-core /usr/local/bin/mailent-core
USER 65532:65532
ENV MAILENT_CORE_HOST=0.0.0.0
EXPOSE 8080
CMD ["mailent-core"]
