FROM node:22-bookworm-slim AS web
WORKDIR /app
RUN npm install --global pnpm@11.26.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile
COPY apps/web apps/web
RUN pnpm --filter @mailent/web build

FROM rust:1.94-bookworm AS rust
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY apps apps
COPY crates crates
COPY schemas schemas
COPY policies policies
COPY fixtures fixtures
COPY zeek zeek
RUN cargo build --locked --release -j 2 -p mailent-core -p mailent-sensor

FROM zeek/zeek:8.0.4
COPY --from=rust /app/target/release/mailent-core /usr/local/bin/mailent-core
COPY --from=rust /app/target/release/mailent-sensor /usr/local/bin/mailent-sensor
COPY --from=web /app/apps/web/dist /app/web
WORKDIR /app
ENV MAILENT_CORE_HOST=0.0.0.0 MAILENT_CORE_ENVIRONMENT=production MAILENT_WEB_DIR=/app/web MAILENT_SENSOR_BIN=/usr/local/bin/mailent-sensor MAILENT_ZEEK=/usr/local/zeek/bin/zeek MAILENT_DATABASE_SCHEMA=mailent MAILENT_RUN_MIGRATIONS=false
USER 65532:65532
EXPOSE 10000
CMD ["mailent-core"]
