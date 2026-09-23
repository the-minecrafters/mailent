# Mailent

Rust-first email transport security observability. The project direction lives in
[`notes/project.md`](notes/project.md), [`notes/features.md`](notes/features.md),
[`notes/stack.md`](notes/stack.md), and [`notes/architecture.md`](notes/architecture.md).

Mailent operates as a **continuous passive cryptographic monitoring system**:

```text
Live Network Interface (or PCAP)
        ↓
Mailent Sensor (bounded spooler + Zeek sniffer + heartbeat telemetry)
        ↓
Continuous Zeek Observations (SMTP / IMAP / POP3)
        ↓
Mailent Core Ingestion Pipeline
        ↓
Dual Persistent Storage Engine
├── PostgreSQL 18 (Control Plane: Assets, Drift, Certificates, Findings, Sensors)
└── ClickHouse 24.8 (High-Volume Analytical Telemetry: Sessions, Observations, Timeline, Cert History)
        ↓
Continuous Security Posture UI (Assets, Drift, Timeline, Fleet Telemetry)
```

A restart of Core no longer erases analysis history or discovered asset posture.

---

## Run locally

Requirements: Rust stable (edition 2024; dependencies require at least Rust 1.88),
`protoc`, Node.js 24+, and pnpm 11.26.0. Zeek 8.0+ is required for live network capture and real PCAP analysis.

### 1. Start Persistent Storage Services

```sh
docker compose -f deploy/compose/docker-compose.yml up -d postgres clickhouse minio
```

Storage endpoints:
- PostgreSQL 18: `127.0.0.1:5432` (`mailent` / `mailent_dev_password`)
- ClickHouse 24.8: `127.0.0.1:8123` (HTTP) / `127.0.0.1:9000` (Native)
- MinIO: `127.0.0.1:9002` (API) / `127.0.0.1:9001` (Console)

*(Note: If no database environment variables are configured, Core automatically falls back to ephemeral in-memory storage for unit tests and local iteration).*

### 2. Start Mailent Core

```sh
export MAILENT_DATABASE_URL=postgres://mailent:mailent_dev_password@127.0.0.1:5432/mailent
export MAILENT_CLICKHOUSE_URL=http://127.0.0.1:8123

cargo run -p mailent-core
```

### 3. Start Frontend Console

```sh
pnpm install --frozen-lockfile
pnpm --filter @mailent/web dev
```

Open <http://127.0.0.1:5173>. The web console provides dedicated views for:
- **Assets**: Discovered MTA servers, endpoints, certificates, and real-time configuration drift events.
- **Sessions**: Analyzed mail transport sessions with expandable protocol handshake timelines.
- **Findings**: Deterministic policy findings with RFC citations, remediation steps, and evidence links.
- **Sensors**: Active sensor fleet status, tap interfaces, heartbeat timestamps, and spooling telemetry.
- **Observation Evaluator**: Interactive tester for synthetic fixtures and custom observation payloads.

---

## Live Capture & Ingestion

### Continuous Network Sniffing (Live Tap)

```sh
cargo run -p mailent-sensor -- listen -i eth0 --core http://127.0.0.1:8080
```

Runs live Zeek traffic sniffing on the specified network interface with automatic log tailing, normalization, bounded memory/disk spooling on Core disconnections, and periodic heartbeat telemetry.

### Offline Forensic PCAP Analysis

```sh
cargo run -p mailent-sensor -- analyze capture.pcap --core http://127.0.0.1:8080
```

Parses PCAP / PCAPNG network traces, normalizes handshake timelines, and posts observations to Core with strict idempotent deduplication.

### Synthetic Fixture Evaluation

```sh
cargo run --quiet -p mailent-sensor -- --sample | \
  curl --fail-with-body http://127.0.0.1:8080/api/v1/observations \
    -H 'Content-Type: application/json' --data-binary @-
```

---

## Verification & Test Suite

```sh
# Rust checks & tests
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Storage integration tests (PostgreSQL 18 & ClickHouse 24.8)
cargo test -p mailent-storage --test integration_test

# Core persistence, restart survival, and drift detection tests
cargo test -p mailent-core --test persistence_integration

# Frontend unit, typecheck, lint, and build
pnpm --filter @mailent/web lint
pnpm --filter @mailent/web typecheck
pnpm --filter @mailent/web test
pnpm --filter @mailent/web build
pnpm exec buf lint
pnpm exec buf format --diff --exit-code

# Real browser end-to-end Playwright tests (no mock APIs)
pnpm --filter @mailent/web test:e2e
```

---

## Architecture & Documentation

- [Persistent Storage & Sensor Architecture](docs/persistence.md)
- [Initialization Notes](docs/initialization.md)
- [Project Vision](notes/project.md)
- [Target Architecture](notes/architecture.md)
