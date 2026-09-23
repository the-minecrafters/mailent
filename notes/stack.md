# Mailent Technology Stack

The rule for this stack is simple:

> use fast systems software on the hot path, proven security tooling for packet semantics, analytical databases for telemetry, and Python only where its ecosystem is genuinely better.

Do not reimplement TCP/TLS/email parsing in JavaScript for sport.

## 1. packet and protocol layer

### Zeek
**Role:** primary protocol-analysis engine.

Use Zeek for:

- TCP/session metadata
- SMTP
- IMAP
- POP3
- TLS
- X.509
- protocol events
- custom Mailent Zeek scripts

Why:

- mature passive network-analysis semantics
- already handles ugly network realities better than a fresh parser
- emits structured JSON
- extensible through scripts/plugins
- lets Mailent focus on security posture rather than rebuilding Wireshark

Mailent-specific Zeek packages should emit a normalized event schema for STARTTLS state, email protocol transitions, TLS/X.509 evidence and packet/session references.

### Rust sensor agent
**Role:** sensor lifecycle, capture orchestration, local buffering, normalization and secure transport.

Recommended crates/components:

- Tokio
- serde / serde_json
- bytes
- tracing
- rustls for Mailent's own transport
- pcap/libpcap bindings where direct capture control is needed

Optional high-throughput capture paths can use AF_PACKET/AF_XDP on supported Linux deployments, but these are optimizations, not requirements for correctness.

## 2. core backend

### Rust
Primary backend language.

Use for:

- ingestion
- event normalization
- policy evaluation
- correlation
- asset state
- investigation state
- streaming consumers
- query orchestration
- integration adapters
- live updates

### Axum + Tokio + Tower

```text
Axum  → HTTP/WebSocket surface
Tokio → async runtime
Tower → middleware, limits, timeouts, tracing
```

Why:

- low overhead
- strong type system
- excellent concurrency
- predictable memory behavior
- shared Rust types with sensor/core libraries

Architecture stays a **modular monolith** initially. Internal modules communicate directly when co-located rather than pretending the network is free.

## 3. event transport

### Redpanda
**Role:** durable event backbone for distributed deployments.

Use for streams such as:

```text
sensor.observations
tls.handshakes
mail.sessions
certificates.observed
policy.findings
baseline.events
alerts
```

Why:

- Kafka-protocol compatibility
- high-throughput streaming
- no JVM runtime requirement
- easy fan-out to ClickHouse, integrations and independent consumers

### important

Redpanda is **not mandatory in workstation mode**.

Single-node/offline Mailent can use bounded in-process Tokio channels and persist directly. Distributed mode swaps the transport adapter to Redpanda without changing the domain schema.

This avoids making local development dependent on a distributed log.

## 4. analytical storage

### ClickHouse
**Role:** high-volume immutable/semi-immutable telemetry.

Store:

- sessions
- TLS handshakes
- protocol events
- certificate observations
- time-series posture facts
- baseline feature aggregates
- historical findings/events

Why:

- columnar storage fits security telemetry
- very high ingest rates
- fast high-cardinality aggregation
- suitable for interactive dashboards over large event histories

Do not put every packet in ClickHouse. Raw capture belongs in object storage.

## 5. transactional/control storage

### PostgreSQL 18
**Role:** authoritative control-plane state.

Store:

- users/organizations
- sensors
- sites
- assets
- policy definitions and versions
- finding lifecycle
- investigations
- integration configuration
- report metadata
- retention policies
- RBAC references

PostgreSQL and ClickHouse have different jobs:

```text
PostgreSQL = mutable business/control state
ClickHouse = large analytical event history
```

Do not duplicate everything into both.

## 6. object/evidence storage

### S3-compatible storage
Production:

- S3-compatible object store
- MinIO for self-hosted/air-gapped deployments

Store:

- PCAP/PCAPNG
- retained suspicious-session slices
- imported TLS-RPT bundles
- generated reports
- larger forensic artifacts

Objects are content-addressed where useful and referenced by metadata, not copied through database rows.

## 7. schema and contracts

### Protobuf + Buf

Use one canonical schema for sensor/core event contracts.

Benefits:

- compact binary transport
- generated Rust/Python/TypeScript types
- compatibility checks
- explicit schema evolution

For human-facing export use JSON.

Do not use ad-hoc JSON blobs as the internal long-lived event contract.

## 8. cryptographic policy engine

### native Rust rule engine + versioned policy DSL

Policy should be data, not a pile of `if` statements spread through handlers.

Example conceptual rule:

```yaml
id: TLS_LEGACY_VERSION
when:
  tls.version: ["TLS1.0", "TLS1.1"]
severity: critical
remediation: DISABLE_LEGACY_TLS
references:
  - policy://modern-tls
```

The DSL compiles into typed internal predicates.

Reasons not to make an LLM the policy engine:

- reproducibility
- auditability
- air-gapped operation
- deterministic evidence
- versioned historical re-evaluation

## 9. DNS and mail-policy intelligence

Prefer Rust-native libraries/services for:

- DNS
- DNSSEC validation
- TLSA/DANE
- MTA-STS retrieval
- MX discovery
- TLS-RPT parsing
- REQUIRETLS observations

Likely building blocks:

- Hickory DNS
- reqwest
- rustls
- dedicated standards parsers with conformance fixtures

For active compatibility/probing that requires OpenSSL-specific behavior, isolate it in the probe module rather than coupling the entire application to OpenSSL.

## 10. post-quantum probing/readiness

### OpenSSL 3.5+ in the controlled probe/lab component

Use where support for standardized TLS 1.3 PQ/traditional hybrid groups is required, including:

- X25519MLKEM768
- SecP256r1MLKEM768
- SecP384r1MLKEM1024

Passive observation remains the preferred signal. Active probing only targets assets/domains explicitly authorized by the operator.

## 11. baseline/statistical engine

### Rust + Polars

Use Polars for:

- feature aggregation
- historical windows
- distributions
- drift calculations
- batch re-evaluation
- policy simulation datasets

Prefer straightforward statistics before fancy ML:

- frequency/rareness
- rolling distributions
- robust z-scores where applicable
- divergence from endpoint baseline
- change-point signals

### Python analysis lab
Python is allowed for experiments/training where ecosystem leverage matters.

Suggested:

- Polars Python
- scikit-learn
- PyTorch only if a model genuinely needs it

A model does not get promoted into the hot path unless evaluation shows it beats simpler methods.

## 12. Jev

### Jev adapter
Use Jev as a constrained decision layer, not a prose generator.

Inputs:

- deterministic findings
- baseline deviation
- asset/context metadata
- observation coverage
- affected scope
- policy-simulation result

Outputs:

- risk class
- anomaly decision
- human-review decision
- remediation priority
- rollout risk
- calibrated confidence

Requirements:

- feature minimization before external transmission
- timeout/circuit breaker
- cached/reproducible decision metadata
- explicit model/version provenance
- deterministic/local fallback when unavailable
- provider interface so an air-gapped decision model can replace Jev

## 13. frontend

### React + TypeScript
Use for the analyst console.

### Vite 8
Vite 8 uses Rolldown as its Rust-based unified bundler and is a good fit for fast dev/build cycles.

### TanStack
Use selectively:

- TanStack Router
- TanStack Query
- TanStack Table
- TanStack Virtual

Especially useful for large session/finding tables without rendering 50,000 DOM rows.

### Apache ECharts
Use for:

- posture trends
- TLS/cipher distributions
- certificate timelines
- site comparisons
- anomaly timelines
- high-cardinality aggregated charts

Prefer Canvas rendering for dense datasets.

### styling
Use plain modern CSS/CSS modules or a restrained utility layer.

The product should look like an analyst tool, not a rounded-card SaaS landing page.

## 14. realtime UI

Preferred flow:

```text
Redpanda / core events
        ↓
Rust aggregation
        ↓
WebSocket/SSE
        ↓
TanStack Query cache
```

Do not stream every raw packet into the browser.

Push:

- job progress
- new findings
- posture updates
- investigation changes
- aggregated live counters

## 15. PDF/report generation

### Typst
Use Typst for high-quality deterministic PDF reports.

Why:

- fast native engine
- reproducible templates
- easier audit/report versioning than browser screenshot hacks

HTML/JSON exports use separate renderers over the same report model.

## 16. observability

### OpenTelemetry
Instrument:

- sensor health
- ingestion latency
- queue lag
- parser failures
- ClickHouse ingest
- policy evaluation time
- Jev latency/failures
- report jobs

Export to:

- Prometheus
- Grafana
- compatible OTLP backends

Mailent should monitor itself because a silent sensor is a security blind spot.

## 17. authentication and authorization

- OIDC as the primary authentication interface
- compatible enterprise IdPs / SSO
- scoped RBAC
- site/sensor/case boundaries
- audit log for privileged actions

Avoid inventing a password/auth stack.

## 18. secrets

Production:

- Vault/KMS-compatible secret providers

Local/dev:

- environment/sealed local config
- SOPS + age for repository-managed encrypted configuration where appropriate

Never put API keys into frontend bundles.

## 19. packaging and deployment

### local development
- Podman Compose or Docker Compose
- native Rust/JS processes where convenient

### production
- OCI containers
- Kubernetes for distributed deployments
- Helm or equivalent manifests
- bare-metal/systemd option for high-throughput sensors

Sensors should not require Kubernetes.

## 20. testing

### Rust
- cargo test
- cargo-nextest
- property tests for parsers/rules
- golden event fixtures

### protocol/integration
- known-good PCAP fixtures
- malformed/truncated PCAP fixtures
- Postfix + Dovecot test lab
- tcpreplay
- tcpdump-generated captures
- deterministic certificate fixtures
- DNSSEC/DANE/MTA-STS fixture zones

### frontend
- Vitest
- Playwright

### compatibility
CI should test policy parsing and event-schema compatibility independently from UI tests.

## 21. developer tooling

- Cargo workspace
- rustfmt
- Clippy
- cargo-nextest
- pnpm
- Vite 8
- Biome for JS/TS lint/format where it fits the project
- Buf for Protobuf
- just or mise for reproducible project commands

## 22. what we deliberately do not use

### Node.js as the hot-path backend
Fine for frontend tooling; unnecessary for packet/security telemetry processing.

### MongoDB as the primary datastore
The workload naturally splits into relational control state + columnar telemetry.

### Redis for everything
Add a cache only when measurements show one is needed.

### Kubernetes on sensors
Unnecessary operational pain.

### dozens of microservices
Network calls are not architecture.

### an LLM for TLS validation
Cryptographic facts must be deterministic.

## 23. stack summary

```text
Capture/Protocol     Zeek + Mailent Zeek package
Sensor               Rust / Tokio
Core                 Rust / Axum / Tower
Distributed Stream   Redpanda
Telemetry             ClickHouse
Control State         PostgreSQL 18
Evidence              S3 / MinIO
Contracts             Protobuf / Buf
Policy                Typed Rust engine + versioned DSL
Analytics             Rust + Polars
AI Decisions          Jev adapter + local fallback
DNS/Mail Policy       Hickory/reqwest/rustls-based modules
PQC Lab               OpenSSL 3.5+
Frontend              React / TypeScript / Vite 8
Data UI               TanStack + Apache ECharts
Reports               Typst
Observability         OpenTelemetry / Prometheus / Grafana
Deployment            OCI / Compose / Kubernetes / systemd sensors
```

## references

- Zeek logging and JSON output: https://docs.zeek.org/
- Axum: https://docs.rs/axum/
- Redpanda: https://docs.redpanda.com/
- ClickHouse real-time analytics: https://clickhouse.com/use-cases/real-time-analytics
- PostgreSQL 18: https://www.postgresql.org/docs/18/
- Polars: https://pola.rs/
- Vite 8: https://vite.dev/
- Jev / TypeSafe: https://typesafe.ai/
- RFC 8460 (TLS-RPT): https://www.rfc-editor.org/rfc/rfc8460
- RFC 8461 (MTA-STS): https://www.rfc-editor.org/rfc/rfc8461
- RFC 8689 (REQUIRETLS): https://www.rfc-editor.org/rfc/rfc8689
- RFC 10024 (PQ/T hybrid TLS 1.3): https://www.rfc-editor.org/rfc/rfc10024
