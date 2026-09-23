# Persistent Monitoring & Storage Architecture

Mailent has transitioned from a one-shot PCAP analysis tool into a **continuous passive cryptographic monitoring system**.

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

A restart of Mailent Core no longer erases analysis history or asset state.

---

## 1. Storage Architecture

Mailent enforces strict state partitioning across specialized storage systems:

### PostgreSQL (Control Plane)
Stores operational entities that require relational integrity, transactions, and point lookups:
- `sites`: Monitored environments and datacenters.
- `sensors`: Active network probes, interfaces, modes, and heartbeat states (`Online`, `Stale`, `Offline`).
- `assets`: Discovered email infrastructure servers and MTAs.
- `asset_identities`: EHLO strings, PTR records, and hostnames linked to assets.
- `asset_endpoints`: Ports and protocols (SMTP:25, 465, 587; IMAP:143, 993; POP3:110, 995).
- `certificates`: Presented X.509 leaf certificates with SHA-256 fingerprint, subject, issuer, SANs, and validity windows.
- `asset_certificates`: Association mapping certificates to assets.
- `findings`: Active and historical policy findings with affected counts.
- `finding_evidence`: Session and observation references backing each finding.
- `drift_events`: Real-time cryptographic configuration changes.

### ClickHouse (Analytical Telemetry)
Stores immutable time-series data optimized for append-only ingestion and analytics:
- `normalized_observations`: Raw structured observations (`ReplacingMergeTree`).
- `email_sessions`: Correlated mail transport sessions with flow and TLS state (`ReplacingMergeTree`).
- `timeline_events`: Fine-grained protocol handshake timeline (`MergeTree`).
- `certificate_history`: Historical log of all certificate presentations (`MergeTree`).
- `finding_events`: Finding lifecycle events (`MergeTree`).

### Object Storage (MinIO / S3)
Stores large binary blobs:
- Captured PCAP / PCAPNG slices and packet streams.
- Raw parsed Zeek logs and connection evidence.

---

## 2. Mailent Sensor: Live Capture & Reliability

The sensor supports both offline forensic analysis and live wire tapping:

```sh
# Continuous live capture on interface eth0:
mailent-sensor listen -i eth0 --core http://127.0.0.1:8080

# Analyze offline capture file:
mailent-sensor analyze capture.pcap --core http://127.0.0.1:8080
```

### Reliability & Bounded Spooling
- **In-Memory & Disk Buffering**: If Mailent Core is unreachable, observations are queued in memory and overflow to a bounded disk spool directory (`/tmp/mailent-spool`).
- **Automatic FIFO Drain**: When Core connectivity is restored, the spooler automatically drains observations in FIFO order.
- **Drop Accounting**: If the spool reaches capacity (default: 10,000 items), oldest observations are dropped and `observations_dropped` counter is incremented.
- **Heartbeat Telemetry**: Sends periodic health pings to `/api/v1/sensors/heartbeat` with interface status, mode, and processed/spooled/dropped counts.

---

## 3. Passive Asset Discovery & Cryptographic Drift

As observations flow through the pipeline, Core continuously updates the asset inventory:

### Identity Correlation
- MTAs are identified by observed IP addresses, SMTP EHLO greetings, and X.509 certificate Subject Alternative Names (SANs).
- Multiple IP addresses sharing identical cryptographic identities and server banners are unified into a single logical asset.

### Cryptographic Drift Detection
When an asset's cryptographic configuration deviates from historical baseline, a `DriftEvent` is recorded:
- `NewTlsVersion`: An endpoint negotiates a previously unseen TLS version (e.g., upgrading to TLS 1.3 or falling back to TLS 1.0).
- `NewCipherSuite`: An endpoint negotiates a previously unseen cipher suite.
- `ForwardSecrecyLost`: An endpoint that previously used forward secrecy (ECDHE/DHE) negotiates a static key exchange (Static RSA).
- `CertificateChanged`: The presented certificate SHA-256 fingerprint changes.
- `NewCertificateIssuer`: A certificate issued by a new CA is presented on the endpoint.
- `NewEndpoint`: A new service port or protocol becomes active on the asset.

---

## 4. Replay Safety & Idempotence

Mailent maintains strict deduplication guarantees:
- Re-analyzing or replaying a capture does not create duplicate sessions, duplicate assets, or duplicate findings.
- Replayed findings update `last_seen` timestamps without incrementing violation counts.
- Database unique constraints and ClickHouse `ReplacingMergeTree` engines guarantee idempotent writes.

---

## 5. Verification Commands

```sh
# Start storage containers:
docker compose -f deploy/compose/docker-compose.yml up -d postgres clickhouse minio

# Run storage integration tests (Postgres & ClickHouse):
cargo test -p mailent-storage --test integration_test

# Run core persistence and restart tests:
cargo test -p mailent-core --test persistence_integration

# Run full workspace test suite:
cargo test --workspace

# Run frontend tests & e2e verification:
pnpm --filter @mailent/web test
pnpm --filter @mailent/web test:e2e
```
