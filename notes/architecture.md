# Mailent Architecture

## 1. architecture thesis

Mailent has two very different workloads:

1. **data plane** — continuous, high-volume, mostly append-only network/security observations.
2. **control plane** — comparatively low-volume mutable state: assets, policies, findings, investigations, users and integrations.

Treating both like a CRUD web app would be a mistake.

Mailent therefore uses:

```text
event-driven data plane
+
modular control plane
+
analytical event store
+
relational state store
```

The core application is a **modular monolith**, not a microservice zoo. Components become separate deployables only where scaling, trust boundaries or sensor locality require it.

## 2. top-level system

```text
                         ┌────────────────────────────┐
                         │ External Intelligence      │
                         │ DNS / MTA-STS / DANE      │
                         │ TLS-RPT / CT / Probes     │
                         └──────────────┬─────────────┘
                                        │
                                        ▼
┌──────────────┐       ┌───────────────────────────────────┐
│ SPAN / TAP   │──────▶│ Mailent Sensor                   │
└──────────────┘       │ Zeek + Rust Agent                │
                       └────────────────┬──────────────────┘
                                        │ normalized events
┌──────────────┐                        │
│ PCAP/PCAPNG  │────────────────────────┤
└──────────────┘                        ▼
                              ┌──────────────────────┐
                              │ Ingestion Boundary   │
                              └──────────┬───────────┘
                                         │
                          ┌──────────────┴──────────────┐
                          │                             │
                          ▼                             ▼
                 ┌─────────────────┐          ┌─────────────────┐
                 │ Event Pipeline  │          │ Evidence Store  │
                 │ Redpanda*       │          │ S3 / MinIO      │
                 └────────┬────────┘          └─────────────────┘
                          │
          ┌───────────────┼───────────────────────┐
          │               │                       │
          ▼               ▼                       ▼
 ┌────────────────┐ ┌───────────────┐   ┌────────────────────┐
 │ Session/Asset  │ │ Policy Engine │   │ Baseline / Drift   │
 │ Correlator     │ │ deterministic │   │ Analytics          │
 └───────┬────────┘ └──────┬────────┘   └──────────┬─────────┘
         │                 │                       │
         └─────────────────┼───────────────────────┘
                           ▼
                  ┌──────────────────┐
                  │ Decision Context │
                  └────────┬─────────┘
                           ▼
                  ┌──────────────────┐
                  │ Jev Adapter      │
                  │ optional         │
                  └────────┬─────────┘
                           ▼
            ┌────────────────────────────┐
            │ Findings / Investigations │
            │ Posture / Alerts          │
            └─────────────┬──────────────┘
                          │
             ┌────────────┼─────────────┐
             ▼            ▼             ▼
        Analyst UI       SIEM        Reports
```

`*` Redpanda is used in distributed mode. Single-node mode may route the same typed events through in-process bounded channels.

## 3. sensor architecture

Each sensor contains two major pieces:

```text
NIC / mirror
    ↓
  Zeek
    ↓
Mailent Zeek package
    ↓
normalized local events
    ↓
Rust Sensor Agent
    ├─ buffer
    ├─ redact/minimize
    ├─ health metrics
    ├─ evidence references
    └─ secure forwarding
```

### why keep Zeek

TCP reassembly and protocol parsing have many edge cases. Mailent should extend a mature network-analysis engine rather than recreate it.

### sensor responsibilities

- collect passive evidence
- reconstruct/extract relevant protocol events
- assign stable sensor/site metadata
- minimize sensitive payloads
- optionally retain packet evidence
- survive central-node outages with bounded local buffering
- report packet loss and sensor health

### sensor non-responsibilities

- organization-wide baselines
- final finding lifecycle
- cross-site correlation
- Jev calls
- SIEM routing policy

This keeps sensors simple and safer.

## 4. normalized observation model

All ingestion paths map into one canonical observation model.

Conceptually:

```text
Observation
├─ identity
│  ├─ observation_id
│  ├─ source
│  ├─ sensor/site
│  └─ timestamp
├─ flow
│  ├─ client
│  ├─ server
│  └─ connection/session IDs
├─ mail
│  ├─ protocol
│  ├─ protocol state
│  └─ STARTTLS state
├─ tls
│  ├─ version
│  ├─ cipher
│  ├─ key exchange
│  ├─ groups
│  └─ handshake state
├─ certificate refs
├─ evidence refs
└─ parser provenance
```

PCAP import, live Zeek, TLS-RPT and external probes have different source-specific records, but all produce typed domain observations.

## 5. ingestion boundary

The ingestion layer performs:

- schema validation
- version compatibility checks
- deduplication
- source authentication
- coarse normalization
- backpressure
- event routing

It does **not** perform expensive posture queries inline with sensor ingestion.

Hot-path rule:

> accept, validate, persist/stream, then analyze asynchronously.

## 6. event transport

### single-node mode

```text
sensor/import
    ↓
bounded Tokio channels
    ↓
core consumers
```

No Redpanda required.

### distributed mode

```text
sensors
   ↓
Redpanda
   ├─ session consumers
   ├─ policy consumers
   ├─ ClickHouse sink
   ├─ integration consumers
   └─ replay/reprocessing
```

Domain event schemas remain identical in both modes.

This makes scale a deployment concern rather than a rewrite.

## 7. storage architecture

### ClickHouse

Authoritative analytical history for high-volume observations:

```text
mail_sessions
tls_handshakes
certificate_observations
protocol_events
posture_events
baseline_features
finding_events
```

Data is partitioned primarily by time and organization/site dimensions.

Materialized views/aggregates provide:

- TLS-version distributions
- cipher distributions
- endpoint baselines
- STARTTLS success
- certificate usage
- posture trends

### PostgreSQL

Authoritative mutable state:

```text
organizations
sites
sensors
assets
asset_identity_links
policies
policy_versions
findings
investigations
integrations
report_jobs
users/roles
retention_config
```

### object storage

```text
pcap/
pcap-slices/
reports/
tls-rpt/
forensic-artifacts/
```

Database rows contain references and hashes, not giant binary blobs.

## 8. session correlation

The correlator converts low-level observations into durable logical sessions.

```text
flow events
+ protocol events
+ STARTTLS events
+ TLS handshake
+ certificates
       ↓
EmailSession
```

A session can be incomplete.

Confidence/completeness fields explicitly represent:

- capture began midstream
- packet loss observed
- TLS handshake missing
- certificate unavailable
- protocol inferred only

Unknown is a valid state; Mailent must not fabricate missing evidence.

## 9. asset identity graph

IPs are not assets.

Mailent correlates:

```text
IP
SNI
MX hostname
certificate SAN
observed protocol endpoint
DNS records
sensor/site
```

into an asset identity.

Conceptually:

```text
Asset: smtp-prod-01
├─ mail.example.gov
├─ smtp.example.gov
├─ 10.20.1.12
├─ 203.0.113.44
└─ Certificate fingerprints [...]
```

The graph does not assume every relation is permanent. Links have first/last-seen and confidence/provenance.

## 10. deterministic policy pipeline

```text
normalized session
       ↓
policy facts
       ↓
rule evaluation
       ↓
FindingCandidate
       ↓
dedup/correlation
       ↓
Finding
```

Important properties:

- rules are versioned
- evidence is immutable
- severity is reproducible
- re-evaluation can run after a policy-pack update
- historical findings retain the rule version that produced them

## 11. finding correlation

The correlator prevents alert storms.

Key dimensions may include:

```text
rule
asset
certificate
protocol
policy
time window
```

Thousands of session-level violations can roll into one finding with:

- affected count
- first seen
- last seen
- representative evidence
- severity
- trend

Raw session links remain available.

## 12. baseline engine

Baselines are computed from ClickHouse windows rather than held only in RAM.

Example features per asset:

```text
tls_version_distribution
cipher_distribution
key_exchange_distribution
certificate_distribution
issuer_distribution
starttls_success_rate
handshake_failure_rate
peer_set
port_set
session_rate
```

Baselines have:

- window
- sample count
- freshness
- observation coverage
- version

A baseline built from eight sessions must not be treated like one built from eight million.

## 13. anomaly pipeline

```text
new observation/session
       ↓
deterministic feature extraction
       ↓
compare to baseline
       ↓
statistical deviation signals
       ↓
decision context
       ↓
Jev (optional)
       ↓
anomaly decision + confidence
```

Jev sees summarized context, not raw packet payload.

If Jev times out:

```text
deterministic findings  → unaffected
statistical anomaly     → still available
Jev decision            → unavailable
```

No security pipeline blocks waiting forever on an external model.

## 14. Jev boundary

Jev is behind a provider interface:

```text
DecisionProvider
├─ JevProvider
├─ LocalProvider
└─ DisabledProvider
```

A request contains:

```text
structured observations
deterministic findings
baseline deviations
asset criticality
scope
coverage/confidence
```

A response must fit a versioned constrained schema.

The result stores:

- provider
- model/version when exposed
- input feature-set version
- decision
- confidence
- timestamp
- latency

This is required for forensic reproducibility.

## 15. external-intelligence architecture

Separate adapters fetch/receive:

```text
DNS/MX
DNSSEC
TLSA/DANE
MTA-STS
TLS-RPT
Certificate Transparency
controlled probes
```

They emit observations into the same data plane.

Example:

```text
MTA-STS says TLS required
        +
live sensor observes STARTTLS absent
        +
TLS-RPT reports external STARTTLS failures
        ↓
correlated transport-policy investigation
```

No one adapter owns the final verdict.

## 16. multi-vantage analysis

Mailent may operate external probes from multiple authorized vantage points.

The comparator groups observations by:

- asset/domain
- time window
- vantage
- certificate
- STARTTLS state
- TLS characteristics

It flags inconsistent perspectives for review.

A mismatch is evidence of inconsistency, not automatic proof of MITM.

## 17. Crypto Digital Twin

The simulator never touches production.

```text
historical observations
       +
proposed policy
       ↓
vectorized policy replay
       ↓
compatibility matrix
       ↓
asset/partner blast radius
       ↓
rollout groups
       ↓
Jev rollout-risk decision
```

Use ClickHouse for historical selection and Polars/Rust for vectorized simulation.

Results are immutable simulation runs so teams can compare:

```text
Policy A vs Policy B
```

and reproduce decisions later.

## 18. post-quantum readiness

Passive observations record supported/negotiated TLS groups where visible.

The controlled probe component can test operator-owned infrastructure with a crypto stack supporting current hybrid PQ/T groups.

Mailent stores:

```text
observed capability
probed capability
policy requirement
```

as separate facts.

Never convert "not observed" into "unsupported" without evidence.

## 19. report architecture

All output formats consume one typed report model:

```text
ReportModel
├─ summary
├─ assets
├─ findings
├─ evidence
├─ posture
├─ trends
├─ recommendations
└─ provenance
```

Renderers:

```text
Typst → PDF
HTML renderer → HTML
serializer → JSON
tabular exporter → CSV
```

Business/security logic never lives inside report templates.

## 20. frontend query architecture

The browser never queries raw event tables directly.

```text
React UI
   ↓
Rust query layer
   ↓
predefined analytical queries
   ├─ PostgreSQL
   └─ ClickHouse
```

The query layer:

- enforces organization/site authorization
- limits expensive ranges
- returns aggregated datasets
- paginates/virtualizes large lists
- avoids arbitrary user-generated SQL

Live updates use SSE/WebSocket for small state changes and invalidation, not raw packet streaming.

## 21. integration boundary

Outbound integrations consume normalized alert/finding events.

```text
Finding/Alert
     ↓
Integration Router
     ├─ Syslog
     ├─ webhook
     ├─ Splunk
     ├─ Sentinel
     ├─ Elastic/OpenSearch
     └─ other adapters
```

Integrations must be retryable and idempotent.

Failure to forward an alert must not roll back the underlying security finding.

## 22. privacy boundary

Default data minimization:

```text
raw traffic
   ↓ local sensor
extract required metadata
   ↓
normalized security observations
   ↓
central control plane
```

Raw PCAP retention is optional and policy-controlled.

Sensitive fields should be tagged in the schema so:

- logging can redact them
- external AI adapters can reject them
- exports can apply policy

## 23. failure design

### sensor disconnected
- local bounded spool
- health alert
- reconnect + resume
- explicit visibility gap

### Redpanda unavailable
- sensors spool
- consumers resume from offsets

### ClickHouse unavailable
- event stream remains durable
- analytical queries degrade
- ingestion resumes from stream

### PostgreSQL unavailable
- mutable control actions pause
- sensors continue buffering/streaming
- no fake "success"

### Jev unavailable
- deterministic analysis continues
- Jev status becomes unavailable
- decisions can be retried later

### packet loss
- observation quality decreases
- affected sessions marked incomplete

## 24. security boundaries

### sensor → central
- mutual authentication
- encrypted transport
- per-sensor identity
- revocable credentials

### external probes
- explicit authorization scope
- rate limits
- auditable targets

### analyst actions
- OIDC
- RBAC
- audit events

### evidence
- hashes
- retention rules
- access control
- optional immutable/WORM-compatible object storage

## 25. repository shape

Recommended monorepo:

```text
mailent/
├─ apps/
│  ├─ core/              # Rust control/query plane
│  ├─ sensor/            # Rust sensor agent
│  ├─ web/               # React analyst console
│  └─ probe/             # authorized external/PQC probe
│
├─ crates/
│  ├─ domain/            # core types
│  ├─ events/            # generated/event adapters
│  ├─ policy/            # rule engine + DSL
│  ├─ correlation/
│  ├─ baseline/
│  ├─ storage/
│  ├─ integrations/
│  ├─ decision/
│  └─ reporting/
│
├─ zeek/
│  └─ mailent/           # Mailent Zeek package
│
├─ schemas/
│  └─ protobuf/
│
├─ policies/
│  ├─ modern/
│  ├─ high-security/
│  └─ legacy-compatible/
│
├─ analysis/
│  └─ experiments/       # optional Python notebooks/models
│
├─ fixtures/
│  ├─ pcap/
│  ├─ certs/
│  ├─ dns/
│  └─ tls-rpt/
│
├─ deploy/
│  ├─ compose/
│  ├─ kubernetes/
│  └─ systemd/
│
└─ docs/
```

## 26. scale path

### phase 1 — single-node

```text
Zeek → Rust Core → PostgreSQL + ClickHouse + MinIO
```

In-process event transport.

### phase 2 — distributed sensors

```text
Sensors → Redpanda → Core/Consumers → stores
```

### phase 3 — high-volume enterprise

Scale independently:

- sensor fleet
- Redpanda partitions
- ClickHouse cluster
- stateless query/core replicas
- report workers
- external probes

The domain model and event schemas do not change between phases.

## 27. architectural rules

1. raw packets are evidence, not the primary database model.
2. a protocol parser never decides organizational risk.
3. an AI model never decides deterministic cryptographic truth.
4. PostgreSQL is not the telemetry warehouse.
5. ClickHouse is not the control-plane database.
6. object storage is for large immutable evidence.
7. Redpanda is optional for single-node deployment.
8. no service split without a scaling, locality or trust-boundary reason.
9. every finding must be reproducible from evidence + rule/model versions.
10. "unknown" is better than invented certainty.
