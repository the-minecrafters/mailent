# Mailent Features

## 1. ingestion

### live passive sensors
- capture from SPAN/TAP/mirrored interfaces
- SMTP, IMAP, POP3 and implicit-TLS variants
- multi-interface and multi-site sensors
- sensor health and packet-loss telemetry
- metadata-only, rolling-buffer, suspicious-session, or full-PCAP retention modes

### forensic imports
- PCAP
- PCAPNG
- batch imports
- watched directories
- S3-compatible evidence buckets
- case-scoped imports

### existing network tooling
- consume Zeek JSON streams
- ingest compatible structured network-event feeds
- import historical Zeek logs when original PCAP is unavailable

## 2. protocol reconstruction

- TCP stream/session correlation
- packet reordering and retransmission handling
- partial-capture awareness
- client/server role inference
- protocol detection independent of well-known ports
- SMTP reconstruction
- IMAP reconstruction
- POP3 reconstruction
- implicit TLS detection
- STARTTLS/STLS state-machine reconstruction

## 3. STARTTLS security

Detect and distinguish:

- STARTTLS advertised and used
- STARTTLS advertised but ignored
- STARTTLS unavailable
- STARTTLS rejected
- TLS handshake failed after upgrade
- plaintext continuation after failed upgrade
- authentication observed before TLS
- unexpected encryption-state transitions
- downgrade-like behavior

Every result links to its protocol timeline and underlying evidence.

## 4. TLS intelligence

Extract where observable:

- negotiated TLS version
- ClientHello / ServerHello characteristics
- cipher suite
- key exchange
- symmetric cipher
- signature algorithm
- supported groups
- SNI
- relevant TLS extensions
- session resumption
- handshake timing
- handshake failure reason
- Forward Secrecy state

### fingerprinting
- JA3/JA4-family fingerprints where useful
- stable server/client TLS behavior fingerprints
- fingerprint history per asset

Fingerprinting is supporting evidence, not a security verdict.

## 5. X.509 intelligence

- leaf certificate extraction
- chain reconstruction
- subject / SAN / issuer
- validity period
- fingerprints
- public-key algorithm and size
- signature algorithm
- hostname validation
- trust-chain validation
- self-signed detection
- near-expiry detection
- unexpected issuer detection
- certificate-change history

## 6. certificate transparency correlation

For organization-owned domains:

- monitor relevant CT entries
- correlate CT-issued certificates with observed mail certificates
- flag unexpected issuers or names
- distinguish "issued but never observed" from "now active in traffic"
- escalate when an unexpected CT certificate later appears on the wire

## 7. cryptographic policy engine

Deterministic checks include:

- deprecated TLS versions
- disallowed cipher suites
- weak/legacy encryption
- static RSA key exchange
- unavailable Forward Secrecy
- weak public keys
- deprecated signature algorithms
- invalid/expired certificates
- hostname mismatch
- incomplete/untrusted chains
- STARTTLS policy violations
- plaintext-authentication exposure
- organization-specific minimums

### policy packs

Versioned profiles:

- modern
- balanced
- legacy-compatible
- high-security
- organization-defined

Observed facts and policy verdicts stay separate so the same capture can be evaluated against multiple policy packs.

## 8. MTA-STS

- discover policy domains
- retrieve and validate MTA-STS policy
- detect `none`, `testing`, and `enforce`
- validate MX patterns
- correlate policy expectations with observed TLS behavior
- identify policy/traffic mismatches
- detect policy regressions

## 9. DANE / TLSA / DNSSEC

- discover TLSA records for SMTP infrastructure
- validate DNSSEC state
- compare observed certificates/keys to TLSA expectations
- identify DANE configuration errors
- detect policy drift between DNS and observed transport

## 10. TLS-RPT

- receive/import aggregate SMTP TLS reports
- parse success/failure statistics
- correlate external failures with internal observations
- group recurring certificate, STARTTLS, DNS, DANE and MTA-STS failures
- expose sender-domain and time-window trends

This gives Mailent a view of failures seen by external senders, not only traffic visible from inside the organization.

## 11. REQUIRETLS readiness

- detect observed REQUIRETLS support
- inventory compatible infrastructure
- estimate which known mail paths are safe for enforcement
- identify relays/partners that would break
- track adoption over time

Mailent assesses readiness; it does not silently force REQUIRETLS onto production mail.

## 12. external perspective checks

Controlled probes for domains the operator is authorized to assess:

- MX resolution
- STARTTLS availability
- presented certificate
- negotiated TLS capabilities
- MTA-STS/DANE consistency
- perspective comparison across regions/sensors

Useful signal:

```text
inside:  STARTTLS + Certificate A
outside: STARTTLS missing
```

or:

```text
inside:  Certificate A
outside: Certificate X
```

These differences become investigation evidence, not automatic claims of compromise.

## 13. asset discovery

Automatically maintain an observed mail-infrastructure inventory:

- hostnames
- IPs
- MX relationships
- protocols
- ports
- site/sensor
- first seen
- last seen
- TLS capabilities
- certificate history
- posture history
- related findings
- related investigations

New infrastructure appears automatically from observed evidence.

## 14. behavioral baselines

Build baselines per:

- endpoint
- endpoint group
- site
- protocol
- organization

Dimensions include:

- TLS-version distribution
- cipher distribution
- key-exchange distribution
- certificate fingerprints
- issuers
- STARTTLS success/failure rates
- handshake failure rates
- peer relationships
- ports
- session volume
- time-of-day behavior

## 15. configuration drift

Detect changes such as:

- TLS 1.3 → TLS 1.2
- ECDHE → static RSA
- certificate/issuer replacement
- Forward Secrecy disappearing
- STARTTLS success-rate regression
- new cipher suite
- new port/protocol
- new mail endpoint
- DNS/MTA-STS/DANE policy change

## 16. anomaly detection

Anomalies can combine statistical rarity, historical divergence and Jev decisions.

Examples:

- unseen certificate
- rare cipher
- unusual TLS version
- abnormal handshake failures
- new peer relationship
- unexpected certificate issuer
- abrupt STARTTLS behavior change
- cross-perspective inconsistency

"anomalous" means "different enough to inspect," not "malicious."

## 17. Jev decision layer

Jev receives minimized structured context such as:

- deterministic findings
- baseline deviation
- asset importance
- affected-session count
- certificate changes
- external-policy mismatches
- investigation context

Constrained decisions:

- `risk`: LOW / MEDIUM / HIGH / CRITICAL
- `anomalous`: YES / NO
- `human_review`: YES / NO
- `priority`: LOW / NORMAL / HIGH / IMMEDIATE
- `rollout_risk`: LOW / MEDIUM / HIGH
- confidence/probability for each decision

Jev never overrides a deterministic fact.

If Jev is unavailable, Mailent still performs parsing, policy evaluation, baseline analysis and deterministic scoring.

## 18. Crypto Digital Twin

Replay historical observations against hypothetical future policy.

Examples:

- require TLS 1.3
- disable TLS 1.2
- disable static RSA
- require Forward Secrecy
- raise minimum RSA size
- enforce MTA-STS
- require DANE for selected domains
- enforce REQUIRETLS for selected routes
- require hybrid PQ/T key agreement where supported

Outputs:

- compatible sessions/assets
- would-fail sessions/assets
- affected partner domains
- blast radius
- staged rollout groups
- confidence based on observation coverage
- Jev-assisted rollout-risk decision

The simulator never changes production configuration.

## 19. post-quantum readiness

Track migration toward standardized TLS 1.3 PQ/traditional hybrid key agreement.

- detect observed supported/negotiated groups where visible
- recognize X25519MLKEM768
- recognize SecP256r1MLKEM768
- recognize SecP384r1MLKEM1024
- inventory PQ-capable endpoints
- show classical-only dependencies
- simulate a future PQ/T policy

Do not label conventional strong TLS as currently broken; this is migration/readiness posture.

## 20. Secure SMTP research readiness

Track compatibility with the emerging Secure SMTP model:

- TLS from connection start
- mandatory encryption
- certificate validation expectations
- infrastructure dependency analysis

This must be explicitly marked **experimental / standards-track work in progress**, not a production Internet standard.

## 21. posture

### asset posture
Per endpoint:

- transport posture
- certificate posture
- STARTTLS posture
- policy posture
- behavioral state
- unresolved findings

### organization posture
Aggregate:

- observed mail assets
- total sessions
- modern TLS percentage
- Forward Secrecy percentage
- valid-certificate percentage
- STARTTLS success
- MTA-STS/DANE coverage
- critical findings
- anomalies
- trend over time

## 22. findings and correlation

Each finding includes:

- stable rule ID
- affected asset/session(s)
- severity
- evidence
- first/last seen
- policy version
- remediation
- standards reference
- lifecycle state

Mailent correlates repeated low-level events into one useful finding.

Bad:

```text
8,421 identical TLS 1.0 alerts
```

Good:

```text
legacy-mail-02 uses TLS 1.0
8,421 affected sessions
first seen 09:43
last seen 14:32
```

## 23. investigations

Correlate related signals into one workspace:

```text
certificate changed
+ issuer changed
+ TLS version regressed
+ handshake failures spiked
        ↓
cryptographic configuration-change investigation
```

Investigations expose:

- timeline
- assets
- sessions
- certificates
- deterministic findings
- baseline comparison
- external intelligence
- Jev decisions
- analyst notes/status

## 24. reporting

- executive posture report
- technical cryptographic report
- forensic case report
- asset report
- policy-simulation report
- historical trend report

Exports:

- PDF
- HTML
- JSON
- CSV for tabular datasets

Scheduled daily/weekly/monthly reports are supported.

## 25. integrations

### security operations
- Syslog
- CEF where required
- webhooks
- Splunk
- Elastic/OpenSearch
- Microsoft Sentinel
- QRadar-compatible forwarding
- generic event-stream consumers

### evidence/storage
- local filesystem
- NFS
- S3-compatible object storage
- MinIO

### identity
- OIDC
- enterprise SSO through compatible providers

## 26. alerting

Destinations:

- Mailent
- SIEM
- webhook
- email
- ticketing adapters

Features:

- deduplication
- grouping
- suppression windows
- per-policy severity
- escalation state
- acknowledgement
- auto-close candidate when remediation is continuously observed

## 27. forensic provenance

Preserve:

- source/capture/sensor
- timestamps
- session identity
- packet references when retained
- extracted evidence
- parser version
- rule-pack version
- baseline version
- Jev decision/model metadata
- report generation time

A future analyst must be able to reproduce why a finding existed.

## 28. privacy

- no raw mail body is required for normal posture analysis
- credentials are never intentionally retained
- raw PCAP can stay local to a sensor/site
- central processing can use normalized metadata
- Jev receives minimized structured features
- retention is configurable per source and site
