# Mailent · Canonical System Architecture, Operational Reference & SIH Knowledge Base

> **Version**: 0.1.4 (Feature-Complete Production Release)  
> **Problem Statement**: SIH26159 — AI-Assisted Passive Network Forensic Framework for Cryptographic Security Posture Assessment of Email Infrastructures  
> **Primary Repository**: `https://github.com/the-minecrafters/mailent`  
> **Live Deployment**: `https://mailent.onrender.com`  
> **Target Audience**: Evaluators, Judges, Technical Developers, Security Operations Center (SOC) Analysts, and LLM Context Systems.

---

## Table of Contents

1. [Executive Summary & Problem Space](#1-executive-summary--problem-space)
2. [Complete Product Concept & User Personas](#2-complete-product-concept--user-personas)
3. [Core Operational Workflows](#3-core-operational-workflows)
4. [Comprehensive Feature Deep-Dive](#4-comprehensive-feature-deep-dive)
5. [System Architecture & Data Flows](#5-system-architecture--data-flows)
6. [The Mailent Trust Model](#6-the-mailent-trust-model)
7. [Jev AI Decision Engine Specification](#7-jev-ai-decision-engine-specification)
8. [Zeek Forensics Engine Integration](#8-zeek-forensics-engine-integration)
9. [Domain Data Model & Entities](#9-domain-data-model--entities)
10. [Persistence & Database Architecture](#10-persistence--database-architecture)
11. [Security, Authorization & Threat Model](#11-security-authorization--threat-model)
12. [SIH Demo Walkthrough](#12-sih-demo-walkthrough)
13. [SIH26159 Problem Statement Mapping Matrix](#13-sih26159-problem-statement-mapping-matrix)
14. [Real-World Limitations & Constraints](#14-real-world-limitations--constraints)
15. [Testing, Verification & Evidence Catalog](#15-testing-verification--evidence-catalog)
16. [Compact ChatGPT Context](#16-compact-chatgpt-context)

---

## 1. Executive Summary & Problem Space

### 1.1 The Strategic Problem
Electronic mail (SMTP, IMAP, POP3) is the fundamental backbone of inter-organizational communication across governments, financial systems, healthcare networks, defense bodies, and enterprises. Despite the universal availability of Transport Layer Security (TLS), email transport remains plagued by silent, pervasive cryptographic decay:

1. **Obsolete Protocols**: Systems continue to negotiate deprecated TLS 1.0 and TLS 1.1 protocols (formally deprecated under RFC 8996), exposing sessions to BEAST, POODLE, and downgrade vulnerabilities.
2. **Weak Key Exchange & Absence of Forward Secrecy (PFS)**: Static RSA key exchange without ephemeral Diffie-Hellman (ECDHE/DHE) remains widespread. Adversaries who capture encrypted traffic today can decrypt entire historical archives if the server's private key is compromised in the future ("Harvest Now, Decrypt Later").
3. **Insecure STARTTLS Implementations**: Because SMTP relies on in-flight opportunistic upgrades via the `STARTTLS` command, active network adversaries (man-in-the-middle) can strip the STARTTLS capability advertisement from server responses (downgrade attack), forcing the client to transmit authentication credentials and email content in cleartext.
4. **Certificate Hygiene Failures**: Mail servers frequently serve expired X.509 leaf certificates, self-signed certificates without verifiable trust anchors, or incomplete certificate chains missing intermediate CAs.
5. **Lack of Policy Enforcement**: Domain owners fail to publish or enforce modern transport hardening policies such as **MTA-STS** (RFC 8461), **DANE / TLSA** (RFC 7672), and **TLS-RPT** (RFC 8460), leaving incoming delivery vulnerable to silent interception.

### 1.2 The Visibility & Tooling Gap
Traditional network diagnostic tools (such as Wireshark, tcpdump, or generic IDS) decode packets at the link and transport layers. However:
- They do not evaluate cryptographic security compliance against standards like RFC 8996, RFC 8461, or BCP 195.
- They do not track cross-session cryptographic configuration drift or security regressions over time.
- They do not passively validate certificate trust chains against root CA stores.
- They lack automated, explainable security posture scoring and risk prioritization.
- They provide no verifiable remediation workflows to prove that an applied cryptographic fix was effective.

### 1.3 The Mailent Solution
Mailent is an end-to-end passive forensic and transport security monitoring platform. It ingests raw packet captures (PCAP/PCAPNG) or monitors live wire taps, reconstructs application-layer email sessions (SMTP, IMAP, POP3), tracks STARTTLS negotiations, validates TLS parameters and X.509 certificate chains, applies deterministic RFC-based policy evaluations, computes versioned posture scores, provides contextual AI risk classification via Jev, and actively verifies vulnerability remediation.

---

## 2. Complete Product Concept & User Personas

### 2.1 Intended Users
1. **Security Operations Center (SOC) Analysts**: Rapidly triage captured network anomalies, evaluate cryptographic health across corporate mail gateways, and investigate suspicious cleartext downgrade events.
2. **Digital Forensics & Incident Response (DFIR) Teams**: Reconstruct email sessions from incident PCAPs, establish evidentiary timelines, prove whether mail content was encrypted in transit, and export forensically signed dossiers.
3. **Enterprise Email & Systems Administrators**: Continuously monitor mail infrastructure for cryptographic drift (e.g., certificate rotations, cipher deprecations), schedule automated domain assessments, and actively verify server configuration fixes.
4. **Compliance & Risk Auditors**: Audit email transport security against strict standards (RFC 8996, NIST SP 800-52r2, PCI-DSS v4.0), generate audit-ready PDF/HTML/JSON reports, and maintain verifiable historical posture records.

### 2.2 Complete Product Concept
Mailent operates as a hybrid architecture:
- **Core Engine & Web Console**: Centralized orchestration, multi-tenant workspace management, deterministic policy evaluation, posture scoring, baseline correlation, investigation dossiers, and report generation.
- **Sensor & Forensics Engine**: Deep packet inspection driven by Zeek 8+, extracting protocol timelines, STARTTLS state transitions, and X.509 metadata without capturing private message content or credentials.
- **Active Discovery & Probe Engine**: Autonomous scanner probing mail infrastructure (MX, SRV, SMTP:25/465/587, IMAP:143/993, POP3:110/995, MTA-STS, DANE, TLS-RPT, DNSSEC).
- **Connected Device Agents**: Distributed CLI workers running on local or on-premise hosts, enabling scheduled assessments and active checks directly from local network vantage points, completely bypassing cloud port-25 egress blocks.
- **Jev AI Assistant**: Contextual risk scoring and prioritization engine that assists analysts without ever overriding deterministic cryptographic facts.

---

## 3. Core Operational Workflows

```text
┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CORE OPERATIONAL WORKFLOWS                                      │
├─────────────────────────┬─────────────────────────┬───────────────────────┬───────────────────────┤
│ 1. PCAP Forensics       │ 2. Domain Assessment    │ 3. Continuous Tap     │ 4. Remediation        │
│ Upload capture → Zeek   │ Discover MX/DNS → Probe │ Sniff interface → tail│ Flag finding → apply  │
│ extraction → Handshake  │ STARTTLS/ciphers/PFS →  │ Zeek logs → spool →   │ fix → probe challenge │
│ timeline → Policy check │ MTA-STS/DANE → Score &  │ drift detection →     │ → verify resolution   │
│ → Posture & Reports.    │ Dossier.                │ regression alerts.    │ (VerifiedFixed).      │
└─────────────────────────┴─────────────────────────┴───────────────────────┴───────────────────────┘
```

### 3.1 Passive PCAP Forensic Analysis Workflow
1. **Ingestion**: An analyst uploads a PCAP or PCAPNG file via the web console (`POST /api/v1/assessments/analyze`) or runs the CLI (`mailent analyze capture.pcap --format json`).
2. **Zeek Processing**: The sensor executes Zeek with the custom `zeek/mailent` package, isolating protocol transitions and writing structured JSON logs (`conn.log`, `ssl.log`, `x509.log`, `mailent.log`).
3. **Normalization**: Zeek logs are normalized into `NormalizedObservation` records, extracting timestamps, network flows, TLS versions, cipher IDs, key exchange methods, and certificate details.
4. **Policy Evaluation**: The deterministic policy pack (`modern`) inspects sessions for deprecated TLS, missing STARTTLS, expired certs, or lack of forward secrecy.
5. **Posture Scoring**: The correlation engine calculates the composite 0–100 posture score, qualitative grade, and category breakdown.
6. **AI Risk Assessment**: Jev evaluates the structured findings to assign risk level, anomaly flag, and triage priority.
7. **Dossier Generation**: The assessment is saved with SHA-256 capture hash and made exportable as JSON, standalone HTML, or native PDF.

### 3.2 Live Infrastructure Assessment Workflow
1. **Target Discovery**: An analyst or scheduled job specifies a target domain (e.g., `example.com`).
2. **DNS & Policy Enumeration**: The scanner queries:
   - MX records (with fallback to RFC 5321 direct A/AAAA resolution).
   - SRV records (`_submission._tcp`, `_imaps._tcp`, `_pop3s._tcp`).
   - MTA-STS policy (`https://mta-sts.<domain>/.well-known/mta-sts.txt` and TXT `_mta-sts.<domain>`).
   - DANE TLSA records (`_<port>._tcp.<mx-host>`).
   - TLS-RPT policy (TXT `_smtp._tls.<domain>`).
   - DNSSEC validation status.
3. **Endpoint Probing**: The probe engine connects to discovered mail endpoints across ports 25, 465, 587, 143, 993, 110, 995, executes application handshakes, negotiates STARTTLS or direct TLS, and extracts certificate chains.
4. **Correlation & Drift**: Core correlates findings against prior infrastructure scans, identifying newly opened ports, rotated certificates, or removed ciphers.

### 3.3 Continuous Live Wire Monitoring Workflow
1. **Live Tap Activation**: An administrator deploys `mailent monitor --interface eth0` on an email gateway or mirror port.
2. **Continuous Packet Normalization**: Zeek captures live traffic, tails connection logs, and streams normalized observations over HTTPS to Mailent Core.
3. **Spooling & Resiliency**: If Core is temporarily unreachable, observations buffer in memory and overflow to a bounded local spool (`/tmp/mailent-spool`), draining automatically when connectivity resumes.
4. **Real-Time Drift Engine**: Core unifies incoming observations into logical assets, alerting immediately when an asset loses forward secrecy, rotates a certificate, or negotiates an unexpected TLS version.

### 3.4 Connected-Device & Local Companion Workflow
1. **Registration**: An operator runs `mailent login --server https://mailent.onrender.com` on an on-premise Linux/Windows host.
2. **Challenge Authorization**: The CLI generates a unique device challenge (e.g. `MLT-A1B2C3D4`). The operator approves it in the web workspace (`/settings?tab=devices`).
3. **Hashed Token Issuance**: Core returns an authentication token (`mlt_...`), storing only its SHA-256 hash in `device_tokens`.
4. **Companion Execution**: The operator runs `mailent companion install` to register a systemd user/system service, or `mailent companion run` in the foreground. This starts both the workspace job listener and the local loopback bridge on `http://127.0.0.1:15488`.
5. **Job Dispatch & Loopback Ingestion**:
   - For domain scans, the companion leases typed jobs from Core, executes the check locally (unimpeded by cloud port-25 blocks), and posts results back over HTTPS.
   - For capture analysis, the web workspace streams PCAP bytes directly to the companion bridge on loopback. Zeek runs locally, and only the structured assessment syncs to Core.
6. **Instant Revocation**: If the device is revoked in the web UI, active jobs are cancelled immediately, the token hash is deleted, and the running CLI clears credentials and halts.

### 3.5 Remediation & Active Transport Verification Workflow
1. **Remediation Initiation**: An analyst reviews an active finding (e.g. `TLS_LEGACY_VERSION` on port 25) and clicks **Start fix**.
2. **Immutable Snapshot**: Core freezes the finding and passive evidence session into an immutable `RemediationRecord` (`state: InProgress`).
3. **Admin Applies Fix**: The administrator reconfigures the mail server (e.g., updates Postfix `smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1`).
4. **Fix Notification**: The admin clicks **Mark applied** in Mailent (`state: Applied`).
5. **Active Probe Challenge**: The admin triggers **Verify fix** (`state: Verifying`). Mailent issues an active probe challenge:
   - For `TLS_LEGACY_VERSION`: Attempts TLS 1.0/1.1 handshakes; requires protocol version alert rejection.
   - For `CERTIFICATE_EXPIRED`: Verifies the leaf certificate has valid dates and a trusted chain.
   - For `STARTTLS_MISSING`: Verifies STARTTLS advertisement, acceptance, and successful TLS upgrade.
6. **Conclusive Outcome**:
   - If the challenge confirms the flaw is gone → `VerifiedFixed`.
   - If the challenge still reproduces the flaw → `StillPresent`.
   - If the target is unreachable/timed out → `Inconclusive` (never falsely marked fixed!).

### 3.6 Multi-Format Forensic Reporting Workflow
1. **Compilation**: At any time, an assessment, asset, or investigation can be compiled into a canonical `ForensicReport` model.
2. **Format Generation**:
   - **JSON**: Machine-readable canonical dossier with SHA-256 integrity hash.
   - **HTML**: Standalone, print-ready, CSS-inlined technical document with zero external asset dependencies.
   - **PDF**: Binary PDF-1.4 file generated directly by the Mailent reporting engine with byte-exact typography and layout.
3. **Provenance Labels**: Every row in the report explicitly displays its evidentiary origin: `[PASSIVE CAPTURE]`, `[ACTIVE PROBE]`, `[EXTERNAL INTELLIGENCE]`, or `[POLICY EVALUATION]`.

---

## 4. Comprehensive Feature Deep-Dive

### 4.1 PCAP & PCAPNG Ingestion
- **Formats Supported**: Standard libpcap (`.pcap`), Next-Generation PCAP (`.pcapng`), and gzip-compressed captures.
- **Edge-Case Resilience**: The parser gracefully handles:
  - Microsecond and nanosecond timestamps (big-endian and little-endian).
  - Out-of-order TCP segments and duplicate ACKs.
  - Truncated packets and zero-length snaplen captures.
  - Multi-stream captures with concurrent mixed traffic (SMTP, IMAP, POP3, HTTP, SSH).
  - 802.1Q VLAN-tagged frames and IPv6 traffic.
  - Non-standard port SMTP (e.g., port 2525).
  - Packet injection attacks and mid-handshake TCP RST terminations.

### 4.2 Zeek Integration & Protocol Normalization
- **Custom Mailent Package (`zeek/mailent/__load__.zeek`)**:
  - Intercepts `connection_established`, `smtp_request`, `smtp_reply`, `smtp_starttls`, `imap_capabilities`, `imap_starttls`, `pop3_request`, `pop3_reply`, `pop3_starttls`, `ssl_client_hello`, `ssl_server_hello`, `ssl_established`, and `x509_certificate`.
  - Normalizes events into a unified stream: `tcp_connected`, `ehlo`, `starttls_advertised`, `starttls_not_advertised`, `starttls_requested`, `starttls_accepted`, `starttls_rejected`, `plaintext_continuation`, `tls_client_hello`, `tls_server_hello`, `tls_established`, `tls_fatal_alert`.
- **Privacy Guarantees**:
  - `SMTP::LOG` is disabled (`Log::disable_stream(SMTP::LOG)`).
  - Message envelopes, message bodies, subject lines, attachments, and user credentials (`AUTH LOGIN`, `AUTH PLAIN`, `PASS`) are **never logged, parsed, or persisted**. Only protocol state transitions and handshake metadata are captured.

### 4.3 TLS Analysis, Cipher Suites & Forward Secrecy
- **TLS Protocol Versions**: Identifies SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3.
- **Cipher Suite Inspection**: Decodes IANA cipher suite numbers (e.g., `0x002F` → `TLS_RSA_WITH_AES_128_CBC_SHA`, `0x1302` → `TLS_AES_256_GCM_SHA384`).
- **Key Exchange Classification**:
  - `Ecdhe`: Ephemeral Elliptic Curve Diffie-Hellman (P-256, X25519, etc.) → **Forward Secrecy Available**.
  - `Dhe`: Ephemeral Finite-Field Diffie-Hellman → **Forward Secrecy Available**.
  - `RsaStatic`: Static RSA key exchange → **Forward Secrecy Absent** (Triggers `NO_FORWARD_SECRECY` finding).
  - `Unknown`: Handshake unobserved or encrypted.

### 4.4 X.509 Certificate Extraction & Passive Chain Validation
- **Metadata Extracted**: Subject DN, Issuer DN, Serial Number, SHA-256 Fingerprint, Validity Window (`not_before`, `not_after`), Subject Alternative Names (SANs), Basic Constraints (CA flag).
- **Cryptographic Details**: Signature algorithm (e.g., SHA256withRSA, ECDSA), Public Key algorithm, RSA key length (bits), EC curve name.
- **Passive Chain Validation**:
  - Loads Zeek’s official `policy/protocols/ssl/validate-certs.zeek`.
  - Zeek performs `x509_verify(chain, root_certs)` using the Mozilla root CA store.
  - Normalizer maps `validation_status`: `"ok"` → `ChainValidation::Verified`; specific failure strings → `ChainValidation::Failed`; missing data (e.g., TLS 1.3 encrypted certs) → `ChainValidation::NotVerified`.
  - Evaluates expiration relative to capture timestamp: if `session.last_seen > cert.not_after` → `CERTIFICATE_EXPIRED`.

### 4.5 Visibility & Evidence Gap Tracking
Mailent never fabricates protocol stages. If a partial PCAP begins mid-stream or misses the TCP handshake:
- `ProtocolLadder` displays distinct states: `Observed`, `Inferred`, `Unavailable`, `Failed`.
- It records explicit `evidence_gaps` (e.g., `"missing_tcp_handshake"`, `"incomplete_certificate_chain"`).
- Missing evidence is never scored as a vulnerability, nor is it displayed as successful encryption.

### 4.6 Deterministic Policy Engine
Mailent ships with versioned, YAML-defined policy packs (`policies/`):
- **`modern` (v1.1.0)**:
  - `TLS_LEGACY_VERSION` (Critical): Flag TLS 1.0 / 1.1 (RFC 8996).
  - `CERTIFICATE_EXPIRED` (High): Flag expired leaf certs (RFC 5280).
  - `NO_FORWARD_SECRECY` (High): Flag static RSA key exchange (BCP 195).
  - `STARTTLS_MISSING` (High): Flag absence of STARTTLS on port 25 (RFC 3207).
- **`high-security` (v1.0.0)**: Mandates TLS 1.3 exclusively.
- **`legacy-compatible` (v1.0.0)**: Allows TLS 1.2 with broader cipher interoperability.

### 4.7 Posture Scoring Engine
The deterministic posture algorithm (`crates/correlation/src/posture.rs`) produces an explainable composite score (0–100):
- **Category Weights**:
  - `TransportSecurity`: 40% (Protocols, Ciphers, PFS)
  - `CertificateHygiene`: 25% (Validity, Chains, Key lengths)
  - `ProtocolConfiguration`: 25% (STARTTLS, MTA-STS, DANE)
  - `AnomalyRiskContext`: 10% (Drift, Behavioral deviations)
- **Point Deductions**: Applied per finding based on severity (Critical: -40, High: -25, Medium: -15, Low: -5).
- **Severe Finding Caps**:
  - Any **Critical** finding caps overall score at **29/100** (`Grade: Critical`).
  - Any **High** finding caps overall score at **60/100** (`Grade: Moderate`).
  - Prevents serious cryptographic flaws from hiding behind an inflated category average.
- **Qualitative Grades**:
  - `90.0 ..= 100.0` → **Strong** (Grade A)
  - `75.0 ..< 90.0` → **Good** (Grade B)
  - `55.0 ..< 75.0` → **Moderate** (Grade C)
  - `30.0 ..< 55.0` → **Weak** (Grade D)
  - `0.0 ..< 30.0` → **Critical** (Grade F)

### 4.8 Behavioral Baselines & Cryptographic Drift
- **Baselines**: Tracks statistical distributions for an asset over time (TLS version % share, cipher % share, STARTTLS success rate, handshake failure rate).
- **Drift Events**: Generated automatically when an asset changes configuration:
  - `NewTlsVersion`: Negotiated an unseen TLS version.
  - `ForwardSecrecyLost`: Dropped from ECDHE to static RSA.
  - `CertificateChanged`: Presented a new certificate SHA-256 fingerprint.
  - `NewCertificateIssuer`: Certificate signed by an unexpected CA.
  - `NewEndpoint`: Asset responded on a new mail port.

### 4.9 External Infrastructure Discovery
The domain scanner (`crates/scanner/src/scanner.rs`) inspects target mail domains:
- **MX Discovery**: Queries DNS MX records with priority sorting.
- **RFC 5321 Fallback**: If no MX exists, falls back to direct A/AAAA domain address.
- **SRV Discovery**: Discovers submission and client-access endpoints.
- **MTA-STS**: Fetches `_mta-sts.<domain>` DNS TXT record and parses policy file via HTTPS.
- **DANE / TLSA**: Validates DNSSEC-signed TLSA records on port 25.
- **TLS-RPT**: Verifies presence of `_smtp._tls.<domain>` reporting address.

### 4.10 Investigations & Incident Dossiers
When high-severity findings or critical drift events occur, Core correlates them into an `Investigation`:
- Groups related assets, findings, drift events, and baseline anomaly signals.
- Attaches the contextual Jev AI decision.
- Provides a SOC incident lifecycle: `Open` → `In Review` → `Remediated` → `Closed`.

---

## 5. System Architecture & Data Flows

### 5.1 System Overview & Workspace Crates
Mailent is organized as a Cargo and pnpm monorepo:

```text
mailent/
├── apps/
│   ├── core/         # Central Axum REST API, scheduler, DualStorage, and pipeline orchestrator
│   ├── sensor/       # Zeek capture runner, log normalizer, spooler, and heartbeat client
│   ├── probe/        # Scoped active network prober (SMTP, IMAP, POP3 TLS challenges)
│   ├── cli/          # Unified terminal binary (mailent analyze, scan, monitor, agent, login)
│   └── web/          # React 19 / Vite web console and forensic dashboard
├── crates/
│   ├── domain/       # Core types: Assessment, Session, Finding, Posture, Remediation, etc.
│   ├── events/       # Protobuf message schemas and internal event bus
│   ├── policy/       # Deterministic policy engine and YAML pack evaluator
│   ├── correlation/  # Posture scoring, guidance builder, and multi-session correlation
│   ├── baseline/     # Asset behavioral baseline generator and anomaly detector
│   ├── storage/      # Repositories for PostgreSQL, ClickHouse, and in-memory storage
│   ├── decision/     # Jev AI client, circuit breaker, and deterministic fallback
│   ├── integrations/ # Live DNS/DoH resolver, webhook dispatcher, and syslog CEF exporter
│   ├── reporting/    # Canonical ForensicReport model, JSON/HTML/PDF deterministic exporters
│   └── scanner/      # Active domain scanner (DNS discovery + probe coordination)
├── zeek/             # Custom Mailent Zeek scripts (mailent/__load__.zeek, dpd.sig)
├── policies/         # Versioned YAML policy packs (modern, high-security, legacy-compatible)
└── supabase/         # PostgreSQL schema migrations and multi-tenant RLS policies
```

### 5.2 Dependency Architecture

```text
                  ┌───────────────┐
                  │   apps/cli    │
                  └───────┬───────┘
                          │ (uses scanner, correlation, domain, probe)
                          ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│   apps/web    │  │   apps/core   │  │  apps/sensor  │
└───────┬───────┘  └───────┬───────┘  └───────┬───────┘
        │ (HTTP)           │                  │ (Zeek logs)
        └─────────────────►│                  │
                           ▼                  ▼
┌────────────────────────────────────────────────────────┐
│                     CRATE LIBRARIES                    │
│ ┌───────────────┐ ┌───────────────┐ ┌────────────────┐ │
│ │crates/scanner │ │crates/policy  │ │crates/decision │ │
│ └───────────────┘ └───────────────┘ └────────────────┘ │
│ ┌───────────────┐ ┌───────────────┐ ┌────────────────┐ │
│ │crates/correl. │ │crates/storage │ │crates/reporting│ │
│ └───────────────┘ └───────────────┘ └────────────────┘ │
│ ┌───────────────┐ ┌───────────────┐ ┌────────────────┐ │
│ │crates/baseline│ │crates/integr. │ │crates/events   │ │
│ └───────────────┘ └───────────────┘ └────────────────┘ │
│                          │                             │
│                          ▼                             │
│                 ┌─────────────────┐                    │
│                 │  crates/domain  │                    │
│                 └─────────────────┘                    │
└────────────────────────────────────────────────────────┘
```

---

### 5.3 Complete End-to-End Data Flow Diagrams

#### Flow 1: Offline Forensic PCAP Assessment
```text
Analyst (Web/CLI)
       │
       │ 1. Uploads PCAP / PCAPNG
       ▼
[ apps/core (API: /api/v1/assessments/analyze) ]
       │
       │ 2. Spawns sensor subprocess
       ▼
[ apps/sensor + Zeek 8 Engine ]
       │
       │ 3. Executes custom Zeek scripts (mailent/__load__.zeek)
       │    Parses SMTP/IMAP/POP3, STARTTLS, TLS, and X.509
       ▼
[ Raw Zeek JSON Logs: conn.log, ssl.log, x509.log, mailent.log ]
       │
       │ 4. Normalization (apps/sensor/src/normalize.rs)
       ▼
[ Vec<NormalizedObservation> ]
       │
       │ 5. process_observation() Pipeline
       ├─────────────────────────────────────────┐
       ▼                                         ▼
[ Policy Engine (crates/policy) ]      [ Baseline & Anomaly Engine ]
Evaluates rules (RFC 8996, RFC 5280)    Checks statistical deviations
       │                                         │
       ▼                                         ▼
[ Deterministic Findings ]              [ AnomalySignals & DriftEvents ]
       │                                         │
       └────────────────────┬────────────────────┘
                            │
                            ▼
           [ Posture Engine (crates/correlation) ]
           Computes composite score & category caps
                            │
                            ▼
           [ Jev AI Engine (crates/decision) ]
           Provides contextual risk & priority
                            │
                            ▼
              [ Assessment Record Created ]
       Stored in DualStorage (Postgres or InMemory)
                            │
                            ▼
    [ Multi-Format Reports Generated: JSON / HTML / PDF ]
```

#### Flow 2: Live Infrastructure Assessment
```text
Admin (Web/CLI)
       │
       │ 1. Submits domain (e.g., mailent.test)
       ▼
[ apps/core (API: /api/v1/scans/infrastructure) ]
       │
       │ 2. DomainScanner::scan_domain()
       ▼
[ DNS & Intelligence Resolver (crates/integrations) ]
Queries MX records, RFC 5321 fallback, SRV, MTA-STS, DANE TLSA, TLS-RPT
       │
       ▼
[ Endpoint Probe Orchestrator (crates/scanner + apps/probe) ]
Performs authorized TCP handshakes to ports 25, 465, 587, 143, 993, 110, 995
Checks STARTTLS advertisement, negotiation, cipher, PFS, and certificates
       │
       ▼
[ ScanResult: Endpoints, Sessions, DNS policies ]
       │
       ▼
[ Core Pipeline Evaluation ]
Correlates findings, evaluates policy, updates asset catalog
       │
       ▼
[ Drift Detection Engine ]
Compares against prior domain assessments (detects rotated certs, lost PFS)
       │
       ▼
[ Investigation Dossier Created / Enriched ]
```

#### Flow 3: Scheduled Connected-Agent Assessment
```text
[ InfrastructureMonitor (Core Scheduler) ]
Detects due schedule (Hourly / Daily / Weekly)
       │
       │ 1. Enqueues typed AgentJob
       ▼
[ agent_jobs table (State: Pending) ]
       │
       │ 2. Agent polls /api/v1/agent/jobs/poll
       ▼
[ On-Premise Connected Device (mailent companion daemon) ]
Leases job with distributed expiration timeout
       │
       │ 3. Executes DomainScanner locally on device
       │    (Bypasses cloud outbound port 25 blocking!)
       ▼
[ Local Mail Servers / MX Endpoints (Port 25) ]
       │
       │ 4. Completed assessment payload posted over HTTPS
       ▼
[ Core API: /api/v1/agent/jobs/{id}/complete ]
       │
       │ 5. Stores Assessment, findings, and drift events
       ▼
[ Organization Workspace Updated & Notifications Dispatched ]
```

#### Flow 4: Continuous Live Zeek Wire Monitoring
```text
[ Physical / Virtual Mail Gateway Interface (e.g. eth0) ]
       │
       │ 1. Promiscuous packet capture
       ▼
[ apps/sensor (mailent-sensor listen -i eth0) ]
       │
       │ 2. Real-time Zeek live analysis
       ▼
[ Local Zeek Event Stream ]
       │
       │ 3. Continuous log tailer & normalizer
       ▼
[ Bounded Spooler (/tmp/mailent-spool) ]
In-memory FIFO buffer with automatic disk spill & drop accounting
       │
       │ 4. HTTPS POST /api/v1/observations (with periodic /heartbeat)
       ▼
[ apps/core Ingestion Pipeline ]
       │
       ▼
[ Real-Time Drift Engine ]
Emits DriftEvent immediately if live connection deviates from asset baseline
```

#### Flow 5: Remediation Verification Flow
```text
Security Admin
       │
       │ 1. Resolves vulnerability & clicks "Verify fix"
       ▼
[ apps/core (API: /api/v1/remediations/{id}/verify) ]
       │
       │ 2. Loads RemediationRecord (Immutable Before Session)
       ▼
[ apps/probe (Scoped Probe Engine) ]
       │
       │ 3. Issues cryptographic challenge to affected endpoint:
       │    • Legacy TLS Challenge: Attempts TLS 1.0/1.1; expects rejection
       │    • Expiration Challenge: Checks leaf cert validity & chain
       │    • STARTTLS Challenge: Tests advertisement & completed upgrade
       ▼
[ Target Mail Server Endpoint ]
       │
       │ 4. Raw handshake challenge response
       ▼
[ Verification Evaluation ]
       ├── Conclusively fixed?      → state = VerifiedFixed
       ├── Vulnerability persists?   → state = StillPresent
       └── Endpoint unreachable?    → state = Inconclusive
       │
       ▼
[ RemediationRecord Updated & Training Outcome Label Recorded ]
```

---

## 6. The Mailent Trust Model

Mailent implements a strict 6-stage trust hierarchy. Higher stages can interpret or prioritize lower stages, but **can never alter or contradict them**:

```text
Stage 1: Observed Network Evidence
         (Raw PCAP packets, Zeek protocol logs, TCP streams, probe sockets)
                           │
                           ▼
Stage 2: Deterministic Policy Evaluation
         (Rigid verification against RFC 8996, RFC 5280, RFC 8461, RFC 3207)
                           │
                           ▼
Stage 3: Behavioral Baselines & Historical Drift
         (Statistical deviations, unseen ciphers, rotated certificates, lost PFS)
                           │
                           ▼
Stage 4: Deterministic Posture Scoring
         (Versioned 1.0.0 composite 0-100 score, weighted categories, caps)
                           │
                           ▼
Stage 5: Jev Contextual AI Assessment
         (High-level risk triage, priority classification, anomaly explanations)
                           │
                           ▼
Stage 6: Analyst Investigation & Active Verification
         (Human triage, patch deployment, active probe verification)
```

### 6.1 Component Responsibility Matrix

| Component | Nature | What It Decides | What It CANNOT Decide |
| :--- | :--- | :--- | :--- |
| **Zeek** | Deterministic Packet Parser | Protocol identification, handshake event order, cipher ID, cert bytes, TCP state | Whether a cipher is compliant, overall security score |
| **Deterministic Policy** | Mathematical Logic (Rust) | RFC violations, weak ciphers, expired certs, missing STARTTLS | Subjective risk level, incident triage priority |
| **Baseline & Drift** | Statistical Math | Historical deviations, newly introduced ciphers, rotated certs | Whether a change is malicious or intentional |
| **Posture Engine** | Deterministic Weighted Math | Numeric score (0–100), category score, grade (Strong–Critical) | Business risk context, external attacker intent |
| **Jev AI Engine** | LLM / Probabilistic AI | Risk tier (`Low`–`Critical`), triage priority, operational advice | **Never determines objective cryptographic truth** |
| **Active Probe** | Socket Challenge Engine | Live verification outcome (`VerifiedFixed`, `StillPresent`) | Historical packet evidence |

---

## 7. Jev AI Decision Engine Specification

### 7.1 Provider Configuration & Endpoints
- **Service Name**: Jev AI Decision Engine (integrated via Codiv Typesafe API).
- **Environment Variables**:
  - `MAILENT_JEV_ENABLED`: Toggle AI integration (`true` / `false`).
  - `MAILENT_JEV_BASE_URL`: Base API endpoint (default: `https://api.codiv.ai`).
  - `MAILENT_JEV_MODEL`: Model identifier (default: `openjev-latest`).
  - `MAILENT_JEV_API_KEY`: Authentication secret.
- **Circuit Breaker**: Trips open after **3 consecutive failures**, remaining open for **30 seconds** before attempting half-open recovery.
- **Timeout**: Hard **10-second** deadline per request.

### 7.2 Structured Input Payload
Jev receives strictly sanitized, structured context:
```json
{
  "model": "openjev-latest",
  "state": {
    "session_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "findings": [
      {
        "severity": "critical",
        "title": "Deprecated TLS Version Negotiated",
        "description": "Observed TLSv1.0 on connection 192.168.1.10:49210 -> 10.0.0.1:25"
      }
    ],
    "metadata": {
      "assessment_id": "...",
      "anomalies_count": 0,
      "posture_score": 25.0,
      "posture_grade": "Critical"
    }
  },
  "questions": {
    "risk": { "type": "choice", "criteria": { "low": "...", "medium": "...", "high": "...", "critical": "..." } },
    "anomalous": { "type": "choice", "criteria": { "yes": "...", "no": "..." } },
    "human_review": { "type": "choice", "criteria": { "yes": "...", "no": "..." } },
    "priority": { "type": "choice", "criteria": { "low": "...", "normal": "...", "high": "...", "immediate": "..." } }
  }
}
```
> **Privacy Guarantee**: Raw packet payloads, email bodies, subject headers, and user credentials are **strictly excluded** from the Jev payload.

### 7.3 Output Schema & Deterministic Fallback
Jev returns structured categorical classifications:
- `risk`: `Low`, `Medium`, `High`, or `Critical`.
- `anomalous`: Boolean.
- `human_review`: Boolean.
- `priority`: `Low`, `Normal`, `High`, or `Immediate`.
- `confidence`: Floating-point scalar (0.0 to 1.0).

**Graceful Degradation (`deterministic_fallback`)**:  
If Jev is disabled, times out, or errors out, Mailent immediately executes local fallback logic:
- Any Critical finding → `Risk: Critical`, `Priority: Immediate`, `HumanReview: true`.
- Any High finding → `Risk: High`, `Priority: High`, `HumanReview: true`.
- Any Medium finding → `Risk: Medium`, `Priority: Normal`, `HumanReview: false`.
- Low/None → `Risk: Low`, `Priority: Low`, `HumanReview: false`.
- The provider string is explicitly tagged as `mailent-deterministic-fallback` (ensuring transparent provenance in reports and UI).

---

## 8. Zeek Forensics Engine Integration

### 8.1 Why Zeek 8+ is Mandatory
Zeek provides industrial-grade stream reassembly, protocol state tracking, dynamic protocol detection (DPD), and cryptographic analysis:
1. **TCP Stream Normalization**: Reassembles fragmented, out-of-order, or overlapping TCP segments across complex network topologies.
2. **Dynamic Protocol Detection (DPD)**: Detects SMTP, IMAP, and POP3 running on non-standard ports via signature matching (`dpd.sig`) rather than port assumptions.
3. **Application State Tracking**: Accurately tracks multi-turn protocol dialogues (`EHLO` → `250 STARTTLS` → `STARTTLS` → `220 Ready` → TLS ClientHello).
4. **X.509 Extraction**: Automatically extracts binary DER certificates, computes SHA-256 fingerprints, and performs root-trust validation.

### 8.2 Custom Mailent Zeek Package
Located in `zeek/mailent/`:
- `__load__.zeek`:
  - Registers analyzers for standard and non-standard mail ports.
  - Subscribes to SSL and X.509 events.
  - Implements state flags: `mailent_ehlo`, `mailent_advertised`, `mailent_pending`, `mailent_rejected`, `mailent_capa`.
  - Disables message content logging.
  - Loads `policy/protocols/ssl/validate-certs` and `policy/frameworks/files/hash-all-files`.
- `dpd.sig`: Signatures matching SMTP greetings (`220 *ESMTP*`), IMAP banners (`* OK *`), and POP3 greetings (`+OK *`).

### 8.3 Runtime Discovery (`locate_zeek`)
The engine discovers Zeek in the following priority order:
1. Environment variable `MAILENT_ZEEK`.
2. Repository helper scripts: `scripts/mailent-zeek` or `scripts/zeek-container` (Podman/Docker wrapper for `zeek/zeek:8.0.4`).
3. System `PATH` search for `zeek`.

---

## 9. Domain Data Model & Entities

The domain model (`crates/domain/src/`) defines strongly typed, serialization-safe entities:

```text
┌────────────────────────────────────────────────────────────────────────────────┐
│                           CORE DOMAIN ENTITIES                                 │
├───────────────────────┬────────────────────────────────────────────────────────┤
│ Organization          │ Multi-tenant workspace boundary (UUID, Name, Slug).    │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ Device                │ Enrolled CLI device / agent (ID, Hostname, Platform,   │
│                       │ Capabilities, Status, LastSeenAt).                     │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ AgentJob              │ Typed work item (InfrastructureAssessment, LeasedAt,   │
│                       │ LeaseExpiresAt, State, ResultAssessmentId).            │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ InfrastructureMonitor │ Scheduled domain monitoring configuration (Domain,     │
│                       │ Cadence: Hourly/Daily/Weekly, Target: Cloud/Agent).    │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ Assessment            │ First-class forensic dossier (Title, Source, Hash,     │
│                       │ PostureScore, Grade, FindingIds, EvidenceGaps).        │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ Asset                 │ Logical email infrastructure host (IPs, Hostnames,     │
│                       │ Endpoints, Certificates, ActiveFindingsCount).         │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ EmailSession          │ Normalized transport session (Flow, Protocol, TLS ver, │
│                       │ Cipher, KeyExchange, StartTlsState, Certificate).      │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ Finding               │ Deterministic policy violation (RuleId, Title, Severity│
│                       │ Category, Remediation, Reference RFC, EvidenceRefs).   │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ SecurityPosture       │ Composite score snapshot (Score: 0-100, Grade, Capped, │
│                       │ CategoryBreakdown, Deductions, WorstFindings).         │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ DriftEvent            │ Cryptographic state delta (Kind: NewTlsVersion,        │
│                       │ ForwardSecrecyLost, CertChanged, PrevValue, NewValue). │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ Investigation         │ Correlated incident record (AssetId, Title, Risk,      │
│                       │ Priority, Status: Open/Remediated, JevDecision).       │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ RemediationRecord     │ Append-only fix tracking (Finding, Guidance, Before,   │
│                       │ Condition, State: InProgress/Verifying/VerifiedFixed). │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ ProbeRun              │ Active socket verification result (Target, Port,       │
│                       │ Outcome, PerspectiveMismatches, HasMismatch).          │
├───────────────────────┼────────────────────────────────────────────────────────┤
│ TrainingRecord        │ Immutable decision-time feature snapshot (Features,    │
│                       │ AutomatedLabel, AnalystLabel, RemediationOutcomes).    │
└───────────────────────┴────────────────────────────────────────────────────────┘
```

---

## 10. Persistence & Database Architecture

### 10.1 DualStorage Engine
Mailent solves multi-tenant persistence and guest exploration through `DualStorage`:
- **Authenticated Requests**: Scoped by `organization_id` extracted from validated Supabase JWTs or device tokens; persisted to PostgreSQL.
- **Guest Requests (`X-Mailent-Guest: true`)**: Routed to high-speed in-memory repositories (`InMemoryStorage`). Guests can evaluate PCAPs and inspect dossiers without polluting production databases or requiring account creation.

### 10.2 PostgreSQL Schema (`supabase/migrations/`)
All tables are partitioned under the dedicated `mailent` schema with Row Level Security (RLS) active:
1. `organizations` & `organization_members`: Workspace isolation and user roles.
2. `devices`, `device_tokens`, `device_challenges`: Device enrollment, challenge handshake, and hashed tokens.
3. `agent_jobs` & `infrastructure_monitors`: Distributed job queues, lease management, and scheduled monitoring.
4. `assessments`: First-class audit dossier records.
5. `assets`, `asset_identities`, `asset_endpoints`, `certificates`, `asset_certificates`: Infrastructure asset catalog.
6. `findings` & `finding_evidence`: Policy violations linked to sessions.
7. `drift_events` & `anomaly_signals`: Historical configuration changes.
8. `investigations` & `decision_records`: Triage dossiers and Jev audit logs.
9. `remediations` & `probe_runs`: Verification records and active probe results.
10. `archived_reports` & `training_records`: Immutable compliance reports and ML diagnostic snapshots.
11. `mail_sessions` & `mail_observations`: JSONB tables storing full session telemetry in serverless deployments without ClickHouse.

---

## 11. Security, Authorization & Threat Model

### 11.1 Zero-Trust Device Authorization Flow
1. Device initiates challenge via CLI (`POST /api/v1/devices/authorize/challenge`).
2. Server returns temporary code (e.g. `MLT-4X89A2`).
3. Authenticated workspace user reviews hostname, OS, and platform, clicking **Approve**.
4. Device polling receives an issued token (`mlt_...`).
5. Only the SHA-256 hash of the token is stored in the database (`device_tokens.token_hash`).
6. Revocation permanently removes the hash and cancels all active jobs in a single atomic database query.

### 11.2 Typed Agent Jobs (Absence of Remote Shell)
The Mailent Agent **never** implements an arbitrary remote command shell or bash executor. Jobs are strictly typed domain enums:
```rust
pub enum AgentJobType {
    InfrastructureAssessment { domain: String, timeout_seconds: u64 },
    ProbeVerification { probe_request: ProbeRequest },
}
```
An attacker compromising the control plane cannot execute arbitrary commands on connected agent hosts.

### 11.3 Active Probe Safety & SSRF Prevention
The probe engine protects internal networks:
- **SSRF Protection**: Probing private, loopback, link-local, broadcast, or multicast IPs is strictly blocked by default (`is_restricted_ip`).
- **Scope Enforcement**: Operators can restrict probing to an explicit domain whitelist (`MAILENT_PROBE_ALLOWED_DOMAINS`).
- **Safe Protocol Sequences**: Active SMTP checks issue only safe handshake commands (`EHLO`, `STARTTLS`, `QUIT`). They **never send `MAIL FROM`, `RCPT TO`, or message data**, preventing unintended mail delivery or spam flagging.

---

## 12. SIH Demo Walkthrough

### Recommended Presentation Script (ThinkPad Lab + Cloud Platform)

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SIH DEMO SCRIPT TIMELINE                                       │
├─────────┬───────────────────────────────┬────────────────────────────────────────────────────────┤
│ Time    │ Stage                         │ Key Actions & Visible Output                           │
├─────────┼───────────────────────────────┼────────────────────────────────────────────────────────┤
│ 00:00   │ Introduction & Landing        │ Present problem statement, show editorial landing page │
│ 01:00   │ Passive PCAP Forensics        │ Upload smtp_legacy.pcap; reveal TLS 1.0 & expired cert │
│ 02:30   │ Protocol Evidence Ladder      │ Inspect connection stages, timeline, and X.509 cert    │
│ 03:30   │ Domain Assessment             │ Scan mailent.test via connected agent on ThinkPad      │
│ 05:00   │ Simulated Regression & Drift  │ Mutate Postfix config; detect STARTTLS stripping drift │
│ 06:30   │ Triage & Jev AI Assessment    │ Review investigation dossier; explain Jev's role       │
│ 08:00   │ Remediation & Verification    │ Apply Postfix fix; run active probe → VerifiedFixed    │
│ 09:30   │ Multi-Format Reporting        │ Download PDF/HTML dossier; highlight byte-exact match  │
└─────────┴───────────────────────────────┴────────────────────────────────────────────────────────┘
```

#### Detailed Stage Breakdown:

1. **Stage 1: Opening & Problem Statement Presentation**
   - **Action**: Open `https://mailent.onrender.com`.
   - **Talking Point**: "Governments and enterprises communicate over email, but silent cryptographic decay—TLS 1.0, missing STARTTLS, static RSA without forward secrecy, and expired certificates—leaves communications open to interception. Mailent solves this with passive forensics, continuous monitoring, and verified remediation."
   - **Component**: Editorial Landing Page (`apps/web/src/LandingPage.tsx`).

2. **Stage 2: Passive PCAP Forensic Analysis**
   - **Action**: Navigate to `/workspace/overview`, click **+ Analyze capture**, choose `fixtures/pcap/smtp_legacy.pcap`.
   - **Visible Result**:
     - Status: `Complete`.
     - Score: `25/100` (Grade: `Critical`).
     - Findings: `TLS_LEGACY_VERSION` (Critical), `NO_FORWARD_SECRECY` (High), `CERTIFICATE_EXPIRED` (High).
     - AI Risk Triage: `CRITICAL` risk with human review recommended.
   - **Component**: Zeek Forensics Engine + Policy Evaluator (`apps/core/src/api/assessments.rs`).

3. **Stage 3: Protocol Timeline & Evidence Ladder**
   - **Action**: Click on the analyzed SMTP session.
   - **Visible Result**: Expand connection stages showing `tcp_connected` → `ehlo` → `starttls_advertised` → `starttls_accepted` → `tls_established`. Show leaf certificate details (`CN=mail.mailent.test`, expired `2021-01-01`).
   - **Component**: ProtocolLadder (`apps/web/src/components/ProtocolLadder.tsx`).

4. **Stage 4: Connected Companion & Live Domain Assessment**
   - **Action**: In the terminal on the ThinkPad, run `mailent doctor` and show the running companion daemon (`mailent companion status`). In the web console, click **Scan infrastructure**, enter `mailent.test`, and run the check through the ThinkPad companion.
   - **Visible Result**: The ThinkPad companion leases the job, connects locally to Postfix on port 25, extracts STARTTLS and DNS policies, and syncs the assessment back to the cloud console over HTTPS.
   - **Component**: Connected Companion Daemon (`apps/cli/src/companion.rs`) + Scanner (`crates/scanner`).

5. **Stage 5: Live Cryptographic Regression & Drift Detection**
   - **Action**: On the ThinkPad Postfix lab, simulate an adversary or misconfiguration by disabling STARTTLS:
     ```sh
     podman exec mailent-probe-lab postconf -e "smtpd_tls_security_level = none"
     podman exec mailent-probe-lab postfix reload
     ```
     Trigger a scan via the web UI or wait for the monitor.
   - **Visible Result**:
     - New Finding: `STARTTLS_MISSING` (High severity).
     - New Drift Event: `TlsDegradation` detected.
     - New Incident: Automatically creates an **Investigation** dossier flagged for high-priority review.
   - **Component**: Drift Engine (`crates/storage/src/postgres.rs`) + Scheduler (`apps/core/src/scheduler.rs`).

6. **Stage 6: Remediation & Active Transport Verification**
   - **Action**: Open the finding in the web UI, click **Start fix**. Re-enable STARTTLS on Postfix:
     ```sh
     podman exec mailent-probe-lab postconf -e "smtpd_tls_security_level = may"
     podman exec mailent-probe-lab postfix reload
     ```
     Click **Mark applied**, then click **Verify fix**.
   - **Visible Result**: Mailent's probe actively challenges Postfix port 25, receives the STARTTLS advertisement, completes TLS negotiation, and transitions the state to **`VerifiedFixed`**.
   - **Component**: Remediation Lifecycle (`apps/core/src/remediation.rs`) + Scoped Prober (`apps/probe`).

7. **Stage 7: Multi-Format Forensic Dossier Export**
   - **Action**: Click **Export** → download **PDF**, **HTML**, and **JSON**.
   - **Visible Result**: Open the generated PDF and HTML reports side-by-side to demonstrate byte-exact content parity, complete provenance markers (`[PASSIVE CAPTURE]`, `[ACTIVE PROBE]`), and cryptographic hashes.
   - **Component**: Reporting Engine (`crates/reporting/src/export.rs`).

---

## 13. SIH26159 Problem Statement Mapping Matrix

| SIH26159 Requirement | Mailent Implementation & Source Location | Direct Req vs Extension |
| :--- | :--- | :--- |
| **Passive analysis of SMTP, IMAP, POP3 traffic from PCAP** | Zeek DPD analyzers in `zeek/mailent/__load__.zeek` + `apps/sensor/src/normalize.rs` | **Direct Requirement** |
| **Reconstruction of complete TCP communication streams** | Stream reassembly via Zeek 8 engine + flow normalizer in `crates/domain/src/flow.rs` | **Direct Requirement** |
| **Parsing and reconstruction of TLS handshakes** | Normalization of ClientHello, ServerHello, ciphers, and alerts in `apps/sensor/src/normalize.rs` | **Direct Requirement** |
| **STARTTLS / STLS negotiation & transition detection** | Explicit state tracking (`starttls_advertised`, `accepted`, `rejected`, `plaintext_continuation`) in `zeek/mailent/__load__.zeek` | **Direct Requirement** |
| **X.509 digital certificate extraction** | DER parsing, SAN extraction, SHA-256 fingerprinting in `apps/sensor/src/normalize.rs` | **Direct Requirement** |
| **Certificate chain validation** | Passive chain validation via Zeek `validate-certs.zeek` against Mozilla CA root store | **Direct Requirement** |
| **Detection of deprecated protocols & weak cipher suites** | Deterministic policies for TLS 1.0/1.1, static RSA, CBC ciphers in `crates/policy/src/evaluator.rs` | **Direct Requirement** |
| **Forward Secrecy assessment** | Evaluation of ephemeral ECDHE/DHE vs static RSA in `crates/domain/src/tls.rs` | **Direct Requirement** |
| **Cryptographic feature extraction for AI analysis** | Extraction of structured `TrainingFeatures` vector in `crates/domain/src/training.rs` | **Direct Requirement** |
| **AI/ML risk classification & anomaly detection** | Jev AI decision engine integration in `crates/decision/src/jev.rs` with circuit breaker and fallback | **Direct Requirement** |
| **Security posture scoring & prioritization** | Versioned 1.0.0 composite 0–100 scoring model with category caps in `crates/correlation/src/posture.rs` | **Direct Requirement** |
| **Recommendation of mitigation measures** | Rule-specific remediation instructions and RFC citations in `crates/correlation/src/guidance.rs` | **Direct Requirement** |
| **Exportable forensic reports (JSON, PDF, HTML)** | Native PDF-1.4 writer, standalone HTML, and JSON dossier exporter in `crates/reporting/src/export.rs` | **Direct Requirement** |
| **Interactive visualization dashboard** | React 19 web console with protocol ladder, session timeline, and asset inventory in `apps/web` | **Direct Requirement** |
| **Continuous live wire sniffing** | Live network tap mode (`mailent monitor` / `mailent-sensor listen`) with spooling buffer | *Mailent Extension* |
| **Active infrastructure discovery (MTA-STS, DANE, TLS-RPT)** | Active domain scanner checking DNSSEC, MTA-STS, TLSA, and TLS-RPT in `crates/scanner` | *Mailent Extension* |
| **Connected Device Agents for Port-25 egress bypass** | Distributed agent daemon leasing typed jobs to bypass cloud egress limits in `apps/cli/src/agent.rs` | *Mailent Extension* |
| **Verifiable Remediation Lifecycle** | Append-only fix tracking with active socket verification challenges in `crates/domain/src/remediation.rs` | *Mailent Extension* |
| **Cryptographic Configuration Drift Tracking** | Real-time detection of rotated certs, lost forward secrecy, and protocol downgrades | *Mailent Extension* |

---

## 14. Real-World Limitations & Constraints

1. **Cloud Outbound Port 25 Blocking**:
   - *Limitation*: Major cloud providers (Render, AWS, GCP, Azure) block outbound TCP port 25 to prevent spam. Direct scans initiated from cloud containers to port 25 will fail or timeout.
   - *Mailent Solution*: **Connected Local Companions**. Local machines or on-premise servers enroll as companions (`mailent companion install` or `mailent companion run`), lease scan jobs from the cloud control plane, execute scans locally on unrestricted networks, and sync results back over HTTPS.
2. **TLS 1.3 Passive Certificate Encryption**:
   - *Limitation*: In the TLS 1.3 specification (RFC 8446), the server certificate is encrypted on the wire during the handshake. In passive PCAP captures of TLS 1.3 sessions, the leaf certificate cannot be extracted or validated unless observed via cleartext STARTTLS negotiation or active probing.
   - *Impact*: Mailent honestly reports certificate fields as `NotCaptured` in pure TLS 1.3 passive captures rather than guessing or fabricating certificate data.
3. **Windows Live Wire Sniffing Constraints**:
   - *Limitation*: Zeek requires raw packet socket privileges and native Linux AF_PACKET drivers to perform live promiscuous interface sniffing. The Windows container runner uses `--network none`.
   - *Impact*: Live network tapping (`mailent monitor`) requires native Linux or WSL2. However, **PCAP forensic analysis (`mailent analyze`) and domain scanning (`mailent scan`) work natively on Windows**.

---

## 15. Testing, Verification & Evidence Catalog

### 15.1 Confirmed Test Suites
All test suites have been verified clean against commit `4f1fc35`:

1. **Rust Workspace Suite (`cargo test --workspace`)**:
   - **Result**: All tests passed (0 failures across all 14 crates and binaries).
2. **Adversarial PCAP Suite (`apps/sensor/tests/adversarial_pcaps.rs`)**:
   - **Result**: 13/13 passed. Covers IPv6 SMTP, unencrypted IMAP, POP3 STLS rejections, corrupted packet headers, non-mail HTTP/SSH on port 25, mid-handshake RSTs, huge 32KB greetings, VLAN-tagged frames, out-of-order TCP streams, and endian variants.
3. **Captures & RFC Policy Suite (`apps/sensor/tests/captures.rs`)**:
   - **Result**: 7/7 passed. Validates real PCAPs: `smtp_legacy.pcap`, `smtp_starttls.pcapng`, `imap_starttls.pcap`, `pop3_stls.pcap`, `imap_tls13.pcap`.
4. **Agent, Monitoring & Multi-Tenant Isolation (`apps/core/tests/`)**:
   - **Result**: Passed. Covers agent heartbeats, multi-tenant isolation, job leasing race conditions, lease expiration recovery, monitor creation, and historical drift detection.
5. **Storage & Database Integration Suite (`crates/storage/tests/`)**:
   - **Result**: Passed. Validates PostgreSQL 18 and ClickHouse 24.8 integration, conflict handling, and reconnection survivability.
6. **Frontend Test Suite (Vitest: `pnpm --filter @mailent/web test`)**:
   - **Result**: 19/19 passed. Covers protocol ladder evidence rendering, copy validation, installer command copying, and core application rendering.
7. **Production Build Suite**:
   - **Result**: Passed. `pnpm --filter @mailent/web typecheck` (0 TypeScript errors) and `vite build` completed successfully.

---

## 16. Compact ChatGPT Context

```text
=== BEGIN MAILENT CANONICAL BRIEFING ===
PRODUCT: Mailent (v0.1.4, feature-complete, GPL-3.0)
PURPOSE: AI-assisted passive network forensics and continuous transport security platform for enterprise email (SMTP, IMAP, POP3). Built for SIH problem statement SIH26159.
TECH STACK: Rust 2024 (Axum, Tokio, SQLx, Tower), Zeek 8.0.4+ (custom mailent package), React 19 + TypeScript + Vite, PostgreSQL 18 (Supabase) + optional ClickHouse, Jev AI (Codiv API).
DEPLOYMENT: Live on Render (Singapore) + Supabase PostgreSQL; CLI distributed for Linux and Windows x86_64.

CORE CAPABILITIES:
1. Passive PCAP/PCAPNG Forensics: Uses Zeek to reassemble TCP, reconstruct SMTP/IMAP/POP3 sessions, track STARTTLS/STLS state transitions, parse TLS handshakes (1.0-1.3, ciphers, PFS), extract X.509 certs, and passively validate cert chains.
2. Active Domain Infrastructure Scanner: Resolves MX (with RFC 5321 fallback), SRV, MTA-STS, DANE/TLSA, TLS-RPT, and DNSSEC; probes ports 25, 465, 587, 143, 993, 110, 995 for STARTTLS/ciphers/certs.
3. Continuous Live Wire Monitoring: Zeek interface sniffing with bounded memory/disk spooling (/tmp/mailent-spool) and real-time cryptographic drift detection.
4. Deterministic Policy Engine: Evaluates compliance against RFC 8996 (legacy TLS), RFC 5280 (expired certs), BCP 195 (forward secrecy/static RSA), and RFC 3207 (STARTTLS).
5. Posture Scoring: Version 1.0.0 composite 0-100 score across 4 weighted categories (Transport 40%, Certs 25%, Protocol 25%, Anomaly 10%). Critical/High findings strictly cap overall scores (Critical <= 29, High <= 60). Grades: Strong, Good, Moderate, Weak, Critical.
6. Jev AI Decision Engine: Contextual risk classification (Low, Medium, High, Critical), anomaly detection, and triage priority. Uses openjev-latest via Codiv with circuit breaker (3 fails, 30s open) and deterministic fallback. NEVER alters cryptographic facts or posture scores.
7. Connected Local Companions: CLI background companion ('mailent companion') leases typed jobs from Core to execute scans locally and exposes loopback bridge (http://127.0.0.1:15488) for local browser capture analysis.
8. Verifiable Remediation Lifecycle: Tracks fixes from InProgress -> Applied -> Verifying -> VerifiedFixed / StillPresent / Inconclusive via active socket challenge probes.
9. Reporting: Exports byte-deterministic forensic dossiers in JSON, standalone HTML, and native binary PDF-1.4.
10. Training Data Collection: Freezes versioned feature snapshots ('TrainingRecord') at decision time with privacy redactions for offline ML evaluation and benchmarking.

TRUST MODEL:
Raw Evidence -> Zeek Normalization -> Deterministic Policy Findings -> Baselines/Drift -> Deterministic Posture -> Jev AI Contextual Triage -> Analyst Remediation & Active Probe Verification.

CLI COMMANDS:
mailent analyze <pcap> [--format table|json] [--sync]
mailent scan <domain> [--format table|json] [--sync]
mailent monitor --interface <iface>
mailent login / status / logout
mailent companion install / start / stop / status / run
mailent doctor

AUTHENTICATION & MULTI-TENANCY:
Supabase JWT auth, device challenges (MLT-XXXX), SHA-256 hashed device tokens ('mlt_...'), immediate revocation with active job cancellation, DualStorage routing guest requests (X-Mailent-Guest) to ephemeral in-memory storage.

REAL LIMITATIONS:
- Cloud port 25 blocked by cloud hosts -> Solved by Connected Device Agents on local networks.
- TLS 1.3 encrypts certs on wire -> Passive PCAP reports certs as NotCaptured unless seen in cleartext/probed.
- Windows live interface sniffing requires Linux/WSL2; Windows CLI fully supports PCAP analysis and domain scans.
=== END MAILENT CANONICAL BRIEFING ===
```
