# Mailent

> Passive cryptographic observability, posture management, and forensic intelligence for enterprise email.

Mailent is a security platform for continuously assessing how SMTP, IMAP, POP3 and their TLS/STARTTLS transports are actually secured in production.

It combines passive network evidence, DNS/mail-security policy, certificate intelligence, historical baselines, deterministic cryptographic rules, and constrained AI decisions to answer:

- what email infrastructure exists?
- how is it cryptographically protected?
- what is weak, broken, or misconfigured?
- what changed?
- what is anomalous?
- what requires analyst attention first?
- what would break if we enforce a stronger policy?

Mailent is not a packet viewer with an AI summary. It is a persistent security control plane for email cryptography.

## problem statement

Built for **SIH26159 — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**.

The original requirement focuses on passive PCAP analysis of SMTP, IMAP and POP3. Mailent broadens that into a production-grade platform while preserving the required forensic workflow.

## operating model

Mailent supports four complementary modes:

### 1. continuous passive monitoring

```text
TAP / SPAN / mirror
        ↓
   Mailent Sensor
        ↓
 SMTP / IMAP / POP3
 STARTTLS / TLS / X.509
        ↓
 central posture engine
```

No active interference with production mail traffic is required.

### 2. offline forensics

```text
PCAP / PCAPNG
      ↓
same analysis pipeline
      ↓
sessions + evidence + findings + report
```

Historical captures can be imported manually or discovered from monitored evidence storage.

### 3. external security intelligence

Mailent correlates passive observations with:

- MTA-STS policy
- DANE/TLSA and DNSSEC state
- SMTP TLS Reporting (TLS-RPT)
- REQUIRETLS readiness
- Certificate Transparency
- controlled external TLS/MX probes
- current cryptographic standards and policy packs

This lets Mailent distinguish "the session looked encrypted" from "the transport is actually downgrade-resistant and policy-compliant."

### 4. cryptographic change simulation

Mailent can replay historical observations against a proposed future policy.

Example:

```text
proposed:
- require TLS 1.3
- require forward secrecy
- reject static RSA
- require valid MTA-STS/DANE
- prefer X25519MLKEM768

historical replay:
2,431,844 sessions evaluated
2,384,021 compatible
47,823 would fail

affected:
- legacy-relay-03
- scanner-gateway-02
- partner.example
```

This is the **Crypto Digital Twin**.

## core pipeline

```text
network / PCAP / external signals
              ↓
      protocol reconstruction
              ↓
      normalized observations
              ↓
     deterministic policy engine
              ↓
       historical baselines
              ↓
 anomaly + configuration drift
              ↓
       Jev decision layer
              ↓
 findings / investigations / posture
              ↓
 SIEM / dashboard / reports / alerts
```

## trust model

Mailent separates four things deliberately:

```text
Observed Fact
    ↓
Policy Finding
    ↓
Behavioral Context
    ↓
AI Decision
```

Example:

```text
Observed:
TLS 1.2 + static RSA key exchange

Policy:
Forward Secrecy unavailable

Baseline:
static RSA appeared in 0.2% of this server's sessions

Jev:
anomalous = 0.96
human_review = YES
priority = HIGH
```

Jev does not decide whether TLS 1.0 is deprecated or whether a certificate is expired. Those are deterministic facts.

## key product surfaces

- organization posture
- assets and discovered mail infrastructure
- live sessions
- offline forensic cases
- findings
- anomalies
- certificates and certificate history
- cryptographic inventory
- STARTTLS analysis
- MTA-STS / DANE / TLS-RPT posture
- policy simulation
- investigations
- historical trends
- reports
- integrations
- policy packs

## deployment modes

### workstation

Single machine for forensic PCAP analysis.

### enterprise node

Central server with continuous ingestion and multiple analysts.

### distributed

Multiple passive sensors feeding one control plane.

### air-gapped

Core parsing, rules, baselines, reporting and local analysis work without Internet access. External intelligence and Jev are optional adapters.

## non-goals

Mailent is not intended to:

- decrypt protected email bodies
- bypass TLS or endpoint encryption
- replace Wireshark for arbitrary packet debugging
- become a mail server
- automatically mutate production MTA configuration without explicit operator action
- let an LLM invent cryptographic policy
- retain credentials or email contents when metadata is sufficient

## product principles

1. **evidence first** — every security conclusion is traceable.
2. **passive by default** — observe production safely.
3. **AI is advisory and constrained** — deterministic rules remain authoritative.
4. **persistent context** — assets, certificates, baselines and changes matter more than isolated captures.
5. **local-first security** — raw packet data stays local unless explicitly exported.
6. **single-node friendly, distributed when needed** — no mandatory distributed-systems tax for small deployments.
7. **standards-aware** — policy evolves independently from packet parsing.
8. **fast enough for continuous use** — high-cardinality session data belongs in an analytical store, not an ORM-shaped bottleneck.

## success state

A production Mailent deployment should be able to continuously discover email infrastructure, reconstruct transport security behavior, detect deterministic cryptographic weaknesses, identify drift and anomalies, correlate external transport policy, simulate stronger future policy, prioritize investigations, and produce defensible evidence without requiring analysts to inspect every TLS handshake manually.
