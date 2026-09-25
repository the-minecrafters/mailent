# Mailent

**AI-Assisted Passive Network Forensics & Continuous Transport Security Platform**  
*Built for SIH Problem Statement SIH26159*

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Rust 2024](https://img.shields.io/badge/Rust-2024_Edition-orange.svg)](Cargo.toml)
[![Zeek 8+](https://img.shields.io/badge/Zeek-8.0.4%2B-purple.svg)](zeek/mailent)
[![TypeScript / React 19](https://img.shields.io/badge/Frontend-React_19_%2B_Vite-cyan.svg)](apps/web)
[![Deployment: Render + Supabase](https://img.shields.io/badge/Deployed-Render_%2B_Supabase-emerald.svg)](https://mailent.onrender.com)

Mailent is an enterprise-grade cryptographic security platform designed for Security Operations Centers (SOC), incident response teams, and mail administrators. It reconstructs and evaluates the transport security posture of email communications across SMTP, IMAP, and POP3.

Mailent combines **passive network forensics (PCAP/PCAPNG inspection via Zeek)**, **active mail infrastructure probing (MX, STARTTLS, MTA-STS, DANE, TLS-RPT)**, **continuous live wire monitoring**, **cryptographic drift tracking**, **remediation verification**, and **contextual AI risk triage via Jev**.

---

## Live Deployment & Quick Links

- **Web Console**: [https://mailent.onrender.com](https://mailent.onrender.com)
- **GitHub Repository**: [https://github.com/the-minecrafters/mailent](https://github.com/the-minecrafters/mailent)
- **Comprehensive Technical Guide**: [docs/MAILENT_COMPLETE_GUIDE.md](docs/MAILENT_COMPLETE_GUIDE.md)
- **CLI Reference & Setup**: [docs/cli.md](docs/cli.md)
- **Remediation & Fix Verification**: [docs/remediation.md](docs/remediation.md)

---

## Why Mailent Exists

Electronic mail remains the backbone of enterprise, government, and financial communication. Despite widespread TLS adoption, email infrastructures frequently suffer from critical cryptographic misconfigurations:

- **Obsolete TLS Protocols**: Lingering TLS 1.0 and TLS 1.1 deployments vulnerable to BEAST, POODLE, and downgrade attacks (RFC 8996).
- **Weak Cipher Suites & Static RSA**: Ciphers lacking Ephemeral Diffie-Hellman (PFS), leaving historical traffic vulnerable to retroactive decryption if private keys are compromised.
- **Insecure or Broken STARTTLS**: Opportunistic TLS that is stripped or downgraded in-flight by network adversaries to plaintext.
- **Expired or Untrusted X.509 Certificates**: Invalid leaf certificates or broken certificate trust chains.
- **Missing Delivery Hardening**: Absence of MTA-STS (RFC 8461), DANE/TLSA (RFC 7672), or TLS-RPT (RFC 8460) reporting.

**The Visibility Problem**: Existing packet analyzers (e.g., Wireshark, tcpdump) decode packets at the wire level, but they do not automatically calculate cryptographic posture, track cross-session configuration drift, evaluate compliance against modern IETF standards, or provide actionable remediation workflows.

**Mailent's Solution**: A unified forensic platform that passively reconstructs email sessions from raw packets, executes deterministic policy evaluations, detects configuration drift and anomalies, delivers contextual AI risk analysis, and verifies remediation actions with active cryptographic challenges.

---

## Major Capabilities

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               MAILENT PLATFORM                                  │
├───────────────────────────────┬─────────────────────────────────────────────────┤
│ 1. Passive PCAP Forensics     │ Reconstructs full TCP streams, STARTTLS/STLS,   │
│                               │ TLS handshakes, ciphers, and X.509 chains.      │
├───────────────────────────────┼─────────────────────────────────────────────────┤
│ 2. Infrastructure Assessment  │ Discovers MX/SRV endpoints, tests STARTTLS,     │
│                               │ verifies MTA-STS, DANE/TLSA, TLS-RPT, & DNSSEC. │
├───────────────────────────────┼─────────────────────────────────────────────────┤
│ 3. Continuous Wire Monitoring │ Runs live Zeek taps on mail gateways, streaming │
│                               │ normalized connection evidence to your console. │
├───────────────────────────────┼─────────────────────────────────────────────────┤
│ 4. Deterministic Policies     │ Verifies compliance against RFC 8996, RFC 8461, │
│                               │ RFC 5280, RFC 3207; zero AI hallucinations.     │
├───────────────────────────────┼─────────────────────────────────────────────────┤
│ 5. Cryptographic Drift        │ Automatically detects changes in TLS versions,  │
│                               │ cipher suites, certificate fingerprints, or PFS.│
├───────────────────────────────┼─────────────────────────────────────────────────┤
│ 6. Connected Device Agents    │ Enlists on-premise hosts to scan mail servers   │
│                               │ locally, bypassing cloud port-25 egress blocks. │
├───────────────────────────────┼─────────────────────────────────────────────────┤
│ 7. Remediation Lifecycle      │ Tracks fixes through an append-only lifecycle:  │
│                               │ InProgress → Applied → Verifying → VerifiedFixed│
├───────────────────────────────┼─────────────────────────────────────────────────┤
│ 8. Jev Contextual AI Triage   │ Evaluates structured findings for risk levels,  │
│                               │ anomalous behavior, and triage priority.        │
├───────────────────────────────┼─────────────────────────────────────────────────┤
│ 9. Multi-Format Dossiers      │ Exports identical, byte-deterministic forensic  │
│                               │ reports in JSON, standalone HTML, and PDF.      │
└───────────────────────────────┴─────────────────────────────────────────────────┘
```

---

## The Mailent Trust Model

Mailent maintains a strict separation between **objective cryptographic facts** and **probabilistic AI triage**:

```text
[ Raw Packets / Wire Traffic / Active Probes ]
                       │
                       ▼
         [ Zeek Protocol Normalization ]
    (Extracts handshakes, certs, ciphers, gaps)
                       │
                       ▼
     [ Deterministic Policy Engine (Rust) ]
   (RFC 8996, RFC 5280, RFC 8461, RFC 3207 rules)
                       │
                       ▼
       [ Baseline & Drift Event Detection ]
 (Unseen ciphers, PFS lost, cert rotated, anomalies)
                       │
                       ▼
        [ Deterministic Posture Scoring ]
 (Composite 0-100 score, weighted categories, caps)
                       │
                       ▼
     [ Jev Contextual AI Assessment (LLM) ]
  (Risk level, triage priority, anomaly explanation)
                       │
                       ▼
      [ Security Analyst / Incident Response ]
   (Investigation review, fix application, probe verification)
```

> **Key Architectural Guarantee**: The Jev AI engine **never** determines whether a cipher is weak, whether a certificate is expired, or whether STARTTLS failed. Objective security facts and numeric posture scores are computed entirely by deterministic Rust algorithms and Zeek parsers. Jev acts solely as a high-level triage assistant for risk prioritization and operational context.

---

## Architecture & Technology Stack

- **Backend / Core Engine**: Rust (2024 edition, Rust 1.94+), Axum 0.8, Tokio, SQLx, Tower-HTTP, Protobuf (prost).
- **Network Forensic Engine**: Zeek 8.0.4+ with custom Mailent package (`zeek/mailent/__load__.zeek`) for deep state-machine tracking of SMTP, IMAP, and POP3 STARTTLS negotiations and passive X.509 certificate validation (`validate-certs.zeek`).
- **Frontend Console**: React 19, TypeScript, Vite, Tailwind CSS, Radix UI primitives, Lucide icons.
- **Persistence Layer**:
  - **PostgreSQL 18** (Supabase in production): Relational control plane, multi-tenancy, asset inventories, policy findings, drift events, investigations, remediations, and agent jobs.
  - **ClickHouse 24.8** (Optional): High-throughput analytical telemetry for immutable connection logs.
  - **DualStorage Engine**: Thread-safe in-memory fallback for ephemeral guest analysis without database setup.
- **CLI & Agent Daemon**: Unified `mailent` binary with embedded subcommands for analysis, scanning, live sniffing, system diagnostics, and background systemd service management.
- **Container Infrastructure**: Production multi-stage Dockerfile built on `zeek/zeek:8.0.4`.

---

## CLI Installation & Quick Start

### 1. Install via One-Line Script

**Linux x86_64** (Ubuntu 22.04+, Debian 12+, Fedora, Arch):
```sh
curl -fsSL https://mailent.onrender.com/install.sh | bash
```

**Windows x86_64** (PowerShell):
```powershell
irm https://mailent.onrender.com/install.ps1 | iex
```

The installer verifies SHA-256 release checksums, checks for Zeek 8+ (or Docker/Podman container runtime), and installs the binary to `~/.local/bin` (or `C:\Users\<user>\.mailent\bin`).

### 2. Verify Installation

```sh
mailent --version
mailent doctor
```

`mailent doctor` checks your local environment for:
- Zeek forensic engine availability
- Container runtime status (Podman / Docker)
- Network capture capabilities
- Connectivity to Mailent Core
- Active workspace authentication status

---

## Common CLI Workflows

### Analyze a Capture File (PCAP / PCAPNG)
Passively inspect an existing packet capture and output structured findings:
```sh
# Render formatted terminal tables
mailent analyze capture.pcapng

# Output raw forensic JSON and generate HTML/PDF dossiers
mailent analyze capture.pcap --format json --output-dir ./reports

# Analyze and sync results to your cloud workspace
mailent analyze capture.pcap --sync
```

### Scan a Live Mail Domain
Actively check DNS (MX, SRV, MTA-STS, DANE, TLS-RPT) and probe mail servers:
```sh
mailent scan example.com

# Sync results to workspace
mailent scan example.com --sync
```

### Connect Device to Your Workspace
```sh
# Initiates terminal device authorization challenge (e.g. MLT-AB12CD34)
mailent login --server https://mailent.onrender.com

# View connection status
mailent status

# Revoke credentials and logout
mailent logout
```

### Run as a Continuous Monitoring Agent
Deploy the background agent on an on-premise mail server or test machine:
```sh
# Install as a systemd user service
mailent agent install

# Start the background service
mailent agent start

# Inspect service state and lease heartbeat
mailent agent status

# Or run directly in the foreground
mailent agent run --poll-interval 5
```

### Sniff Live Wire Traffic
Monitor live traffic on a mail gateway network tap:
```sh
sudo mailent monitor --interface eth0
```

### Safely Remediate Mail Server Findings (`mailent fix`)
Apply deterministic, safety-guaranteed configuration fixes to local Postfix and Dovecot installations:
```sh
# 1. Preview changes, safety checks, and active verification steps (zero mutation dry-run)
mailent fix TLS_LEGACY_VERSION --plan

# 2. Apply fix with automatic timestamped backup, syntax check, reload, & active challenge probe
sudo mailent fix TLS_LEGACY_VERSION

# 3. Apply fix and sync remediation record and verification evidence to workspace
sudo mailent fix TLS_LEGACY_VERSION --sync

# 4. Instant one-command rollback if needed
sudo mailent fix --rollback /etc/postfix/main.cf.mailent-backup-20260925T...
```

---

## Local Development Setup

### Prerequisites
- **Rust**: 1.94+ (2024 edition)
- **Node.js**: 22+ & **pnpm**: 11.26.0+
- **Protobuf Compiler**: `protoc`
- **Zeek**: 8.0+ (native or via Podman/Docker)

### 1. Clone & Build
```sh
git clone https://github.com/the-minecrafters/mailent.git
cd mailent

# Build Rust workspace
cargo build --workspace

# Install frontend dependencies
pnpm install --frozen-lockfile
```

### 2. Run Mailent Core (Backend)
```sh
# Runs in lightweight ephemeral mode (no external database required)
cargo run -p mailent-core
```
*Core listens on `http://127.0.0.1:8080`.*

### 3. Run Web Console (Frontend)
```sh
pnpm --filter @mailent/web dev
```
*Web console opens on `http://127.0.0.1:5173` with an automatic Vite API proxy to `:8080`.*

---

## Testing & Verification

The Mailent test suite covers unit tests, integration slices, real lab environments, and edge-case PCAPs:

```sh
# 1. Run all workspace Rust tests
cargo test --workspace

# 2. Run adversarial PCAP suite (IPv6, truncated, VLAN, packet injections)
cargo test -p mailent-sensor --test adversarial_pcaps

# 3. Run multi-tenant API and device revocation integration tests
cargo test -p mailent-core --test multi_tenant_api
cargo test -p mailent-core --test verification_review

# 4. Run frontend test suite (Vitest)
pnpm --filter @mailent/web test

# 5. Typecheck & production frontend build
pnpm --filter @mailent/web typecheck
pnpm --filter @mailent/web build
```

---

## Production Deployment (Render + Supabase)

Mailent is deployed in production using a containerized microservice architecture:

- **Compute**: Render Web Service (`render.yaml`) running Docker image built from `Dockerfile` on `zeek/zeek:8.0.4`.
- **Database**: Supabase PostgreSQL 18 in Singapore region (`vuskxbttfmmyxpqudjwv.supabase.co`).
  - Isolated under a dedicated `mailent` database schema with Row Level Security (RLS) enabled.
  - SQL migrations managed through `supabase/migrations/`.
- **Egress Workaround**: Because cloud platforms (including Render, AWS, and GCP) block outbound TCP port 25, Mailent utilizes **Connected Device Agents**. An operator connects a local machine or server using `mailent login` and `mailent agent install`. Scheduled checks are leased and executed locally by the agent, returning full cryptographic results over HTTPS.

---

## Environment Variables & Configuration

Key configuration parameters (see `.env.example`):

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `MAILENT_CORE_HOST` | `127.0.0.1` | Binding host address |
| `MAILENT_CORE_PORT` | `8080` | Binding HTTP port |
| `MAILENT_DATABASE_URL` | *(empty)* | PostgreSQL connection string (in-memory mode if unset) |
| `MAILENT_DATABASE_SCHEMA` | `mailent` | PostgreSQL target schema |
| `MAILENT_CLICKHOUSE_URL` | *(empty)* | Optional ClickHouse URL for high-volume telemetry |
| `MAILENT_ZEEK` | `zeek` | Path to Zeek executable or wrapper script |
| `MAILENT_SENSOR_BIN` | `mailent-sensor`| Path to compiled `mailent-sensor` binary |
| `MAILENT_JEV_ENABLED` | `true` | Toggle Jev AI triage integration |
| `MAILENT_JEV_BASE_URL` | `https://api.codiv.ai` | Jev / Codiv API endpoint |
| `MAILENT_JEV_MODEL` | `openjev-latest` | Decision engine model identifier |
| `MAILENT_JEV_API_KEY` | *(empty)* | API key for Jev AI decision engine |
| `MAILENT_PROBE_ALLOWED_DOMAINS` | `*` | Scoped domain/IP authorization list for active probes |

---

## Important Constraints & Environment Boundaries

1. **Port 25 Egress**: Cloud hosting providers block outbound TCP port 25. Cloud-initiated domain checks will report port 25 as unreachable unless run through an authorized **Connected Device Agent**.
2. **TLS 1.3 Passive Visibility**: In TLS 1.3, server certificates and handshake parameters are encrypted on the wire. Passive PCAP analysis extracts SNI, negotiated versions, and cipher suites, but cannot validate encrypted certificate chains unless certificates are observed in cleartext (e.g. TLS 1.2 or active probing).
3. **Windows Live Sniffing**: Live network packet sniffing via Zeek requires native Linux raw socket privileges or WSL2. The Windows CLI natively supports PCAP forensic analysis and domain scanning.

---

## Documentation Index

- [Canonical Mailent A-to-Z Guide](docs/MAILENT_COMPLETE_GUIDE.md) — Comprehensive technical guide, architecture diagrams, data models, SIH mapping, and ChatGPT briefing context.
- [CLI Reference Manual](docs/cli.md) — Detailed terminal command guide and service installation.
- [Remediation & Fix Verification](docs/remediation.md) — Remediation lifecycle and probe verification specifications.
- [Project Showcase Walkthrough](SHOWCASE.md) — Evaluator demo script and PCAP fixtures guide.
