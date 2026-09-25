# Remediation and transport fix verification

Remediation is attached to an existing deterministic finding and one captured
session. The record keeps the original `Finding`, `EmailSession`, and guidance;
active results are separate `ProbeRun` snapshots. The lifecycle is in progress →
applied → verifying → verified fixed / still present / inconclusive. Each request
has a client UUID, so retrying that request never starts another network operation.
A new request can reverify after the existing per-target cooldown.

The guidance card on asset/session details provides the workflow. Investigation
details, posture responses and JSON/HTML/PDF reports include the same lifecycle.
Historical findings and posture remain visible after a fix; a point-in-time probe
does not establish global health. Only the analyst changes investigation status.
Best-practice guidance has no remediation finding or automatic fix claim.

## Verification conditions

- `CERTIFICATE_EXPIRED`: the same endpoint must present a currently valid leaf
  with verified identity and trust chain. A new fingerprint alone is insufficient.
- `TLS_LEGACY_VERSION`: establish modern TLS, then explicitly challenge TLS 1.0
  and TLS 1.1 with the existing authorized probe. Both must return a server
  protocol-version alert. Local OpenSSL limitations, reset/EOF, timeout and
  generic handshake failures are inconclusive. One accepted legacy handshake
  establishes that the issue is still present.
- `STARTTLS_MISSING`: an explicit captured SMTP capability exchange lacking
  STARTTLS produces the modern policy 1.1.0 finding. Verification requires
  advertisement, acceptance and completed TLS at the same endpoint. Missing
  capture data is unknown, not a finding. This verifies availability, not a
  server's refusal to deliver plaintext mail.
- `NO_FORWARD_SECRECY`: a preferred ECDHE handshake cannot prove static RSA
  support is disabled. The lifecycle retains the probe but reports inconclusive;
  constrained cipher refusal verification is not implemented.

No authentication or mail delivery occurs. Scope validation precedes DNS/TCP.
Legacy verification uses at most three bounded connections inside one reserved
probe job. Authorization, concurrency, cooldown and deduplication are shared with
ordinary probes. An address change makes verification inconclusive for the
original endpoint. DANE/MTA-STS context remains the existing cached expectation;
this slice does not verify their remediation conditions.

## Persistence and recovery

Postgres migration `20260923000003_remediation.sql` adds lifecycle records and
links existing probes and training records. Updates use revision comparisons;
probe results persist before their derived lifecycle outcome. Recovery applies
persisted results without repeating network operations. Interrupted work becomes
inconclusive. Before snapshots and completed attempts remain available.

Training feature snapshots and automated labels are immutable. Final remediation
outcomes are separate typed labels keyed by verification request, attached only
to matching investigation, asset, capture time, protocol, port and policy rule.
Analyst labels remain separate and are never replaced. No model training runs.

Posture/report code uses an owned request-scoped evidence snapshot. Reports of an
investigation load that exact investigation. Existing asset findings are linked
during ingestion; older unlinked findings are recovered from captured session
references. Replaying ingestion does not duplicate finding evidence or reset an
analyst's investigation status.

## Local verification

Use the existing disposable Postfix/Dovecot container, published on a loopback
port, with CAP_NET_RAW for its tcpdump capture. Do not run the rotation script on
a real mail server. These operations create only ephemeral lab keys/certificates
and temporary captures; committed packet fixtures are unchanged.

```sh
# Example existing container from the probe lab; its SMTP port is 12526.
podman cp fixtures/lab/rotate_certificate.py mailent-probe-evidence-lab:/tmp/rotate_certificate.py
podman cp fixtures/lab/record_probe.py mailent-probe-evidence-lab:/tmp/record_probe.py
podman exec mailent-probe-evidence-lab python3 /tmp/rotate_certificate.py expired
podman cp mailent-probe-evidence-lab:/tmp/remediation-ca.crt /tmp/mailent-remediation-ca.pem
# Use a fresh output filename on each capture (tcpdump drops privileges).
podman exec mailent-probe-evidence-lab python3 /tmp/record_probe.py /tmp/fix-before-1.pcap 12526 TLSv1.2
podman cp mailent-probe-evidence-lab:/tmp/fix-before-1.pcap /tmp/mailent-fix-before.pcap
cargo build -p mailent-core -p mailent-sensor
MAILENT_ZEEK="$PWD/scripts/zeek-container" target/debug/mailent-sensor analyze /tmp/mailent-fix-before.pcap --json > /tmp/mailent-fix-before.json

SSL_CERT_FILE=/tmp/mailent-remediation-ca.pem \
MAILENT_REQUIRE_DATABASES=1 \
MAILENT_REMEDIATION_CAPTURE=/tmp/mailent-fix-before.json \
MAILENT_REMEDIATION_LAB=mailent-probe-evidence-lab \
cargo test -p mailent-core --test remediation_lifecycle real_postfix_fix_cycle -- --ignored --nocapture
```

The real test first verifies the unchanged expired certificate, rotates it using
the same temporary CA, verifies the fix, recreates Core's application state and
checks persisted findings, attempts, investigation status, report and training
labels. It changes the lab to a valid certificate. Reset to expired and capture
again before the browser test:

```sh
SSL_CERT_FILE=/tmp/mailent-remediation-ca.pem \
MAILENT_REMEDIATION_CAPTURE=/tmp/mailent-fix-before.json \
MAILENT_REMEDIATION_LAB=mailent-probe-evidence-lab \
MAILENT_PROBE_ALLOWED_DOMAINS=127.0.0.1 \
MAILENT_PROBE_COOLDOWN_SECONDS=1 MAILENT_JEV_ENABLED=false \
pnpm --filter @mailent/web test:e2e remediation.spec.ts
```

The short cooldown is only for this controlled lab. The default is five minutes.
Database integration tests create fresh Postgres schemas and ClickHouse databases;
successful tests remove only their own test storage. A failed test can leave its
uniquely named `test_<uuid>` schema/database for debugging, but later runs never
reuse those rows. Set `MAILENT_REQUIRE_DATABASES=1` to make missing databases a
failure instead of skipping optional database tests.

## CLI Safe Remediation (`mailent fix`)

Mailent provides deterministic, CLI-first remediation for local Postfix and Dovecot mail servers. Instead of manual trial-and-error configuration editing, `mailent fix` applies validated changes atomically and verifies the outcome with active cryptographic challenges.

### Supported Auto-Fixes vs. Guided Remediation

- **`TLS_LEGACY_VERSION` (Supported - Auto-Fix)**:
  - **Postfix**: Updates `/etc/postfix/main.cf` parameters `smtpd_tls_protocols` and `smtpd_tls_mandatory_protocols` to `>=TLSv1.2, !SSLv2, !SSLv3, !TLSv1, !TLSv1.1`.
  - **Dovecot**: Updates `/etc/dovecot/dovecot.conf` parameter `ssl_min_protocol` to `TLSv1.2`.
  - **Verification**: Actively challenges TLS 1.0 and TLS 1.1 handshakes; both must receive explicit server protocol refusal alerts.
- **`STARTTLS_MISSING` (Conditional Auto-Fix)**:
  - If valid certificate and private key files exist on disk, configures `smtpd_tls_security_level = may`.
  - If no certificate is found, falls back to guided instructions (obtaining certificates via ACME/Certbot).
- **`CERTIFICATE_EXPIRED`, `NO_FORWARD_SECRECY`, `MTA_STS_POLICY_MISSING`, `DANE_MISSING` (Strictly Guided-Only)**:
  - Requires external CA issuance, DNS records, or PKI management. `mailent fix` outputs step-by-step administrative guidance without modifying local files.

### Safety Invariants

1. **Pre-Flight Plan (`--plan`)**: Always accessible without root or modifications to inspect the exact planned key-value diffs, validation command, and verification steps.
2. **Timestamped Backup**: Prior to any file alteration, an exact copy is preserved at `<config>.mailent-backup-<timestamp>`.
3. **Atomic Staging**: Writes are performed to a sibling temporary file, flushed to disk with `sync_all()`, and renamed atomically.
4. **Syntax Validation Before Reload**: Runs `postfix check` or `doveconf -n`. If syntax validation fails, the configuration is immediately rolled back to the backup without executing service reload.
5. **Active Challenge Verification**: Executes live handshake challenge probes against the target endpoint to establish `VerifiedFixed`, `StillPresent`, or `Inconclusive`.
6. **Workspace Sync (`--sync`)**: Posts the full `RemediationRecord` and active `ProbeRun` evidence to `/api/v1/remediations/sync` for team auditability and drift tracking.
7. **Manual Rollback**: At any time, restore a previous backup using `mailent fix --rollback <backup-path>`.

