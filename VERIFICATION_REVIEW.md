# Mailent verification — 24 September 2026

Reviewed checkout `98ad762` against `notes/problem_statement.md`, plus the user's mandatory Zeek, live monitoring, device revocation, guest sign-in, copy, and free-hosting requirements. This was verification, not an implementation or deployment pass. No product source was changed. Two isolated regression tests were added in `apps/core/tests/verification_review.rs`; both currently fail, documenting reproducible defects.

## Minimum-requirement assessment

| Required capability | Evidence and current result |
| --- | --- |
| Passive SMTP, IMAP, POP3 PCAP analysis and identification | Real Zeek fixture tests pass for these protocols, PCAP/PCAPNG, IPv6, VLAN, and nonstandard-port SMTP. This proves the covered fixtures, not all possible traffic. |
| TCP reconstruction and STARTTLS/TLS transitions | Parser tests cover out-of-order traffic, partial captures, upgrades, rejections, and direct TLS. New dashboard diagram incorrectly asserts some unobserved transitions succeeded; see finding 2. |
| TLS version, cipher, key exchange, Forward Secrecy and weak crypto detection | Existing policy/capture tests pass. Unknown values must remain unknown. No additional general standards-compliance certification was performed. |
| X.509 extraction, expiration, key and signature details | Extraction code and a real sample report verified; the sample correctly identifies an expired leaf certificate. |
| **Certificate chain validation from passive evidence** | **Incomplete.** `apps/sensor/src/normalize.rs:432` always sets `ChainValidation::NotVerified`. Active connection validation in `apps/probe/src/smtp.rs:283` does not validate the historical chain from the uploaded PCAP. Implement validation where the capture contains enough chain material and trust anchors; preserve unknown when it does not. |
| AI-assisted scoring, anomaly detection, prioritization and recommendations | Provider integration and deterministic fallback exist. This review did not perform a fresh external AI request or establish model quality. Capture context currently sends anomaly/drift counts; fallback reads `metadata.anomalies`, so the counts do not establish anomaly-aware fallback behavior. Do not equate a provider badge with verified end-to-end AI capability. |
| Comprehensive posture and prioritized findings | Present, but web upload and CLI use inconsistent score/risk calculations; see finding 4. |
| JSON, HTML, PDF reports | Actual CLI exports generated successfully for the sample. New web report route has a confirmed workspace-isolation defect; see finding 1. |
| Interactive dashboard | Production guest device gate verified. New protocol visualization exists in checkout but has evidence errors. Newest web changes are not deployed. |
| User additions: required Zeek and ongoing monitoring | Linux setup checks enforce Zeek and pass installer tests. Windows setup still reports success without required Zeek. Device/live monitoring code exists; actual long-running live traffic and daemon-revocation cleanup were not independently proven in this review. |

The broader `notes/features.md` describes a larger product roadmap. It is not evidence that all listed features exist. The problem statement's passive-PCAP capabilities are the minimum acceptance baseline; domain checks are complementary.

## Findings, highest priority first

### 1. P1 — New report endpoint exposes another workspace's assessment report

`apps/core/src/api/reports.rs:232` has no execution-context/org check and loads by unscoped ID at line 240. `EvidenceSnapshot::assessment` also uses unscoped reads (`apps/core/src/evidence.rs:131`).

Reproduced in an isolated in-memory server: a device in workspace A gets 404 for workspace B's assessment detail, but **200** for the same assessment's `/report?format=json`. The regression test expects 404 and fails. This is not a speculative issue or a production-data test. Fix authorization before deploying this endpoint; knowing another assessment UUID must not grant access.

### 2. P1 — Protocol diagram fabricates successful stages

`apps/web/src/components/ProtocolLadder.tsx:27` uses `hasEvent("tcp_connected") || true`. Lines 41 and 57 return `completed` in both branches. The component therefore claims a TCP handshake and plaintext capabilities succeeded even when absent from a partial capture. This violates the required evidence-based reconstruction. Show observed, inferred, unavailable and failed states distinctly; never fill missing evidence with success.

### 3. P1 — Passive chain-validation requirement remains unimplemented

The problem statement explicitly requires certificate chain validation (`notes/problem_statement.md:44`). The passive adapter unconditionally emits NotVerified (`apps/sensor/src/normalize.rs:432`). Counting chain entries and extracting a leaf are not chain validation. Current active checks do not close this requirement for imported historical traffic.

### 4. P2 — Risk/posture differs for the same capture

Real local analysis of `fixtures/pcap/smtp_starttls.pcapng` (SHA-256 `c2877835223b21abe61a522d9a6c96741707ca2d0d28d1eb0425d453e4ba06e6`) yields:

- One `CERTIFICATE_EXPIRED` finding, severity HIGH.
- Certificate `CN=mail.mailent.test`, expired 2021-01-01; observed 2026-09-21.
- CLI score 60, grade Moderate, overall risk MEDIUM, while its rationale describes a High-severity issue.
- The web upload code subtracts 15 for one High (`apps/core/src/api/assessments.rs:348`), producing 85/B, and takes overall risk separately from the decision provider/fallback (`:469`).

Thus the expired-certificate finding is supported by evidence; the capture-gap count is not its cause. The score and classification policies need a coherent, documented interpretation across web, CLI, and exports. Do not simply remove a valid finding to make the dashboard greener.

### 5. P2 — Revocation cancels only the first 200 workspace jobs

`apps/core/src/api/devices.rs:349` calls `list_for_org(org_id, 200)` and filters afterward. Reproduced with 201 queued jobs: revocation returns 200, but at least one job remains Pending. Older active jobs can also be excluded by unrelated/history records. Token rejection still works in the existing revocation test; the queue lifecycle is incomplete. Cancel active jobs directly by device without an arbitrary history cap.

### 6. P2 — Windows installer can falsely report ready

`scripts/install.ps1:111` runs a container pull without checking the native exit status or running Zeek. If no runtime/native Zeek exists, it prints advice and then “Installation successful!” at line 121. It copies binaries and changes PATH before dependency validation. This contradicts mandatory-Zeek readiness. Windows live wrapper also always uses `--network none` (`scripts/mailent-zeek.cmd:27`), so it cannot capture the Windows host interface as the Linux workflow does. A successful Windows compilation does not establish these workflows work.

### 7. P2 — Release and website are out of sync

GitHub v0.1.2 exists with Linux and Windows assets; Actions run **35992247290** succeeded. Render's live deployment is **460db8d**, deployment **dep-daqeei8u01pc73fsb38g**, preceding the new reports/protocol UI/Windows installer. Direct GET of the advertised website `/install.ps1` returns the SPA HTML, not PowerShell. Do not deploy the latest checkout until finding 1 is fixed. No deployment was initiated by this review.

### 8. P2 — Copy requirements were not completed

The homepage hero and core marketing copy remain unchanged in both checkout and live UI, including “Your mail. Every connection. In the clear.” The only landing-page diff concerns release/platform information. The new risk tab reintroduces “Jev AI Threat Prioritization & Risk Engine,” “Jev Engine Online,” and model details (`apps/web/src/AssessmentWorkspace.tsx:1765`), contrary to the user's instructions. Preserve the requested AI functionality, but use ordinary product copy and move vendor/privacy details to Privacy. Do not redesign the approved homepage UI.

## Checks actually run

- `MAILENT_ZEEK=/home/dipak/code/mailent/scripts/mailent-zeek cargo test -p mailent -p mailent-scanner -p mailent-sensor -p mailent-core`: **97 passed, 3 ignored**. The ignored tests require controlled mail-server/database labs; this is not verification of those environments. Log: `/tmp/mailent-verify-rust-full.log`.
- New isolated review tests: **2 failed**, reproducing cross-workspace report access and the 200-job revocation cap. Log: `/tmp/mailent-verify-regressions.log`.
- Frontend: **14 tests passed**, TypeScript and production build passed. Existing tests do not cover the new security/visualization defects. Logs: `/tmp/mailent-verify-web-tests.log`, `/tmp/mailent-verify-web-build.log`.
- `bash scripts/test-install.sh`: passed Linux installer checks. This is not a Windows installer test.
- Actual Zeek 8.0.4 sample analysis and JSON/HTML/PDF exports: `/tmp/mailent-current-review-pcap.json`, `/tmp/mailent-current-review-reports/`.
- Live browser: homepage text checked; guest Devices shows sign-in CTA instead of approval form and retains a supplied test code in URL. No real device was registered or revoked.
- GitHub release/assets and Render deployment queried live. Windows binary execution, real AI response, authenticated desktop table layout, cloud DB migrations, and live traffic capture were not independently verified this pass.

## Completion order

Fix report access and evidence fabrication first. Complete passive chain validation and unify scoring. Verify AI-assisted anomaly/prioritization on actual structured evidence. Finish complete revocation and Windows readiness; add regression coverage. Rewrite homepage copy around the required PCAP/Zeek/crypto workflows without changing its design. Then publish any necessary patch, deploy the fixed web revision, and perform live acceptance checks. Free connected-device checks remain subject to the device network permitting target SMTP ports.
