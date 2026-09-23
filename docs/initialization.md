# Initialization continuation

## State at takeover

`main` contained the original README/license commit. The previous agent's Rust
workspace and project notes were untracked; `.gitignore` was modified. Those
sources were inspected and continued in place, without resetting or regenerating
the repository. There was no frontend, pnpm workspace, Protobuf schema, or Compose
file. Rust formatting, Clippy, and 13 tests passed before continuation.

Existing work included 12 Rust workspace packages, observation/session/finding
models, three deterministic policy checks, an Axum evaluation endpoint,
in-memory repositories, a broadcast event bus, four synthetic fixtures, three
YAML policy packs, and initial sensor/probe/baseline/report/decision boundaries.

## Completed and corrected

- Added the real frontend path from submitted synthetic observation to Rust
  evaluation response, including evidence, remediation, policy provenance,
  unknown evidence, empty, loading and failure states.
- Loaded and validated YAML policy packs, replacing the duplicate hardcoded pack.
  Predicate types are explicit; unknown predicates, typos, empty definitions,
  and duplicate IDs fail validation. High-security actually flags TLS 1.2.
- Preserved absent STARTTLS state; missing evidence no longer becomes successful
  STARTTLS. Added observation source/parser provenance and basic input validation.
- Findings retain policy name/version, standards reference, observation/session
  links, and stable identity. Replaying an observation does not inflate counts.
  Different sessions remain separate. Reusing an observation ID with changed
  evaluated evidence returns HTTP 409.
- Corrected the synthetic TLS 1.3 cipher ID/name pair and invalid-length synthetic
  certificate fingerprints. These are synthetic metadata, not parsed certificates.
- Added generated Protobuf v1 event types and tested adapters. Unknown optional
  evidence survives transport; unsupported schema versions are rejected and
  arbitrary raw metadata must be minimized before transport.
- Readiness validates the loaded policy and reports storage/decision mode.
  Invalid configured policies fail startup. Removed permissive cross-origin API
  access; the frontend uses a same-origin proxy.
- Removed the unused fabricated development anomaly/confidence provider. Kept
  the real disabled decision boundary and other correct scaffold work.
- Sensor sample output is explicit; no false delivery/capture claims. The event
  bus returns an error when no consumer exists. Probe scope defaults to empty.
- Added local pnpm/Buf tooling, reproducible dependency locks, Compose and
  container source, and run/check documentation. No additional databases.

## Acceptance scope

The expected modern-policy results are 2 / 0 / 1 / 1 findings for legacy TLS,
TLS 1.3, expired certificate, and TLS 1.2 static RSA respectively. All findings
are evaluated at the supplied observation time, not the current wall clock.

A zero-finding result only means the implemented predicates found no violation
in the evidence supplied. It is not an overall healthy/security verdict.

The synchronous `/api/v1/observations/evaluate` helper and in-memory storage are
intentional initialization limits. Authenticated, bounded asynchronous ingestion,
spooling, durable stores, cross-session correlation, and historical replay remain
future work. Policy content changes require a new pack version for reproducibility.

## Next vertical slice

Import a small, provenance-preserved Zeek JSON fixture through the sensor's
normalization boundary into the canonical observation contract and existing
policy/core/UI path. Verify partial captures and unknown fields with real Zeek
output. Keep TCP/TLS/mail reconstruction in Zeek. Add bounded ingestion and
explicit delivery failure handling as part of that concrete slice, then connect
appropriate durable stores when retention is implemented.

## Verification performed on 2026-09-22

- `cargo fmt --check`, workspace Clippy with warnings denied, and 20 Rust tests.
- Frontend Biome lint, TypeScript checking, five Vitest tests, and Vite production build.
- Buf lint and format check; Protobuf round trips are part of Rust tests.
- Compose configuration validation with and without `distributed`; default services
  are core/web, and only the profile adds Redpanda. Container images were not built
  or started during this verification.
- One Playwright browser integration test against a real Rust process: all four
  fixture responses, rendered findings and evidence, zero-finding state, and
  narrow-screen overflow check. Desktop/mobile screenshots inspected visually.
- Manual HTTP checks: health/readiness 200, all four fixture outputs, exact replay
  response equality, malformed JSON 400, sensor `--sample` output evaluated by
  core, and failed startup for a missing configured policy file.

Test servers were stopped after verification. No commits, external deployments,
active network probes, database migrations, or messages to other people were made.
