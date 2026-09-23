import { z } from "zod";
import { authenticatedFetch } from "./auth";

export async function checkDecisionProvider(): Promise<{
  connected: boolean;
  message: string;
}> {
  const response = await authenticatedFetch("/api/v1/decisions/check", {
    method: "POST",
  });
  if (!response.ok) throw new Error("Could not check Jev. Please try again.");
  return z
    .object({ connected: z.boolean(), message: z.string() })
    .parse(await response.json());
}

export const findingSchema = z.object({
  id: z.string(),
  rule_id: z.string(),
  policy_name: z.string(),
  policy_version: z.string(),
  reference: z.string(),
  severity: z.enum(["low", "medium", "high", "critical"]),
  category: z.string(),
  title: z.string(),
  description: z.string(),
  remediation: z.string(),
  affected_count: z.number(),
  first_seen: z.string(),
  last_seen: z.string(),
  evidence: z.array(
    z.object({
      session_id: z.string().nullable(),
      observation_id: z.string().nullable(),
      description: z.string(),
    }),
  ),
});
export type Finding = z.infer<typeof findingSchema>;

export const timelineEventSchema = z.object({
  timestamp: z.string(),
  kind: z.string(),
  source: z.string(),
});
export type TimelineEvent = z.infer<typeof timelineEventSchema>;

export const captureEvidenceSchema = z.object({
  capture_sha256: z.string(),
  connection_uid: z.string(),
  normalizer_version: z.string(),
  source_logs: z.array(z.string()),
  timeline: z.array(timelineEventSchema),
  gaps: z.array(z.string()),
  tls_established: z.boolean().nullable().optional(),
  protocol_hint: z.string().nullable().optional(),
});
export type CaptureEvidence = z.infer<typeof captureEvidenceSchema>;

export const certificateObservationSchema = z.object({
  reference: z.object({
    sha256_fingerprint: z.string(),
    subject: z.string(),
    issuer: z.string(),
  }),
  validity: z.object({
    not_before: z.string(),
    not_after: z.string(),
  }),
  is_self_signed: z.boolean().nullable().optional(),
  san: z.array(z.string()),
});
export type CertificateObservation = z.infer<
  typeof certificateObservationSchema
>;

export const emailSessionSchema = z.object({
  session_id: z.string(),
  sensor_id: z.string(),
  provenance: z.object({
    source: z.string(),
    parser: z.string(),
    parser_version: z.string(),
  }),
  flow: z.object({
    src_ip: z.string(),
    src_port: z.number(),
    dst_ip: z.string(),
    dst_port: z.number(),
  }),
  protocol: z.string(),
  starttls_state: z.string().nullable().optional(),
  tls_version: z.string().nullable().optional(),
  cipher_suite: z
    .object({
      id: z.number().nullable().optional(),
      name: z.string(),
    })
    .nullable()
    .optional(),
  key_exchange: z.unknown().nullable().optional(),
  certificate: certificateObservationSchema.nullable().optional(),
  capture: captureEvidenceSchema.nullable().optional(),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type EmailSession = z.infer<typeof emailSessionSchema>;

export const sessionListItemSchema = z.object({
  session_id: z.string(),
  sensor_id: z.string(),
  protocol: z.string(),
  client: z.string(),
  server: z.string(),
  starttls_state: z.string().nullable().optional(),
  tls_version: z.string().nullable().optional(),
  cipher_suite: z.string().nullable().optional(),
  forward_secrecy: z.enum(["supported", "not_supported", "unknown"]),
  certificate_state: z.string(),
  findings_count: z.number(),
  first_seen: z.string(),
  last_seen: z.string(),
  has_capture_evidence: z.boolean(),
  session: emailSessionSchema,
});
export type SessionListItem = z.infer<typeof sessionListItemSchema>;

export const sessionDetailSchema = z.object({
  session: emailSessionSchema,
  findings: z.array(findingSchema),
  forward_secrecy: z.enum(["supported", "not_supported", "unknown"]),
  certificate_state: z.string(),
});
export type SessionDetail = z.infer<typeof sessionDetailSchema>;

const responseSchema = z.object({
  session_id: z.string(),
  candidate_count: z.number(),
  findings: z.array(findingSchema),
  observation: z.object({
    timestamp: z.string(),
    sensor_id: z.string(),
    protocol: z.string(),
    provenance: z.object({
      source: z.string(),
      parser: z.string(),
      parser_version: z.string(),
    }),
    flow: z.object({
      src_ip: z.string(),
      src_port: z.number(),
      dst_ip: z.string(),
      dst_port: z.number(),
    }),
    tls_version: z.string().nullable(),
    starttls_state: z.string().nullable(),
  }),
});

const readinessSchema = z.object({
  ready: z.boolean(),
  policy_loaded: z.boolean(),
  policy_name: z.string(),
  policy_version: z.string(),
  rule_count: z.number(),
  storage: z.string(),
  decision_provider: z.string(),
});

async function request(
  path: string,
  init?: RequestInit,
  timeoutMs = 10000,
): Promise<unknown> {
  const response = await authenticatedFetch(path, {
    ...init,
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok)
    throw new Error(
      `Request failed (${response.status}): ${(await response.text()).slice(0, 500)}`,
    );
  if (response.status === 204) return null;
  return response.json();
}

export const protocolEvidenceSchema = z.object({
  protocol: z.string(),
  role: z.string(),
  proof: z.string(),
  verified_by: z.string(),
});
export type ProtocolEvidence = z.infer<typeof protocolEvidenceSchema>;

export const assessmentSummarySchema = z.object({
  id: z.string(),
  title: z.string(),
  source_type: z.string().optional(),
  target: z.string().optional(),
  capture_name: z.string(),
  capture_hash: z.string(),
  capture_size_bytes: z.number(),
  created_at: z.string(),
  protocols_identified: z.array(z.string()),
  session_count: z.number(),
  finding_count: z.number(),
  posture_score: z.number(),
  posture_grade: z.string(),
  ai_risk_classification: z.string(),
  organization_id: z.string().nullable().optional(),
});
export type AssessmentSummary = z.infer<typeof assessmentSummarySchema>;

export const assessmentRecordSchema = z.object({
  id: z.string(),
  title: z.string(),
  source: z.any().optional(),
  capture_name: z.string(),
  capture_hash: z.string(),
  capture_size_bytes: z.number(),
  created_at: z.string(),
  time_range_start: z.string().nullable().optional(),
  time_range_end: z.string().nullable().optional(),
  protocols_identified: z.array(z.string()),
  protocol_evidence: z.array(protocolEvidenceSchema),
  session_ids: z.array(z.string()),
  asset_ids: z.array(z.string()),
  finding_ids: z.array(z.string()),
  posture_score: z.number(),
  posture_grade: z.string(),
  evidence_gaps: z.array(z.string()),
  ai_risk_classification: z.string(),
  ai_risk_rationale: z.string(),
  ai_confidence: z.number(),
  metadata: z.record(z.string(), z.any()).default({}),
  organization_id: z.string().nullable().optional(),
});
export type AssessmentRecord = z.infer<typeof assessmentRecordSchema>;

export interface AnalyzeCaptureRequest {
  title?: string;
  pcap_base64?: string;
  file_name?: string;
}

export async function fetchAssessments(): Promise<AssessmentSummary[]> {
  return z
    .array(assessmentSummarySchema)
    .parse(await request("/api/v1/assessments"));
}

export async function fetchAssessment(id: string): Promise<AssessmentRecord> {
  return assessmentRecordSchema.parse(
    await request(`/api/v1/assessments/${id}`),
  );
}

export async function analyzeCapture(
  req: AnalyzeCaptureRequest,
): Promise<AssessmentRecord> {
  return assessmentRecordSchema.parse(
    await request(
      "/api/v1/assessments/analyze",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      },
      60000,
    ),
  );
}

export async function readReadiness() {
  return readinessSchema.parse(await request("/ready"));
}

export async function evaluateObservation(input: string) {
  JSON.parse(input); // Prevent sending malformed JSON; security validation remains in Rust.
  return responseSchema.parse(
    await request("/api/v1/observations/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: input,
    }),
  );
}

export async function fetchSessions(): Promise<SessionListItem[]> {
  return z
    .array(sessionListItemSchema)
    .parse(await request("/api/v1/sessions"));
}

export async function fetchSessionDetail(id: string): Promise<SessionDetail> {
  return sessionDetailSchema.parse(await request(`/api/v1/sessions/${id}`));
}

export async function fetchFindings(sessionId?: string): Promise<Finding[]> {
  const url = sessionId
    ? `/api/v1/findings?session_id=${sessionId}`
    : "/api/v1/findings";
  return z.array(findingSchema).parse(await request(url));
}

export const assetIdentitySchema = z.object({
  kind: z.string(),
  value: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type AssetIdentity = z.infer<typeof assetIdentitySchema>;

export const assetEndpointSchema = z.object({
  protocol: z.string(),
  port: z.number(),
  tls_versions: z.array(z.string()),
  cipher_suites: z.array(z.string()),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type AssetEndpoint = z.infer<typeof assetEndpointSchema>;

export const assetSchema = z.object({
  probe_authorized: z.boolean().optional(),
  id: z.string(),
  primary_name: z.string().nullable().optional(),
  addresses: z.array(z.string()),
  hostnames: z.array(z.string()),
  identities: z.array(assetIdentitySchema).default([]),
  endpoints: z.array(assetEndpointSchema).default([]),
  tls_versions: z.array(z.string()).default([]),
  cipher_suites: z.array(z.string()).default([]),
  certificate_fingerprints: z.array(z.string()).default([]),
  active_findings_count: z.number().default(0),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type Asset = z.infer<typeof assetSchema>;

export const driftEventSchema = z.object({
  id: z.string(),
  asset_id: z.string(),
  kind: z.string(),
  title: z.string(),
  description: z.string(),
  previous_value: z.string().nullable().optional(),
  new_value: z.string(),
  observed_at: z.string(),
  session_id: z.string().nullable().optional(),
});
export type DriftEvent = z.infer<typeof driftEventSchema>;

export const certificateRecordSchema = z.object({
  sha256_fingerprint: z.string(),
  subject: z.string(),
  issuer: z.string(),
  sans: z.array(z.string()).default([]),
  not_before: z.string(),
  not_after: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
  associated_asset_ids: z.array(z.string()).default([]),
});
export type CertificateRecord = z.infer<typeof certificateRecordSchema>;

export const sensorRecordSchema = z.object({
  sensor_id: z.string(),
  site_id: z.string(),
  hostname: z.string(),
  version: z.string(),
  mode: z.string(),
  interface: z.string().nullable().optional(),
  status: z.enum(["Online", "Stale", "Offline"]),
  last_seen: z.string(),
  registered_at: z.string(),
});
export type SensorRecord = z.infer<typeof sensorRecordSchema>;

export async function fetchAssets(): Promise<Asset[]> {
  return z.array(assetSchema).parse(await request("/api/v1/assets"));
}

export async function fetchAsset(id: string): Promise<Asset> {
  return assetSchema.parse(await request(`/api/v1/assets/${id}`));
}

export async function fetchAssetDrift(id: string): Promise<DriftEvent[]> {
  return z
    .array(driftEventSchema)
    .parse(await request(`/api/v1/assets/${id}/drift`));
}

export async function fetchAssetCertificates(
  id: string,
): Promise<CertificateRecord[]> {
  return z
    .array(certificateRecordSchema)
    .parse(await request(`/api/v1/assets/${id}/certificates`));
}

export async function fetchAssetSessions(id: string): Promise<EmailSession[]> {
  return z
    .array(emailSessionSchema)
    .parse(await request(`/api/v1/assets/${id}/sessions`));
}

export async function fetchAssetFindings(id: string): Promise<Finding[]> {
  return z
    .array(findingSchema)
    .parse(await request(`/api/v1/assets/${id}/findings`));
}

export async function fetchDriftEvents(): Promise<DriftEvent[]> {
  return z.array(driftEventSchema).parse(await request("/api/v1/drift"));
}

export async function fetchSensors(): Promise<SensorRecord[]> {
  return z.array(sensorRecordSchema).parse(await request("/api/v1/sensors"));
}

export const probeRunSchema = z.object({
  id: z.string(),
  asset_id: z.string(),
  target: z.string(),
  protocol: z.string(),
  port: z.number(),
  trigger: z.string(),
  investigation_id: z.string().nullable(),
  started_at: z.string(),
  finished_at: z.string().nullable(),
  outcome: z.string(),
  has_mismatch: z.boolean(),
  perspective_mismatches: z.array(
    z.object({
      kind: z.string(),
      passive_value: z.string(),
      active_value: z.string(),
      description: z.string(),
    }),
  ),
  result: z
    .object({
      resolved_host: z.string(),
      resolved_ip: z.string().nullable(),
      smtp_greeting: z.string().nullable(),
      ehlo_capabilities: z.array(z.string()),
      starttls: z.string(),
      tls_version: z.string().nullable(),
      cipher_suite: z
        .object({ id: z.number().nullable(), name: z.string() })
        .nullable(),
      forward_secrecy: z.string(),
      certificate: certificateObservationSchema.nullable(),
      certificate_hostname_valid: z.boolean().nullable(),
      certificate_trusted: z.boolean().nullable().optional(),
      mta_sts_mode: z.string().nullable(),
      mta_sts_result: z.string().nullable(),
      dane_status: z.string(),
      dane_result: z.string().nullable(),
      latency_ms: z.number(),
      warnings: z.array(z.string()),
      error: z.string().nullable(),
      tls_challenges: z
        .array(
          z.object({
            version: z.string(),
            outcome: z.string(),
            detail: z.string(),
          }),
        )
        .default([]),
      verification: z
        .object({
          passive_session_id: z.string().nullable(),
          confidence: z.string(),
          anomaly_ids: z.array(z.string()),
          anomalies: z
            .array(
              z.object({
                anomaly_id: z.string(),
                active_value: z.string(),
                conclusion: z.string(),
              }),
            )
            .optional(),
          drift: z.array(
            z.object({
              drift_id: z.string(),
              active_value: z.string(),
              confirmed: z.boolean(),
            }),
          ),
        })
        .nullable()
        .optional(),
    })
    .nullable(),
});
export type ProbeRun = z.infer<typeof probeRunSchema>;
export async function fetchAssetProbes(id: string) {
  return z
    .array(probeRunSchema)
    .parse(await request(`/api/v1/assets/${id}/probes`));
}

export const anomalySignalSchema = z.object({
  id: z.string(),
  asset_id: z.string(),
  signal: z.string(),
  title: z.string(),
  current_value: z.string(),
  baseline_value: z.string(),
  deviation: z.number(),
  confidence: z.number(),
  evidence: z.string(),
  observed_at: z.string(),
});
export type AnomalySignal = z.infer<typeof anomalySignalSchema>;

export async function fetchAssetAnomalies(
  id: string,
): Promise<AnomalySignal[]> {
  return z
    .array(anomalySignalSchema)
    .parse(await request(`/api/v1/assets/${id}/anomalies`));
}
export async function triggerAssetProbe(
  id: string,
  port: number,
  protocol: string,
  investigationId?: string,
) {
  return z.object({ probe_id: z.string(), status: z.string() }).parse(
    await request(`/api/v1/assets/${id}/probe`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        port,
        protocol,
        investigation_id: investigationId ?? null,
        trigger: "manual_analyst",
      }),
    }),
  );
}
export const postureCategoryScoreSchema = z.object({
  category: z.string(),
  score: z.number(),
  weight: z.number(),
  weighted_score: z.number(),
  finding_rule_ids: z.array(z.string()),
  rationale: z.string(),
});
export type PostureCategoryScore = z.infer<typeof postureCategoryScoreSchema>;

export const postureDeductionSchema = z.object({
  rule_id: z.string(),
  finding_id: z.string(),
  severity: z.string(),
  category: z.string(),
  points: z.number(),
  evidence_description: z.string(),
});
export type PostureDeduction = z.infer<typeof postureDeductionSchema>;

export const securityPostureSchema = z.object({
  id: z.string(),
  score_version: z.string(),
  subject_kind: z.enum(["asset", "session", "investigation"]),
  subject_id: z.string(),
  score: z.number(),
  grade: z.enum(["strong", "good", "moderate", "weak", "critical"]),
  score_capped: z.boolean(),
  pre_cap_score: z.number(),
  categories: z.array(postureCategoryScoreSchema),
  deductions: z.array(postureDeductionSchema),
  worst_findings: z.array(z.string()),
  findings_considered: z.number(),
  computed_at: z.string(),
});
export type SecurityPosture = z.infer<typeof securityPostureSchema>;

export const remediationGuidanceSchema = z.object({
  id: z.string(),
  kind: z.enum(["remediation", "best_practice"]),
  finding_id: z.string().nullable(),
  rule_id: z.string(),
  title: z.string(),
  observed: z.string(),
  why_it_matters: z.string(),
  recommendation: z.string(),
  recommended_state: z.string(),
  compatibility_caveats: z.array(z.string()),
  verification: z.string(),
  evidence: z.array(
    z.object({
      session_id: z.string().nullable(),
      observation_id: z.string().nullable(),
      description: z.string(),
    }),
  ),
  severity: z.string(),
  category: z.string(),
  generated_at: z.string(),
});
export type RemediationGuidance = z.infer<typeof remediationGuidanceSchema>;

export const remediationStateSchema = z.enum([
  "in_progress",
  "applied",
  "verifying",
  "verified_fixed",
  "still_present",
  "inconclusive",
]);
export const remediationRecordSchema = z.object({
  id: z.string(),
  asset_id: z.string(),
  investigation_id: z.string().nullable(),
  finding: findingSchema,
  guidance: remediationGuidanceSchema,
  before: emailSessionSchema,
  condition: z.string(),
  state: remediationStateSchema,
  revision: z.number(),
  started_at: z.string(),
  applied_at: z.string().nullable(),
  analyst_note: z.string().nullable(),
  attempts: z.array(
    z.object({
      request_id: z.string(),
      probe_id: z.string(),
      requested_at: z.string(),
      completed_at: z.string().nullable(),
      outcome: remediationStateSchema.nullable(),
      explanation: z.string(),
      after: probeRunSchema.nullable(),
    }),
  ),
});
export type RemediationRecord = z.infer<typeof remediationRecordSchema>;
async function remediationPost(path: string, body: unknown) {
  return remediationRecordSchema.parse(
    await request(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
}
export function startRemediation(
  assetId: string,
  findingId: string,
  sessionId?: string,
) {
  return remediationPost(`/api/v1/assets/${assetId}/remediations`, {
    finding_id: findingId,
    session_id: sessionId,
  });
}
export function applyRemediation(id: string, note: string) {
  return remediationPost(`/api/v1/remediations/${id}/applied`, { note });
}
export function verifyRemediation(id: string, requestId: string) {
  return remediationPost(`/api/v1/remediations/${id}/verify`, {
    request_id: requestId,
  });
}
export async function fetchRemediation(id: string) {
  return remediationRecordSchema.parse(
    await request(`/api/v1/remediations/${id}`),
  );
}

export const assetPostureResponseSchema = z.object({
  posture: securityPostureSchema,
  guidance: z.array(remediationGuidanceSchema),
  remediations: z.array(remediationRecordSchema).default([]),
  asset_id: z.string().nullable().default(null),
  verification_conditions: z.record(z.string(), z.string()).default({}),
});
export type AssetPostureResponse = z.infer<typeof assetPostureResponseSchema>;

export async function fetchAssetPosture(
  id: string,
): Promise<AssetPostureResponse> {
  return assetPostureResponseSchema.parse(
    await request(`/api/v1/assets/${id}/posture`),
  );
}

export async function fetchSessionPosture(
  id: string,
): Promise<AssetPostureResponse> {
  return assetPostureResponseSchema.parse(
    await request(`/api/v1/sessions/${id}/posture`),
  );
}

export type ReportFormat = "json" | "html" | "pdf";

/** Generate and download a forensic report for an asset in the chosen format. */
export async function downloadAssetReport(
  id: string,
  format: ReportFormat,
): Promise<void> {
  const response = await authenticatedFetch(
    `/api/v1/assets/${id}/report?format=${format}`,
    {
      signal: AbortSignal.timeout(15000),
    },
  );
  if (!response.ok)
    throw new Error(
      `Report generation failed (${response.status}): ${(await response.text()).slice(0, 300)}`,
    );
  const disposition = response.headers.get("content-disposition") ?? "";
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match?.[1] ?? `mailent-report-${id.slice(0, 8)}.${format}`;
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export const investigationSchema = z.object({
  remediations: z.array(remediationRecordSchema).default([]),
  id: z.string(),
  asset_id: z.string(),
  title: z.string(),
  summary: z.string(),
  status: z.string(),
  risk: z.string(),
  anomaly_ids: z.array(z.string()),
  external_intelligence: z
    .object({
      active_verifications: z.record(z.string(), probeRunSchema).optional(),
    })
    .passthrough(),
});
export async function fetchInvestigations() {
  return z
    .array(investigationSchema)
    .parse(await request("/api/v1/investigations"));
}

export async function fetchInvestigation(id: string) {
  return investigationSchema.parse(
    await request(`/api/v1/investigations/${id}`),
  );
}

// Verification Freshness
export const verificationFreshnessSchema = z.enum([
  "never_verified",
  "fresh",
  "aging",
  "stale",
]);
export type VerificationFreshness = z.infer<typeof verificationFreshnessSchema>;

export const assetVerificationStateSchema = z.object({
  asset_id: z.string(),
  freshness: verificationFreshnessSchema,
  last_verified_at: z.string().nullable().optional(),
  last_probe_outcome: z.string().nullable().optional(),
  last_probe_id: z.string().nullable().optional(),
  consecutive_failures: z.number().default(0),
  failure_reasons: z.array(z.string()).default([]),
  freshness_reasons: z.array(z.string()).default([]),
  drift_detected_since_verification: z.boolean().default(false),
  authorized_target: z.string().nullable().optional(),
  next_scheduled_check: z.string().nullable().optional(),
});
export type AssetVerificationState = z.infer<
  typeof assetVerificationStateSchema
>;

export async function fetchAssetVerification(
  id: string,
): Promise<AssetVerificationState> {
  return assetVerificationStateSchema.parse(
    await request(`/api/v1/assets/${id}/verification`),
  );
}

// Posture Snapshots & History
export const postureSnapshotSchema = z.object({
  id: z.string(),
  asset_id: z.string(),
  captured_at: z.string(),
  score: z.number(),
  previous_score: z.number().nullable().optional(),
  grade: z.string(),
  findings_count: z.number(),
  critical_count: z.number(),
  high_count: z.number(),
  medium_count: z.number(),
  low_count: z.number(),
  change_reason: z.string().nullable().optional(),
  trigger_evidence_id: z.string().nullable().optional(),
  finding_hashes: z.array(z.string()).default([]),
});
export type PostureSnapshot = z.infer<typeof postureSnapshotSchema>;

export const postureChangeSummarySchema = z.object({
  has_changed: z.boolean(),
  score_delta: z.number(),
  previous_score: z.number().nullable().optional(),
  current_score: z.number(),
  previous_grade: z.string().nullable().optional(),
  current_grade: z.string(),
  last_snapshot_at: z.string().nullable().optional(),
  reason: z.string().nullable().optional(),
});
export type PostureChangeSummary = z.infer<typeof postureChangeSummarySchema>;

export const assetPostureHistorySchema = z.object({
  asset_id: z.string(),
  current_posture: securityPostureSchema,
  current_score: z.number(),
  snapshots: z.array(postureSnapshotSchema),
  total_snapshots: z.number(),
  change_summary: postureChangeSummarySchema,
});
export type AssetPostureHistory = z.infer<typeof assetPostureHistorySchema>;

export async function fetchAssetPostureHistory(
  id: string,
): Promise<AssetPostureHistory> {
  return assetPostureHistorySchema.parse(
    await request(`/api/v1/assets/${id}/posture/history`),
  );
}

// Policy Simulation
export const policyPackSummarySchema = z
  .object({
    name: z.string(),
    version: z.string(),
    title: z.string().optional().default(""),
    description: z.string().default(""),
    rule_count: z.number().optional().default(0),
    rules_count: z.number().optional().default(0),
    min_tls_version: z.string().nullable().optional(),
    require_pfs: z.boolean().optional().default(false),
    max_cert_validity_days: z.number().nullable().optional(),
    require_mta_sts: z.boolean().optional().default(false),
    require_dane: z.boolean().optional().default(false),
  })
  .transform((p) => ({
    ...p,
    title: p.title || p.name,
    rule_count: p.rule_count || p.rules_count || 0,
  }));
export type PolicyPackSummary = z.infer<typeof policyPackSummarySchema>;

export const simulationBreakageSchema = z
  .object({
    rule_id: z.string(),
    severity: z.string(),
    title: z.string().default(""),
    description: z.string().default(""),
    remediation: z.string().default(""),
    deprecated_behavior: z.string().default(""),
    affected_sessions_count: z.number().default(0),
    sample_flow: z.string().default(""),
    rule_title: z.string().optional(),
    reason: z.string().optional(),
    category: z.string().optional(),
    observed_value: z.string().optional(),
    required_value: z.string().optional(),
    session_id: z.string().nullable().optional(),
  })
  .transform((data) => ({
    ...data,
    rule_title: data.rule_title ?? data.title ?? data.rule_id,
    reason: data.reason ?? data.description ?? data.deprecated_behavior,
  }));
export type SimulationBreakage = z.infer<typeof simulationBreakageSchema>;

export const assetSimulationResultSchema = z
  .object({
    asset_id: z.string(),
    primary_name: z.string().default(""),
    asset_name: z.string().optional(),
    addresses: z.array(z.string()).default([]),
    compatibility: z.enum([
      "compatible",
      "would_fail",
      "insufficient_evidence",
    ]),
    evaluated_sessions_count: z.number(),
    breakages: z.array(simulationBreakageSchema).default([]),
    explanation: z.string().default(""),
    breakage_count: z.number().optional(),
    evaluation_notes: z.array(z.string()).default([]),
  })
  .transform((data) => ({
    ...data,
    asset_name: data.asset_name ?? data.primary_name,
    breakage_count: data.breakage_count ?? data.breakages.length,
  }));
export type AssetSimulationResult = z.infer<typeof assetSimulationResultSchema>;

export const breakageSummarySchema = z
  .object({
    rule_id: z.string(),
    deprecated_behavior: z.string().default(""),
    affected_assets_count: z.number(),
    affected_sessions_count: z.number().default(0),
    description: z.string().default(""),
    rule_title: z.string().optional(),
    sample_reason: z.string().optional(),
  })
  .transform((data) => ({
    ...data,
    rule_title: data.rule_title ?? data.deprecated_behavior ?? data.rule_id,
    sample_reason: data.sample_reason ?? data.description,
  }));
export type BreakageSummary = z.infer<typeof breakageSummarySchema>;

export const policySimulationResultSchema = z
  .object({
    id: z.string().optional(),
    policy_name: z.string(),
    policy_version: z.string().default("1.0.0"),
    policy_description: z.string().default(""),
    total_assets: z.number().optional(),
    total_assets_evaluated: z.number().optional(),
    compatible_assets_count: z.number(),
    would_fail_assets_count: z.number().optional(),
    incompatible_assets_count: z.number().optional(),
    insufficient_evidence_assets_count: z.number().optional(),
    unknown_assets_count: z.number().optional(),
    total_sessions_evaluated: z.number().default(0),
    breakage_summaries: z.array(breakageSummarySchema).default([]),
    breakages_by_rule: z.array(breakageSummarySchema).optional(),
    asset_results: z.array(assetSimulationResultSchema).default([]),
    simulated_at: z.string().optional(),
    evaluated_at: z.string().optional(),
  })
  .transform((data) => {
    const would_fail =
      data.would_fail_assets_count ?? data.incompatible_assets_count ?? 0;
    const insufficient =
      data.insufficient_evidence_assets_count ?? data.unknown_assets_count ?? 0;
    const breakages =
      data.breakage_summaries.length > 0
        ? data.breakage_summaries
        : (data.breakages_by_rule ?? []);
    return {
      ...data,
      total_assets:
        data.total_assets ??
        data.total_assets_evaluated ??
        data.compatible_assets_count + would_fail + insufficient,
      total_assets_evaluated:
        data.total_assets_evaluated ??
        data.total_assets ??
        data.compatible_assets_count + would_fail + insufficient,
      would_fail_assets_count: would_fail,
      incompatible_assets_count: would_fail,
      insufficient_evidence_assets_count: insufficient,
      unknown_assets_count: insufficient,
      breakage_summaries: breakages,
      breakages_by_rule: breakages,
      simulated_at:
        data.simulated_at ?? data.evaluated_at ?? new Date().toISOString(),
      evaluated_at:
        data.evaluated_at ?? data.simulated_at ?? new Date().toISOString(),
    };
  });
export type PolicySimulationResult = z.infer<
  typeof policySimulationResultSchema
>;

export async function fetchPolicies(): Promise<PolicyPackSummary[]> {
  return z
    .array(policyPackSummarySchema)
    .parse(await request("/api/v1/policies"));
}

export async function simulatePolicy(
  policyName: string,
): Promise<PolicySimulationResult> {
  return policySimulationResultSchema.parse(
    await request("/api/v1/policies/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ policy_name: policyName }),
    }),
  );
}

// Workflow Integrations
export const integrationConfigSchema = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.enum(["webhook", "syslog"]),
  destination: z.string(),
  enabled: z.boolean(),
  auth_header: z.string().nullable().optional(),
  event_types: z.array(z.string()),
  syslog_facility: z.number().nullable().optional(),
  syslog_severity: z.number().nullable().optional(),
  created_at: z.string(),
  updated_at: z.string(),
  last_delivery_at: z.string().nullable().optional(),
  last_status_code: z.number().nullable().optional(),
  last_error: z.string().nullable().optional(),
});
export type IntegrationConfig = z.infer<typeof integrationConfigSchema>;

export interface UpsertIntegrationInput {
  name: string;
  kind: "webhook" | "syslog";
  destination: string;
  enabled: boolean;
  auth_header?: string | null;
  event_types: string[];
  syslog_facility?: number | null;
  syslog_severity?: number | null;
}

export async function fetchIntegrations(): Promise<IntegrationConfig[]> {
  return z
    .array(integrationConfigSchema)
    .parse(await request("/api/v1/integrations"));
}

export async function createIntegration(
  input: UpsertIntegrationInput,
): Promise<IntegrationConfig> {
  return integrationConfigSchema.parse(
    await request("/api/v1/integrations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    }),
  );
}

export async function updateIntegration(
  id: string,
  input: UpsertIntegrationInput,
): Promise<IntegrationConfig> {
  return integrationConfigSchema.parse(
    await request(`/api/v1/integrations/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    }),
  );
}

export async function deleteIntegration(id: string): Promise<void> {
  await request(`/api/v1/integrations/${id}`, { method: "DELETE" });
}

export async function testIntegration(
  id: string,
): Promise<{ success: boolean; message: string; error?: string }> {
  return request(`/api/v1/integrations/${id}/test`, {
    method: "POST",
  }) as Promise<{ success: boolean; message: string; error?: string }>;
}

// Archived Reports
export const archivedReportSummarySchema = z.object({
  id: z.string(),
  report_id: z.string(),
  subject_kind: z.string(),
  subject_id: z.string(),
  title: z.string(),
  fingerprint: z.string(),
  generated_at: z.string(),
  archived_at: z.string(),
  archived_by: z.string(),
  notes: z.string().nullable().optional(),
});
export type ArchivedReportSummary = z.infer<typeof archivedReportSummarySchema>;

export const archivedReportRecordSchema = z.object({
  id: z.string(),
  report_id: z.string(),
  subject_kind: z.string(),
  subject_id: z.string(),
  title: z.string(),
  fingerprint: z.string(),
  generated_at: z.string(),
  archived_at: z.string(),
  archived_by: z.string(),
  notes: z.string().nullable().optional(),
  raw_report_json: z.string(),
});
export type ArchivedReportRecord = z.infer<typeof archivedReportRecordSchema>;

export async function fetchArchivedReports(): Promise<ArchivedReportSummary[]> {
  return z
    .array(archivedReportSummarySchema)
    .parse(await request("/api/v1/reports/archived"));
}

export async function archiveReport(input: {
  subject_kind: "asset" | "session" | "investigation";
  subject_id: string;
  notes?: string;
  archived_by?: string;
}): Promise<ArchivedReportRecord> {
  return archivedReportRecordSchema.parse(
    await request("/api/v1/reports/archive", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    }),
  );
}

export async function downloadArchivedReport(
  id: string,
  format: ReportFormat,
): Promise<void> {
  const response = await authenticatedFetch(
    `/api/v1/reports/archived/${id}?format=${format}`,
    {
      signal: AbortSignal.timeout(15000),
    },
  );
  if (!response.ok)
    throw new Error(
      `Download failed (${response.status}): ${(await response.text()).slice(0, 300)}`,
    );
  const disposition = response.headers.get("content-disposition") ?? "";
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename =
    match?.[1] ?? `mailent-archived-report-${id.slice(0, 8)}.${format}`;
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export async function downloadInvestigationReport(
  id: string,
  format: ReportFormat,
) {
  const response = await authenticatedFetch(
    `/api/v1/investigations/${id}/report?format=${format}`,
    { signal: AbortSignal.timeout(15000) },
  );
  if (!response.ok)
    throw new Error(`Report failed (${response.status}). Please try again.`);
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `mailent-investigation-${id}.${format}`;
  document.body.appendChild(anchor);
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const organizationSchema = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  created_at: z.string(),
});
export type Organization = z.infer<typeof organizationSchema>;

export const deviceSchema = z.object({
  id: z.string(),
  organization_id: z.string(),
  registered_by_user_id: z.string().nullable().optional(),
  name: z.string(),
  hostname: z.string(),
  platform: z.string(),
  architecture: z.string(),
  created_at: z.string(),
  last_seen_at: z.string(),
  revoked_at: z.string().nullable().optional(),
  capabilities: z.array(z.string()).default([]),
  version: z.string().nullable().optional(),
  agent_enabled: z.boolean().default(false),
  agent_status: z.string().nullable().optional(),
  current_job_id: z.string().nullable().optional(),
  completed_jobs_count: z.number().default(0),
});
export type Device = z.infer<typeof deviceSchema>;

export const deviceChallengeSchema = z.object({
  code: z.string(),
  device_name: z.string(),
  hostname: z.string(),
  platform: z.string(),
  architecture: z.string(),
  expires_at: z.string(),
});
export type DeviceChallenge = z.infer<typeof deviceChallengeSchema>;

export async function fetchCurrentOrganization(): Promise<Organization> {
  return organizationSchema.parse(
    await request("/api/v1/organizations/current"),
  );
}

export async function fetchDevices(): Promise<Device[]> {
  return z.array(deviceSchema).parse(await request("/api/v1/devices"));
}

export async function revokeDevice(id: string): Promise<void> {
  await request(`/api/v1/devices/${id}`, { method: "DELETE" });
}

export async function getDeviceChallenge(
  code: string,
): Promise<DeviceChallenge> {
  return deviceChallengeSchema.parse(
    await request(`/api/v1/devices/authorize/${code}`),
  );
}

export async function approveDeviceChallenge(
  code: string,
): Promise<{ status: string; device: Device }> {
  return (await request(`/api/v1/devices/authorize/${code}/approve`, {
    method: "POST",
  })) as {
    status: string;
    device: Device;
  };
}

export async function scanInfrastructure(domain: string): Promise<{
  assessment: AssessmentRecord;
  report: unknown;
  endpoints_checked: number;
  endpoints_succeeded: number;
  endpoints_failed: number;
}> {
  return (await request(
    "/api/v1/scans/infrastructure",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    },
    45000,
  )) as {
    assessment: AssessmentRecord;
    report: unknown;
    endpoints_checked: number;
    endpoints_succeeded: number;
    endpoints_failed: number;
  };
}

export type MonitorCadence =
  | "hourly"
  | "every_6_hours"
  | "every_12_hours"
  | "daily"
  | "weekly";
export type MonitorExecutionTarget =
  | { type: "cloud" }
  | { type: "agent"; agent_id: string };

export interface InfrastructureMonitor {
  id: string;
  organization_id: string;
  domain: string;
  enabled: boolean;
  execution_target: MonitorExecutionTarget;
  cadence: MonitorCadence;
  next_run_at: string;
  last_run_at?: string | null;
  last_success_at?: string | null;
  last_failure_at?: string | null;
  last_assessment_id?: string | null;
  last_error?: string | null;
  created_at: string;
  updated_at: string;
}

export interface DomainHistoryEntry {
  assessment_id: string;
  created_at: string;
  posture_score: number;
  posture_grade: string;
  protocols_identified: string[];
  findings_count: number;
  drift_events: DriftEvent[];
  security_regressions: DriftEvent[];
}

export interface DomainHistoryResponse {
  domain: string;
  monitor: InfrastructureMonitor | null;
  history: DomainHistoryEntry[];
}

export async function fetchMonitors(): Promise<InfrastructureMonitor[]> {
  return (await request("/api/v1/monitors")) as InfrastructureMonitor[];
}

export async function createMonitor(data: {
  domain: string;
  cadence: MonitorCadence;
  target: MonitorExecutionTarget;
}): Promise<InfrastructureMonitor> {
  return (await request("/api/v1/monitors", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  })) as InfrastructureMonitor;
}

export async function runNowMonitor(
  id: string,
): Promise<{ status: string; job_id: string; monitor_id: string }> {
  return (await request(`/api/v1/monitors/${id}/run_now`, {
    method: "POST",
  })) as {
    status: string;
    job_id: string;
    monitor_id: string;
  };
}

export async function deleteMonitor(id: string): Promise<{ deleted: boolean }> {
  return (await request(`/api/v1/monitors/${id}`, { method: "DELETE" })) as {
    deleted: boolean;
  };
}

export async function fetchDomainHistory(
  domain: string,
): Promise<DomainHistoryResponse> {
  return (await request(
    `/api/v1/monitors/domain/${encodeURIComponent(domain)}/history`,
  )) as DomainHistoryResponse;
}
