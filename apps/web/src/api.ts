import { z } from "zod";

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

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(path, {
    ...init,
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok)
    throw new Error(
      `Core request failed (${response.status}): ${(await response.text()).slice(0, 500)}`,
    );
  return response.json();
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
  const response = await fetch(`/api/v1/assets/${id}/report?format=${format}`, {
    signal: AbortSignal.timeout(15000),
  });
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
