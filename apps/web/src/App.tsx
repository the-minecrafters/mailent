import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import expired from "../../../fixtures/synthetic/smtp_cert_expired.json";
import rsa from "../../../fixtures/synthetic/smtp_static_rsa.json";
import legacy from "../../../fixtures/synthetic/smtp_tls10_legacy.json";
import modern from "../../../fixtures/synthetic/smtp_tls13_healthy.json";
import {
  type ArchivedReportRecord,
  type ArchivedReportSummary,
  type Asset,
  type AssetPostureHistory,
  type AssetPostureResponse,
  type AssetVerificationState,
  archiveReport,
  type CertificateRecord,
  createIntegration,
  type DriftEvent,
  deleteIntegration,
  downloadArchivedReport,
  downloadAssetReport,
  type EmailSession,
  evaluateObservation,
  type Finding,
  fetchArchivedReports,
  fetchAsset,
  fetchAssetCertificates,
  fetchAssetDrift,
  fetchAssetFindings,
  fetchAssetPosture,
  fetchAssetPostureHistory,
  fetchAssetSessions,
  fetchAssets,
  fetchAssetVerification,
  fetchDriftEvents,
  fetchFindings,
  fetchIntegrations,
  fetchInvestigation,
  fetchInvestigations,
  fetchPolicies,
  fetchSensors,
  fetchSessionDetail,
  fetchSessionPosture,
  fetchSessions,
  type IntegrationConfig,
  type PolicyPackSummary,
  type PolicySimulationResult,
  type ProbeRun,
  type RemediationGuidance,
  type RemediationRecord,
  type ReportFormat,
  readReadiness,
  type SecurityPosture,
  type SensorRecord,
  type SessionDetail,
  type SessionListItem,
  simulatePolicy,
  type TimelineEvent,
  testIntegration,
  triggerAssetProbe,
  updateIntegration,
  type VerificationFreshness,
} from "./api";
import { ProbePanel } from "./ProbePanel";
import { RemediationWorkflow } from "./RemediationWorkflow";

export function PostureGradeBadge({ grade }: { grade: string }) {
  const g = grade.toUpperCase();
  return <span className={`grade-badge ${g}`}>{g}</span>;
}

export function VerificationFreshnessBadge({
  freshness,
}: {
  freshness?: VerificationFreshness | string;
}) {
  const f = (freshness || "never_verified").toLowerCase();
  const label =
    f === "fresh"
      ? "Fresh (<24h)"
      : f === "aging"
        ? "Aging (24h-7d)"
        : f === "stale"
          ? "Stale (>7d / Drift)"
          : "Never Verified";
  return <span className={`badge ${f}`}>{label}</span>;
}

export function EvidenceGapBadge({ state }: { state: string }) {
  const s = state.toLowerCase();
  const cls = s.replace(/\s+/g, "-");
  return <span className={`evidence-state ${cls}`}>{state}</span>;
}

export function PosturePanel({ posture }: { posture: SecurityPosture }) {
  return (
    <section className="card" aria-label="Security Posture">
      <div className="card-header">
        <h3 className="card-title">
          Security Posture (model v{posture.score_version})
        </h3>
        <PostureGradeBadge grade={posture.grade} />
      </div>

      <div className="metrics-grid">
        <div className="metric-tile">
          <div className="metric-tile-label">Score</div>
          <div className="metric-tile-value">
            {posture.score.toFixed(0)} / 100
          </div>
          {posture.score_capped && (
            <div className="metric-tile-sub">
              {posture.pre_cap_score.toFixed(0)} → {posture.score.toFixed(0)}
            </div>
          )}
        </div>

        <div className="metric-tile">
          <div className="metric-tile-label">Grade</div>
          <PostureGradeBadge grade={posture.grade} />
        </div>

        <div className="metric-tile">
          <div className="metric-tile-label">Findings Considered</div>
          <div className="metric-tile-value">{posture.findings_considered}</div>
        </div>
      </div>

      <h4 style={{ margin: "1.25rem 0 0.5rem", fontSize: "0.9375rem" }}>
        Category Breakdown
      </h4>
      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        {posture.categories.map((cat) => (
          <div
            key={cat.category}
            style={{
              padding: "0.75rem",
              background: "var(--surface-subtle)",
              borderRadius: "6px",
              border: "1px solid var(--hairline)",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                marginBottom: "0.35rem",
              }}
            >
              <span>{cat.category.replace(/_/g, " ")}</span>
              <span className="mono">
                {cat.score.toFixed(0)} × {cat.weight.toFixed(2)}
              </span>
            </div>
            <div
              style={{
                height: "6px",
                background: "#e5e7eb",
                borderRadius: "3px",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${Math.max(0, Math.min(100, cat.score))}%`,
                  background:
                    cat.score >= 85
                      ? "#10b981"
                      : cat.score >= 70
                        ? "#f59e0b"
                        : "#ef4444",
                }}
              />
            </div>
            {cat.finding_rule_ids.length > 0 && (
              <p
                className="mono secondary-text"
                style={{ margin: "0.4rem 0 0", fontSize: "0.75rem" }}
              >
                {cat.finding_rule_ids.join(", ")}
              </p>
            )}
          </div>
        ))}
      </div>

      {posture.deductions.length > 0 && (
        <details style={{ marginTop: "1rem" }}>
          <summary style={{ cursor: "pointer", fontSize: "0.875rem" }}>
            View {posture.deductions.length} deduction(s)
          </summary>
          <div style={{ marginTop: "0.5rem" }}>
            {posture.deductions.map((d, i) => (
              <div
                key={i}
                style={{
                  padding: "0.5rem",
                  borderBottom: "1px solid var(--hairline)",
                  fontSize: "0.8125rem",
                }}
              >
                <div
                  style={{ display: "flex", justifyContent: "space-between" }}
                >
                  <span className="mono">{d.rule_id}</span>
                  <span style={{ color: "var(--status-danger-ink)" }}>
                    -{d.points} pts
                  </span>
                </div>
                <div className="secondary-text" style={{ fontSize: "0.75rem" }}>
                  {d.evidence_description}
                </div>
              </div>
            ))}
          </div>
        </details>
      )}
    </section>
  );
}

export function App({ initialView = "overview" }: { initialView?: string }) {
  const [activeTab, setActiveTab] = useState(initialView);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    null,
  );
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<
    string | null
  >(null);

  const readinessQuery = useQuery({
    queryKey: ["readiness"],
    queryFn: readReadiness,
    refetchInterval: 10000,
  });

  const tabTitles: Record<string, string> = {
    overview: "Cryptographic Posture & Operational Overview",
    assets: "Mail Assets & Identity Inventory",
    sessions: "Observed Email Sessions & Handshake Timelines",
    findings: "Active Findings & Cryptographic Non-Compliances",
    investigations: "Forensic Investigation Cases",
    remediations: "Remediation & Active Verification Lifecycle",
    simulation: "Policy Twin & Historical Traffic Simulation",
    reports: "Forensic Reports & Evidence Archive Vault",
    integrations: "SIEM & SOC Workflow Integrations",
    sensors: "Passive Sensor Fleet Status",
    evaluator: "Passive Observation Evaluator",
  };

  return (
    <div className="app-shell menu-layout">
      <aside className="console-sidebar">
        <div className="sidebar-brand">
          <div className="brand-title">
            <strong>MAILENT</strong>
            <span className="brand-badge">ANALYST CONSOLE</span>
          </div>
          <div className="brand-sub">Passive Cryptographic Observability</div>
        </div>

        <div className="sidebar-status">
          {readinessQuery.isPending ? (
            <span role="status" className="badge">
              <span className="status-indicator warning" /> Connecting to core…
            </span>
          ) : readinessQuery.isError ? (
            <span role="alert" className="badge critical">
              <span className="status-indicator offline" /> Core unavailable.{" "}
              {(readinessQuery.error as any)?.message}
            </span>
          ) : (
            <span className="badge fresh">
              <span className="status-indicator online" />{" "}
              <strong>
                {readinessQuery.data?.ready ? "Core ready" : "Core not ready"}
              </strong>{" "}
              · {readinessQuery.data?.policy_name} v
              {readinessQuery.data?.policy_version} ·{" "}
              {readinessQuery.data?.rule_count} rules · Storage:{" "}
              {readinessQuery.data?.storage}
            </span>
          )}
        </div>

        <nav className="sidebar-nav" aria-label="Main Navigation">
          <div className="nav-group">
            <div className="nav-group-title">OBSERVABILITY</div>
            <button
              className={`nav-item ${activeTab === "overview" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("overview");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ◉
              </span>
              <span>Overview</span>
            </button>
            <button
              className={`nav-item ${activeTab === "assets" ? "active" : ""}`}
              onClick={() => {
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("assets");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ◈
              </span>
              <span>Assets</span>
            </button>
            <button
              className={`nav-item ${activeTab === "sessions" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedInvestigationId(null);
                setActiveTab("sessions");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ☵
              </span>
              <span>Sessions</span>
            </button>
            <button
              className={`nav-item ${activeTab === "sensors" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("sensors");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ◬
              </span>
              <span>Sensors</span>
            </button>
          </div>

          <div className="nav-group">
            <div className="nav-group-title">SECURITY &amp; POSTURE</div>
            <button
              className={`nav-item ${activeTab === "findings" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("findings");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ⚠
              </span>
              <span>Findings</span>
            </button>
            <button
              className={`nav-item ${activeTab === "investigations" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setActiveTab("investigations");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ⌕
              </span>
              <span>Investigations</span>
            </button>
            <button
              className={`nav-item ${activeTab === "remediations" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("remediations");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ✓
              </span>
              <span>Remediation</span>
            </button>
          </div>

          <div className="nav-group">
            <div className="nav-group-title">GOVERNANCE &amp; TOOLS</div>
            <button
              className={`nav-item ${activeTab === "simulation" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("simulation");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ⚇
              </span>
              <span>Policy Twin &amp; Simulation</span>
            </button>
            <button
              className={`nav-item ${activeTab === "reports" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("reports");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ▤
              </span>
              <span>Reports &amp; Archive</span>
            </button>
            <button
              className={`nav-item ${activeTab === "integrations" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("integrations");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ⇋
              </span>
              <span>Integrations &amp; CEF</span>
            </button>
            <button
              className={`nav-item ${activeTab === "evaluator" ? "active" : ""}`}
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("evaluator");
              }}
            >
              <span className="nav-icon" aria-hidden="true">
                ⚡
              </span>
              <span>Observation Evaluator</span>
            </button>
          </div>
        </nav>
      </aside>

      <div className="console-body">
        <header className="console-topbar">
          <div className="topbar-context">
            <span className="topbar-title">
              {tabTitles[activeTab] ?? "Analyst Console"}
            </span>
          </div>
          <div
            style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}
          >
            <button
              className="btn"
              onClick={() => {
                setSelectedAssetId(null);
                setSelectedSessionId(null);
                setSelectedInvestigationId(null);
                setActiveTab("evaluator");
              }}
            >
              Inspect Observation
            </button>
          </div>
        </header>

        <main className="console-main">
          {activeTab === "overview" && (
            <OverviewTab
              onSelectAsset={(id) => {
                setSelectedAssetId(id);
                setActiveTab("assets");
              }}
              onSelectSession={(id) => {
                setSelectedSessionId(id);
                setActiveTab("sessions");
              }}
              onSelectInvestigation={(id) => {
                setSelectedInvestigationId(id);
                setActiveTab("investigations");
              }}
              onSelectSimulation={() => setActiveTab("simulation")}
            />
          )}

          {activeTab === "assets" && (
            <AssetsTab
              selectedAssetId={selectedAssetId}
              onSelectAsset={(id) => setSelectedAssetId(id)}
              onBack={() => setSelectedAssetId(null)}
            />
          )}

          {activeTab === "sessions" && (
            <SessionsTab
              selectedSessionId={selectedSessionId}
              onSelectSession={(id) => setSelectedSessionId(id)}
              onBack={() => setSelectedSessionId(null)}
            />
          )}

          {activeTab === "findings" && (
            <FindingsTab
              onStartRemediation={(assetId) => {
                setSelectedAssetId(assetId);
                setActiveTab("assets");
              }}
            />
          )}

          {activeTab === "investigations" && (
            <InvestigationsTab
              selectedId={selectedInvestigationId}
              onSelect={(id) => setSelectedInvestigationId(id)}
              onBack={() => setSelectedInvestigationId(null)}
            />
          )}

          {activeTab === "remediations" && <RemediationsTab />}

          {activeTab === "simulation" && <SimulationTab />}

          {activeTab === "reports" && <ReportsTab />}

          {activeTab === "integrations" && <IntegrationsTab />}

          {activeTab === "sensors" && <SensorsTab />}

          {activeTab === "evaluator" && (
            <EvaluatorTab readiness={readinessQuery.data} />
          )}
        </main>
      </div>
    </div>
  );
}

// ---------------------------------------------------------
// 1. OVERVIEW VIEW
// ---------------------------------------------------------
function OverviewTab({
  onSelectAsset,
  onSelectSession,
  onSelectInvestigation,
  onSelectSimulation,
}: {
  onSelectAsset: (id: string) => void;
  onSelectSession: (id: string) => void;
  onSelectInvestigation: (id: string) => void;
  onSelectSimulation: () => void;
}) {
  const assetsQuery = useQuery({ queryKey: ["assets"], queryFn: fetchAssets });
  const findingsQuery = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
  });
  const driftQuery = useQuery({
    queryKey: ["drift"],
    queryFn: fetchDriftEvents,
  });
  const investigationsQuery = useQuery({
    queryKey: ["investigations"],
    queryFn: fetchInvestigations,
  });

  const assets = assetsQuery.data ?? [];
  const findings = findingsQuery.data ?? [];
  const driftEvents = driftQuery.data ?? [];
  const investigations = investigationsQuery.data ?? [];

  const criticalCount = findings.filter(
    (f) => f.severity === "critical",
  ).length;
  const highCount = findings.filter((f) => f.severity === "high").length;

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Security Analyst Overview</h1>
        <p className="secondary-text">
          Continuous passive traffic intelligence, deterministic posture
          scoring, and scheduled active re-verification.
        </p>
      </div>

      <div className="metrics-grid">
        <div className="metric-tile">
          <div className="metric-tile-label">Monitored Mail Assets</div>
          <div className="metric-tile-value">{assets.length}</div>
          <div className="metric-tile-sub">Discovered via passive PCAP</div>
        </div>

        <div className="metric-tile">
          <div className="metric-tile-label">Active Findings</div>
          <div className="metric-tile-value">{findings.length}</div>
          <div className="metric-tile-sub">
            <span style={{ color: "var(--status-danger-ink)" }}>
              {criticalCount} Critical
            </span>{" "}
            · {highCount} High
          </div>
        </div>

        <div className="metric-tile">
          <div className="metric-tile-label">Configuration Drift Events</div>
          <div className="metric-tile-value">{driftEvents.length}</div>
          <div className="metric-tile-sub">Tracked baseline regressions</div>
        </div>

        <div className="metric-tile">
          <div className="metric-tile-label">Open Investigations</div>
          <div className="metric-tile-value">
            {investigations.filter((i) => i.status !== "resolved").length}
          </div>
          <div className="metric-tile-sub">Correlated incident cases</div>
        </div>
      </div>

      <div className="grid-2col">
        {/* Assets needing attention */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Assets Needing Immediate Attention</h3>
            <span className="badge warning">Priority Action</span>
          </div>

          {assets.length === 0 ? (
            <p className="secondary-text">
              No mail assets currently discovered.
            </p>
          ) : (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "0.75rem",
              }}
            >
              {assets.slice(0, 5).map((asset) => (
                <div
                  key={asset.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "0.75rem 1rem",
                    border: "1px solid var(--hairline)",
                    borderRadius: "6px",
                    background: "var(--surface-alt)",
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600 }}>
                      {asset.primary_name || asset.addresses[0] || "Unknown"}
                    </div>
                    <div
                      className="mono secondary-text"
                      style={{ fontSize: "0.75rem" }}
                    >
                      {asset.addresses.join(", ")}
                    </div>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      gap: "0.5rem",
                      alignItems: "center",
                    }}
                  >
                    <span className="badge">
                      {asset.active_findings_count} finding(s)
                    </span>
                    <button
                      className="btn"
                      style={{
                        padding: "0.25rem 0.65rem",
                        fontSize: "0.75rem",
                      }}
                      onClick={() => onSelectAsset(asset.id)}
                    >
                      View
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Drift & Changes */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Recent Drift & Security Changes</h3>
            <span className="badge">Audit Trail</span>
          </div>

          {driftEvents.length === 0 ? (
            <p className="secondary-text">
              No configuration drift detected since baseline creation.
            </p>
          ) : (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "0.6rem",
              }}
            >
              {driftEvents.slice(0, 5).map((event) => (
                <div
                  key={event.id}
                  style={{
                    padding: "0.65rem 0.85rem",
                    border: "1px solid var(--hairline)",
                    borderRadius: "6px",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      marginBottom: "0.2rem",
                    }}
                  >
                    <span style={{ fontSize: "0.875rem", fontWeight: 600 }}>
                      {event.title}
                    </span>
                    <span
                      className="mono secondary-text"
                      style={{ fontSize: "0.75rem" }}
                    >
                      {new Date(event.observed_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <div
                    className="secondary-text"
                    style={{ fontSize: "0.8125rem" }}
                  >
                    {event.description}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------
// 2. ASSETS VIEW & DETAIL
// ---------------------------------------------------------
function AssetsTab({
  selectedAssetId,
  onSelectAsset,
  onBack,
}: {
  selectedAssetId: string | null;
  onSelectAsset: (id: string) => void;
  onBack: () => void;
}) {
  const assetsQuery = useQuery({ queryKey: ["assets"], queryFn: fetchAssets });
  const assets = assetsQuery.data ?? [];

  if (selectedAssetId) {
    return <AssetDetailView assetId={selectedAssetId} onBack={onBack} />;
  }

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Discovered Mail Assets</h1>
        <p className="secondary-text">
          Network endpoints continuously discovered through passive observation.
          No active probes are executed without explicit operator allowlist
          scope.
        </p>
      </div>

      {assetsQuery.isPending && <p role="status">Loading assets…</p>}
      {assetsQuery.isError && (
        <p role="alert" className="error">
          Failed to load assets: {assetsQuery.error.message}
        </p>
      )}

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Asset Target</th>
              <th>IP Addresses</th>
              <th>Endpoints</th>
              <th>Findings</th>
              <th>Probe Allowlist</th>
              <th>Last Seen</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {assets.length === 0 && !assetsQuery.isPending ? (
              <tr>
                <td
                  colSpan={7}
                  style={{ textAlign: "center", padding: "2rem" }}
                >
                  <span className="secondary-text">
                    No assets discovered yet. Passive sensors stream
                    observations automatically.
                  </span>
                </td>
              </tr>
            ) : (
              assets.map((asset) => (
                <tr key={asset.id}>
                  <td>
                    <div style={{ fontWeight: 600 }}>
                      {asset.primary_name ||
                        asset.hostnames[0] ||
                        asset.addresses[0]}
                    </div>
                    {asset.hostnames.length > 0 &&
                      asset.hostnames.join(", ") !== asset.primary_name && (
                        <div
                          className="mono secondary-text"
                          style={{ fontSize: "0.75rem" }}
                        >
                          {asset.hostnames.join(", ")}
                        </div>
                      )}
                  </td>
                  <td className="mono">{asset.addresses.join(", ")}</td>
                  <td>
                    {asset.endpoints.map((e, idx) => (
                      <span
                        key={idx}
                        className="badge"
                        style={{ marginRight: "0.35rem" }}
                      >
                        {e.protocol.toUpperCase()}:{e.port}
                      </span>
                    ))}
                  </td>
                  <td>
                    {asset.active_findings_count > 0 ? (
                      <span className="badge high">
                        {asset.active_findings_count} finding(s)
                      </span>
                    ) : (
                      <span className="badge fresh">Clean</span>
                    )}
                  </td>
                  <td>
                    {asset.probe_authorized ? (
                      <span className="badge fresh">Authorized</span>
                    ) : (
                      <span className="badge">Scope Excluded</span>
                    )}
                  </td>
                  <td
                    className="mono secondary-text"
                    style={{ fontSize: "0.8125rem" }}
                  >
                    {new Date(asset.last_seen).toLocaleString()}
                  </td>
                  <td>
                    <button
                      className="btn"
                      onClick={() => onSelectAsset(asset.id)}
                    >
                      View Asset
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AssetDetailView({
  assetId,
  onBack,
}: {
  assetId: string;
  onBack: () => void;
}) {
  const queryClient = useQueryClient();
  const [archiveNotes, setArchiveNotes] = useState("");
  const [isArchiving, setIsArchiving] = useState(false);
  const [archiveStatus, setArchiveStatus] = useState<string | null>(null);

  const assetQuery = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () => fetchAsset(assetId),
  });
  const postureQuery = useQuery({
    queryKey: ["asset-posture", assetId],
    queryFn: () => fetchAssetPosture(assetId),
  });
  const historyQuery = useQuery({
    queryKey: ["asset-posture-history", assetId],
    queryFn: () => fetchAssetPostureHistory(assetId),
  });
  const verificationQuery = useQuery({
    queryKey: ["asset-verification", assetId],
    queryFn: () => fetchAssetVerification(assetId),
  });
  const certsQuery = useQuery({
    queryKey: ["asset-certs", assetId],
    queryFn: () => fetchAssetCertificates(assetId),
  });
  const driftQuery = useQuery({
    queryKey: ["asset-drift", assetId],
    queryFn: () => fetchAssetDrift(assetId),
  });

  const probeMutation = useMutation({
    mutationFn: () => triggerAssetProbe(assetId, 25, "smtp"),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["asset-verification", assetId],
      });
      void queryClient.invalidateQueries({
        queryKey: ["asset-posture", assetId],
      });
      void queryClient.invalidateQueries({
        queryKey: ["asset-posture-history", assetId],
      });
    },
  });

  const handleArchiveReport = async () => {
    setIsArchiving(true);
    setArchiveStatus(null);
    try {
      const record = await archiveReport({
        subject_kind: "asset",
        subject_id: assetId,
        notes: archiveNotes || undefined,
        archived_by: "analyst",
      });
      setArchiveStatus(
        `Report archived successfully! Fingerprint: ${record.fingerprint.slice(0, 16)}...`,
      );
      setArchiveNotes("");
      void queryClient.invalidateQueries({ queryKey: ["archived-reports"] });
    } catch (e: any) {
      setArchiveStatus(`Archive failed: ${e.message}`);
    } finally {
      setIsArchiving(false);
    }
  };

  const asset = assetQuery.data;
  const postureData = postureQuery.data;
  const historyData = historyQuery.data;
  const verification = verificationQuery.data;
  const certs = certsQuery.data ?? [];
  const driftEvents = driftQuery.data ?? [];

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <button onClick={onBack}>← Back to Assets</button>
        <div>
          <h2>PERSISTENT ASSET IDENTITY & POSTURE</h2>
          <div className="mono secondary-text">
            {asset?.primary_name || asset?.addresses[0]} · ID: {assetId}
          </div>
        </div>
      </div>

      {/* Freshness & Verification Status Bar */}
      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <div className="card-header">
          <h3 className="card-title">Active Verification Freshness</h3>
          <VerificationFreshnessBadge freshness={verification?.freshness} />
        </div>

        <div className="metrics-grid">
          <div className="metric-tile">
            <div className="metric-tile-label">Freshness State</div>
            <div className="metric-tile-value">
              <VerificationFreshnessBadge freshness={verification?.freshness} />
            </div>
            <div className="metric-tile-sub">
              {verification?.freshness_reasons.join(". ") ||
                "Evaluated by policy"}
            </div>
          </div>

          <div className="metric-tile">
            <div className="metric-tile-label">Last Active Verification</div>
            <div className="metric-tile-value" style={{ fontSize: "1.2rem" }}>
              {verification?.last_verified_at
                ? new Date(verification.last_verified_at).toLocaleDateString()
                : "Never verified"}
            </div>
            <div className="metric-tile-sub">
              Outcome: {verification?.last_probe_outcome || "None"}
            </div>
          </div>

          <div className="metric-tile">
            <div className="metric-tile-label">Consecutive Failures</div>
            <div className="metric-tile-value">
              {verification?.consecutive_failures ?? 0}
            </div>
            <div className="metric-tile-sub">
              {verification?.consecutive_failures &&
              verification.consecutive_failures >= 3
                ? "Backoff enabled (avoiding target spam)"
                : "Normal recheck frequency"}
            </div>
          </div>
        </div>

        <div
          style={{
            display: "flex",
            gap: "1rem",
            alignItems: "center",
            marginTop: "1rem",
          }}
        >
          <button
            className="btn-primary"
            onClick={() => probeMutation.mutate()}
            disabled={probeMutation.isPending || !asset?.probe_authorized}
          >
            {probeMutation.isPending
              ? "Running Verification..."
              : "Run Verification Probe Now"}
          </button>
          {!asset?.probe_authorized && (
            <span className="secondary-text" style={{ fontSize: "0.8125rem" }}>
              (Target not in probe allowlist scope)
            </span>
          )}
          {verification?.drift_detected_since_verification && (
            <span className="badge stale">
              Drift detected since last verification!
            </span>
          )}
        </div>
      </div>

      {/* Posture Panel */}
      {postureData && <PosturePanel posture={postureData.posture} />}

      {/* Guidance Surfaces */}
      {postureData && (
        <div style={{ marginTop: "1.5rem" }}>
          <div className="card">
            <h3>
              Remediation Guidance (
              {
                postureData.guidance.filter((g) => g.kind === "remediation")
                  .length
              }
              )
            </h3>
            {postureData.guidance
              .filter((g) => g.kind === "remediation")
              .map((g) => (
                <div
                  key={g.id}
                  style={{
                    padding: "1rem",
                    border: "1px solid var(--hairline)",
                    borderRadius: "8px",
                    marginBottom: "1rem",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      marginBottom: "0.5rem",
                    }}
                  >
                    <strong>{g.title}</strong>
                    <span className={`badge ${g.severity}`}>{g.severity}</span>
                  </div>
                  <p className="secondary-text">{g.recommendation}</p>
                  {g.compatibility_caveats.length > 0 && (
                    <div style={{ marginTop: "0.5rem" }}>
                      <span style={{ fontSize: "0.8125rem", fontWeight: 600 }}>
                        Observed compatibility caveats
                      </span>
                      <ul
                        style={{ margin: "0.25rem 0", paddingLeft: "1.25rem" }}
                      >
                        {g.compatibility_caveats.map((c, idx) => (
                          <li
                            key={idx}
                            className="secondary-text"
                            style={{ fontSize: "0.8125rem" }}
                          >
                            {c}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div style={{ marginTop: "0.75rem" }}>
                    <RemediationWorkflow assetId={assetId} guidance={g} />
                  </div>
                </div>
              ))}
          </div>

          <div className="card">
            <h3>
              Best Practice Guidance (
              {
                postureData.guidance.filter((g) => g.kind === "best_practice")
                  .length
              }
              )
            </h3>
            {postureData.guidance
              .filter((g) => g.kind === "best_practice")
              .map((g) => (
                <div
                  key={g.id}
                  style={{
                    padding: "1rem",
                    border: "1px solid var(--hairline)",
                    borderRadius: "8px",
                    marginBottom: "0.75rem",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      marginBottom: "0.25rem",
                    }}
                  >
                    <strong>{g.title}</strong>
                    <span className="badge">Best Practice</span>
                  </div>
                  <p className="secondary-text">{g.recommendation}</p>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Observed Certificates Surface */}
      <div className="card" style={{ marginTop: "1.5rem" }}>
        <h3>Observed Leaf Certificates ({certs.length})</h3>
        {certs.length === 0 ? (
          <p className="secondary-text">
            No certificates recorded for this asset.
          </p>
        ) : (
          certs.map((c) => (
            <div
              key={c.sha256_fingerprint}
              style={{
                padding: "1rem",
                border: "1px solid var(--hairline)",
                borderRadius: "8px",
                marginBottom: "1rem",
              }}
            >
              <dl className="cert-dl">
                <dt>Subject</dt>
                <dd className="mono">{c.subject}</dd>
                <dt>Issuer</dt>
                <dd className="mono">{c.issuer}</dd>
                <dt>Fingerprint (SHA-256)</dt>
                <dd className="mono">{c.sha256_fingerprint}</dd>
                <dt>Validity</dt>
                <dd className="mono">
                  {c.not_before} → {c.not_after}
                </dd>
                {c.sans.length > 0 && (
                  <>
                    <dt>SANs</dt>
                    <dd className="mono">{c.sans.join(", ")}</dd>
                  </>
                )}
              </dl>
            </div>
          ))
        )}
      </div>

      {/* Configuration Drift Surface */}
      <div className="card" style={{ marginTop: "1.5rem" }}>
        <h3>Configuration Drift ({driftEvents.length})</h3>
        {driftEvents.length === 0 ? (
          <p className="secondary-text">
            No drift events recorded for this asset.
          </p>
        ) : (
          driftEvents.map((d) => (
            <div
              key={d.id}
              style={{
                padding: "0.875rem",
                border: "1px solid var(--hairline)",
                borderRadius: "6px",
                marginBottom: "0.75rem",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginBottom: "0.25rem",
                }}
              >
                <strong>{d.title}</strong>
                <span
                  className="mono secondary-text"
                  style={{ fontSize: "0.75rem" }}
                >
                  {new Date(d.observed_at).toLocaleString()}
                </span>
              </div>
              <p className="secondary-text" style={{ margin: "0.25rem 0" }}>
                {d.description}
              </p>
              {d.previous_value && (
                <div
                  className="mono secondary-text"
                  style={{ fontSize: "0.75rem" }}
                >
                  Previous: {d.previous_value} → New: {d.new_value}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Forensic Report Export & Freeze Surface */}
      <div className="card" style={{ marginTop: "1.5rem" }}>
        <div className="card-header">
          <h3 className="card-title">Forensic Report</h3>
          <a
            href={`/api/v1/assets/${assetId}/report?format=html`}
            target="_blank"
            rel="noreferrer"
            style={{ fontSize: "0.875rem", color: "var(--accent)" }}
          >
            View HTML report
          </a>
        </div>
        <p className="secondary-text">
          Export an objective, cryptographically signed forensic case report or
          freeze the state into an immutable archived record.
        </p>

        <div
          style={{
            display: "flex",
            gap: "0.75rem",
            flexWrap: "wrap",
            marginBottom: "1rem",
          }}
        >
          <button onClick={() => downloadAssetReport(assetId, "json")}>
            Export JSON
          </button>
          <button onClick={() => downloadAssetReport(assetId, "html")}>
            Export HTML
          </button>
          <button onClick={() => downloadAssetReport(assetId, "pdf")}>
            Export PDF
          </button>
        </div>

        <div
          style={{
            marginTop: "1.25rem",
            paddingTop: "1.25rem",
            borderTop: "1px solid var(--hairline)",
          }}
        >
          <h4 style={{ margin: "0 0 0.5rem" }}>Freeze Case Report Snapshot</h4>
          <p className="secondary-text" style={{ fontSize: "0.8125rem" }}>
            Archives the exact report with a SHA-256 fingerprint for evidentiary
            integrity. Subsequent policy changes will never alter archived
            records.
          </p>
          <div
            style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}
          >
            <input
              type="text"
              placeholder="Optional analyst investigation notes..."
              value={archiveNotes}
              onChange={(e) => setArchiveNotes(e.target.value)}
              style={{ flex: 1 }}
            />
            <button
              className="btn-primary"
              onClick={handleArchiveReport}
              disabled={isArchiving}
            >
              {isArchiving ? "Archiving..." : "Archive Report"}
            </button>
          </div>
          {archiveStatus && (
            <div
              className="secondary-text"
              style={{ marginTop: "0.5rem", fontSize: "0.8125rem" }}
            >
              {archiveStatus}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------
// 3. SESSIONS VIEW & FORENSIC DETAIL
// ---------------------------------------------------------
function SessionsTab({
  selectedSessionId,
  onSelectSession,
  onBack,
}: {
  selectedSessionId: string | null;
  onSelectSession: (id: string) => void;
  onBack: () => void;
}) {
  const sessionsQuery = useQuery({
    queryKey: ["sessions"],
    queryFn: fetchSessions,
  });
  const sessions = sessionsQuery.data ?? [];

  if (selectedSessionId) {
    return <SessionDetailView sessionId={selectedSessionId} onBack={onBack} />;
  }

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Analyzed Mail Sessions</h1>
        <p className="secondary-text">
          Passive mail traffic sessions reconstructed with forensic connection
          timelines.
        </p>
      </div>

      {sessionsQuery.isPending && (
        <p role="status">Loading captured sessions…</p>
      )}
      {sessionsQuery.isError && (
        <p role="alert" className="error">
          Failed to load sessions: {sessionsQuery.error.message}
        </p>
      )}

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Client Flow</th>
              <th>Server Flow</th>
              <th>Protocol</th>
              <th>STARTTLS</th>
              <th>TLS Version</th>
              <th>Cipher Suite</th>
              <th>Findings</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {sessions.length === 0 && !sessionsQuery.isPending ? (
              <tr>
                <td
                  colSpan={8}
                  style={{ textAlign: "center", padding: "2rem" }}
                >
                  <span className="secondary-text">
                    No sessions recorded yet. Feed PCAP observations through the
                    sensor or evaluator.
                  </span>
                </td>
              </tr>
            ) : (
              sessions.map((s) => (
                <tr key={s.session_id}>
                  <td className="mono">{s.client}</td>
                  <td className="mono">{s.server}</td>
                  <td>{s.protocol.toUpperCase()}</td>
                  <td>
                    <span className="badge">{s.starttls_state || "none"}</span>
                  </td>
                  <td>{s.tls_version || "Plaintext"}</td>
                  <td
                    className="mono secondary-text"
                    style={{ fontSize: "0.75rem" }}
                  >
                    {s.cipher_suite || "None"}
                  </td>
                  <td>
                    {s.findings_count > 0 ? (
                      <span className="badge high">
                        {s.findings_count} finding(s)
                      </span>
                    ) : (
                      <span className="badge fresh">0</span>
                    )}
                  </td>
                  <td>
                    <button
                      className="btn"
                      onClick={() => onSelectSession(s.session_id)}
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SessionDetailView({
  sessionId,
  onBack,
}: {
  sessionId: string;
  onBack: () => void;
}) {
  const sessionQuery = useQuery({
    queryKey: ["session-detail", sessionId],
    queryFn: () => fetchSessionDetail(sessionId),
  });

  const detail = sessionQuery.data;
  if (!detail) {
    return (
      <div>
        <button onClick={onBack}>← Back to Sessions</button>
        <div style={{ padding: "2rem", textAlign: "center" }}>
          Loading session evidence...
        </div>
      </div>
    );
  }

  const s = detail.session;
  const timeline = s.capture?.timeline ?? [];

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <button onClick={onBack}>← Back to Sessions</button>
        <div>
          <h2>SESSION EVIDENCE & FORENSICS</h2>
          <div className="mono secondary-text">Session ID: {sessionId}</div>
        </div>
      </div>

      <div className="grid-2col">
        {/* Left Column: Metadata & Explicit Evidence Gaps */}
        <div>
          <div className="card">
            <h3>Connection Flow & Provenance</h3>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "0.75rem",
                fontSize: "0.875rem",
              }}
            >
              <div>
                <span className="secondary-text">Client:</span>{" "}
                <strong className="mono">
                  {s.flow.src_ip}:{s.flow.src_port}
                </strong>
              </div>
              <div>
                <span className="secondary-text">Server:</span>{" "}
                <strong className="mono">
                  {s.flow.dst_ip}:{s.flow.dst_port}
                </strong>
              </div>
              <div>
                <span className="secondary-text">Protocol:</span>{" "}
                <strong>{s.protocol.toUpperCase()}</strong>
              </div>
              <div>
                <span className="secondary-text">Sensor:</span>{" "}
                <span className="mono">{s.sensor_id}</span>
              </div>
            </div>
          </div>

          <div className="card">
            <h3>Explicit Cryptographic Facts & Evidence Gaps</h3>
            <p className="secondary-text" style={{ fontSize: "0.8125rem" }}>
              Every cryptographic state is evaluated strictly as observed facts.
              Absence of evidence is never equated with security.
            </p>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "0.6rem",
                marginTop: "1rem",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "0.5rem 0",
                  borderBottom: "1px solid var(--hairline)",
                }}
              >
                <span>TLS Protocol Version</span>
                <div>
                  {s.tls_version ? (
                    <EvidenceGapBadge state={`Observed (${s.tls_version})`} />
                  ) : (
                    <EvidenceGapBadge state="Not observed" />
                  )}
                </div>
              </div>

              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "0.5rem 0",
                  borderBottom: "1px solid var(--hairline)",
                }}
              >
                <span>Cipher Suite</span>
                <div>
                  {s.cipher_suite ? (
                    <EvidenceGapBadge
                      state={`Observed (${s.cipher_suite.name})`}
                    />
                  ) : (
                    <EvidenceGapBadge state="Not observed" />
                  )}
                </div>
              </div>

              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "0.5rem 0",
                  borderBottom: "1px solid var(--hairline)",
                }}
              >
                <span>Forward Secrecy</span>
                <div>
                  {detail.forward_secrecy === "supported" ? (
                    <EvidenceGapBadge state="Observed (PFS Supported)" />
                  ) : detail.forward_secrecy === "not_supported" ? (
                    <EvidenceGapBadge state="Observed (No PFS)" />
                  ) : (
                    <EvidenceGapBadge state="Unknown" />
                  )}
                </div>
              </div>

              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "0.5rem 0",
                  borderBottom: "1px solid var(--hairline)",
                }}
              >
                <span>Certificate Leaf</span>
                <div>
                  {s.certificate ? (
                    <EvidenceGapBadge state="Observed" />
                  ) : (
                    <EvidenceGapBadge state="Not observed" />
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Certificate observation */}
          {s.certificate && (
            <div className="card">
              <h3>Presented Leaf Certificate</h3>
              <div style={{ fontSize: "0.875rem" }}>
                <div>
                  <span className="secondary-text">Subject:</span>{" "}
                  <strong>{s.certificate.reference.subject}</strong>
                </div>
                <div style={{ marginTop: "0.35rem" }}>
                  <span className="secondary-text">Issuer:</span>{" "}
                  <strong>{s.certificate.reference.issuer}</strong>
                </div>
                <div
                  className="mono secondary-text"
                  style={{ fontSize: "0.75rem", margin: "0.35rem 0" }}
                >
                  Fingerprint: {s.certificate.reference.sha256_fingerprint}
                </div>
                <div
                  className="secondary-text"
                  style={{ fontSize: "0.8125rem" }}
                >
                  Valid: {s.certificate.validity.not_before} to{" "}
                  {s.certificate.validity.not_after}
                </div>
              </div>
            </div>
          )}

          {/* Associated Findings */}
          <div className="card">
            <h3>Associated Security Findings ({detail.findings.length})</h3>
            {detail.findings.length === 0 ? (
              <p className="secondary-text">
                No policy violations identified on this session.
              </p>
            ) : (
              detail.findings.map((f) => (
                <div
                  key={f.id}
                  style={{
                    padding: "0.75rem",
                    border: "1px solid var(--hairline)",
                    borderRadius: "6px",
                    marginBottom: "0.5rem",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      marginBottom: "0.25rem",
                    }}
                  >
                    <strong>{f.title}</strong>
                    <span className={`badge ${f.severity}`}>{f.severity}</span>
                  </div>
                  <div
                    className="mono secondary-text"
                    style={{ fontSize: "0.75rem" }}
                  >
                    {f.rule_id}
                  </div>
                  <p
                    className="secondary-text"
                    style={{ fontSize: "0.8125rem" }}
                  >
                    {f.description}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column: Forensic Timeline */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Session Timeline</h3>
            <span className="badge">Connection Progression</span>
          </div>

          {timeline.length === 0 ? (
            <p className="secondary-text">
              No timeline events recorded in capture evidence.
            </p>
          ) : (
            <div className="timeline">
              {timeline.map((event, idx) => {
                const title = formatTimelineKind(event.kind);
                return (
                  <div key={idx} className="timeline-item">
                    <div className="timeline-dot" />
                    <div className="timeline-content">
                      <div className="timeline-time">{event.timestamp}</div>
                      <div className="timeline-title">{title}</div>
                      <div
                        className="mono secondary-text"
                        style={{ fontSize: "0.75rem" }}
                      >
                        {event.source}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function formatTimelineKind(kind: string): string {
  switch (kind) {
    case "tcp_connected":
      return "TCP connected";
    case "smtp_greeting":
      return "SMTP greeting";
    case "ehlo":
      return "EHLO";
    case "starttls_advertised":
      return "STARTTLS advertised";
    case "starttls_requested":
      return "STARTTLS requested";
    case "starttls_accepted":
      return "STARTTLS accepted";
    case "tls_client_hello":
      return "TLS ClientHello";
    case "tls_server_hello":
      return "TLS ServerHello";
    case "certificate_observed":
      return "Certificate observed";
    case "tls_established":
      return "TLS established";
    default:
      return kind.replace(/_/g, " ");
  }
}

// ---------------------------------------------------------
// 4. FINDINGS VIEW
// ---------------------------------------------------------
function FindingsTab({
  onStartRemediation,
}: {
  onStartRemediation: (assetId: string) => void;
}) {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const findingsQuery = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
  });
  const findings = findingsQuery.data ?? [];

  const filtered = findings.filter((f) =>
    severityFilter === "all" ? true : f.severity === severityFilter,
  );

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          marginBottom: "1.5rem",
        }}
      >
        <div>
          <h1>Deterministic Security Findings</h1>
          <p className="secondary-text">
            Observable policy non-compliances evaluated against verifiable
            traffic. Explanations avoid technical jargon and outline concrete
            remediation.
          </p>
        </div>

        <div style={{ display: "flex", gap: "0.5rem" }}>
          {["all", "critical", "high", "medium", "low"].map((sev) => (
            <button
              key={sev}
              className={severityFilter === sev ? "btn-primary" : "btn"}
              style={{ padding: "0.35rem 0.75rem", fontSize: "0.75rem" }}
              onClick={() => setSeverityFilter(sev)}
            >
              {sev.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {findingsQuery.isPending && <p role="status">Loading findings…</p>}
      {findingsQuery.isError && (
        <p role="alert" className="error">
          Failed to load findings: {findingsQuery.error.message}
        </p>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        {filtered.length === 0 && !findingsQuery.isPending ? (
          <div
            className="card"
            style={{ textAlign: "center", padding: "2rem" }}
          >
            <span className="secondary-text">
              No security findings match the selected filter.
            </span>
          </div>
        ) : (
          filtered.map((finding) => (
            <div key={finding.id} className="card">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  marginBottom: "0.5rem",
                }}
              >
                <div>
                  <h3 style={{ margin: "0 0 0.25rem" }}>{finding.title}</h3>
                  <div
                    className="secondary-text"
                    style={{ fontSize: "0.8125rem" }}
                  >
                    <span className="mono">{finding.rule_id}</span> · Policy:{" "}
                    {finding.policy_name} v{finding.policy_version}
                  </div>
                </div>
                <span className={`badge ${finding.severity}`}>
                  {finding.severity.toUpperCase()}
                </span>
              </div>

              <p style={{ margin: "0.75rem 0" }}>{finding.description}</p>

              <div
                style={{
                  padding: "0.875rem",
                  background: "var(--surface-subtle)",
                  borderRadius: "6px",
                  border: "1px solid var(--hairline)",
                  marginTop: "0.75rem",
                }}
              >
                <div
                  style={{
                    fontSize: "0.8125rem",
                    fontWeight: 600,
                    marginBottom: "0.25rem",
                  }}
                >
                  Recommended Remediation:
                </div>
                <div
                  className="secondary-text"
                  style={{ fontSize: "0.875rem" }}
                >
                  {finding.remediation}
                </div>
              </div>

              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginTop: "1rem",
                  paddingTop: "0.75rem",
                  borderTop: "1px solid var(--hairline)",
                  fontSize: "0.8125rem",
                }}
              >
                <span className="secondary-text">
                  Affected systems: <strong>{finding.affected_count}</strong> ·
                  Evidence links: <strong>{finding.evidence.length}</strong>
                </span>

                <button
                  className="btn"
                  onClick={() => {
                    const sessId = finding.evidence[0]?.session_id;
                    if (sessId) onStartRemediation(sessId);
                  }}
                >
                  Investigate & Fix
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------
// 5. INVESTIGATIONS VIEW
// ---------------------------------------------------------
function InvestigationsTab({
  selectedId,
  onSelect,
  onBack,
}: {
  selectedId: string | null;
  onSelect: (id: string) => void;
  onBack: () => void;
}) {
  const invQuery = useQuery({
    queryKey: ["investigations"],
    queryFn: fetchInvestigations,
  });
  const investigations = invQuery.data ?? [];

  if (selectedId) {
    return <InvestigationDetailView id={selectedId} onBack={onBack} />;
  }

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Security Incident Investigations</h1>
        <p className="secondary-text">
          Correlated case files uniting findings, anomalies, intelligence, and
          active verification runs.
        </p>
      </div>

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Investigation Title</th>
              <th>Status</th>
              <th>Risk Level</th>
              <th>Anomalies</th>
              <th>Remediations</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {investigations.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  style={{ textAlign: "center", padding: "2rem" }}
                >
                  <span className="secondary-text">
                    No active incident investigations currently opened.
                  </span>
                </td>
              </tr>
            ) : (
              investigations.map((inv) => (
                <tr key={inv.id}>
                  <td>
                    <strong>{inv.title}</strong>
                    <div
                      className="secondary-text"
                      style={{ fontSize: "0.8125rem" }}
                    >
                      {inv.summary}
                    </div>
                  </td>
                  <td>
                    <span className="badge">{inv.status}</span>
                  </td>
                  <td>
                    <span className={`badge ${inv.risk}`}>{inv.risk}</span>
                  </td>
                  <td>{inv.anomaly_ids.length}</td>
                  <td>{inv.remediations.length}</td>
                  <td>
                    <button className="btn" onClick={() => onSelect(inv.id)}>
                      Open Case
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function InvestigationDetailView({
  id,
  onBack,
}: {
  id: string;
  onBack: () => void;
}) {
  const query = useQuery({
    queryKey: ["investigation", id],
    queryFn: () => fetchInvestigation(id),
  });
  const inv = query.data;

  if (!inv) {
    return (
      <div>
        <button onClick={onBack}>← Back to Investigations</button>
        <div style={{ padding: "2rem", textAlign: "center" }}>
          Loading investigation case file...
        </div>
      </div>
    );
  }

  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <button onClick={onBack}>← Back to Investigations</button>
        <div>
          <h2>CASE FILE: {inv.title}</h2>
          <div className="mono secondary-text">ID: {inv.id}</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Incident Summary</h3>
          <span className={`badge ${inv.risk}`}>{inv.risk} Risk</span>
        </div>
        <p>{inv.summary}</p>
        <div className="secondary-text" style={{ fontSize: "0.8125rem" }}>
          Status: <strong>{inv.status}</strong> · Asset ID:{" "}
          <span className="mono">{inv.asset_id}</span>
        </div>
      </div>

      <div className="card">
        <h3>Correlated Anomalies ({inv.anomaly_ids.length})</h3>
        {inv.anomaly_ids.length === 0 ? (
          <p className="secondary-text">No behavioral anomalies correlated.</p>
        ) : (
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
            {inv.anomaly_ids.map((aid) => (
              <span key={aid} className="badge">
                {aid}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h3>Export Forensic Case Report</h3>
        <div style={{ display: "flex", gap: "0.75rem" }}>
          <a
            href={`/api/v1/investigations/${id}/report?format=json`}
            target="_blank"
            rel="noreferrer"
            className="btn"
          >
            Export JSON
          </a>
          <a
            href={`/api/v1/investigations/${id}/report?format=html`}
            target="_blank"
            rel="noreferrer"
            className="btn"
          >
            Export HTML
          </a>
          <a
            href={`/api/v1/investigations/${id}/report?format=pdf`}
            target="_blank"
            rel="noreferrer"
            className="btn"
          >
            Export PDF
          </a>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------
// 6. REMEDIATION TAB
// ---------------------------------------------------------
function RemediationsTab() {
  const assetsQuery = useQuery({ queryKey: ["assets"], queryFn: fetchAssets });
  const [selectedAssetId, setSelectedAssetId] = useState<string>("");

  const postureQuery = useQuery({
    queryKey: ["asset-posture", selectedAssetId],
    enabled: !!selectedAssetId,
    queryFn: () => fetchAssetPosture(selectedAssetId),
  });

  const assets = assetsQuery.data ?? [];
  const guidanceList =
    postureQuery.data?.guidance.filter((g) => g.kind === "remediation") ?? [];

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Remediation & Fix Verification</h1>
        <p className="secondary-text">
          Close the security loop: compare before-and-after cryptographic
          evidence and actively verify fixes against real protocol refusals.
        </p>
      </div>

      <div className="card">
        <label className="form-label">Select Target Asset</label>
        <select
          value={selectedAssetId}
          onChange={(e) => setSelectedAssetId(e.target.value)}
        >
          <option value="">Select an asset...</option>
          {assets.map((a) => (
            <option key={a.id} value={a.id}>
              {a.primary_name || a.addresses[0]} ({a.addresses.join(", ")})
            </option>
          ))}
        </select>
      </div>

      {selectedAssetId && (
        <div style={{ marginTop: "1.5rem" }}>
          <h2>Available Remediation Workflows</h2>
          {guidanceList.length === 0 ? (
            <div className="card">
              <p className="secondary-text">
                No active remediation workflows required for this asset.
              </p>
            </div>
          ) : (
            guidanceList.map((guidance) => (
              <div key={guidance.id} className="card">
                <h3>{guidance.title}</h3>
                <p className="secondary-text">{guidance.recommendation}</p>
                <RemediationWorkflow
                  assetId={selectedAssetId}
                  guidance={guidance}
                />
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------
// 7. POLICY SIMULATION (CRYPTO DIGITAL TWIN)
// ---------------------------------------------------------
function SimulationTab() {
  const [selectedPolicy, setSelectedPolicy] = useState("high-security");
  const policiesQuery = useQuery({
    queryKey: ["policies"],
    queryFn: fetchPolicies,
  });

  const simulationMutation = useMutation({
    mutationFn: () => simulatePolicy(selectedPolicy),
  });

  const policies = policiesQuery.data ?? [];
  const result = simulationMutation.data;

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Practical Crypto Digital Twin & Policy Simulation</h1>
        <p className="secondary-text">
          Test proposed cryptographic hardening policies against historical
          traffic before enforcement. Evaluates deterministic compatibility
          without mutating assets or database records.
        </p>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Select Proposed Policy Pack</h3>
          <span className="badge">Read-Only Simulation</span>
        </div>

        <div style={{ display: "flex", gap: "1rem", alignItems: "flex-end" }}>
          <div style={{ flex: 1 }}>
            <label className="form-label">Available Policy Packs</label>
            <select
              value={selectedPolicy}
              onChange={(e) => setSelectedPolicy(e.target.value)}
            >
              {policies.length === 0 ? (
                <>
                  <option value="high-security">
                    High Security (TLS 1.3, Strict PFS, MTA-STS)
                  </option>
                  <option value="modern">
                    Modern Recommended (TLS 1.2+, PFS)
                  </option>
                  <option value="legacy-compatible">
                    Legacy Compatible (TLS 1.0+)
                  </option>
                </>
              ) : (
                policies.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.title} (v{p.version})
                  </option>
                ))
              )}
            </select>
          </div>

          <button
            className="btn-primary"
            onClick={() => simulationMutation.mutate()}
            disabled={simulationMutation.isPending}
          >
            {simulationMutation.isPending
              ? "Replaying Observations..."
              : "Run Policy Simulation"}
          </button>
        </div>

        {simulationMutation.isError && (
          <div className="alert-banner danger" style={{ marginTop: "1rem" }}>
            Simulation failed: {(simulationMutation.error as any).message}
          </div>
        )}
      </div>

      {result && (
        <div style={{ marginTop: "1.5rem" }}>
          <h2>Simulation Results: {result.policy_name}</h2>

          <div className="metrics-grid">
            <div className="metric-tile">
              <div className="metric-tile-label">Total Assets Evaluated</div>
              <div className="metric-tile-value">
                {result.total_assets_evaluated}
              </div>
              <div className="metric-tile-sub">Historical traffic sessions</div>
            </div>

            <div className="metric-tile">
              <div className="metric-tile-label">Compatible Assets</div>
              <div
                className="metric-tile-value"
                style={{ color: "var(--status-success-ink)" }}
              >
                {result.compatible_assets_count}
              </div>
              <div className="metric-tile-sub">
                Safe for immediate enforcement
              </div>
            </div>

            <div className="metric-tile">
              <div className="metric-tile-label">
                Would Break (Incompatible)
              </div>
              <div
                className="metric-tile-value"
                style={{ color: "var(--status-danger-ink)" }}
              >
                {result.incompatible_assets_count}
              </div>
              <div className="metric-tile-sub">Violates proposed rules</div>
            </div>

            <div className="metric-tile">
              <div className="metric-tile-label">Insufficient Evidence</div>
              <div
                className="metric-tile-value"
                style={{ color: "var(--ink-secondary)" }}
              >
                {result.unknown_assets_count}
              </div>
              <div className="metric-tile-sub">No recent sessions observed</div>
            </div>
          </div>

          {/* Breakages by Rule */}
          {result.breakages_by_rule.length > 0 && (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Enforcement Breakages by Rule</h3>
                <span className="badge critical">Policy Violations</span>
              </div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Rule ID</th>
                      <th>Rule Title</th>
                      <th>Affected Assets</th>
                      <th>Sample Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.breakages_by_rule.map((b) => (
                      <tr key={b.rule_id}>
                        <td className="mono">{b.rule_id}</td>
                        <td>{b.rule_title}</td>
                        <td>
                          <span className="badge high">
                            {b.affected_assets_count} asset(s)
                          </span>
                        </td>
                        <td className="secondary-text">{b.sample_reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Asset-by-Asset Breakdown */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Asset Compatibility Breakdown</h3>
              <span className="badge">Detailed Forensic Replay</span>
            </div>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Asset ID / Name</th>
                    <th>Compatibility Outcome</th>
                    <th>Sessions Checked</th>
                    <th>Breakages / Reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {result.asset_results.map((ar) => (
                    <tr key={ar.asset_id}>
                      <td>
                        <strong>{ar.asset_name || ar.asset_id}</strong>
                        <div
                          className="mono secondary-text"
                          style={{ fontSize: "0.75rem" }}
                        >
                          {ar.asset_id}
                        </div>
                      </td>
                      <td>
                        {ar.compatibility === "compatible" ? (
                          <span className="badge fresh">Compatible</span>
                        ) : ar.compatibility === "would_fail" ? (
                          <span className="badge critical">Would Fail</span>
                        ) : (
                          <span className="badge">Insufficient Evidence</span>
                        )}
                      </td>
                      <td>{ar.evaluated_sessions_count}</td>
                      <td>
                        {ar.breakages.length === 0 ? (
                          <span className="secondary-text">No breakages</span>
                        ) : (
                          ar.breakages.map((br, idx) => (
                            <div
                              key={idx}
                              style={{
                                fontSize: "0.8125rem",
                                marginBottom: "0.25rem",
                              }}
                            >
                              <strong className="mono">{br.rule_id}:</strong>{" "}
                              <span className="secondary-text">
                                {br.reason}
                              </span>
                            </div>
                          ))
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------
// 8. REPORTS TAB & ARCHIVED VAULT
// ---------------------------------------------------------
function ReportsTab() {
  const reportsQuery = useQuery({
    queryKey: ["archived-reports"],
    queryFn: fetchArchivedReports,
  });
  const archived = reportsQuery.data ?? [];

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Forensic Reports & Case Archive Vault</h1>
        <p className="secondary-text">
          Frozen report records with immutable content fingerprints. Guarantees
          exact historical reproduction regardless of subsequent rule changes.
        </p>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">
            Archived Reports Vault ({archived.length})
          </h3>
          <span className="badge">Cryptographic Integrity</span>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Report Title</th>
                <th>Subject</th>
                <th>Fingerprint (SHA-256)</th>
                <th>Archived At</th>
                <th>Archived By</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {archived.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    style={{ textAlign: "center", padding: "2rem" }}
                  >
                    <span className="secondary-text">
                      No reports archived yet. Navigate to any Asset or
                      Investigation to freeze a report snapshot.
                    </span>
                  </td>
                </tr>
              ) : (
                archived.map((rep) => (
                  <tr key={rep.id}>
                    <td>
                      <strong>{rep.title}</strong>
                      {rep.notes && (
                        <div
                          className="secondary-text"
                          style={{ fontSize: "0.8125rem" }}
                        >
                          Notes: {rep.notes}
                        </div>
                      )}
                    </td>
                    <td>
                      <span className="badge">
                        {rep.subject_kind}: {rep.subject_id.slice(0, 8)}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: "0.75rem" }}>
                      {rep.fingerprint.slice(0, 24)}...
                    </td>
                    <td
                      className="mono secondary-text"
                      style={{ fontSize: "0.8125rem" }}
                    >
                      {new Date(rep.archived_at).toLocaleString()}
                    </td>
                    <td>{rep.archived_by}</td>
                    <td>
                      <div style={{ display: "flex", gap: "0.4rem" }}>
                        <button
                          className="btn"
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                          }}
                          onClick={() => downloadArchivedReport(rep.id, "json")}
                        >
                          JSON
                        </button>
                        <button
                          className="btn"
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                          }}
                          onClick={() => downloadArchivedReport(rep.id, "html")}
                        >
                          HTML
                        </button>
                        <button
                          className="btn"
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                          }}
                          onClick={() => downloadArchivedReport(rep.id, "pdf")}
                        >
                          PDF
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------
// 9. INTEGRATIONS TAB (WEBHOOK & SYSLOG/CEF)
// ---------------------------------------------------------
function IntegrationsTab() {
  const queryClient = useQueryClient();
  const [showAddForm, setShowAddForm] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [kind, setKind] = useState<"webhook" | "syslog">("webhook");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [secretHeader, setSecretHeader] = useState("X-Mailent-Key");
  const [secretToken, setSecretToken] = useState("");
  const [eventTypes, setEventTypes] = useState<string[]>([
    "investigation_created",
    "finding_confirmed",
    "verification_completed",
    "remediation_verified",
    "verification_failed",
  ]);

  const integrationsQuery = useQuery({
    queryKey: ["integrations"],
    queryFn: fetchIntegrations,
  });

  const createMutation = useMutation({
    mutationFn: () =>
      createIntegration({
        name,
        kind,
        endpoint_url: endpointUrl,
        enabled: true,
        secret_header: secretHeader || undefined,
        secret_token: secretToken || undefined,
        event_types: eventTypes,
      }),
    onSuccess: () => {
      setShowAddForm(false);
      setName("");
      setEndpointUrl("");
      setSecretToken("");
      void queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteIntegration(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => testIntegration(id),
    onSuccess: (res) => {
      setTestResult(
        res.success
          ? `Delivery success: ${res.message}`
          : `Delivery failed: ${res.message} ${res.error || ""}`,
      );
      void queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (err: any) => {
      setTestResult(`Test failed: ${err.message}`);
    },
  });

  const integrations = integrationsQuery.data ?? [];

  const toggleEvent = (evt: string) => {
    setEventTypes((prev) =>
      prev.includes(evt) ? prev.filter((e) => e !== evt) : [...prev, evt],
    );
  };

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          marginBottom: "1.5rem",
        }}
      >
        <div>
          <h1>Workflow Integrations (Webhooks & Syslog / CEF)</h1>
          <p className="secondary-text">
            Publish verifiable events into SIEMs and workflow engines across the
            5 core lifecycle milestones.
          </p>
        </div>

        <button
          className="btn-primary"
          onClick={() => setShowAddForm(!showAddForm)}
        >
          {showAddForm ? "Cancel" : "+ Add Destination"}
        </button>
      </div>

      {testResult && (
        <div
          className="alert-banner info"
          style={{
            marginBottom: "1.5rem",
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <span>{testResult}</span>
          <button
            onClick={() => setTestResult(null)}
            style={{ padding: "0.2rem 0.5rem", fontSize: "0.75rem" }}
          >
            Dismiss
          </button>
        </div>
      )}

      {showAddForm && (
        <div className="card" style={{ marginBottom: "1.5rem" }}>
          <h3>Add New Integration Destination</h3>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "1rem",
            }}
          >
            <div className="form-group">
              <label className="form-label">Destination Name</label>
              <input
                type="text"
                placeholder="e.g. Corporate Splunk / SOAR Webhook"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Integration Type</label>
              <select
                value={kind}
                onChange={(e) => setKind(e.target.value as any)}
              >
                <option value="webhook">Generic Webhook (JSON payload)</option>
                <option value="syslog">
                  Syslog / CEF Sink (ArcSight Common Event Format)
                </option>
              </select>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Endpoint URL</label>
            <input
              type="text"
              placeholder={
                kind === "webhook"
                  ? "https://soar.internal.net/api/v1/alerts"
                  : "https://syslog-collector.internal.net/cef"
              }
              value={endpointUrl}
              onChange={(e) => setEndpointUrl(e.target.value)}
            />
          </div>

          {kind === "webhook" && (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "1rem",
              }}
            >
              <div className="form-group">
                <label className="form-label">Secret Header Name</label>
                <input
                  type="text"
                  value={secretHeader}
                  onChange={(e) => setSecretHeader(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Secret Token</label>
                <input
                  type="password"
                  placeholder="Optional authorization bearer/secret"
                  value={secretToken}
                  onChange={(e) => setSecretToken(e.target.value)}
                />
              </div>
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Subscribed Events</label>
            <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
              {[
                { id: "investigation_created", label: "Investigation Created" },
                { id: "finding_confirmed", label: "Finding Confirmed" },
                {
                  id: "verification_completed",
                  label: "Verification Completed",
                },
                { id: "remediation_verified", label: "Remediation Verified" },
                { id: "verification_failed", label: "Verification Failed" },
              ].map((evt) => (
                <label
                  key={evt.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "0.4rem",
                    fontSize: "0.875rem",
                    cursor: "pointer",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={eventTypes.includes(evt.id)}
                    onChange={() => toggleEvent(evt.id)}
                  />
                  {evt.label}
                </label>
              ))}
            </div>
          </div>

          <button
            className="btn-primary"
            onClick={() => createMutation.mutate()}
            disabled={createMutation.isPending || !name || !endpointUrl}
          >
            {createMutation.isPending ? "Saving..." : "Save Integration"}
          </button>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">
            Configured Destinations ({integrations.length})
          </h3>
          <span className="badge">Active Dispatcher</span>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name & Kind</th>
                <th>Endpoint</th>
                <th>Events</th>
                <th>Last Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {integrations.length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    style={{ textAlign: "center", padding: "2rem" }}
                  >
                    <span className="secondary-text">
                      No webhook or syslog sinks configured yet.
                    </span>
                  </td>
                </tr>
              ) : (
                integrations.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <strong>{item.name}</strong>
                      <div>
                        <span className="badge">{item.kind.toUpperCase()}</span>
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: "0.8125rem" }}>
                      {item.endpoint_url}
                    </td>
                    <td>
                      <span
                        className="secondary-text"
                        style={{ fontSize: "0.8125rem" }}
                      >
                        {item.event_types.length} event type(s)
                      </span>
                    </td>
                    <td>
                      {item.last_delivery_status ? (
                        <span
                          className={`badge ${item.last_delivery_status.includes("20") ? "fresh" : "critical"}`}
                        >
                          {item.last_delivery_status}
                        </span>
                      ) : (
                        <span className="secondary-text">Never tested</span>
                      )}
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: "0.5rem" }}>
                        <button
                          className="btn"
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                          }}
                          onClick={() => testMutation.mutate(item.id)}
                          disabled={testMutation.isPending}
                        >
                          Test Delivery
                        </button>
                        <button
                          className="btn-danger"
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                          }}
                          onClick={() => deleteMutation.mutate(item.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------
// 10. SENSORS TAB
// ---------------------------------------------------------
function SensorsTab() {
  const sensorsQuery = useQuery({
    queryKey: ["sensors"],
    queryFn: fetchSensors,
  });
  const sensors = sensorsQuery.data ?? [];

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Sensor Fleet & Ingestion Telemetry</h1>
        <p className="secondary-text">
          Passive mail inspection sensors capturing TLS handshakes and STARTTLS
          upgrades from raw network taps without reading email bodies.
        </p>
      </div>

      {sensorsQuery.isPending && <p role="status">Loading sensors…</p>}
      {sensorsQuery.isError && (
        <p role="alert" className="error">
          Failed to load sensors: {sensorsQuery.error.message}
        </p>
      )}

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Sensor ID</th>
              <th>Site</th>
              <th>Hostname</th>
              <th>Interface</th>
              <th>Mode</th>
              <th>Version</th>
              <th>Status</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {sensors.length === 0 && !sensorsQuery.isPending ? (
              <tr>
                <td
                  colSpan={8}
                  style={{ textAlign: "center", padding: "2rem" }}
                >
                  <span className="secondary-text">
                    No passive sensors connected.
                  </span>
                </td>
              </tr>
            ) : (
              sensors.map((s) => (
                <tr key={s.sensor_id}>
                  <td className="mono">{s.sensor_id}</td>
                  <td>{s.site_id}</td>
                  <td>{s.hostname}</td>
                  <td className="mono">{s.interface || "n/a"}</td>
                  <td>{s.mode}</td>
                  <td className="mono">{s.version}</td>
                  <td>
                    <span
                      className={`badge ${s.status === "Online" ? "fresh" : "stale"}`}
                    >
                      {s.status}
                    </span>
                  </td>
                  <td
                    className="mono secondary-text"
                    style={{ fontSize: "0.8125rem" }}
                  >
                    {new Date(s.last_seen).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ---------------------------------------------------------
// 11. EVALUATOR TAB (OBSERVATION INSPECTOR)
// ---------------------------------------------------------
function EvaluatorTab({ readiness }: { readiness?: { ready: boolean } }) {
  const [selectedFixture, setSelectedFixture] = useState("modern");
  const [jsonInput, setJsonInput] = useState(() =>
    JSON.stringify(modern, null, 2),
  );

  const mutation = useMutation({
    mutationFn: evaluateObservation,
  });

  const handleFixtureChange = (name: string) => {
    setSelectedFixture(name);
    let fixture: unknown = modern;
    if (name === "legacy") fixture = legacy;
    if (name === "rsa") fixture = rsa;
    if (name === "expired") fixture = expired;
    setJsonInput(JSON.stringify(fixture, null, 2));
    mutation.reset();
  };

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Passive Observation Evaluator</h1>
        <p className="secondary-text">
          Inspect and test raw normalized observation JSON against loaded policy
          rules.
        </p>
      </div>

      <div className="grid-2col">
        {/* Input Panel */}
        <div className="card">
          <div className="form-group">
            <label className="form-label" htmlFor="fixture-select">
              Synthetic fixture
            </label>
            <select
              id="fixture-select"
              value={selectedFixture}
              onChange={(e) => handleFixtureChange(e.target.value)}
            >
              <option value="modern">Modern TLS 1.3 Healthy</option>
              <option value="legacy">Legacy TLS 1.0 Negotiation</option>
              <option value="rsa">Static RSA Cipher (No PFS)</option>
              <option value="expired">Expired Certificate Leaf</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="json-input">
              Normalized observation JSON
            </label>
            <textarea
              id="json-input"
              rows={16}
              value={jsonInput}
              onChange={(e) => {
                setJsonInput(e.target.value);
                mutation.reset();
              }}
            />
          </div>

          <button
            className="btn-primary"
            onClick={() => mutation.mutate(jsonInput)}
            disabled={mutation.isPending || !readiness?.ready}
          >
            {mutation.isPending ? "Evaluating…" : "Evaluate observation"}
          </button>
        </div>

        {/* Output Panel */}
        <div className="card">
          <h3>Evaluation Result</h3>

          {mutation.isPending && (
            <p role="status">Evaluating observation in core…</p>
          )}

          {mutation.isError && (
            <p role="alert" className="error">
              Evaluation failed. {(mutation.error as any)?.message}
            </p>
          )}

          {!mutation.data && !mutation.isPending && !mutation.isError && (
            <div
              className="secondary-text"
              style={{ padding: "2rem", textAlign: "center" }}
            >
              <h3>No observation evaluated</h3>
            </div>
          )}

          {mutation.data && (
            <div>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginBottom: "1rem",
                }}
              >
                <span className="mono secondary-text">
                  Session: {mutation.data.session_id}
                </span>
                <span className="badge">
                  {mutation.data.findings.length} Finding(s)
                </span>
              </div>

              {mutation.data.findings.length === 0 ? (
                <div className="alert-banner info">
                  No violations found by the evaluated rules
                </div>
              ) : (
                mutation.data.findings.map((finding) => (
                  <div
                    key={finding.id}
                    style={{
                      padding: "0.875rem",
                      border: "1px solid var(--hairline)",
                      borderRadius: "6px",
                      marginBottom: "0.75rem",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        marginBottom: "0.25rem",
                      }}
                    >
                      <strong>{finding.title}</strong>
                      <span className={`badge ${finding.severity}`}>
                        {finding.severity}
                      </span>
                    </div>
                    <div
                      className="mono secondary-text"
                      style={{ fontSize: "0.75rem" }}
                    >
                      {finding.rule_id}
                    </div>
                    <p
                      className="secondary-text"
                      style={{ fontSize: "0.8125rem", margin: "0.35rem 0" }}
                    >
                      {finding.description}
                    </p>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
