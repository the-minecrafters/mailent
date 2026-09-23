import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  type AssessmentRecord,
  type Asset,
  archiveReport,
  type EmailSession,
  type Finding,
  fetchAssessment,
  fetchAssetAnomalies,
  fetchAssetPosture,
  fetchAssets,
  fetchFindings,
  fetchSessions,
} from "./api";
import { Icon } from "./components/Icon";
import { ErrorState, LoadingState } from "./components/ui";
import { ProbeEvidence } from "./ProbePanel";
import { RemediationWorkflow } from "./RemediationWorkflow";

interface AssessmentWorkspaceProps {
  assessmentId: string;
  onBack: () => void;
  onSelectAsset?: (assetId: string) => void;
}

type WorkspaceTab =
  | "summary"
  | "sessions"
  | "tls"
  | "certificates"
  | "findings"
  | "risk"
  | "remediation"
  | "report";

export function AssessmentWorkspace({
  assessmentId,
  onBack,
  onSelectAsset,
}: AssessmentWorkspaceProps) {
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const tabs: WorkspaceTab[] = [
    "summary",
    "sessions",
    "tls",
    "certificates",
    "findings",
    "risk",
    "remediation",
    "report",
  ];
  const activeTab = tabs.includes(params.get("tab") as WorkspaceTab)
    ? (params.get("tab") as WorkspaceTab)
    : "summary";
  const setActiveTab = (tab: WorkspaceTab) =>
    setParams((previous) => {
      const next = new URLSearchParams(previous);
      next.set("tab", tab);
      return next;
    });
  const [printing, setPrinting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [archiving, setArchiving] = useState(false);
  useEffect(() => {
    if (!printing || activeTab !== "report") return;
    const frame = requestAnimationFrame(() => {
      window.print();
      setPrinting(false);
    });
    return () => cancelAnimationFrame(frame);
  }, [printing, activeTab]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    null,
  );
  const [copiedHash, setCopiedHash] = useState(false);
  const [archiveSuccess, setArchiveSuccess] = useState<string | null>(null);

  // Queries
  const assessmentQuery = useQuery({
    queryKey: ["assessment", assessmentId],
    queryFn: () => fetchAssessment(assessmentId),
  });

  const sessionsQuery = useQuery({
    queryKey: ["sessions"],
    queryFn: fetchSessions,
  });

  const findingsQuery = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
  });

  const assetsQuery = useQuery({
    queryKey: ["assets"],
    queryFn: fetchAssets,
  });

  const assessment = assessmentQuery.data;

  // Filter entities belonging to this assessment
  const assessmentSessions = (sessionsQuery.data ?? [])
    .filter((s) => assessment?.session_ids.includes(s.session_id))
    .map((s) => s.session);

  const assessmentFindings = (findingsQuery.data ?? []).filter((f) =>
    assessment?.finding_ids.includes(f.id),
  );

  const assessmentAssets = (assetsQuery.data ?? []).filter((a) =>
    assessment?.asset_ids.includes(a.id),
  );

  const primaryAsset = assessmentAssets[0];

  const assetPostureQuery = useQuery({
    queryKey: ["asset-posture", primaryAsset?.id],
    queryFn: () => (primaryAsset ? fetchAssetPosture(primaryAsset.id) : null),
    enabled: !!primaryAsset,
  });

  const assetAnomaliesQuery = useQuery({
    queryKey: ["asset-anomalies", primaryAsset?.id],
    queryFn: () => (primaryAsset ? fetchAssetAnomalies(primaryAsset.id) : []),
    enabled: !!primaryAsset,
  });

  const selectedSession =
    assessmentSessions.find((s) => s.session_id === selectedSessionId) ||
    assessmentSessions[0];

  const handleCopyHash = async () => {
    if (!assessment?.capture_hash) return;
    try {
      await navigator.clipboard.writeText(assessment.capture_hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    } catch {
      setActionError(
        "Could not copy the hash. Select the displayed hash and copy it manually.",
      );
    }
  };
  const handlePrintReport = () => {
    setActiveTab("report");
    setPrinting(true);
  };

  const handleDownloadJson = () => {
    if (!assessment) return;
    const blob = new Blob(
      [
        JSON.stringify(
          {
            assessment,
            sessions: assessmentSessions,
            findings: assessmentFindings,
            assets: assessmentAssets,
          },
          null,
          2,
        ),
      ],
      {
        type: "application/json",
      },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `assessment-${assessment.id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleArchiveReport = async () => {
    if (!assessment || archiving) return;
    setActionError(null);
    const targetId = primaryAsset?.id || assessment.session_ids[0];
    if (!targetId) {
      setActionError("No server or session is available to archive.");
      return;
    }
    setArchiving(true);
    try {
      const result = await archiveReport({
        subject_kind: primaryAsset ? "asset" : "session",
        subject_id: targetId,
        notes: `Forensic Assessment: ${assessment.title}. Posture score: ${assessment.posture_score} (${assessment.posture_grade}). ${assessment.ai_risk_rationale}`,
      });
      setArchiveSuccess(`Server report saved: ${result.id.slice(0, 8)}`);
      setTimeout(() => setArchiveSuccess(null), 4000);
      void queryClient.invalidateQueries({ queryKey: ["archived-reports"] });
    } catch (err: any) {
      setActionError(`Archive failed: ${err.message}`);
    } finally {
      setArchiving(false);
    }
  };

  if (assessmentQuery.isPending) {
    return (
      <div style={{ textAlign: "center", padding: "4rem 2rem" }}>
        <div
          style={{
            display: "inline-block",
            width: "36px",
            height: "36px",
            border: "3px solid var(--border)",
            borderTopColor: "var(--accent)",
            borderRadius: "50%",
            animation: "spin 0.8s linear infinite",
            marginBottom: "1rem",
          }}
        />
        <p className="secondary-text">Loading capture…</p>
      </div>
    );
  }

  if (assessmentQuery.isError || !assessment) {
    return (
      <div className="card" style={{ padding: "2rem", textAlign: "center" }}>
        <h3 style={{ color: "var(--status-danger-ink)" }}>
          Capture could not be loaded
        </h3>
        <p className="secondary-text">
          {(assessmentQuery.error as any)?.message ||
            "Assessment record not found"}
        </p>
        <button
          className="btn btn-secondary"
          onClick={onBack}
          style={{ marginTop: "1rem" }}
        >
          ← Back to captures
        </button>
      </div>
    );
  }

  const requiredQueries = [sessionsQuery, findingsQuery, assetsQuery];
  const evidenceError = requiredQueries.find((query) => query.isError);
  if (evidenceError)
    return (
      <>
        <button onClick={onBack}>Back to captures</button>
        <ErrorState
          title="Capture evidence could not be loaded"
          description={evidenceError.error?.message ?? "Try again."}
          onRetry={() => {
            for (const query of requiredQueries) void query.refetch();
          }}
        />
      </>
    );
  if (requiredQueries.some((query) => query.isPending))
    return <LoadingState label="Loading capture evidence…" />;

  // Count severities
  const criticalCount = assessmentFindings.filter(
    (f) => f.severity === "critical",
  ).length;
  const highCount = assessmentFindings.filter(
    (f) => f.severity === "high",
  ).length;
  const mediumCount = assessmentFindings.filter(
    (f) => f.severity === "medium",
  ).length;
  const lowCount = assessmentFindings.filter(
    (f) => f.severity === "low",
  ).length;

  return (
    <div className="assessment-workspace">
      {actionError && (
        <ErrorState
          title="Action could not be completed"
          description={actionError}
        />
      )}
      {/* Top Breadcrumb & Controls */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "1rem",
        }}
      >
        <button
          className="btn btn-secondary"
          onClick={onBack}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "0.4rem",
          }}
        >
          <Icon name="arrow_back" size={16} />
          <span>Back to captures</span>
        </button>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button
            className="btn btn-secondary"
            onClick={handleDownloadJson}
            title="Export JSON"
          >
            <Icon name="download" size={16} />
            <span>Export JSON</span>
          </button>
          <button
            className="btn btn-secondary"
            onClick={handlePrintReport}
            title="Print or save as PDF"
          >
            <Icon name="print" size={16} />
            <span>Print / PDF</span>
          </button>
          <button
            className="btn btn-primary"
            onClick={handleArchiveReport}
            title="Save a snapshot of the primary server and its evidence"
            disabled={archiving}
          >
            <Icon name="archive" size={16} />
            <span>{archiving ? "Saving…" : "Archive server report"}</span>
          </button>
        </div>
      </div>

      {archiveSuccess && (
        <div
          className="badge fresh"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.4rem",
            padding: "0.6rem 0.85rem",
            marginBottom: "1rem",
            borderRadius: "4px",
          }}
        >
          <Icon name="check_circle" size={16} />
          <span>{archiveSuccess}</span>
        </div>
      )}

      {/* Primary Assessment Header Card */}
      <div
        className="card"
        style={{ marginBottom: "1.25rem", padding: "1.25rem 1.5rem" }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            flexWrap: "wrap",
            gap: "1rem",
          }}
        >
          <div style={{ flex: "1 1 500px" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.6rem",
                marginBottom: "0.4rem",
              }}
            >
              <span className="badge">Capture analysis</span>
              <span
                className="secondary-text"
                style={{ fontSize: "0.8125rem" }}
              >
                Created {new Date(assessment.created_at).toLocaleString()}
              </span>
            </div>
            <h1
              style={{
                margin: "0 0 0.5rem 0",
                fontSize: "1.5rem",
                letterSpacing: "-0.02em",
                fontWeight: 600,
              }}
            >
              {assessment.title}
            </h1>
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "0.75rem",
                alignItems: "center",
                fontSize: "0.8125rem",
              }}
            >
              <span className="mono secondary-text">
                File: <strong>{assessment.capture_name}</strong> (
                {(assessment.capture_size_bytes / 1024).toFixed(1)} KB)
              </span>
              <span style={{ color: "var(--border)" }}>•</span>
              <span
                className="mono secondary-text"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "0.35rem",
                }}
              >
                SHA-256: {assessment.capture_hash.slice(0, 16)}…
                <button
                  type="button"
                  onClick={handleCopyHash}
                  style={{
                    background: "transparent",
                    border: "none",
                    cursor: "pointer",
                    padding: "0 0.25rem",
                    fontSize: "0.75rem",
                    color: "var(--accent)",
                  }}
                  title="Copy full SHA-256 hash"
                >
                  {copiedHash ? "Copied!" : "Copy"}
                </button>
              </span>
            </div>
          </div>

          {/* Posture Score & AI Risk Box */}
          <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
            <div
              style={{
                padding: "0.85rem 1.25rem",
                borderRadius: "8px",
                textAlign: "center",
                background:
                  assessment.posture_score >= 80
                    ? "var(--status-success-bg)"
                    : assessment.posture_score >= 60
                      ? "var(--status-warning-bg)"
                      : "var(--status-danger-bg)",
                border:
                  assessment.posture_score >= 80
                    ? "1px solid var(--status-success-border)"
                    : assessment.posture_score >= 60
                      ? "1px solid var(--status-warning-border)"
                      : "1px solid var(--status-danger-border)",
              }}
            >
              <div
                style={{
                  fontSize: "1.75rem",
                  fontWeight: 700,
                  lineHeight: 1,
                  color:
                    assessment.posture_score >= 80
                      ? "var(--status-success-ink)"
                      : assessment.posture_score >= 60
                        ? "var(--status-warning-ink)"
                        : "var(--status-danger-ink)",
                }}
              >
                {Math.round(assessment.posture_score)}
                <span style={{ fontSize: "0.875rem", fontWeight: 500 }}>
                  /100
                </span>
              </div>
              <div
                style={{
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  marginTop: "0.25rem",
                  color:
                    assessment.posture_score >= 80
                      ? "var(--status-success-ink)"
                      : assessment.posture_score >= 60
                        ? "var(--status-warning-ink)"
                        : "var(--status-danger-ink)",
                }}
              >
                Grade {assessment.posture_grade} Posture
              </div>
            </div>

            <div
              style={{
                padding: "0.85rem 1.25rem",
                borderRadius: "8px",
                textAlign: "center",
                background: "var(--surface-alt)",
                border: "1px solid var(--border)",
              }}
            >
              <div
                className={`badge ${
                  assessment.ai_risk_classification === "CRITICAL"
                    ? "critical"
                    : assessment.ai_risk_classification === "HIGH"
                      ? "high"
                      : assessment.ai_risk_classification === "LOW"
                        ? "fresh"
                        : ""
                }`}
                style={{
                  fontSize: "0.8125rem",
                  fontWeight: 700,
                  padding: "0.3rem 0.6rem",
                }}
              >
                {assessment.ai_risk_classification} RISK
              </div>
              <div
                className="secondary-text"
                style={{ fontSize: "0.72rem", marginTop: "0.35rem" }}
              >
                Based on policy rules
              </div>
            </div>
          </div>
        </div>

        {/* Protocols Identified Tags */}
        <div
          style={{
            display: "flex",
            gap: "0.5rem",
            marginTop: "1rem",
            paddingTop: "0.85rem",
            borderTop: "1px solid var(--hairline)",
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          <span style={{ fontSize: "0.8125rem", fontWeight: 600 }}>
            Protocols Reconstructed:
          </span>
          {assessment.protocols_identified.length === 0 ? (
            <span className="badge">No mail protocols detected</span>
          ) : (
            assessment.protocols_identified.map((proto, idx) => (
              <span
                key={idx}
                className="badge fresh"
                style={{ fontWeight: 600 }}
              >
                {proto}
              </span>
            ))
          )}
          {assessment.evidence_gaps.length > 0 && (
            <span
              className="badge warning"
              style={{
                marginLeft: "auto",
                display: "inline-flex",
                alignItems: "center",
                gap: "0.35rem",
              }}
            >
              <Icon name="warning" size={14} />
              <span>
                {assessment.evidence_gaps.length} capture gap(s) observed
              </span>
            </span>
          )}
        </div>
      </div>

      {/* 8 Workspace Tabs */}
      <nav
        aria-label="Capture sections"
        className="tabs-nav"
        style={{ marginBottom: "1.25rem" }}
      >
        <button
          className={`tab-btn ${activeTab === "summary" ? "active" : ""}`}
          aria-current={activeTab === "summary" ? "page" : undefined}
          onClick={() => setActiveTab("summary")}
        >
          <Icon name="description" size={16} />
          <span>Summary</span>
        </button>
        <button
          className={`tab-btn ${activeTab === "sessions" ? "active" : ""}`}
          aria-current={activeTab === "sessions" ? "page" : undefined}
          onClick={() => setActiveTab("sessions")}
        >
          <Icon name="swap_horiz" size={16} />
          <span>Sessions ({assessment.session_ids.length})</span>
        </button>
        <button
          className={`tab-btn ${activeTab === "tls" ? "active" : ""}`}
          aria-current={activeTab === "tls" ? "page" : undefined}
          onClick={() => setActiveTab("tls")}
        >
          <Icon name="lock" size={16} />
          <span>TLS &amp; STARTTLS</span>
        </button>
        <button
          className={`tab-btn ${activeTab === "certificates" ? "active" : ""}`}
          aria-current={activeTab === "certificates" ? "page" : undefined}
          onClick={() => setActiveTab("certificates")}
        >
          <Icon name="verified_user" size={16} />
          <span>Certificates</span>
        </button>
        <button
          className={`tab-btn ${activeTab === "findings" ? "active" : ""}`}
          aria-current={activeTab === "findings" ? "page" : undefined}
          onClick={() => setActiveTab("findings")}
        >
          <Icon name="warning" size={16} />
          <span>Findings ({assessment.finding_ids.length})</span>
        </button>
        <button
          className={`tab-btn ${activeTab === "risk" ? "active" : ""}`}
          aria-current={activeTab === "risk" ? "page" : undefined}
          onClick={() => setActiveTab("risk")}
        >
          <Icon name="security" size={16} />
          <span>Risk &amp; anomalies</span>
        </button>
        <button
          className={`tab-btn ${activeTab === "remediation" ? "active" : ""}`}
          aria-current={activeTab === "remediation" ? "page" : undefined}
          onClick={() => setActiveTab("remediation")}
        >
          <Icon name="build" size={16} />
          <span>Remediation</span>
        </button>
        <button
          className={`tab-btn ${activeTab === "report" ? "active" : ""}`}
          aria-current={activeTab === "report" ? "page" : undefined}
          onClick={() => setActiveTab("report")}
        >
          <Icon name="article" size={16} />
          <span>Report</span>
        </button>
      </nav>

      {assessmentAssets.length > 0 && (
        <div className="capture-servers">
          <span>Mail servers in this capture</span>
          {assessmentAssets.map((asset) => (
            <button
              key={asset.id}
              className="text-link"
              onClick={() => onSelectAsset?.(asset.id)}
            >
              {asset.primary_name || asset.addresses[0]}{" "}
              <Icon name="chevron_right" size={14} />
            </button>
          ))}
        </div>
      )}
      {/* TAB 1: SUMMARY & EVIDENCE */}
      {activeTab === "summary" && (
        <div
          style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}
        >
          {/* Key Metrics Row */}
          <div className="metrics-row">
            <div className="metric-tile">
              <div className="metric-tile-label">Analyzed Sessions</div>
              <div className="metric-tile-value">
                {assessment.session_ids.length}
              </div>
              <div className="metric-tile-sub">Reconstructed flows</div>
            </div>
            <div className="metric-tile">
              <div className="metric-tile-label">Mail Assets</div>
              <div className="metric-tile-value">
                {assessment.asset_ids.length}
              </div>
              <div className="metric-tile-sub">Fingerprinted endpoints</div>
            </div>
            <div className="metric-tile">
              <div className="metric-tile-label">Critical Issues</div>
              <div
                className="metric-tile-value"
                style={{
                  color:
                    criticalCount > 0 ? "var(--status-danger-ink)" : undefined,
                }}
              >
                {criticalCount}
              </div>
              <div className="metric-tile-sub">RFC violations</div>
            </div>
            <div className="metric-tile">
              <div className="metric-tile-label">Total Findings</div>
              <div className="metric-tile-value">
                {assessment.finding_ids.length}
              </div>
              <div className="metric-tile-sub">
                {highCount} High · {mediumCount} Med · {lowCount} Low
              </div>
            </div>
          </div>

          {/* AI Risk Classification & Rationale */}
          <div
            className="card"
            style={{
              padding: "1.25rem 1.5rem",
              background:
                assessment.ai_risk_classification === "CRITICAL"
                  ? "var(--status-danger-bg)"
                  : "var(--surface-card-solid)",
              border:
                assessment.ai_risk_classification === "CRITICAL"
                  ? "1px solid var(--status-danger-border)"
                  : "1px solid var(--hairline)",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
                marginBottom: "0.5rem",
              }}
            >
              <span className="badge critical" style={{ fontWeight: 700 }}>
                RISK LEVEL: {assessment.ai_risk_classification}
              </span>
              <span className="secondary-text" style={{ fontSize: "0.75rem" }}>
                Rule-based assessment
              </span>
            </div>
            <p style={{ margin: 0, fontSize: "0.9375rem", lineHeight: 1.5 }}>
              {assessment.ai_risk_rationale}
            </p>
          </div>

          {/* Reconstructed Protocol Proof & Role Table */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Reconstructed Protocol Evidence</h3>
              <span className="badge fresh">Cryptographic Traceability</span>
            </div>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Inferred Server Role</th>
                    <th>Technical Proof</th>
                    <th>Forensic Verification Engine</th>
                  </tr>
                </thead>
                <tbody>
                  {assessment.protocol_evidence.length === 0 ? (
                    <tr>
                      <td
                        colSpan={4}
                        style={{ textAlign: "center", padding: "1.5rem" }}
                      >
                        <span className="secondary-text">
                          No protocol handshakes recorded
                        </span>
                      </td>
                    </tr>
                  ) : (
                    assessment.protocol_evidence.map((pe, idx) => (
                      <tr key={idx}>
                        <td>
                          <span
                            className="badge fresh"
                            style={{ fontWeight: 600 }}
                          >
                            {pe.protocol}
                          </span>
                        </td>
                        <td>
                          <strong>{pe.role}</strong>
                        </td>
                        <td
                          className="secondary-text"
                          style={{ fontSize: "0.8125rem" }}
                        >
                          {pe.proof}
                        </td>
                        <td className="mono" style={{ fontSize: "0.75rem" }}>
                          {pe.verified_by}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Evidence Integrity & Capture Completeness */}
          <div className="card" style={{ padding: "1.25rem 1.5rem" }}>
            <h3 className="card-title" style={{ marginBottom: "0.5rem" }}>
              Evidence Integrity &amp; Packet Quality
            </h3>
            <p
              className="secondary-text"
              style={{ fontSize: "0.875rem", margin: "0 0 1rem 0" }}
            >
              Mailent enforces defensible forensic evidentiary standards. All
              timeline transitions must be backed by observed packets or
              explicitly declared as inferred/unavailable.
            </p>
            {assessment.evidence_gaps.length === 0 ? (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.6rem",
                  padding: "0.75rem 1rem",
                  background: "var(--status-success-bg)",
                  border: "1px solid var(--status-success-border)",
                  borderRadius: "6px",
                }}
              >
                <Icon
                  name="check_circle"
                  size={18}
                  style={{ color: "var(--status-success-ink)" }}
                />
                <span
                  style={{
                    fontSize: "0.875rem",
                    color: "var(--status-success-ink)",
                  }}
                >
                  Zero Packet Gaps Detected: Full TCP handshake and application
                  payload recorded without frame loss.
                </span>
              </div>
            ) : (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "0.5rem",
                }}
              >
                {assessment.evidence_gaps.map((gap, idx) => (
                  <div
                    key={idx}
                    className="badge warning"
                    style={{
                      padding: "0.5rem 0.75rem",
                      borderRadius: "4px",
                      textAlign: "left",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.35rem",
                    }}
                  >
                    <Icon name="warning" size={14} />
                    <span>{gap}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: SESSIONS & RECONSTRUCTED TIMELINE */}
      {activeTab === "sessions" && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "1.25rem",
          }}
        >
          {/* Sessions List */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Reconstructed Sessions</h3>
              <span className="badge">{assessmentSessions.length} Flows</span>
            </div>
            <div
              className="table-container"
              style={{ maxHeight: "500px", overflowY: "auto" }}
            >
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Flow Endpoints</th>
                    <th>TLS Version</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {assessmentSessions.length === 0 ? (
                    <tr>
                      <td
                        colSpan={4}
                        style={{ textAlign: "center", padding: "2rem" }}
                      >
                        <span className="secondary-text">
                          No sessions found in assessment
                        </span>
                      </td>
                    </tr>
                  ) : (
                    assessmentSessions.map((s) => {
                      const isSelected =
                        selectedSession?.session_id === s.session_id;
                      return (
                        <tr
                          key={s.session_id}
                          style={{
                            background: isSelected
                              ? "var(--accent-tint)"
                              : undefined,
                            cursor: "pointer",
                          }}
                          onClick={() => setSelectedSessionId(s.session_id)}
                        >
                          <td>
                            <span className="badge fresh">
                              {s.protocol.toUpperCase()}
                            </span>
                          </td>
                          <td className="mono" style={{ fontSize: "0.75rem" }}>
                            {s.flow.src_ip}:{s.flow.src_port} → {s.flow.dst_ip}:
                            {s.flow.dst_port}
                          </td>
                          <td>
                            {s.tls_version ? (
                              <span
                                className={`badge ${
                                  s.tls_version === "tls10" ||
                                  s.tls_version === "tls11"
                                    ? "critical"
                                    : "fresh"
                                }`}
                              >
                                {s.tls_version.toUpperCase()}
                              </span>
                            ) : (
                              <span className="badge">Plaintext</span>
                            )}
                          </td>
                          <td>
                            <button
                              className="btn btn-secondary"
                              style={{
                                padding: "0.25rem 0.5rem",
                                fontSize: "0.75rem",
                              }}
                              onClick={() => setSelectedSessionId(s.session_id)}
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Deep Reconstructed Timeline */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Deep Forensic Timeline</h3>
              <span className="badge fresh">Truthful Evidence</span>
            </div>
            <div style={{ padding: "1.25rem" }}>
              {selectedSession ? (
                <>
                  <div style={{ marginBottom: "1rem", fontSize: "0.8125rem" }}>
                    <strong>Session UID:</strong>{" "}
                    <span className="mono">{selectedSession.session_id}</span>
                  </div>
                  {selectedSession.capture?.timeline &&
                  selectedSession.capture.timeline.length > 0 ? (
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "0.75rem",
                      }}
                    >
                      {selectedSession.capture.timeline.map((event, idx) => (
                        <div
                          key={idx}
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: "0.75rem",
                            padding: "0.6rem 0.85rem",
                            border: "1px solid var(--border)",
                            borderRadius: "6px",
                            background: "var(--canvas-sunken)",
                          }}
                        >
                          <span
                            className="badge fresh"
                            style={{ fontSize: "0.7rem", marginTop: "2px" }}
                          >
                            [Observed]
                          </span>
                          <div style={{ flex: 1 }}>
                            <div
                              style={{ fontWeight: 600, fontSize: "0.875rem" }}
                            >
                              {event.kind}
                            </div>
                            <div
                              className="mono secondary-text"
                              style={{ fontSize: "0.75rem" }}
                            >
                              Source: {event.source} ·{" "}
                              {new Date(event.timestamp).toLocaleTimeString()}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div
                      className="secondary-text"
                      style={{ fontSize: "0.875rem", padding: "1rem 0" }}
                    >
                      No detailed Zeek packet timeline events recorded for this
                      session.
                    </div>
                  )}
                </>
              ) : (
                <div
                  className="secondary-text"
                  style={{ textAlign: "center", padding: "2rem" }}
                >
                  Select a session from the left to inspect its timeline.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: TLS & STARTTLS */}
      {activeTab === "tls" && (
        <div
          style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}
        >
          {selectedSession ? (
            <div className="card" style={{ padding: "1.5rem" }}>
              <h3 className="card-title" style={{ marginBottom: "1rem" }}>
                Protocol Negotiation &amp; Cryptographic Parameters
              </h3>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
                  gap: "1rem",
                }}
              >
                <div className="drift-card">
                  <h4>STARTTLS Negotiation</h4>
                  <div style={{ marginTop: "0.5rem" }}>
                    <span
                      className={`badge ${
                        selectedSession.starttls_state === "tls_established"
                          ? "fresh"
                          : selectedSession.starttls_state ===
                              "advertised_not_used"
                            ? "critical"
                            : ""
                      }`}
                    >
                      {selectedSession.starttls_state ||
                        "Plaintext (No STARTTLS)"}
                    </span>
                  </div>
                  <p
                    className="secondary-text"
                    style={{ fontSize: "0.8125rem", marginTop: "0.5rem" }}
                  >
                    {selectedSession.starttls_state === "tls_established"
                      ? "Clean STARTTLS upgrade successfully completed."
                      : selectedSession.starttls_state === "advertised_not_used"
                        ? "STARTTLS capability advertised, but communication proceeded unencrypted (Downgrade/Cleartext Risk)!"
                        : "Direct connection or unencrypted plain protocol."}
                  </p>
                </div>

                <div className="drift-card">
                  <h4>Negotiated TLS Version</h4>
                  <div style={{ marginTop: "0.5rem" }}>
                    <span
                      className={`badge ${
                        selectedSession.tls_version === "tls10" ||
                        selectedSession.tls_version === "tls11"
                          ? "critical"
                          : selectedSession.tls_version
                            ? "fresh"
                            : ""
                      }`}
                    >
                      {selectedSession.tls_version
                        ? selectedSession.tls_version.toUpperCase()
                        : "None"}
                    </span>
                  </div>
                  <p
                    className="secondary-text"
                    style={{ fontSize: "0.8125rem", marginTop: "0.5rem" }}
                  >
                    {selectedSession.tls_version === "tls10" ||
                    selectedSession.tls_version === "tls11"
                      ? "RFC 8996 Prohibited: TLS 1.0/1.1 are deprecated and vulnerable to POODLE, BEAST, and downgrade attacks."
                      : selectedSession.tls_version
                        ? "Compliant modern TLS protocol version."
                        : "No TLS handshake established."}
                  </p>
                </div>

                <div className="drift-card">
                  <h4>Negotiated Cipher Suite</h4>
                  <div style={{ marginTop: "0.5rem" }}>
                    <span
                      className="badge mono"
                      style={{ fontSize: "0.75rem" }}
                    >
                      {selectedSession.cipher_suite?.name || "Unavailable"}
                    </span>
                  </div>
                  <p
                    className="secondary-text"
                    style={{ fontSize: "0.8125rem", marginTop: "0.5rem" }}
                  >
                    IANA ID:{" "}
                    {selectedSession.cipher_suite?.id
                      ? `0x${selectedSession.cipher_suite.id.toString(16).toUpperCase()}`
                      : "N/A"}
                  </p>
                </div>

                <div className="drift-card">
                  <h4>Perfect Forward Secrecy (PFS)</h4>
                  <div style={{ marginTop: "0.5rem" }}>
                    <span
                      className={`badge ${
                        selectedSession.cipher_suite?.name?.includes("RSA") &&
                        !selectedSession.cipher_suite?.name?.includes(
                          "ECDHE",
                        ) &&
                        !selectedSession.cipher_suite?.name?.includes("DHE")
                          ? "critical"
                          : selectedSession.cipher_suite
                            ? "fresh"
                            : ""
                      }`}
                    >
                      {selectedSession.cipher_suite?.name?.includes("RSA") &&
                      !selectedSession.cipher_suite?.name?.includes("ECDHE") &&
                      !selectedSession.cipher_suite?.name?.includes("DHE")
                        ? "STATIC RSA (NO PFS)"
                        : selectedSession.cipher_suite
                          ? "PFS SUPPORTED (ECDHE)"
                          : "UNKNOWN"}
                    </span>
                  </div>
                  <p
                    className="secondary-text"
                    style={{ fontSize: "0.8125rem", marginTop: "0.5rem" }}
                  >
                    Static RSA allows retrospective decryption of recorded mail
                    traffic if the server private key is compromised.
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div
              className="card"
              style={{ padding: "2rem", textAlign: "center" }}
            >
              <p className="secondary-text">
                No session selected. Please select a session in the Sessions
                tab.
              </p>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: CERTIFICATES */}
      {activeTab === "certificates" && (
        <div
          style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}
        >
          {selectedSession?.certificate ? (
            <div className="card" style={{ padding: "1.5rem" }}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  marginBottom: "1rem",
                }}
              >
                <div>
                  <h3 className="card-title" style={{ margin: 0 }}>
                    X.509 Certificate Inspector
                  </h3>
                  <div
                    className="mono secondary-text"
                    style={{ fontSize: "0.75rem", marginTop: "0.25rem" }}
                  >
                    Fingerprint:{" "}
                    {selectedSession.certificate.reference.sha256_fingerprint}
                  </div>
                </div>
                <span
                  className={`badge ${
                    new Date(
                      selectedSession.certificate.validity.not_after,
                    ).getTime() < Date.now()
                      ? "critical"
                      : "fresh"
                  }`}
                >
                  {new Date(
                    selectedSession.certificate.validity.not_after,
                  ).getTime() < Date.now()
                    ? "EXPIRED"
                    : "VALID"}
                </span>
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "1.25rem",
                }}
              >
                <div>
                  <h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem" }}>
                    Subject DN
                  </h4>
                  <div
                    className="mono"
                    style={{
                      padding: "0.6rem 0.85rem",
                      background: "var(--canvas-sunken)",
                      borderRadius: "6px",
                      fontSize: "0.8125rem",
                    }}
                  >
                    {selectedSession.certificate.reference.subject}
                  </div>
                </div>

                <div>
                  <h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem" }}>
                    Issuer DN
                  </h4>
                  <div
                    className="mono"
                    style={{
                      padding: "0.6rem 0.85rem",
                      background: "var(--canvas-sunken)",
                      borderRadius: "6px",
                      fontSize: "0.8125rem",
                    }}
                  >
                    {selectedSession.certificate.reference.issuer}
                  </div>
                </div>

                <div>
                  <h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem" }}>
                    Validity Window
                  </h4>
                  <div
                    style={{
                      padding: "0.6rem 0.85rem",
                      background: "var(--canvas-sunken)",
                      borderRadius: "6px",
                      fontSize: "0.8125rem",
                    }}
                  >
                    <div>
                      <strong>Not Before:</strong>{" "}
                      {selectedSession.certificate.validity.not_before}
                    </div>
                    <div>
                      <strong>Not After:</strong>{" "}
                      {selectedSession.certificate.validity.not_after}
                    </div>
                  </div>
                </div>

                <div>
                  <h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem" }}>
                    Subject Alternative Names (SANs)
                  </h4>
                  <div
                    style={{
                      padding: "0.6rem 0.85rem",
                      background: "var(--canvas-sunken)",
                      borderRadius: "6px",
                      fontSize: "0.8125rem",
                    }}
                  >
                    {selectedSession.certificate.san.length > 0 ? (
                      selectedSession.certificate.san.join(", ")
                    ) : (
                      <span className="secondary-text">
                        No SANs present in certificate
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div
              className="card"
              style={{ padding: "2rem", textAlign: "center" }}
            >
              <p className="secondary-text">
                No X.509 certificate observed on the wire for the active session
                (traffic may be plaintext or certificate packet uncaptured).
              </p>
            </div>
          )}
        </div>
      )}

      {/* TAB 5: FINDINGS */}
      {activeTab === "findings" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {assessmentFindings.length === 0 ? (
            <div
              className="card"
              style={{ padding: "3rem", textAlign: "center" }}
            >
              <Icon
                name="check_circle"
                size={32}
                style={{
                  color: "var(--status-success-ink)",
                  marginBottom: "0.5rem",
                }}
              />
              <h3>Zero Policy Findings</h3>
              <p className="secondary-text">
                Evaluated traffic strictly conforms to cryptographic policies.
                No deprecated ciphers, expired certificates, or cleartext
                exposures detected.
              </p>
            </div>
          ) : (
            assessmentFindings.map((finding) => (
              <div
                key={finding.id}
                className="card"
                style={{
                  borderLeft:
                    finding.severity === "critical"
                      ? "4px solid var(--status-danger-ink)"
                      : finding.severity === "high"
                        ? "4px solid var(--status-warning-ink)"
                        : "4px solid var(--accent)",
                  padding: "1.25rem 1.5rem",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    marginBottom: "0.5rem",
                  }}
                >
                  <div>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "0.5rem",
                        marginBottom: "0.25rem",
                      }}
                    >
                      <span
                        className={`badge ${
                          finding.severity === "critical"
                            ? "critical"
                            : finding.severity === "high"
                              ? "high"
                              : ""
                        }`}
                        style={{ fontWeight: 700 }}
                      >
                        {finding.severity.toUpperCase()}
                      </span>
                      <span
                        className="mono"
                        style={{ fontSize: "0.8125rem", fontWeight: 600 }}
                      >
                        {finding.rule_id}
                      </span>
                      <span className="badge">{finding.category}</span>
                      <span
                        className="secondary-text"
                        style={{ fontSize: "0.75rem" }}
                      >
                        Ref: {finding.reference}
                      </span>
                    </div>
                    <h3 style={{ margin: 0, fontSize: "1.0625rem" }}>
                      {finding.title}
                    </h3>
                  </div>
                  <button
                    className="btn btn-secondary"
                    onClick={() => setActiveTab("remediation")}
                    style={{ fontSize: "0.8125rem" }}
                  >
                    Remediate →
                  </button>
                </div>

                <p style={{ margin: "0.5rem 0", fontSize: "0.875rem" }}>
                  {finding.description}
                </p>

                {finding.evidence.length > 0 && (
                  <div
                    style={{
                      marginTop: "0.75rem",
                      padding: "0.6rem 0.85rem",
                      background: "var(--canvas-sunken)",
                      borderRadius: "6px",
                      fontSize: "0.8125rem",
                    }}
                  >
                    <strong>Forensic Evidence:</strong>
                    <ul
                      style={{
                        margin: "0.25rem 0 0 0",
                        paddingLeft: "1.25rem",
                      }}
                    >
                      {finding.evidence.map((ev, idx) => (
                        <li key={idx} className="mono">
                          {ev.description}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* TAB 6: RISK & ANOMALIES */}
      {activeTab === "risk" && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "1.25rem",
          }}
        >
          {/* Deterministic Violations */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Deterministic Policy Violations</h3>
              <span className="badge critical">
                {assessmentFindings.length} Rules
              </span>
            </div>
            <div style={{ padding: "1.25rem" }}>
              <p
                className="secondary-text"
                style={{ fontSize: "0.8125rem", marginTop: 0 }}
              >
                Hard cryptographic compliance rules based on RFC standards and
                enterprise security policies.
              </p>
              {assessmentFindings.map((f) => (
                <div
                  key={f.id}
                  style={{
                    padding: "0.6rem 0.85rem",
                    border: "1px solid var(--border)",
                    borderRadius: "6px",
                    marginBottom: "0.5rem",
                    background: "var(--canvas-sunken)",
                  }}
                >
                  <div
                    style={{ display: "flex", justifyContent: "space-between" }}
                  >
                    <span
                      className="mono"
                      style={{ fontWeight: 600, fontSize: "0.8125rem" }}
                    >
                      {f.rule_id}
                    </span>
                    <span
                      className={`badge ${
                        f.severity === "critical"
                          ? "critical"
                          : f.severity === "high"
                            ? "high"
                            : ""
                      }`}
                      style={{ fontSize: "0.6875rem" }}
                    >
                      {f.severity}
                    </span>
                  </div>
                  <div style={{ fontSize: "0.8125rem", marginTop: "0.25rem" }}>
                    {f.title}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Behavioral / Baseline Anomalies */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Behavioral &amp; Drift Anomalies</h3>
              <span className="badge">
                {assetAnomaliesQuery.data?.length ?? 0} Detected
              </span>
            </div>
            <div style={{ padding: "1.25rem" }}>
              <p
                className="secondary-text"
                style={{ fontSize: "0.8125rem", marginTop: 0 }}
              >
                Deviations from learned historical server baseline (e.g. cipher
                drift, unexpected ports).
              </p>
              {(assetAnomaliesQuery.data ?? []).length === 0 ? (
                <div
                  className="secondary-text"
                  style={{ textAlign: "center", padding: "1.5rem" }}
                >
                  No behavioral anomalies detected against baseline.
                </div>
              ) : (
                assetAnomaliesQuery.data?.map((anom, idx) => (
                  <div
                    key={idx}
                    style={{
                      padding: "0.6rem 0.85rem",
                      border: "1px solid var(--border)",
                      borderRadius: "6px",
                      marginBottom: "0.5rem",
                      background: "var(--canvas-sunken)",
                    }}
                  >
                    <div style={{ fontWeight: 600, fontSize: "0.8125rem" }}>
                      {anom.title}
                    </div>
                    <div
                      className="secondary-text"
                      style={{ fontSize: "0.75rem", marginTop: "0.2rem" }}
                    >
                      Signal: {anom.signal} · Current: {anom.current_value}{" "}
                      (Baseline: {anom.baseline_value}) · {anom.evidence}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 7: REMEDIATION & VERIFICATION */}
      {activeTab === "remediation" && (
        <div
          style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}
        >
          {primaryAsset && assetPostureQuery.data?.guidance ? (
            <div>
              <div
                className="card"
                style={{ padding: "1.25rem 1.5rem", marginBottom: "1.25rem" }}
              >
                <h3 className="card-title" style={{ margin: "0 0 0.5rem 0" }}>
                  Interactive Remediation &amp; Active Verification Cycle
                </h3>
                <p
                  className="secondary-text"
                  style={{ margin: 0, fontSize: "0.875rem" }}
                >
                  Apply configuration mitigations to eliminate legacy protocols,
                  disable static RSA, or renew expired certificates, then run an
                  active TLS verification probe to prove the fix.
                </p>
              </div>

              {assetPostureQuery.data.guidance.map((g, idx) => (
                <RemediationWorkflow
                  key={idx}
                  assetId={primaryAsset.id}
                  guidance={g}
                  sessionId={selectedSessionId || undefined}
                />
              ))}
            </div>
          ) : (
            <div
              className="card"
              style={{ padding: "2rem", textAlign: "center" }}
            >
              <p className="secondary-text">
                No active remediation guidance found for this capture's assets.
              </p>
            </div>
          )}
        </div>
      )}

      {/* TAB 8: FORENSIC REPORT */}
      {activeTab === "report" && (
        <div className="card" style={{ padding: "2rem" }}>
          <div id="forensic-report-content">
            {/* Formal Report Header */}
            <div
              style={{
                borderBottom: "2px solid var(--hairline)",
                paddingBottom: "1.25rem",
                marginBottom: "1.5rem",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                }}
              >
                <div>
                  <span className="badge" style={{ marginBottom: "0.5rem" }}>
                    CONFIDENTIAL FORENSIC AUDIT REPORT
                  </span>
                  <h1
                    style={{
                      margin: "0.25rem 0 0.5rem 0",
                      fontSize: "1.75rem",
                    }}
                  >
                    {assessment.title}
                  </h1>
                  <div
                    className="secondary-text"
                    style={{ fontSize: "0.875rem" }}
                  >
                    Prepared by Mailent · Email security analysis
                  </div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div
                    style={{
                      fontSize: "1.5rem",
                      fontWeight: 700,
                      color:
                        assessment.posture_score >= 80
                          ? "var(--status-success-ink)"
                          : "var(--status-danger-ink)",
                    }}
                  >
                    {Math.round(assessment.posture_score)}/100 (
                    {assessment.posture_grade})
                  </div>
                  <div
                    className="secondary-text"
                    style={{ fontSize: "0.75rem" }}
                  >
                    Posture Rating
                  </div>
                </div>
              </div>
            </div>

            {/* Forensic Traceability Section */}
            <div style={{ marginBottom: "1.5rem" }}>
              <h3
                style={{
                  fontSize: "1.125rem",
                  borderBottom: "1px solid var(--border)",
                  paddingBottom: "0.35rem",
                }}
              >
                1. Evidence Traceability &amp; Capture Hash
              </h3>
              <table
                style={{
                  width: "100%",
                  fontSize: "0.875rem",
                  borderCollapse: "collapse",
                }}
              >
                <tbody>
                  <tr>
                    <td
                      style={{
                        padding: "0.4rem 0",
                        width: "180px",
                        fontWeight: 600,
                      }}
                    >
                      Capture File:
                    </td>
                    <td className="mono">{assessment.capture_name}</td>
                  </tr>
                  <tr>
                    <td style={{ padding: "0.4rem 0", fontWeight: 600 }}>
                      SHA-256 Fingerprint:
                    </td>
                    <td className="mono" style={{ wordBreak: "break-all" }}>
                      {assessment.capture_hash}
                    </td>
                  </tr>
                  <tr>
                    <td style={{ padding: "0.4rem 0", fontWeight: 600 }}>
                      File Size:
                    </td>
                    <td>
                      {(assessment.capture_size_bytes / 1024).toFixed(1)} KB
                    </td>
                  </tr>
                  <tr>
                    <td style={{ padding: "0.4rem 0", fontWeight: 600 }}>
                      Assessment Timestamp:
                    </td>
                    <td>{new Date(assessment.created_at).toUTCString()}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Executive Summary */}
            <div style={{ marginBottom: "1.5rem" }}>
              <h3
                style={{
                  fontSize: "1.125rem",
                  borderBottom: "1px solid var(--border)",
                  paddingBottom: "0.35rem",
                }}
              >
                2. Executive Cryptographic Summary
              </h3>
              <p style={{ fontSize: "0.875rem", lineHeight: 1.6 }}>
                Passive packet inspection of email transport sessions revealed{" "}
                {assessment.session_ids.length} flow(s) across{" "}
                {assessment.asset_ids.length} target endpoint(s). The evaluated
                traffic received a composite posture rating of{" "}
                <strong>
                  {Math.round(assessment.posture_score)}/100 (Grade{" "}
                  {assessment.posture_grade})
                </strong>
                , with a rule-based risk level of{" "}
                <strong>{assessment.ai_risk_classification}</strong>.
              </p>
              <div
                style={{
                  padding: "0.85rem 1rem",
                  background: "var(--canvas-sunken)",
                  borderRadius: "6px",
                  fontSize: "0.875rem",
                  fontStyle: "italic",
                }}
              >
                "{assessment.ai_risk_rationale}"
              </div>
            </div>

            {/* Findings Section */}
            <div style={{ marginBottom: "1.5rem" }}>
              <h3
                style={{
                  fontSize: "1.125rem",
                  borderBottom: "1px solid var(--border)",
                  paddingBottom: "0.35rem",
                }}
              >
                3. Observed Cryptographic Non-Compliances (
                {assessmentFindings.length})
              </h3>
              {assessmentFindings.length === 0 ? (
                <p className="secondary-text" style={{ fontSize: "0.875rem" }}>
                  No RFC policy non-compliances observed in analyzed traffic.
                </p>
              ) : (
                assessmentFindings.map((f, i) => (
                  <div
                    key={f.id}
                    style={{ marginBottom: "1rem", fontSize: "0.875rem" }}
                  >
                    <div style={{ fontWeight: 600 }}>
                      {i + 1}. [{f.severity.toUpperCase()}] {f.title} (
                      {f.rule_id})
                    </div>
                    <div
                      className="secondary-text"
                      style={{ margin: "0.2rem 0" }}
                    >
                      Reference: {f.reference} · Category: {f.category}
                    </div>
                    <div>{f.description}</div>
                    <div
                      style={{ marginTop: "0.25rem", color: "var(--accent)" }}
                    >
                      <strong>Remediation:</strong> {f.remediation}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
