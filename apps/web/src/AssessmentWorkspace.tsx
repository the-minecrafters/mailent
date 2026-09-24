import { assessmentSummary, connectionSource, domainFromTitle } from "./display-copy";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  type AssessmentRecord,
  type Asset,
  archiveReport,
  downloadAssessmentReport,
  type EmailSession,
  type Finding,
  fetchAssessment,
  fetchAssetAnomalies,
  fetchAssetPosture,
  fetchAssets,
  fetchDomainHistory,
  fetchFindings,
  fetchSessions,
  type ReportFormat,
  runNowMonitor,
} from "./api";
import { Icon } from "./components/Icon";
import { MailentLogo } from "./components/MailentLogo";
import { ErrorState, LoadingState } from "./components/ui";
import { ProbeEvidence } from "./ProbePanel";
import { ProtocolLadder } from "./components/ProtocolLadder";
import { RemediationWorkflow } from "./RemediationWorkflow";
import { ScheduleMonitorModal } from "./ScheduleMonitorModal";

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
  | "report"
  | "history";

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
    "history",
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
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
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
  const scoreAvailable =
    assessment?.posture_grade !== "N/A" &&
    assessment?.posture_grade.toLowerCase() !== "inconclusive" &&
    assessment?.ai_risk_classification !== "INCONCLUSIVE";
  const scoreLabel = scoreAvailable && assessment ? `${Math.round(assessment.posture_score)}/100 (${assessment.posture_grade})` : "Not scored — connection check incomplete";
  const isInfra =
    assessment?.source?.type === "infrastructure" ||
    Boolean(
      assessment?.metadata && assessment?.metadata.source === "infrastructure",
    ) ||
    Boolean(assessment?.title.toLowerCase().includes("infrastructure"));
  const infraMeta = isInfra ? (assessment?.source as any) : null;
  const targetDomain = isInfra
    ? (infraMeta?.target_domain ??
      domainFromTitle(assessment?.title ?? "") ??
      "")
    : "";

  const [scheduleModalOpen, setScheduleModalOpen] = useState(false);

  const historyQuery = useQuery({
    queryKey: ["domainHistory", targetDomain],
    queryFn: () => fetchDomainHistory(targetDomain),
    enabled: isInfra && !!targetDomain,
  });

  const runNowMutation = useMutation({
    mutationFn: (monitorId: string) => runNowMonitor(monitorId),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["domainHistory", targetDomain],
      });
    },
  });

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

  const [exportingFormat, setExportingFormat] = useState<ReportFormat | null>(null);

  const handleCopyCmd = async (cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopiedCmd(cmd);
      setTimeout(() => setCopiedCmd(null), 2000);
    } catch {
      // ignore
    }
  };

  const handleExport = async (format: ReportFormat) => {
    if (!assessment || exportingFormat) return;
    setExportingFormat(format);
    setActionError(null);
    try {
      if (format === "json") {
        try {
          await downloadAssessmentReport(assessment.id, "json", assessment.title);
        } catch {
          handleDownloadJson();
        }
      } else {
        await downloadAssessmentReport(assessment.id, format, assessment.title);
      }
    } catch (err: any) {
      setActionError(`Export failed: ${err.message || err}`);
    } finally {
      setExportingFormat(null);
    }
  };

  const handleArchiveReport = async () => {
    if (!assessment || archiving) return;
    setActionError(null);
    const targetId = primaryAsset?.id || assessment.session_ids[0];
    if (!targetId) {
      setActionError("No server or session is available for this report.");
      return;
    }
    setArchiving(true);
    try {
      const result = await archiveReport({
        subject_kind: primaryAsset ? "asset" : "session",
        subject_id: targetId,
        notes: `Assessment: ${assessment.title}. ${scoreLabel}. ${assessmentSummary(assessment.ai_risk_rationale)}`,
      });
      setArchiveSuccess(`Server report saved: ${result.id.slice(0, 8)}`);
      setTimeout(() => setArchiveSuccess(null), 4000);
      void queryClient.invalidateQueries({ queryKey: ["archived-reports"] });
    } catch (err: any) {
      setActionError(`Could not save report: ${err.message}`);
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
            "Capture not found"}
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
            onClick={() => handleExport("json")}
            disabled={exportingFormat !== null}
            title="Download structured JSON report"
          >
            <Icon name="download" size={16} />
            <span>{exportingFormat === "json" ? "Exporting…" : "Export JSON"}</span>
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => handleExport("html")}
            disabled={exportingFormat !== null}
            title="Download standalone HTML forensic dossier"
          >
            <Icon name="download" size={16} />
            <span>{exportingFormat === "html" ? "Exporting…" : "Export HTML"}</span>
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => handleExport("pdf")}
            disabled={exportingFormat !== null}
            title="Download official PDF forensic report"
          >
            <Icon name="download" size={16} />
            <span>{exportingFormat === "pdf" ? "Exporting…" : "Export PDF"}</span>
          </button>
          <button
            className="btn btn-secondary"
            onClick={handlePrintReport}
            title="Print or save via browser"
          >
            <Icon name="print" size={16} />
            <span>Print</span>
          </button>
          {isInfra && (
            <button
              className="btn btn-secondary"
              onClick={() => setScheduleModalOpen(true)}
              title="Schedule recurring monitoring for this domain"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.4rem",
              }}
            >
              <Icon name="schedule" size={16} />
              <span>Schedule monitoring</span>
            </button>
          )}
          <button
            className="btn btn-primary"
            onClick={handleArchiveReport}
            title="Save a snapshot of the primary server and its evidence"
            disabled={archiving}
          >
            <Icon name="archive" size={16} />
            <span>{archiving ? "Saving…" : "Save server report"}</span>
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
              <span className={`badge ${isInfra ? "fresh" : ""}`}>
                {isInfra ? "Domain check" : "Capture analysis"}
              </span>
              <span
                className="secondary-text"
                style={{ fontSize: "0.875rem" }}
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
                fontSize: "0.875rem",
              }}
            >
              {isInfra ? (
                <>
                  <span className="mono secondary-text">
                    Target:{" "}
                    <strong>
                      {targetDomain}
                    </strong>
                  </span>
                  <span style={{ color: "var(--border)" }}>•</span>
                  <span className="mono secondary-text">
                    Endpoints:{" "}
                    <strong>
                      {infraMeta?.discovered_endpoints?.length ??
                        assessment.asset_ids.length}
                    </strong>
                  </span>
                  <span style={{ color: "var(--border)" }}>•</span>
                  <span className="mono secondary-text">
                    Discovery: <strong>DNS and live connection checks</strong>
                  </span>
                </>
              ) : (
                <>
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
                        fontSize: "0.875rem",
                        color: "var(--accent)",
                      }}
                      title="Copy full SHA-256 hash"
                    >
                      {copiedHash ? "Copied!" : "Copy"}
                    </button>
                  </span>
                </>
              )}
            </div>
          </div>

          {/* Posture Score & AI Risk Box */}
          <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
            <div
              style={{
                padding: "0.85rem 1.25rem",
                borderRadius: "8px",
                textAlign: "center",
                background: !scoreAvailable ? "var(--surface-alt)" :
                  assessment.posture_score >= 80
                    ? "var(--status-success-bg)"
                    : assessment.posture_score >= 60
                      ? "var(--status-warning-bg)"
                      : "var(--status-danger-bg)",
                border: !scoreAvailable ? "1px solid var(--border)" :
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
                  color: !scoreAvailable ? "var(--ink)" :
                    assessment.posture_score >= 80
                      ? "var(--status-success-ink)"
                      : assessment.posture_score >= 60
                        ? "var(--status-warning-ink)"
                        : "var(--status-danger-ink)",
                }}
              >
                {scoreAvailable ? <>{Math.round(assessment.posture_score)}
                <span style={{ fontSize: "0.875rem", fontWeight: 500 }}>
                  /100
                </span></> : "Not scored"}
              </div>
              <div
                style={{
                  fontSize: "0.875rem",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  marginTop: "0.25rem",
                  color: !scoreAvailable ? "var(--ink-muted)" :
                    assessment.posture_score >= 80
                      ? "var(--status-success-ink)"
                      : assessment.posture_score >= 60
                        ? "var(--status-warning-ink)"
                        : "var(--status-danger-ink)",
                }}
              >
                {scoreAvailable ? `Grade ${assessment.posture_grade}` : "Check incomplete"}
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
                  fontSize: "0.875rem",
                  fontWeight: 700,
                  padding: "0.3rem 0.6rem",
                }}
              >
                {assessment.ai_risk_classification === "INCONCLUSIVE"
                  ? "INCONCLUSIVE"
                  : `${assessment.ai_risk_classification} RISK`}
              </div>
              <div
                className="secondary-text"
                style={{ fontSize: "0.875rem", marginTop: "0.35rem" }}
              >
                {assessment.ai_risk_classification === "INCONCLUSIVE"
                  ? "Unverified connections"
                  : "Based on policy rules"}
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
          <span style={{ fontSize: "0.875rem", fontWeight: 600 }}>
            Protocols found:
          </span>
          {!scoreAvailable || assessment.protocols_identified.length === 0 ? (
            <span className="badge">No mail protocols verified</span>
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
          <span>Risk &amp; warnings</span>
        </button>
        {assessmentFindings.length > 0 && (
          <button
            className={`tab-btn ${activeTab === "remediation" ? "active" : ""}`}
            aria-current={activeTab === "remediation" ? "page" : undefined}
            onClick={() => setActiveTab("remediation")}
          >
            <Icon name="build" size={16} />
            <span>Fixes &amp; testing ({assessmentFindings.length})</span>
          </button>
        )}
        <button
          className={`tab-btn ${activeTab === "report" ? "active" : ""}`}
          aria-current={activeTab === "report" ? "page" : undefined}
          onClick={() => setActiveTab("report")}
        >
          <Icon name="article" size={16} />
          <span>Report</span>
        </button>
        {isInfra && (
          <button
            className={`tab-btn ${activeTab === "history" ? "active" : ""}`}
            aria-current={activeTab === "history" ? "page" : undefined}
            onClick={() => setActiveTab("history")}
          >
            <Icon name="history" size={16} />
            <span>Monitoring &amp; history</span>
          </button>
        )}
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
              <div className="metric-tile-label">Sessions checked</div>
              <div className="metric-tile-value">
                {assessment.session_ids.length}
              </div>
              <div className="metric-tile-sub">Recorded connections</div>
            </div>
            <div className="metric-tile">
              <div className="metric-tile-label">Mail servers</div>
              <div className="metric-tile-value">
                {assessment.asset_ids.length}
              </div>
              <div className="metric-tile-sub">Servers identified</div>
            </div>
            <div className="metric-tile">
              <div className="metric-tile-label">Critical findings</div>
              <div
                className="metric-tile-value"
                style={{
                  color:
                    criticalCount > 0 ? "var(--status-danger-ink)" : undefined,
                }}
              >
                {criticalCount}
              </div>
              <div className="metric-tile-sub">High-priority findings</div>
            </div>
            <div className="metric-tile">
              <div className="metric-tile-label">Findings</div>
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
                  : assessment.ai_risk_classification === "HIGH"
                    ? "var(--status-warning-bg)"
                    : "var(--surface-card-solid)",
              border:
                assessment.ai_risk_classification === "CRITICAL"
                  ? "1px solid var(--status-danger-border)"
                  : assessment.ai_risk_classification === "HIGH"
                    ? "1px solid var(--status-warning-border)"
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
              <span
                className={`badge ${
                  assessment.ai_risk_classification === "CRITICAL"
                    ? "critical"
                    : assessment.ai_risk_classification === "HIGH"
                      ? "high"
                      : assessment.ai_risk_classification === "LOW"
                        ? "fresh"
                        : ""
                }`}
                style={{ fontWeight: 700 }}
              >
                {assessment.ai_risk_classification === "INCONCLUSIVE"
                  ? "STATUS: INCONCLUSIVE"
                  : `RISK LEVEL: ${assessment.ai_risk_classification}`}
              </span>
              <span className="secondary-text" style={{ fontSize: "0.875rem" }}>
                {assessment.ai_risk_classification === "INCONCLUSIVE"
                  ? "Unverified connections"
                  : "Rule-based assessment"}
              </span>
            </div>
            <p style={{ margin: 0, fontSize: "0.9375rem", lineHeight: 1.5 }}>
              {assessmentSummary(assessment.ai_risk_rationale)}
            </p>
          </div>

          {/* Reconstructed Protocol Proof & Role Table */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Connection details</h3>
              <span className="badge fresh">From this capture</span>
            </div>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Server role</th>
                    <th>Evidence</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {!scoreAvailable || assessment.protocol_evidence.length === 0 ? (
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
                          style={{ fontSize: "0.875rem" }}
                        >
                          {pe.proof}
                        </td>
                        <td className="mono" style={{ fontSize: "0.875rem" }}>
                          {connectionSource(pe.verified_by)}
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
              Capture quality
            </h3>
            <p
              className="secondary-text"
              style={{ fontSize: "0.875rem", margin: "0 0 1rem 0" }}
            >
              See what this capture includes and where data is missing. Inferred events are labeled separately.
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
                  No gaps reported by the capture parser.
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
            gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
            gap: "1.25rem",
          }}
        >
          {/* Sessions List */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Recorded sessions</h3>
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
                    <th>Client and server</th>
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
                          No sessions found in this capture
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
                          <td className="mono" style={{ fontSize: "0.875rem" }}>
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
                                fontSize: "0.875rem",
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
              <h3 className="card-title">Connection timeline</h3>
              <span className="badge fresh">Recorded events</span>
            </div>
            <div style={{ padding: "1.25rem" }}>
              {selectedSession ? (
                <>
                  <ProtocolLadder session={selectedSession} />
                  <div style={{ marginBottom: "1rem", fontSize: "0.875rem" }}>
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
                            style={{ fontSize: "0.875rem", marginTop: "2px" }}
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
                              style={{ fontSize: "0.875rem" }}
                            >
                              Source: {event.source} ·{" "}
                              {new Date(event.timestamp).toLocaleTimeString()}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : isInfra ? (
                    <div style={{ padding: "0.5rem 0" }}>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "0.5rem",
                          marginBottom: "0.75rem",
                        }}
                      >
                        <span className="badge fresh">
                          Live connection check
                        </span>
                        <span
                          className="secondary-text"
                          style={{ fontSize: "0.875rem" }}
                        >
                          Verified over TCP port {selectedSession.flow.dst_port}
                        </span>
                      </div>
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: "0.75rem",
                        }}
                      >
                        <div
                          style={{
                            padding: "0.75rem 1rem",
                            border: "1px solid var(--border)",
                            borderRadius: "6px",
                            background: "var(--canvas-sunken)",
                          }}
                        >
                          <div
                            style={{ fontWeight: 600, fontSize: "0.875rem" }}
                          >
                            Protocol Handshake:{" "}
                            {selectedSession.protocol.toUpperCase()}
                          </div>
                          <div
                            className="secondary-text mono"
                            style={{
                              fontSize: "0.875rem",
                              marginTop: "0.25rem",
                            }}
                          >
                            STARTTLS Status: {selectedSession.starttls_state}
                          </div>
                        </div>
                        {selectedSession.tls_version && (
                          <div
                            style={{
                              padding: "0.75rem 1rem",
                              border: "1px solid var(--border)",
                              borderRadius: "6px",
                              background: "var(--canvas-sunken)",
                            }}
                          >
                            <div
                              style={{ fontWeight: 600, fontSize: "0.875rem" }}
                            >
                              Negotiated TLS: {selectedSession.tls_version}
                            </div>
                            <div
                              className="secondary-text mono"
                              style={{
                                fontSize: "0.875rem",
                                marginTop: "0.25rem",
                              }}
                            >
                              Cipher:{" "}
                              {selectedSession.cipher_suite?.name || "Standard"}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div
                      className="secondary-text"
                      style={{ fontSize: "0.875rem", padding: "1rem 0" }}
                    >
                      No detailed timeline is available for this connection.
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
                Encryption details
              </h3>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(min(240px, 100%), 1fr))",
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
                    style={{ fontSize: "0.875rem", marginTop: "0.5rem" }}
                  >
                    {selectedSession.starttls_state === "tls_established"
                      ? "The connection upgraded to encryption with STARTTLS."
                      : selectedSession.starttls_state === "advertised_not_used"
                        ? "The server offered STARTTLS, but this connection remained unencrypted."
                        : "No STARTTLS upgrade was recorded."}
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
                    style={{ fontSize: "0.875rem", marginTop: "0.5rem" }}
                  >
                    {selectedSession.tls_version === "tls10" ||
                    selectedSession.tls_version === "tls11"
                      ? "RFC 8996 Prohibited: TLS 1.0/1.1 are deprecated and vulnerable to POODLE, BEAST, and downgrade attacks."
                      : selectedSession.tls_version
                        ? "A modern TLS version was recorded."
                        : "No TLS handshake established."}
                  </p>
                </div>

                <div className="drift-card">
                  <h4>Negotiated Cipher Suite</h4>
                  <div style={{ marginTop: "0.5rem" }}>
                    <span
                      className="badge mono"
                      style={{ fontSize: "0.875rem" }}
                    >
                      {selectedSession.cipher_suite?.name || "Unavailable"}
                    </span>
                  </div>
                  <p
                    className="secondary-text"
                    style={{ fontSize: "0.875rem", marginTop: "0.5rem" }}
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
                    style={{ fontSize: "0.875rem", marginTop: "0.5rem" }}
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
                    Certificate details
                  </h3>
                  <div
                    className="mono secondary-text"
                    style={{ fontSize: "0.875rem", marginTop: "0.25rem" }}
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
                  gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                  gap: "1.25rem",
                }}
              >
                <div>
                  <h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem" }}>
                    Subject
                  </h4>
                  <div
                    className="mono"
                    style={{
                      padding: "0.6rem 0.85rem",
                      background: "var(--canvas-sunken)",
                      borderRadius: "6px",
                      fontSize: "0.875rem",
                    }}
                  >
                    {selectedSession.certificate.reference.subject}
                  </div>
                </div>

                <div>
                  <h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem" }}>
                    Issuer
                  </h4>
                  <div
                    className="mono"
                    style={{
                      padding: "0.6rem 0.85rem",
                      background: "var(--canvas-sunken)",
                      borderRadius: "6px",
                      fontSize: "0.875rem",
                    }}
                  >
                    {selectedSession.certificate.reference.issuer}
                  </div>
                </div>

                <div>
                  <h4 style={{ margin: "0 0 0.5rem 0", fontSize: "0.875rem" }}>
                    Valid dates
                  </h4>
                  <div
                    style={{
                      padding: "0.6rem 0.85rem",
                      background: "var(--canvas-sunken)",
                      borderRadius: "6px",
                      fontSize: "0.875rem",
                    }}
                  >
                    <div>
                      <strong>Valid from:</strong>{" "}
                      {selectedSession.certificate.validity.not_before}
                    </div>
                    <div>
                      <strong>Expires:</strong>{" "}
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
                      fontSize: "0.875rem",
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
                No certificate was recorded for this connection. The traffic may be unencrypted, or the certificate exchange may be missing from the capture.
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
              <h3>No findings</h3>
              <p className="secondary-text">
                The available traffic did not trigger any of the selected policy rules.
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
                        style={{ fontSize: "0.875rem", fontWeight: 600 }}
                      >
                        {finding.rule_id}
                      </span>
                      <span className="badge">{finding.category}</span>
                      <span
                        className="secondary-text"
                        style={{ fontSize: "0.875rem" }}
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
                    style={{ fontSize: "0.875rem" }}
                  >
                    Review fix →
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
                      fontSize: "0.875rem",
                    }}
                  >
                    <strong>Evidence:</strong>
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
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          {/* JEV AI INTELLIGENCE BANNER */}
          <div
            className="card"
            style={{
              padding: "1.25rem 1.5rem",
              background: "var(--canvas-sunken)",
              border: "1px solid var(--border)",
              borderLeft: `4px solid ${
                assessment.ai_risk_classification === "CRITICAL"
                  ? "var(--status-critical-border, #ef4444)"
                  : assessment.ai_risk_classification === "HIGH"
                    ? "var(--status-warning-border, #f59e0b)"
                    : "var(--accent, #3b82f6)"
              }`,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                flexWrap: "wrap",
                gap: "1rem",
                marginBottom: "0.75rem",
              }}
            >
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <span
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "0.35rem",
                      fontWeight: 700,
                      fontSize: "0.9375rem",
                      color: "var(--ink)",
                    }}
                  >
                    <Icon name="psychology" size={20} />
                    Jev AI Threat Prioritization & Risk Engine
                  </span>
                  <span
                    className="badge"
                    style={{
                      background: "var(--accent-subtle)",
                      color: "var(--accent)",
                      fontSize: "0.75rem",
                      fontWeight: 600,
                    }}
                  >
                    {assessment.metadata?.ai_provider === "jev"
                      ? "Jev Engine Online"
                      : "Jev Deterministic Mode"}
                  </span>
                  {assessment.metadata?.jev_model && (
                    <span className="mono" style={{ fontSize: "0.75rem", color: "var(--ink-secondary)" }}>
                      model: {assessment.metadata.jev_model}
                    </span>
                  )}
                </div>
                <p
                  className="secondary-text"
                  style={{ fontSize: "0.875rem", margin: "0.35rem 0 0 0" }}
                >
                  Evaluates cryptographic handshakes, cipher negotiation, and protocol transition boundaries using evidence-grounded reasoning.
                </p>
              </div>

              <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
                <div style={{ textAlign: "right" }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--ink-secondary)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                    AI Confidence
                  </div>
                  <div className="mono" style={{ fontWeight: 700, fontSize: "1.125rem", color: "var(--ink)" }}>
                    {Math.round((assessment.ai_confidence ?? 0) * 100)}%
                  </div>
                </div>
                <span
                  className={`badge ${
                    assessment.ai_risk_classification === "CRITICAL"
                      ? "critical"
                      : assessment.ai_risk_classification === "HIGH"
                        ? "high"
                        : ""
                  }`}
                  style={{ fontSize: "0.9375rem", padding: "0.4rem 0.8rem", fontWeight: 700 }}
                >
                  {assessment.ai_risk_classification} RISK
                </span>
              </div>
            </div>

            <div
              style={{
                padding: "0.85rem 1rem",
                borderRadius: "6px",
                background: "var(--surface)",
                border: "1px solid var(--border)",
                fontSize: "0.875rem",
                lineHeight: "1.5",
              }}
            >
              <div style={{ fontWeight: 600, marginBottom: "0.25rem", color: "var(--ink)" }}>
                Analysis & Decision Rationale:
              </div>
              <div className="mono" style={{ color: "var(--ink-secondary)", fontSize: "0.85rem", whiteSpace: "pre-wrap" }}>
                {assessment.ai_risk_rationale || "No security risks identified in evaluated connections."}
              </div>
            </div>
          </div>

          {/* THREAT PRIORITIZATION MATRIX */}
          {Array.isArray(assessment.metadata?.threat_matrix) && assessment.metadata.threat_matrix.length > 0 && (
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Threat Prioritization Matrix</h3>
                <span className="badge critical">
                  {assessment.metadata.threat_matrix.length} Prioritized Threats
                </span>
              </div>
              <div style={{ padding: "1.25rem" }}>
                <p className="secondary-text" style={{ fontSize: "0.875rem", marginTop: 0, marginBottom: "1rem" }}>
                  Adversarial exploitability analysis mapping identified cryptographic flaws to active attacker attack vectors.
                </p>
                <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                  {assessment.metadata.threat_matrix.map((item: any, idx: number) => (
                    <div
                      key={idx}
                      style={{
                        padding: "1rem",
                        borderRadius: "6px",
                        border: "1px solid var(--border)",
                        background: "var(--canvas-sunken)",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                          <span
                            className="badge"
                            style={{
                              fontWeight: 700,
                              fontSize: "0.8rem",
                              background: item.priority_tier?.startsWith("P1")
                                ? "var(--status-critical-bg, #fee2e2)"
                                : item.priority_tier?.startsWith("P2")
                                  ? "var(--status-warning-bg, #fef3c7)"
                                  : "var(--surface-subtle)",
                              color: item.priority_tier?.startsWith("P1")
                                ? "var(--status-critical-ink, #991b1b)"
                                : item.priority_tier?.startsWith("P2")
                                  ? "var(--status-warning-ink, #92400e)"
                                  : "var(--ink)",
                              border: "1px solid currentColor",
                            }}
                          >
                            {item.priority_tier}
                          </span>
                          <span className="mono" style={{ fontWeight: 600, fontSize: "0.875rem" }}>
                            {item.rule_id}
                          </span>
                          <span style={{ fontSize: "0.875rem", color: "var(--ink-secondary)" }}>
                            — {item.title}
                          </span>
                        </div>
                        <span
                          className={`badge ${item.severity === "critical" ? "critical" : item.severity === "high" ? "high" : ""}`}
                          style={{ fontSize: "0.75rem" }}
                        >
                          {item.severity}
                        </span>
                      </div>
                      <div
                        style={{
                          fontSize: "0.875rem",
                          lineHeight: "1.45",
                          color: "var(--ink)",
                          background: "var(--surface)",
                          padding: "0.65rem 0.85rem",
                          borderRadius: "4px",
                          border: "1px solid var(--border)",
                        }}
                      >
                        <strong style={{ color: "var(--ink-primary)" }}>Exploitability / Attack Vector: </strong>
                        {item.threat_vector}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TWO COLUMN: POLICY FINDINGS & BASELINE ANOMALIES */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
              gap: "1.25rem",
            }}
          >
            {/* Deterministic Violations */}
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Policy findings</h3>
                <span className="badge critical">
                  {assessmentFindings.length} Rules
                </span>
              </div>
              <div style={{ padding: "1.25rem" }}>
                <p
                  className="secondary-text"
                  style={{ fontSize: "0.875rem", marginTop: 0 }}
                >
                  Issues found by checking traffic against policy {assessment.metadata?.policy_name || "BCP 195"}.
                </p>
                {assessmentFindings.length === 0 ? (
                  <div className="secondary-text" style={{ textAlign: "center", padding: "1.5rem" }}>
                    No policy violations detected.
                  </div>
                ) : (
                  assessmentFindings.map((f) => (
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
                          style={{ fontWeight: 600, fontSize: "0.875rem" }}
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
                          style={{ fontSize: "0.875rem" }}
                        >
                          {f.severity}
                        </span>
                      </div>
                      <div style={{ fontSize: "0.875rem", marginTop: "0.25rem" }}>
                        {f.title}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Behavioral / Baseline Anomalies */}
            <div className="card">
              <div className="card-header">
                <h3 className="card-title">Unusual changes & Drifts</h3>
                <span className="badge">
                  {((assessment.metadata?.anomalies as any[])?.length ?? assetAnomaliesQuery.data?.length ?? 0)} Detected
                </span>
              </div>
              <div style={{ padding: "1.25rem" }}>
                <p
                  className="secondary-text"
                  style={{ fontSize: "0.875rem", marginTop: 0 }}
                >
                  Cryptographic drift and anomalies detected across observation captures.
                </p>
                {(() => {
                  const items = (Array.isArray(assessment.metadata?.anomalies) && assessment.metadata.anomalies.length > 0)
                    ? assessment.metadata.anomalies
                    : (assetAnomaliesQuery.data ?? []);
                  if (items.length === 0) {
                    return (
                      <div
                        className="secondary-text"
                        style={{ textAlign: "center", padding: "1.5rem" }}
                      >
                        No unusual changes or drifts found in the available history.
                      </div>
                    );
                  }
                  return items.map((anom: any, idx: number) => (
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
                      <div style={{ fontWeight: 600, fontSize: "0.875rem" }}>
                        {anom.title}
                      </div>
                      <div
                        className="secondary-text"
                        style={{ fontSize: "0.875rem", marginTop: "0.2rem" }}
                      >
                        Signal: {anom.signal} · Current: {anom.current_value}{" "}
                        (Baseline: {anom.baseline_value}) {anom.evidence ? `· ${anom.evidence}` : ""}
                      </div>
                    </div>
                  ));
                })()}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 7: REMEDIATION & VERIFICATION */}
      {/* TAB 7: FIXES & TESTING */}
      {activeTab === "remediation" && (
        <div
          style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}
        >
          {/* Actionable MTA Hardening Recipes */}
          {Array.isArray(assessment.metadata?.remediation_roadmap) && assessment.metadata.remediation_roadmap.length > 0 && (
            <div className="card">
              <div className="card-header">
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <Icon name="build" size={18} />
                  <h3 className="card-title">Actionable MTA Hardening Recipes</h3>
                </div>
                <span className="badge">
                  {assessment.metadata.remediation_roadmap.length} Hardening Plans
                </span>
              </div>
              <div style={{ padding: "1.25rem" }}>
                <p className="secondary-text" style={{ fontSize: "0.875rem", marginTop: 0, marginBottom: "1.25rem" }}>
                  Copy-pasteable configuration directives and shell commands to remediate identified cryptographic flaws on Postfix, Dovecot, and TLS listeners.
                </p>

                <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
                  {assessment.metadata.remediation_roadmap.map((plan: any, idx: number) => {
                    const recipe = plan.recipe || {};
                    const commands: string[] = recipe.commands || [];
                    const dovecotDirectives: string[] = recipe.dovecot || [];

                    return (
                      <div
                        key={idx}
                        style={{
                          border: "1px solid var(--border)",
                          borderRadius: "8px",
                          overflow: "hidden",
                          background: "var(--canvas-sunken)",
                        }}
                      >
                        <div
                          style={{
                            padding: "0.85rem 1rem",
                            background: "var(--surface)",
                            borderBottom: "1px solid var(--border)",
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                          }}
                        >
                          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                            <span
                              className="badge"
                              style={{
                                fontWeight: 700,
                                fontSize: "0.8rem",
                                background: plan.priority?.startsWith("P1")
                                  ? "var(--status-critical-bg, #fee2e2)"
                                  : "var(--status-warning-bg, #fef3c7)",
                                color: plan.priority?.startsWith("P1")
                                  ? "var(--status-critical-ink, #991b1b)"
                                  : "var(--status-warning-ink, #92400e)",
                              }}
                            >
                              {plan.priority}
                            </span>
                            <span className="mono" style={{ fontWeight: 600, fontSize: "0.875rem" }}>
                              {plan.rule_id}
                            </span>
                            <span style={{ fontSize: "0.875rem", color: "var(--ink-secondary)" }}>
                              — {plan.title}
                            </span>
                          </div>
                          <span className="badge" style={{ textTransform: "capitalize", fontSize: "0.75rem" }}>
                            {recipe.service || "MTA"}
                          </span>
                        </div>

                        <div style={{ padding: "1rem" }}>
                          {recipe.action && (
                            <div style={{ fontSize: "0.875rem", fontWeight: 600, marginBottom: "0.75rem", color: "var(--ink)" }}>
                              {recipe.action}
                            </div>
                          )}

                          {commands.length > 0 && (
                            <div style={{ marginBottom: dovecotDirectives.length > 0 ? "1rem" : 0 }}>
                              <div style={{ fontSize: "0.8125rem", color: "var(--ink-secondary)", marginBottom: "0.35rem", fontWeight: 600 }}>
                                Terminal / Shell Execution ({recipe.service || "postfix"}):
                              </div>
                              <div
                                style={{
                                  background: "#0d1117",
                                  color: "#e6edf3",
                                  padding: "0.75rem 1rem",
                                  borderRadius: "6px",
                                  fontFamily: "monospace",
                                  fontSize: "0.8125rem",
                                  lineHeight: "1.6",
                                  position: "relative",
                                }}
                              >
                                {commands.map((cmd, cIdx) => (
                                  <div
                                    key={cIdx}
                                    style={{
                                      display: "flex",
                                      justifyContent: "space-between",
                                      alignItems: "center",
                                      padding: "0.2rem 0",
                                      borderBottom: cIdx < commands.length - 1 ? "1px solid #21262d" : "none",
                                    }}
                                  >
                                    <span style={{ wordBreak: "break-all" }}>{cmd}</span>
                                    <button
                                      type="button"
                                      onClick={() => handleCopyCmd(cmd)}
                                      className="button button-sm"
                                      style={{
                                        marginLeft: "1rem",
                                        padding: "0.15rem 0.5rem",
                                        fontSize: "0.75rem",
                                        background: copiedCmd === cmd ? "var(--accent)" : "#21262d",
                                        color: "#ffffff",
                                        border: "none",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        flexShrink: 0,
                                      }}
                                    >
                                      {copiedCmd === cmd ? "Copied!" : "Copy"}
                                    </button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {dovecotDirectives.length > 0 && (
                            <div>
                              <div style={{ fontSize: "0.8125rem", color: "var(--ink-secondary)", marginBottom: "0.35rem", fontWeight: 600 }}>
                                Dovecot Configuration (/etc/dovecot/conf.d/10-ssl.conf):
                              </div>
                              <div
                                style={{
                                  background: "#0d1117",
                                  color: "#e6edf3",
                                  padding: "0.75rem 1rem",
                                  borderRadius: "6px",
                                  fontFamily: "monospace",
                                  fontSize: "0.8125rem",
                                  lineHeight: "1.6",
                                }}
                              >
                                {dovecotDirectives.map((d, dIdx) => (
                                  <div
                                    key={dIdx}
                                    style={{
                                      display: "flex",
                                      justifyContent: "space-between",
                                      alignItems: "center",
                                    }}
                                  >
                                    <span style={{ wordBreak: "break-all" }}>{d}</span>
                                    <button
                                      type="button"
                                      onClick={() => handleCopyCmd(d)}
                                      className="button button-sm"
                                      style={{
                                        marginLeft: "1rem",
                                        padding: "0.15rem 0.5rem",
                                        fontSize: "0.75rem",
                                        background: copiedCmd === d ? "var(--accent)" : "#21262d",
                                        color: "#ffffff",
                                        border: "none",
                                        borderRadius: "4px",
                                        cursor: "pointer",
                                        flexShrink: 0,
                                      }}
                                    >
                                      {copiedCmd === d ? "Copied!" : "Copy"}
                                    </button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {primaryAsset && assetPostureQuery.data ? (() => {
            const allGuidance = assetPostureQuery.data.guidance ?? [];
            const remediableGuidance = allGuidance.filter(
              (g) => g.kind === "remediation" && Boolean(g.finding_id),
            );
            const bestPractices = allGuidance.filter(
              (g) => g.kind === "best_practice",
            );
            const isClean = assessmentFindings.length === 0 || remediableGuidance.length === 0;

            return (
              <div>
                {isClean ? (
                  <div
                    className="card"
                    style={{
                      padding: "2rem",
                      textAlign: "center",
                      border: "1px solid var(--status-success-border)",
                      background: "var(--status-success-bg)",
                      marginBottom: "1.25rem",
                    }}
                  >
                    <div
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        justifyContent: "center",
                        width: "48px",
                        height: "48px",
                        borderRadius: "50%",
                        background: "var(--status-success-bg)",
                        color: "var(--status-success-ink)",
                        marginBottom: "0.75rem",
                      }}
                    >
                      <Icon name="verified" size={28} />
                    </div>
                    <h3 style={{ margin: "0 0 0.5rem 0", color: "var(--status-success-ink)" }}>
                      No recommended fixes
                    </h3>
                    <p
                      className="secondary-text"
                      style={{ maxWidth: "560px", margin: "0 auto", fontSize: "0.9375rem" }}
                    >
                      No fixes are currently recommended based on the available results.
                    </p>
                  </div>
                ) : (
                  <div>
                    <div
                      className="card"
                      style={{ padding: "1.25rem 1.5rem", marginBottom: "1.25rem" }}
                    >
                      <h3 className="card-title" style={{ margin: "0 0 0.5rem 0" }}>
                        Fixes and verification
                      </h3>
                      <p
                        className="secondary-text"
                        style={{ margin: 0, fontSize: "0.875rem" }}
                      >
                        Apply configuration changes to fix security issues on your mail server, then run a live test to verify the fix works.
                      </p>
                    </div>

                    {remediableGuidance.map((g, idx) => (
                      <RemediationWorkflow
                        key={idx}
                        assetId={primaryAsset.id}
                        guidance={g}
                        initial={assetPostureQuery.data?.remediations?.find(
                          (r) => r.finding?.id === g.finding_id,
                        )}
                        sessionId={selectedSessionId || undefined}
                      />
                    ))}
                  </div>
                )}

                {bestPractices.length > 0 && (
                  <div style={{ marginTop: "1.5rem" }}>
                    <div className="card" style={{ padding: "1.25rem 1.5rem" }}>
                      <h4 style={{ margin: "0 0 0.4rem 0", fontSize: "1rem" }}>
                        Recommendations
                      </h4>
                      <p
                        className="secondary-text"
                        style={{ fontSize: "0.875rem", margin: "0 0 1rem 0" }}
                      >
                        Optional improvements to your mail server settings. These do not affect your score.
                      </p>
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                        {bestPractices.map((bp) => (
                          <div
                            key={bp.id}
                            style={{
                              padding: "1rem",
                              borderRadius: "6px",
                              border: "1px solid var(--hairline)",
                              background: "var(--surface-subtle)",
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                marginBottom: "0.35rem",
                              }}
                            >
                              <strong>{bp.title}</strong>
                              <span className="badge">Optional tip</span>
                            </div>
                            <p className="secondary-text" style={{ fontSize: "0.875rem", margin: "0 0 0.5rem 0" }}>
                              {bp.recommendation}
                            </p>
                            <div style={{ fontSize: "0.875rem", color: "var(--ink-secondary)" }}>
                              <strong>Why it helps:</strong> {bp.why_it_matters}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })() : (
            <div
              className="card"
              style={{ padding: "2rem", textAlign: "center" }}
            >
              <p className="secondary-text">
                No active security issues found for this capture's mail servers.
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
                    Security report
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
                    style={{
                      fontSize: "0.875rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.5rem",
                    }}
                  >
                    <MailentLogo size={20} />
                    <span>Prepared by Mailent · Email security analysis</span>
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
                    {scoreLabel}
                  </div>
                  <div
                    className="secondary-text"
                    style={{ fontSize: "0.875rem" }}
                  >
                    Security Score
                  </div>
                </div>
              </div>
            </div>

            {/* Scan Details Section */}
            <div style={{ marginBottom: "1.5rem" }}>
              <h3
                style={{
                  fontSize: "1.125rem",
                  borderBottom: "1px solid var(--border)",
                  paddingBottom: "0.35rem",
                }}
              >
                1. Check details
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
                      Target / Capture:
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
                      Scanned on:
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
                2. Summary
              </h3>
              <p style={{ fontSize: "0.875rem", lineHeight: 1.6 }}>
                Analyzed {assessment.session_ids.length} email session(s) across{" "}
                {assessment.asset_ids.length} mail server(s). Overall security score is{" "}
                <strong>
                  {scoreLabel}
                </strong>
                , with an assessed risk level of{" "}
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
                "{assessmentSummary(assessment.ai_risk_rationale)}"
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
                3. Security Issues Found (
                {assessmentFindings.length})
              </h3>
              {assessmentFindings.length === 0 ? (
                <p className="secondary-text" style={{ fontSize: "0.875rem" }}>
                  No issues were found by the selected checks in the available traffic.
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
                      Standard: {f.reference} · Category: {f.category}
                    </div>
                    <div>{f.description}</div>
                    <div
                      style={{ marginTop: "0.25rem", color: "var(--accent)" }}
                    >
                      <strong>How to fix:</strong> {f.remediation}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 9: MONITORING & HISTORICAL DRIFT */}
      {activeTab === "history" && isInfra && (
        <div
          style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}
        >
          {/* Active Monitor Card */}
          <div className="card" style={{ padding: "1.25rem 1.5rem" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "0.75rem",
                flexWrap: "wrap",
                gap: "0.75rem",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
              >
                <Icon name="schedule" size={20} />
                <h3 className="card-title" style={{ margin: 0 }}>
                  Scheduled checks
                </h3>
              </div>
              <div>
                {historyQuery.data?.monitor ? (
                  <button
                    className="btn btn-primary"
                    onClick={() =>
                      runNowMutation.mutate(historyQuery.data.monitor!.id)
                    }
                    disabled={runNowMutation.isPending}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "0.4rem",
                    }}
                  >
                    <Icon name="refresh" size={16} />
                    <span>
                      {runNowMutation.isPending ? "Queuing scan…" : "Run Now"}
                    </span>
                  </button>
                ) : (
                  <button
                    className="btn btn-primary"
                    onClick={() => setScheduleModalOpen(true)}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "0.4rem",
                    }}
                  >
                    <Icon name="add" size={16} />
                    <span>Schedule Monitoring</span>
                  </button>
                )}
              </div>
            </div>

            {historyQuery.isLoading ? (
              <LoadingState label="Loading check history…" />
            ) : historyQuery.data?.monitor ? (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                  gap: "1rem",
                  marginTop: "1rem",
                }}
              >
                <div
                  style={{
                    background: "var(--canvas-sunken)",
                    padding: "0.75rem 1rem",
                    borderRadius: "6px",
                  }}
                >
                  <div
                    className="secondary-text"
                    style={{ fontSize: "0.875rem" }}
                  >
                    Frequency
                  </div>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: "0.95rem",
                      textTransform: "capitalize",
                    }}
                  >
                    {historyQuery.data.monitor.cadence.replace(/_/g, " ")}
                  </div>
                </div>
                <div
                  style={{
                    background: "var(--canvas-sunken)",
                    padding: "0.75rem 1rem",
                    borderRadius: "6px",
                  }}
                >
                  <div
                    className="secondary-text"
                    style={{ fontSize: "0.875rem" }}
                  >
                    Run checks from
                  </div>
                  <div style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                    {historyQuery.data.monitor.execution_target.type === "cloud"
                      ? "Mailent cloud"
                      : "Connected device"}
                  </div>
                </div>
                <div
                  style={{
                    background: "var(--canvas-sunken)",
                    padding: "0.75rem 1rem",
                    borderRadius: "6px",
                  }}
                >
                  <div
                    className="secondary-text"
                    style={{ fontSize: "0.875rem" }}
                  >
                    Next Scheduled Run
                  </div>
                  <div style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                    {new Date(
                      historyQuery.data.monitor.next_run_at,
                    ).toLocaleString()}
                  </div>
                </div>
                <div
                  style={{
                    background: "var(--canvas-sunken)",
                    padding: "0.75rem 1rem",
                    borderRadius: "6px",
                  }}
                >
                  <div
                    className="secondary-text"
                    style={{ fontSize: "0.875rem" }}
                  >
                    Last Run Status
                  </div>
                  <div style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                    {historyQuery.data.monitor.last_run_at ? (
                      historyQuery.data.monitor.last_error ? (
                        <span style={{ color: "var(--status-danger-ink)" }}>
                          Failed
                        </span>
                      ) : (
                        <span style={{ color: "var(--status-success-ink)" }}>
                          Success
                        </span>
                      )
                    ) : (
                      "Pending initial run"
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <p
                className="secondary-text"
                style={{ margin: "0.5rem 0 0 0", fontSize: "0.875rem" }}
              >
                Automated continuous monitoring is not yet configured for{" "}
                <strong>{targetDomain}</strong>. Schedule regular checks to follow changes over time.
              </p>
            )}
          </div>

          {/* Historical Scans & "What Changed?" Diff Timeline */}
          <div className="card" style={{ padding: "1.25rem 1.5rem" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "1rem",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
              >
                <Icon name="history" size={20} />
                <h3 className="card-title" style={{ margin: 0 }}>
                  Check history
                </h3>
              </div>
              <span
                className="secondary-text"
                style={{ fontSize: "0.875rem" }}
              >
                {historyQuery.data?.history?.length ?? 0} historical
                assessment(s)
              </span>
            </div>

            {historyQuery.isLoading ? (
              <LoadingState label="Comparing results…" />
            ) : !historyQuery.data?.history ||
              historyQuery.data.history.length === 0 ? (
              <div
                className="secondary-text"
                style={{ padding: "1.5rem", textAlign: "center" }}
              >
                No previous checks for this domain.
              </div>
            ) : (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "1rem",
                }}
              >
                {historyQuery.data.history.map((entry, idx) => {
                  const isCurrent = entry.assessment_id === assessment.id;
                  const hasRegressions = entry.security_regressions.length > 0;
                  const hasDrift = entry.drift_events.length > 0;

                  return (
                    <div
                      key={entry.assessment_id}
                      style={{
                        border: isCurrent
                          ? "2px solid var(--accent)"
                          : "1px solid var(--border)",
                        borderRadius: "8px",
                        padding: "1rem 1.25rem",
                        background: isCurrent
                          ? "var(--surface)"
                          : "var(--canvas-sunken)",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          flexWrap: "wrap",
                          gap: "0.5rem",
                          marginBottom: "0.5rem",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "0.6rem",
                          }}
                        >
                          <span
                            style={{ fontWeight: 600, fontSize: "0.95rem" }}
                          >
                            {new Date(entry.created_at).toLocaleString()}
                          </span>
                          {isCurrent && (
                            <span className="badge fresh">Viewing</span>
                          )}
                          <span className="badge" style={{ fontWeight: 600 }}>
                            Score: {entry.posture_score} ({entry.posture_grade})
                          </span>
                        </div>
                        <div
                          className="secondary-text"
                          style={{ fontSize: "0.875rem" }}
                        >
                          {entry.findings_count} finding(s)
                        </div>
                      </div>

                      {/* Security Regressions Banner */}
                      {hasRegressions && (
                        <div
                          style={{
                            background: "var(--status-danger-bg)",
                            border: "1px solid var(--status-danger-border)",
                            borderRadius: "6px",
                            padding: "0.6rem 0.85rem",
                            marginTop: "0.5rem",
                            fontSize: "0.875rem",
                          }}
                        >
                          <div
                            style={{
                              fontWeight: 700,
                              color: "var(--status-danger-ink)",
                              display: "flex",
                              alignItems: "center",
                              gap: "0.35rem",
                              marginBottom: "0.25rem",
                            }}
                          >
                            <Icon name="warning" size={15} />
                            <span>
                              New issues found
                            </span>
                          </div>
                          <ul
                            style={{
                              margin: 0,
                              paddingLeft: "1.2rem",
                              color: "var(--status-danger-ink)",
                            }}
                          >
                            {entry.security_regressions.map((reg, rIdx) => (
                              <li key={rIdx}>
                                <strong>{reg.title}:</strong> {reg.description}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Configuration Drift Details */}
                      {hasDrift && (
                        <div
                          style={{
                            background: "var(--status-warning-bg)",
                            border: "1px solid var(--status-warning-border)",
                            borderRadius: "6px",
                            padding: "0.6rem 0.85rem",
                            marginTop: "0.5rem",
                            fontSize: "0.875rem",
                          }}
                        >
                          <div
                            style={{
                              fontWeight: 600,
                              color: "var(--status-warning-ink)",
                              marginBottom: "0.25rem",
                            }}
                          >
                            What changed since previous scan:
                          </div>
                          <ul
                            style={{
                              margin: 0,
                              paddingLeft: "1.2rem",
                              color: "var(--text)",
                            }}
                          >
                            {entry.drift_events.map((drift, dIdx) => (
                              <li key={dIdx}>
                                <strong>{drift.title}:</strong>{" "}
                                {drift.description}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {!hasRegressions &&
                        !hasDrift &&
                        idx < historyQuery.data.history.length - 1 && (
                          <div
                            className="secondary-text"
                            style={{
                              fontSize: "0.875rem",
                              marginTop: "0.5rem",
                            }}
                          >
                            No changes or new issues found since the previous check.
                          </div>
                        )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {isInfra && (
        <ScheduleMonitorModal
          isOpen={scheduleModalOpen}
          domain={targetDomain}
          onClose={() => setScheduleModalOpen(false)}
          onCreated={() => {
            setScheduleModalOpen(false);
            void queryClient.invalidateQueries({
              queryKey: ["domainHistory", targetDomain],
            });
          }}
        />
      )}
    </div>
  );
}
