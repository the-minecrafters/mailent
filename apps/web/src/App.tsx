import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import {
  BrowserRouter,
  Link,
  MemoryRouter,
  Navigate,
  NavLink,
  useLocation,
  useNavigate,
  useSearchParams,
} from "react-router-dom";
import expired from "../../../fixtures/synthetic/smtp_cert_expired.json";
import rsa from "../../../fixtures/synthetic/smtp_static_rsa.json";
import legacy from "../../../fixtures/synthetic/smtp_tls10_legacy.json";
import modern from "../../../fixtures/synthetic/smtp_tls13_healthy.json";
import { AssessmentWorkspace } from "./AssessmentWorkspace";
import {
  type ArchivedReportRecord,
  type ArchivedReportSummary,
  type AssessmentRecord,
  type AssessmentSummary,
  type Asset,
  type AssetPostureHistory,
  type AssetPostureResponse,
  type AssetVerificationState,
  archiveReport,
  checkDecisionProvider,
  type CertificateRecord,
  createIntegration,
  type DriftEvent,
  deleteIntegration,
  downloadArchivedReport,
  downloadAssetReport,
  downloadInvestigationReport,
  type EmailSession,
  evaluateObservation,
  type Finding,
  fetchArchivedReports,
  fetchAssessments,
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
import { AuthGate, useAuth } from "./auth";
import { Icon } from "./components/Icon";
import {
  Button,
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  SearchField,
} from "./components/ui";
import { LandingPage } from "./LandingPage";
import { NewAssessmentModal } from "./NewAssessmentModal";
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

function useListSearch() {
  const [params, setParams] = useSearchParams();
  return [
    params.get("q") ?? "",
    (value: string) =>
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          if (value) next.set("q", value);
          else next.delete("q");
          return next;
        },
        { replace: true },
      ),
  ] as const;
}

const navigation = [
  {
    group: "Workspace",
    items: [
      {
        key: "overview",
        path: "/workspace/overview",
        label: "Overview",
        icon: "grid_view",
      },
      {
        key: "assessments",
        path: "/workspace/captures",
        label: "Captures",
        icon: "folder_open",
      },
      {
        key: "assets",
        path: "/workspace/servers",
        label: "Mail servers",
        icon: "dns",
      },
      {
        key: "sessions",
        path: "/workspace/sessions",
        label: "Sessions",
        icon: "swap_horiz",
      },
    ],
  },
  {
    group: "Security",
    items: [
      {
        key: "findings",
        path: "/workspace/findings",
        label: "Findings",
        icon: "shield",
      },
      {
        key: "investigations",
        path: "/workspace/investigations",
        label: "Investigations",
        icon: "search",
      },
      {
        key: "remediations",
        path: "/workspace/fixes",
        label: "Fixes & verification",
        icon: "build",
      },
      {
        key: "reports",
        path: "/workspace/reports",
        label: "Reports",
        icon: "description",
      },
    ],
  },
  {
    group: "Manage",
    items: [
      {
        key: "simulation",
        path: "/workspace/policies",
        label: "Policy checks",
        icon: "rule",
      },
      {
        key: "integrations",
        path: "/workspace/integrations",
        label: "Integrations",
        icon: "sync_alt",
      },
      {
        key: "sensors",
        path: "/workspace/collectors",
        label: "Collectors",
        icon: "sensors",
      },
    ],
  },
];
const pages = navigation.flatMap((group) => group.items);

export function App({
  initialView,
  initialExperience,
}: {
  initialView?: string;
  initialExperience?: "landing" | "auth" | "workspace";
}) {
  // MemoryRouter keeps component tests isolated from browser history.
  if (initialView || initialExperience) {
    return (
      <MemoryRouter
        initialEntries={[
          pages.find((p) => p.key === initialView)?.path ??
            (initialView === "evaluator"
              ? "/workspace/tools/evaluator"
              : "/workspace/overview"),
        ]}
      >
        <Workspace />
      </MemoryRouter>
    );
  }
  return (
    <BrowserRouter>
      <SiteRoutes />
    </BrowserRouter>
  );
}

function SiteRoutes() {
  const location = useLocation();
  if (location.pathname === "/") return <LandingPage />;
  if (!location.pathname.startsWith("/workspace"))
    return (
      <Navigate
        to={`/workspace${location.pathname}${location.search}`}
        replace
      />
    );
  return (
    <AuthGate>
      <Workspace />
    </AuthGate>
  );
}

function Workspace() {
  const { user, signOut } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [uploadOpen, setUploadOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const captureButtonRef = useRef<HTMLButtonElement>(null);
  const segments = location.pathname.split("/").filter(Boolean).slice(1);
  const page = pages.find((p) => p.path === `/workspace/${segments[0]}`);
  const id = segments[1] ? decodeURIComponent(segments[1]) : null;
  const activeTab =
    page?.key ??
    (import.meta.env.DEV && location.pathname === "/workspace/tools/evaluator"
      ? "evaluator"
      : "missing");
  const readinessQuery = useQuery({
    queryKey: ["readiness"],
    queryFn: readReadiness,
    refetchInterval: 15000,
    retry: false,
  });
  const connected = readinessQuery.isSuccess && readinessQuery.data.ready;

  useEffect(() => {
    document.title = `${page?.label ?? "Mailent"} · Mailent`;
    setMenuOpen(false);
    mainRef.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [location.pathname, page?.label]);

  const open = (path: string, entityId?: string) =>
    navigate(`${path}${entityId ? `/${encodeURIComponent(entityId)}` : ""}`);
  const refresh = async () => {
    setRefreshing(true);
    try {
      await queryClient.invalidateQueries();
    } finally {
      setRefreshing(false);
    }
  };
  const sidebar = (
    <>
      <Link
        to="/workspace/overview"
        className="sidebar-brand"
        aria-label="Mailent overview"
      >
        <span className="brand-mark">
          <Icon name="mail" size={22} />
        </span>
        <span className="brand-title">
          mailent<span className="brand-subtitle">Email security</span>
        </span>
      </Link>
      <nav className="sidebar-nav" aria-label="Main navigation">
        {navigation.map((group) => (
          <div className="nav-group" key={group.group}>
            <div className="nav-group-title">{group.group}</div>
            {group.items.map((item) => (
              <NavLink
                key={item.key}
                to={item.path}
                className={({ isActive }) =>
                  `nav-item${isActive ? " active" : ""}`
                }
              >
                <Icon name={item.icon} size={18} />
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="sidebar-footer">
        <span className="workspace-avatar">
          <Icon name="computer" size={19} />
        </span>
        <div>
          <strong>{user ? "Private workspace" : "Local workspace"}</strong>
          <span>
            {readinessQuery.data?.storage === "in_memory"
              ? "Temporary storage"
              : readinessQuery.data?.storage
                ? "Persistent storage"
                : "Storage unavailable"}
          </span>
        </div>
        {signOut && (
          <Button
            variant="secondary"
            aria-label="Sign out"
            title={user?.email}
            onClick={() => void signOut()}
          >
            <Icon name="logout" size={18} />
          </Button>
        )}
      </div>
    </>
  );

  if (
    ["/workspace", "/workspace/"].includes(location.pathname) ||
    ["/workspace/auth", "/workspace/login"].includes(location.pathname)
  )
    return <Navigate to="/workspace/overview" replace />;
  const legacy = {
    "/assessments": "/workspace/captures",
    "/assets": "/workspace/servers",
    "/sensors": "/workspace/collectors",
    "/remediations": "/workspace/fixes",
    "/simulation": "/workspace/policies",
  } as Record<string, string>;
  if (legacy[`/${segments[0]}`])
    return (
      <Navigate
        to={`${legacy[`/${segments[0]}`]}${id ? `/${encodeURIComponent(id)}` : ""}`}
        replace
      />
    );

  return (
    <div className="app-shell menu-layout">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className="console-sidebar desktop-sidebar">{sidebar}</aside>
      <Dialog.Root open={menuOpen} onOpenChange={setMenuOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <Dialog.Content className="mobile-sidebar">
            <Dialog.Title className="sr-only">Navigation</Dialog.Title>
            <Dialog.Description className="sr-only">
              Browse your email security workspace.
            </Dialog.Description>
            <Dialog.Close
              className="icon-button mobile-close"
              aria-label="Close navigation"
            >
              <Icon name="close" />
            </Dialog.Close>
            {sidebar}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
      <div className="console-body">
        <header className="console-topbar">
          <div className="topbar-context">
            <Button
              className="mobile-menu icon-button"
              aria-label="Open navigation"
              onClick={() => setMenuOpen(true)}
            >
              <Icon name="menu" />
            </Button>
            <span className="breadcrumb-root">Workspace</span>
            <Icon name="chevron_right" size={14} />
            <span className="topbar-title">{page?.label ?? "Tools"}</span>
            {id && <span className="breadcrumb-detail">/ Details</span>}
          </div>
          <div className="topbar-actions">
            <span
              role={readinessQuery.isPending ? "status" : undefined}
              className={`connection-status ${connected ? "online" : "offline"}`}
              title={
                connected
                  ? "Connected to the Mailent service"
                  : "Check the Mailent service connection"
              }
            >
              <span className="connection-dot" />
              {readinessQuery.isPending
                ? "Connecting"
                : connected
                  ? "Connected"
                  : "Disconnected"}
            </span>
            <Button
              className="icon-button"
              aria-label="Refresh data"
              title="Refresh data"
              disabled={refreshing}
              onClick={refresh}
            >
              <Icon name="refresh" className={refreshing ? "spin" : ""} />
            </Button>
            <Button
              ref={captureButtonRef}
              variant="primary"
              onClick={() => setUploadOpen(true)}
            >
              <Icon name="add" size={17} />
              <span>Analyze capture</span>
            </Button>
          </div>
        </header>
        <main
          ref={mainRef}
          tabIndex={-1}
          id="main-content"
          className="console-main"
        >
          {readinessQuery.isError && (
            <ErrorState
              title="Cannot connect to Mailent"
              description="Check that the service is running, then try again. Existing data will appear when the connection returns."
              onRetry={() => void readinessQuery.refetch()}
            />
          )}
          {readinessQuery.data?.storage === "in_memory" && (
            <div className="storage-notice">
              <Icon name="info" size={16} />
              <span>
                Temporary storage is active. Connect persistent storage to keep
                your work after a service restart.
              </span>
            </div>
          )}
          <div key={location.pathname} className="route-view">
            {activeTab === "overview" && (
              <OverviewTab
                onSelectAssessment={(id) => open("/workspace/captures", id)}
                onSelectAsset={(id) => open("/workspace/servers", id)}
              />
            )}
            {activeTab === "assessments" && (
              <AssessmentsTab
                selectedAssessmentId={id}
                onSelectAssessment={(id) => open("/workspace/captures", id)}
                onBack={() => open("/workspace/captures")}
                onSelectAsset={(id) => open("/workspace/servers", id)}
              />
            )}
            {activeTab === "assets" && (
              <AssetsTab
                selectedAssetId={id}
                onSelectAsset={(id) => open("/workspace/servers", id)}
                onBack={() => open("/workspace/servers")}
              />
            )}
            {activeTab === "sessions" && (
              <SessionsTab
                selectedSessionId={id}
                onSelectSession={(id) => open("/workspace/sessions", id)}
                onBack={() => open("/workspace/sessions")}
              />
            )}
            {activeTab === "findings" && (
              <FindingsTab
                onStartRemediation={(id) => open("/workspace/servers", id)}
              />
            )}
            {activeTab === "investigations" && (
              <InvestigationsTab
                selectedId={id}
                onSelect={(id) => open("/workspace/investigations", id)}
                onBack={() => open("/workspace/investigations")}
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
            {activeTab === "missing" && (
              <EmptyState
                icon="search"
                title="Page not found"
                description="This address does not match a page in your workspace."
              >
                <Link className="btn btn-primary" to="/workspace/overview">
                  Back to overview
                </Link>
              </EmptyState>
            )}
          </div>
          <footer className="workspace-footnote">
            <Icon name="lock" size={13} />
            <span>
              {readinessQuery.data?.decision_provider === "jev"
                ? "Jev reviews transport findings. Email content is not sent."
                : "Mail transport analysis · Evidence-based security checks"}
            </span>
          </footer>
        </main>
      </div>
      {uploadOpen && (
        <NewAssessmentModal
          isOpen
          onClose={() => {
            setUploadOpen(false);
            captureButtonRef.current?.focus();
          }}
          onCreated={(assessment) => {
            void queryClient.invalidateQueries();
            open("/workspace/captures", assessment.id);
          }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------
// Capture list and details
// ---------------------------------------------------------
function AssessmentsTab({
  selectedAssessmentId,
  onSelectAssessment,
  onBack,
  onSelectAsset,
}: {
  selectedAssessmentId: string | null;
  onSelectAssessment: (id: string) => void;
  onBack: () => void;
  onSelectAsset: (id: string) => void;
}) {
  const [search, setSearch] = useListSearch();
  const assessmentsQuery = useQuery({
    queryKey: ["assessments"],
    queryFn: fetchAssessments,
    refetchInterval: 5000,
  });

  if (selectedAssessmentId) {
    return (
      <AssessmentWorkspace
        assessmentId={selectedAssessmentId}
        onBack={onBack}
        onSelectAsset={onSelectAsset}
      />
    );
  }

  const assessments = [...(assessmentsQuery.data ?? [])]
    .filter((a) =>
      `${a.title} ${a.capture_name}`
        .toLowerCase()
        .includes(search.toLowerCase()),
    )
    .sort((a, b) => b.created_at.localeCompare(a.created_at));

  return (
    <div className="assessments-view">
      <PageHeader
        title="Captures"
        description="Analyze network recordings and review your email security results."
      />
      <div className="list-toolbar">
        <SearchField
          value={search}
          onChange={setSearch}
          label="Search captures"
          placeholder="Search by title or filename…"
        />
        <span className="secondary-text">{assessments.length} captures</span>
      </div>
      {assessmentsQuery.isError && (
        <ErrorState
          description={assessmentsQuery.error.message}
          onRetry={() => void assessmentsQuery.refetch()}
        />
      )}
      {assessmentsQuery.isPending ? (
        <div style={{ textAlign: "center", padding: "3rem" }}>
          <div
            style={{
              display: "inline-block",
              width: "32px",
              height: "32px",
              border: "3px solid var(--hairline)",
              borderTopColor: "var(--accent)",
              borderRadius: "50%",
              animation: "spin 0.8s linear infinite",
              marginBottom: "1rem",
            }}
          />
          <p className="secondary-text">Loading assessments...</p>
        </div>
      ) : assessmentsQuery.isError ? null : assessments.length === 0 ? (
        <div className="card">
          <EmptyState
            title={search ? "No matching captures" : "No captures yet"}
            description={
              search
                ? "Try a different title or filename."
                : "Use Analyze capture to upload a PCAP or PCAPNG file and review its results."
            }
          />
        </div>
      ) : (
        <div className="card">
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Capture</th>
                  <th>Protocols</th>
                  <th>Sessions</th>
                  <th>Findings</th>
                  <th>Security score</th>
                  <th>Risk level</th>
                  <th>Created</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{a.title}</div>
                      <div
                        className="mono secondary-text"
                        style={{ fontSize: "0.75rem", marginTop: "0.15rem" }}
                      >
                        {a.capture_name} · SHA-256:{" "}
                        {a.capture_hash.slice(0, 12)}…
                      </div>
                    </td>
                    <td>
                      {a.protocols_identified.length === 0 ? (
                        <span className="badge">None</span>
                      ) : (
                        a.protocols_identified.map((proto, idx) => (
                          <span
                            key={idx}
                            className="badge fresh"
                            style={{
                              marginRight: "0.25rem",
                              fontSize: "0.7rem",
                            }}
                          >
                            {proto}
                          </span>
                        ))
                      )}
                    </td>
                    <td>
                      <span className="badge">{a.session_count} flows</span>
                    </td>
                    <td>
                      {a.finding_count > 0 ? (
                        <span
                          className={`badge ${
                            a.ai_risk_classification === "CRITICAL"
                              ? "critical"
                              : a.ai_risk_classification === "HIGH"
                                ? "high"
                                : "warning"
                          }`}
                        >
                          {a.finding_count} issue(s)
                        </span>
                      ) : (
                        <span className="badge fresh">0 issues</span>
                      )}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          a.posture_score >= 80
                            ? "fresh"
                            : a.posture_score >= 60
                              ? "warning"
                              : "critical"
                        }`}
                        style={{ fontWeight: 700 }}
                      >
                        {Math.round(a.posture_score)}/100 ({a.posture_grade})
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          a.ai_risk_classification === "CRITICAL"
                            ? "critical"
                            : a.ai_risk_classification === "HIGH"
                              ? "high"
                              : a.ai_risk_classification === "LOW"
                                ? "fresh"
                                : ""
                        }`}
                        style={{ fontSize: "0.7rem", fontWeight: 700 }}
                      >
                        {a.ai_risk_classification}
                      </span>
                    </td>
                    <td
                      className="secondary-text"
                      style={{ fontSize: "0.8125rem", whiteSpace: "nowrap" }}
                    >
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                    <td>
                      <button
                        className="btn btn-primary"
                        style={{
                          padding: "0.3rem 0.75rem",
                          fontSize: "0.8125rem",
                        }}
                        onClick={() => onSelectAssessment(a.id)}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------
// 1. OVERVIEW VIEW
// ---------------------------------------------------------
function OverviewTab({
  onSelectAssessment,
  onSelectAsset,
}: {
  onSelectAssessment: (id: string) => void;
  onSelectAsset: (id: string) => void;
}) {
  const capturesQuery = useQuery({
    queryKey: ["assessments"],
    queryFn: fetchAssessments,
    refetchInterval: 15000,
  });
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
  const captures = [...(capturesQuery.data ?? [])].sort((a, b) =>
    b.created_at.localeCompare(a.created_at),
  );
  const assets = assetsQuery.data ?? [];
  const findings = findingsQuery.data ?? [];
  const changes = [...(driftQuery.data ?? [])].sort((a, b) =>
    b.observed_at.localeCompare(a.observed_at),
  );
  const attention = assets
    .filter((a) => a.active_findings_count > 0)
    .sort((a, b) => b.active_findings_count - a.active_findings_count);
  const urgent = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high",
  ).length;
  const queries = [
    capturesQuery,
    assetsQuery,
    findingsQuery,
    driftQuery,
    investigationsQuery,
  ];
  const failed = queries.find((q) => q.isError);
  const pending = queries.some((q) => q.isPending);
  const empty =
    !pending &&
    !failed &&
    !captures.length &&
    !assets.length &&
    !findings.length;
  const count = (
    query: { isPending: boolean; isError: boolean },
    value: number,
  ) => (query.isPending || query.isError ? "—" : value);
  return (
    <div className="overview-page">
      <PageHeader
        title="Overview"
        description="Track your mail servers, review findings, and verify what needs attention."
      />
      {failed && (
        <ErrorState
          title="Some workspace data is unavailable"
          description={failed.error?.message ?? "Try refreshing the workspace."}
          onRetry={() => {
            for (const q of queries) void q.refetch();
          }}
        />
      )}
      <div className="overview-metrics">
        {[
          {
            label: "Mail servers",
            value: count(assetsQuery, assets.length),
            detail: "Discovered in your traffic",
            icon: "dns",
            to: "/workspace/servers",
          },
          {
            label: "Security findings",
            value: count(findingsQuery, findings.length),
            detail: urgent
              ? `${urgent} high or critical priority`
              : "Issues identified by policy checks",
            icon: "shield",
            to: "/workspace/findings",
          },
          {
            label: "Analyzed captures",
            value: count(capturesQuery, captures.length),
            detail: "Uploaded network recordings",
            icon: "folder_open",
            to: "/workspace/captures",
          },
          {
            label: "Open investigations",
            value: count(
              investigationsQuery,
              (investigationsQuery.data ?? []).filter(
                (i) => i.status !== "resolved",
              ).length,
            ),
            detail: "Related events to review",
            icon: "search",
            to: "/workspace/investigations",
          },
        ].map((metric) => (
          <Link className="overview-metric" to={metric.to} key={metric.label}>
            <div className="metric-heading">
              <span>{metric.label}</span>
              <Icon name={metric.icon} size={19} />
            </div>
            <strong>{metric.value}</strong>
            <span className="metric-description">{metric.detail}</span>
            <Icon name="chevron_right" size={16} className="metric-arrow" />
          </Link>
        ))}
      </div>
      {empty && (
        <section className="getting-started">
          <div className="getting-started-copy">
            <h2>No captures yet</h2>
            <p>
              Use <strong>Analyze capture</strong> to upload a network recording
              and check its email connections.
            </p>
            <span className="supported-formats">
              PCAP, PCAPNG or CAP · Up to 50 MB
            </span>
          </div>
          <ol className="onboarding-steps">
            <li>
              <span>01</span>
              <div>
                <strong>Upload a capture</strong>
                <p>Choose a recording from your network.</p>
              </div>
            </li>
            <li>
              <span>02</span>
              <div>
                <strong>Review the evidence</strong>
                <p>Inspect connections, encryption and certificates.</p>
              </div>
            </li>
            <li>
              <span>03</span>
              <div>
                <strong>Verify a fix</strong>
                <p>Resolve findings and verify your changes.</p>
              </div>
            </li>
          </ol>
        </section>
      )}
      <div className="overview-columns">
        <section className="card overview-captures">
          <div className="card-header">
            <div>
              <h2 className="card-title">Recent captures</h2>
              <p className="card-description">Your latest network analyses</p>
            </div>
            <Link className="text-link" to="/workspace/captures">
              View all <Icon name="chevron_right" size={14} />
            </Link>
          </div>
          {capturesQuery.isPending ? (
            <LoadingState label="Loading captures…" />
          ) : capturesQuery.isError ? (
            <p className="secondary-text">
              Capture history could not be loaded.
            </p>
          ) : captures.length ? (
            <div className="record-list">
              {captures.slice(0, 4).map((c) => (
                <button
                  className="record-row"
                  key={c.id}
                  onClick={() => onSelectAssessment(c.id)}
                >
                  <span className="record-icon">
                    <Icon name="description" size={20} />
                  </span>
                  <span className="record-main">
                    <strong>{c.title}</strong>
                    <span>
                      {c.session_count} sessions ·{" "}
                      {new Date(c.created_at).toLocaleDateString()}
                    </span>
                  </span>
                  <span
                    className={`badge ${c.finding_count ? "high" : "fresh"}`}
                  >
                    {c.finding_count} findings
                  </span>
                  <Icon name="chevron_right" size={16} />
                </button>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No captures analyzed yet"
              description="Your capture history and results will appear here after an upload."
            />
          )}
        </section>
        <section className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Needs attention</h2>
              <p className="card-description">
                Mail servers with open findings
              </p>
            </div>
            <span className="subtle-count">
              {count(assetsQuery, attention.length)}
            </span>
          </div>
          {assetsQuery.isPending ? (
            <LoadingState label="Loading mail servers…" />
          ) : assetsQuery.isError ? (
            <p className="secondary-text">
              Server findings could not be loaded.
            </p>
          ) : attention.length ? (
            <div className="record-list">
              {attention.slice(0, 4).map((a) => (
                <button
                  className="record-row"
                  key={a.id}
                  onClick={() => onSelectAsset(a.id)}
                >
                  <span className="record-main">
                    <strong>{a.primary_name || a.addresses[0]}</strong>
                    <span>{a.addresses.join(", ")}</span>
                  </span>
                  <span className="badge high">
                    {a.active_findings_count} findings
                  </span>
                  <Icon name="chevron_right" size={16} />
                </button>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={assets.length ? "check_circle" : "shield"}
              title={
                assets.length
                  ? "No open server findings"
                  : "No servers to review yet"
              }
              description={
                assets.length
                  ? "No current findings are linked to your discovered mail servers."
                  : "Upload a capture or connect a collector to discover mail servers."
              }
            />
          )}
        </section>
        <section className="card changes-card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Recent changes</h2>
              <p className="card-description">
                Changes to server encryption and certificates
              </p>
            </div>
            <Icon name="monitoring" size={19} />
          </div>
          {driftQuery.isPending ? (
            <LoadingState label="Loading changes…" />
          ) : driftQuery.isError ? (
            <p className="secondary-text">
              Change history could not be loaded.
            </p>
          ) : changes.length ? (
            <div className="activity-list">
              {changes.slice(0, 5).map((e) => (
                <div className="activity-row" key={e.id}>
                  <span className="activity-dot" />
                  <div>
                    <strong>{e.title}</strong>
                    <p>{e.description}</p>
                  </div>
                  <time dateTime={e.observed_at}>
                    {new Date(e.observed_at).toLocaleString()}
                  </time>
                </div>
              ))}
            </div>
          ) : (
            <div className="quiet-empty">
              <Icon name="monitoring" size={22} />
              <div>
                <strong>No changes recorded</strong>
                <p>
                  As traffic arrives, changes to your mail servers will appear
                  here.
                </p>
              </div>
            </div>
          )}
        </section>
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
  const [search, setSearch] = useListSearch();
  const assetsQuery = useQuery({ queryKey: ["assets"], queryFn: fetchAssets });
  const assets = (assetsQuery.data ?? []).filter((a) =>
    `${a.primary_name ?? ""} ${a.addresses.join(" ")} ${a.hostnames.join(" ")}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );

  if (selectedAssetId) {
    return <AssetDetailView assetId={selectedAssetId} onBack={onBack} />;
  }

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Mail servers</h1>
        <p className="secondary-text">
          Mail servers discovered from your captures and connected collectors.
        </p>
      </div>

      {assetsQuery.isPending && <p role="status">Loading assets…</p>}
      {assetsQuery.isError && (
        <p role="alert" className="error">
          Failed to load assets: {assetsQuery.error.message}
        </p>
      )}

      <div className="list-toolbar">
        <SearchField
          value={search}
          onChange={setSearch}
          label="Search mail servers"
          placeholder="Search mail servers…"
        />
        <span className="secondary-text">{assets.length} results</span>
      </div>
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
            {assets.length === 0 &&
            !assetsQuery.isPending &&
            !assetsQuery.isError ? (
              <tr>
                <td
                  colSpan={7}
                  style={{ textAlign: "center", padding: "2rem" }}
                >
                  <span className="secondary-text">
                    No matching mail servers. Upload a capture or connect a
                    collector to discover servers.
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
                      <span className="badge fresh">No findings</span>
                    )}
                  </td>
                  <td>
                    {asset.probe_authorized ? (
                      <span className="badge fresh">Authorized</span>
                    ) : (
                      <span className="badge">Not authorized</span>
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
                      View server
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
  const download = useMutation({
    mutationFn: (format: ReportFormat) => downloadAssetReport(assetId, format),
  });
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
      {download.isError && (
        <ErrorState
          title="Download failed"
          description={download.error.message}
        />
      )}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          marginBottom: "1.5rem",
        }}
      >
        <button onClick={onBack}>← Back to mail servers</button>
        <div>
          <h2>SERVER DETAILS</h2>
          <div className="mono secondary-text">
            {asset?.primary_name || asset?.addresses[0]} · ID: {assetId}
          </div>
        </div>
      </div>

      {/* Freshness & Verification Status Bar */}
      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <div className="card-header">
          <h3 className="card-title">Verification</h3>
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
        <h3>Certificate history ({certs.length})</h3>
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
        <h3>Configuration changes ({driftEvents.length})</h3>
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
        </div>
        <p className="secondary-text">
          Export a report with an integrity hash, or freeze the state into an
          immutable archived record.
        </p>

        <div
          style={{
            display: "flex",
            gap: "0.75rem",
            flexWrap: "wrap",
            marginBottom: "1rem",
          }}
        >
          <button
            disabled={download.isPending}
            onClick={() => download.mutate("json")}
          >
            Export JSON
          </button>
          <button
            disabled={download.isPending}
            onClick={() => download.mutate("html")}
          >
            Export HTML
          </button>
          <button
            disabled={download.isPending}
            onClick={() => download.mutate("pdf")}
          >
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
          <h4 style={{ margin: "0 0 0.5rem" }}>Save report snapshot</h4>
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
  const [search, setSearch] = useListSearch();
  const sessionsQuery = useQuery({
    queryKey: ["sessions"],
    queryFn: fetchSessions,
  });
  const sessions = (sessionsQuery.data ?? []).filter((a) =>
    `${a.client} ${a.server} ${a.protocol} ${a.tls_version ?? ""}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );

  if (selectedSessionId) {
    return <SessionDetailView sessionId={selectedSessionId} onBack={onBack} />;
  }

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Sessions</h1>
        <p className="secondary-text">
          Email connections found in your traffic, with encryption details and
          connection timelines.
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

      <div className="list-toolbar">
        <SearchField
          value={search}
          onChange={setSearch}
          label="Search sessions"
          placeholder="Search sessions…"
        />
        <span className="secondary-text">{sessions.length} results</span>
      </div>
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
            {sessions.length === 0 &&
            !sessionsQuery.isPending &&
            !sessionsQuery.isError ? (
              <tr>
                <td
                  colSpan={8}
                  style={{ textAlign: "center", padding: "2rem" }}
                >
                  <span className="secondary-text">
                    No sessions found. Upload a capture or connect a collector
                    to start recording email connections.
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
          <h2>SESSION DETAILS</h2>
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
  const [search, setSearch] = useListSearch();
  const resolveServer = useMutation({
    mutationFn: async (finding: Finding) => {
      const sessionId = finding.evidence.find((e) => e.session_id)?.session_id;
      if (!sessionId)
        throw new Error("This finding has no linked session to inspect.");
      const [detail, assets] = await Promise.all([
        fetchSessionDetail(sessionId),
        fetchAssets(),
      ]);
      const asset = assets.find((a) =>
        a.addresses.includes(detail.session.flow.dst_ip),
      );
      if (!asset)
        throw new Error(
          "The mail server for this finding is no longer available.",
        );
      return asset.id;
    },
    onSuccess: onStartRemediation,
  });
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const findingsQuery = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
  });
  const findings = findingsQuery.data ?? [];

  const filtered = findings.filter(
    (f) =>
      (severityFilter === "all" || f.severity === severityFilter) &&
      `${f.title} ${f.rule_id} ${f.description}`
        .toLowerCase()
        .includes(search.toLowerCase()),
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
          <h1>Findings</h1>
          <p className="secondary-text">
            Security issues found in your traffic, with evidence and recommended
            fixes.
          </p>
        </div>

        <div style={{ display: "flex", gap: "0.5rem" }}>
          {["all", "critical", "high", "medium", "low"].map((sev) => (
            <button
              key={sev}
              aria-pressed={severityFilter === sev}
              className={severityFilter === sev ? "btn-primary" : "btn"}
              style={{ padding: "0.35rem 0.75rem", fontSize: "0.75rem" }}
              onClick={() => setSeverityFilter(sev)}
            >
              {sev.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="list-toolbar">
        <SearchField
          value={search}
          onChange={setSearch}
          label="Search findings"
          placeholder="Search findings or rules…"
        />
        <span className="secondary-text">{filtered.length} findings</span>
      </div>
      {resolveServer.isError && (
        <ErrorState
          title="Cannot open server"
          description={resolveServer.error.message}
        />
      )}
      {findingsQuery.isPending && <p role="status">Loading findings…</p>}
      {findingsQuery.isError && (
        <p role="alert" className="error">
          Failed to load findings: {findingsQuery.error.message}
        </p>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        {filtered.length === 0 &&
        !findingsQuery.isPending &&
        !findingsQuery.isError ? (
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
                  disabled={
                    resolveServer.isPending ||
                    !finding.evidence.some((e) => e.session_id)
                  }
                  onClick={() => resolveServer.mutate(finding)}
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
          {(["json", "html", "pdf"] as const).map((format) => (
            <ReportDownload
              key={format}
              format={format}
              load={() => downloadInvestigationReport(id, format)}
            />
          ))}
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

  if (assetsQuery.isPending)
    return <LoadingState label="Loading mail servers…" />;
  if (assetsQuery.isError)
    return (
      <ErrorState
        description={assetsQuery.error.message}
        onRetry={() => void assetsQuery.refetch()}
      />
    );

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Fixes & verification</h1>
        <p className="secondary-text">
          Choose a mail server, review recommended changes, and verify that your
          fixes worked.
        </p>
      </div>

      <div className="card">
        <label className="form-label" htmlFor="fix-server">
          Mail server
        </label>
        <select
          id="fix-server"
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
          {postureQuery.isPending ? (
            <LoadingState label="Loading recommended fixes…" />
          ) : postureQuery.isError ? (
            <ErrorState
              description={postureQuery.error.message}
              onRetry={() => void postureQuery.refetch()}
            />
          ) : guidanceList.length === 0 ? (
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

  if (policiesQuery.isPending)
    return <LoadingState label="Loading policies…" />;
  if (policiesQuery.isError)
    return (
      <ErrorState
        description={policiesQuery.error.message}
        onRetry={() => void policiesQuery.refetch()}
      />
    );
  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Policy checks</h1>
        <p className="secondary-text">
          See how a policy would affect your recorded traffic before changing
          your server configuration.
        </p>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Select Proposed Policy Pack</h3>
          <span className="badge">Read-Only Simulation</span>
        </div>

        <div style={{ display: "flex", gap: "1rem", alignItems: "flex-end" }}>
          <div style={{ flex: 1 }}>
            <label className="form-label" htmlFor="policy-select">
              Available policies
            </label>
            <select
              id="policy-select"
              value={selectedPolicy}
              onChange={(e) => {
                setSelectedPolicy(e.target.value);
                simulationMutation.reset();
              }}
            >
              {policies.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.title} (v{p.version})
                </option>
              ))}
            </select>
          </div>

          <button
            className="btn-primary"
            onClick={() => simulationMutation.mutate()}
            disabled={
              simulationMutation.isPending ||
              !policies.some((p) => p.name === selectedPolicy)
            }
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
                Compatible with observed traffic
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
  const download = useMutation({
    mutationFn: ({ id, format }: { id: string; format: ReportFormat }) =>
      downloadArchivedReport(id, format),
  });
  const reportsQuery = useQuery({
    queryKey: ["archived-reports"],
    queryFn: fetchArchivedReports,
  });
  const archived = reportsQuery.data ?? [];

  if (reportsQuery.isPending) return <LoadingState label="Loading reports…" />;
  if (reportsQuery.isError)
    return (
      <ErrorState
        description={reportsQuery.error.message}
        onRetry={() => void reportsQuery.refetch()}
      />
    );

  return (
    <div>
      {download.isError && (
        <ErrorState
          title="Download failed"
          description={download.error.message}
        />
      )}
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Reports</h1>
        <p className="secondary-text">
          Save a snapshot of your evidence and download it as JSON, HTML or PDF.
        </p>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Saved reports ({archived.length})</h3>
          <span className="badge">Saved snapshot</span>
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
                      No saved reports yet. Open a mail server and choose
                      Archive report to save its evidence.
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
                          disabled={download.isPending}
                          onClick={() =>
                            download.mutate({ id: rep.id, format: "json" })
                          }
                        >
                          JSON
                        </button>
                        <button
                          className="btn"
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                          }}
                          disabled={download.isPending}
                          onClick={() =>
                            download.mutate({ id: rep.id, format: "html" })
                          }
                        >
                          HTML
                        </button>
                        <button
                          className="btn"
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                          }}
                          disabled={download.isPending}
                          onClick={() =>
                            download.mutate({ id: rep.id, format: "pdf" })
                          }
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
  const jevCheck = useMutation({ mutationFn: checkDecisionProvider });
  const [deleteTarget, setDeleteTarget] = useState<IntegrationConfig | null>(
    null,
  );
  const [showAddForm, setShowAddForm] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [kind, setKind] = useState<"webhook" | "syslog">("webhook");
  const [endpointUrl, setEndpointUrl] = useState("");
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
        name: name.trim(),
        kind,
        destination: endpointUrl.trim(),
        enabled: true,
        auth_header: kind === "webhook" ? secretToken || null : null,
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

  const toggleMutation = useMutation({
    mutationFn: (item: IntegrationConfig) =>
      updateIntegration(item.id, { ...item, enabled: !item.enabled }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
  });
  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteIntegration(id),
    onSuccess: () => {
      setDeleteTarget(null);
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

  if (integrationsQuery.isPending)
    return <LoadingState label="Loading integrations…" />;
  if (integrationsQuery.isError)
    return (
      <ErrorState
        description={integrationsQuery.error.message}
        onRetry={() => void integrationsQuery.refetch()}
      />
    );

  return (
    <div>
      {(createMutation.error ||
        deleteMutation.error ||
        toggleMutation.error) && (
        <ErrorState
          title="Integration change failed"
          description={
            (
              createMutation.error ||
              deleteMutation.error ||
              toggleMutation.error
            )?.message ?? "Try again."
          }
        />
      )}
      <Dialog.Root
        open={!!deleteTarget}
        onOpenChange={(open) => {
          if (!open && !deleteMutation.isPending) setDeleteTarget(null);
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <Dialog.Content className="capture-dialog">
            <Dialog.Title>Remove this integration?</Dialog.Title>
            <Dialog.Description>
              Events will no longer be sent to {deleteTarget?.name}. You can add
              this destination again later.
            </Dialog.Description>
            <div className="dialog-footer">
              <Button
                disabled={deleteMutation.isPending}
                onClick={() => setDeleteTarget(null)}
              >
                Keep integration
              </Button>
              <Button
                variant="danger"
                disabled={deleteMutation.isPending}
                onClick={() => {
                  if (deleteTarget) deleteMutation.mutate(deleteTarget.id);
                }}
              >
                {deleteMutation.isPending ? "Removing…" : "Remove integration"}
              </Button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          marginBottom: "1.5rem",
        }}
      >
        <div>
          <h1>Integrations</h1>
          <p className="secondary-text">
            Send security events to your existing tools through webhooks or a
            syslog endpoint.
          </p>
        </div>

        <button
          className="btn-primary"
          onClick={() => setShowAddForm(!showAddForm)}
        >
          {showAddForm ? "Cancel" : "+ Add Destination"}
        </button>
      </div>

      <section className="card" style={{ marginBottom: "1.5rem" }} aria-labelledby="jev-title">
        <h2 id="jev-title">Jev</h2>
        <p className="secondary-text">Reviews transport findings to help prioritize investigations. Email content is not sent.</p>
        <Button disabled={jevCheck.isPending} onClick={() => jevCheck.mutate()}>
          {jevCheck.isPending ? "Checking Jev…" : "Check Jev connection"}
        </Button>
        {jevCheck.data && <p role="status">{jevCheck.data.message}</p>}
        {jevCheck.error && <p role="alert">{jevCheck.error.message}</p>}
      </section>

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
        <form
          className="card"
          onSubmit={(event) => {
            event.preventDefault();
            const field =
              event.currentTarget.querySelector<HTMLInputElement>(
                "#integration-url",
              );
            const valid =
              kind === "webhook"
                ? /^https?:\/\//i.test(endpointUrl)
                : /^(udp|tcp):\/\//i.test(endpointUrl);
            if (!valid && field) {
              field.setCustomValidity(
                kind === "webhook"
                  ? "Use an http:// or https:// URL."
                  : "Use a udp:// or tcp:// destination.",
              );
              field.reportValidity();
              return;
            }
            createMutation.mutate();
          }}
          style={{ marginBottom: "1.5rem" }}
        >
          <h3>Add New Integration Destination</h3>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "1rem",
            }}
          >
            <div className="form-group">
              <label className="form-label" htmlFor="integration-name">
                Destination Name
              </label>
              <input
                id="integration-name"
                required
                maxLength={100}
                type="text"
                placeholder="e.g. Corporate Splunk / SOAR Webhook"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="integration-kind">
                Integration Type
              </label>
              <select
                id="integration-kind"
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
            <label className="form-label" htmlFor="integration-url">
              Endpoint URL
            </label>
            <input
              id="integration-url"
              required
              type="url"
              placeholder={
                kind === "webhook"
                  ? "https://soar.internal.net/api/v1/alerts"
                  : "udp://collector:514"
              }
              value={endpointUrl}
              onChange={(e) => {
                e.target.setCustomValidity("");
                setEndpointUrl(e.target.value);
              }}
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
                <label className="form-label" htmlFor="integration-secret">
                  Authorization header
                </label>
                <input
                  id="integration-secret"
                  type="password"
                  placeholder="Optional, such as Bearer …"
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
            type="submit"
            disabled={
              createMutation.isPending ||
              !name.trim() ||
              !endpointUrl.trim() ||
              eventTypes.length === 0
            }
          >
            {createMutation.isPending ? "Saving..." : "Save Integration"}
          </button>
        </form>
      )}

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">
            Configured Destinations ({integrations.length})
          </h3>
          <span className="badge">Delivery destinations</span>
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
                        <span className="badge">{item.kind.toUpperCase()}</span>{" "}
                        {!item.enabled && <span className="badge">Paused</span>}
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: "0.8125rem" }}>
                      {item.destination}
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
                      {item.last_status_code ? (
                        <span
                          className={`badge ${item.last_status_code >= 200 && item.last_status_code < 300 ? "fresh" : "critical"}`}
                        >
                          {item.last_status_code}
                        </span>
                      ) : (
                        <span className="secondary-text">No delivery yet</span>
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
                          disabled={testMutation.isPending || !item.enabled}
                        >
                          Test Delivery
                        </button>
                        <Button
                          aria-pressed={item.enabled}
                          disabled={toggleMutation.isPending}
                          onClick={() => toggleMutation.mutate(item)}
                        >
                          {item.enabled ? "Pause" : "Enable"}
                        </Button>
                        <button
                          className="btn-danger"
                          style={{
                            padding: "0.25rem 0.5rem",
                            fontSize: "0.75rem",
                          }}
                          onClick={() => setDeleteTarget(item)}
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
    refetchInterval: 15000,
  });
  const sensors = sensorsQuery.data ?? [];

  return (
    <div>
      <div style={{ marginBottom: "1.5rem" }}>
        <h1>Collectors</h1>
        <p className="secondary-text">
          Collectors monitor email traffic on your network and send connection
          details to this workspace.
        </p>
      </div>

      {sensorsQuery.isPending && <p role="status">Loading collectors…</p>}
      {sensorsQuery.isError && (
        <p role="alert" className="error">
          Failed to load collectors: {sensorsQuery.error.message}
        </p>
      )}

      <details className="collector-help">
        <summary>Connect a collector</summary>
        <p>
          On the machine that sees your mail traffic, choose the network
          interface and run the Mailent collector with your service address.
        </p>
        <pre>
          <code>
            MAILENT_COLLECTOR_TOKEN=&lt;collector-token&gt; mailent-sensor
            listen -i &lt;network-interface&gt; --core
            &lt;mailent-service-url&gt;
          </code>
        </pre>
        <p>Once connected, its status and last update appear below.</p>
      </details>
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Collector ID</th>
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
                    No collectors connected. Connect a collector to start
                    monitoring live traffic.
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

function ReportDownload({
  format,
  load,
}: {
  format: string;
  load: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <div>
      <Button
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setError("");
          try {
            await load();
          } catch (e) {
            setError(e instanceof Error ? e.message : "Download failed");
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "Preparing…" : `Export ${format.toUpperCase()}`}
      </Button>
      {error && <p role="alert">{error}</p>}
    </div>
  );
}
