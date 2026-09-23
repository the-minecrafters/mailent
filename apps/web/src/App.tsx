import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import expired from "../../../fixtures/synthetic/smtp_cert_expired.json";
import rsa from "../../../fixtures/synthetic/smtp_static_rsa.json";
import legacy from "../../../fixtures/synthetic/smtp_tls10_legacy.json";
import modern from "../../../fixtures/synthetic/smtp_tls13_healthy.json";
import {
  type Asset,
  type CertificateRecord,
  type DriftEvent,
  type EmailSession,
  evaluateObservation,
  type Finding,
  fetchAsset,
  fetchAssetCertificates,
  fetchAssetDrift,
  fetchAssetFindings,
  fetchAssetSessions,
  fetchAssets,
  fetchDriftEvents,
  fetchFindings,
  fetchSensors,
  fetchSessionDetail,
  fetchSessions,
  readReadiness,
  type SensorRecord,
  type SessionListItem,
  type TimelineEvent,
} from "./api";
import { ProbePanel } from "./ProbePanel";

const samples = {
  legacy: { label: "SMTP · TLS 1.0 + static RSA", observation: legacy },
  modern: { label: "SMTP · TLS 1.3 + ECDHE", observation: modern },
  expired: { label: "SMTP · expired certificate", observation: expired },
  rsa: { label: "SMTP · TLS 1.2 + static RSA", observation: rsa },
};

function humanizeTimelineKind(kind: string): string {
  switch (kind) {
    case "tcp_connected":
      return "TCP connected";
    case "smtp_greeting":
      return "SMTP greeting";
    case "ehlo":
      return "EHLO";
    case "starttls_advertised":
      return "STARTTLS advertised";
    case "starttls_not_advertised":
      return "STARTTLS not advertised";
    case "starttls_requested":
      return "STARTTLS requested";
    case "starttls_accepted":
      return "STARTTLS accepted";
    case "starttls_rejected":
      return "STARTTLS rejected";
    case "tls_client_hello":
      return "TLS ClientHello";
    case "tls_server_hello":
      return "TLS ServerHello";
    case "certificate_observed":
      return "Certificate observed";
    case "key_exchange_ecdhe":
      return "Key exchange (ECDHE)";
    case "key_exchange_dhe":
      return "Key exchange (DHE)";
    case "key_exchange_rsa_static":
      return "Key exchange (Static RSA)";
    case "tls_established":
      return "TLS established";
    case "tls_fatal_alert":
      return "TLS fatal alert";
    case "plaintext_continuation":
      return "Plaintext continuation";
    case "protocol_identified":
      return "Protocol identified";
    default:
      return kind.replace(/_/g, " ");
  }
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="finding">
      <div className="finding-heading">
        <span className={`severity ${finding.severity}`}>
          {finding.severity}
        </span>
        <code>{finding.rule_id}</code>
      </div>
      <h3>{finding.title}</h3>
      <p>{finding.description}</p>
      <dl>
        <dt>Remediation</dt>
        <dd>{finding.remediation}</dd>
        <dt>Policy / reference</dt>
        <dd>
          {finding.policy_name} v{finding.policy_version} · {finding.reference}
        </dd>
        <dt>Observed</dt>
        <dd>{finding.first_seen}</dd>
      </dl>
      <details>
        <summary>Evidence and identity</summary>
        <p className="mono">Finding: {finding.id}</p>
        {finding.evidence.map((e) => (
          <div
            className="evidence"
            key={`${e.observation_id}:${e.description}`}
          >
            <p>{e.description}</p>
            <p className="mono">
              Observation: {e.observation_id ?? "Unavailable"}
            </p>
            <p className="mono">Session: {e.session_id ?? "Unavailable"}</p>
          </div>
        ))}
      </details>
    </article>
  );
}

function SessionTimeline({ timeline }: { timeline: TimelineEvent[] }) {
  if (timeline.length === 0) {
    return (
      <div className="timeline-empty">
        <p className="notice">
          No sequential timeline evidence attached to this session.
        </p>
      </div>
    );
  }

  return (
    <div className="timeline-container">
      <h3 className="section-title">Session Timeline</h3>
      <div className="timeline">
        {timeline.map((ev, index) => (
          <div
            className="timeline-item"
            key={`${ev.timestamp}:${ev.kind}:${index}`}
          >
            <div className="timeline-marker" />
            <div className="timeline-content">
              <div className="timeline-header">
                <span className="timeline-kind">
                  {humanizeTimelineKind(ev.kind)}
                </span>
                <span className="timeline-source mono">{ev.source}</span>
              </div>
              <time className="timeline-time mono">{ev.timestamp}</time>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SessionInspector({
  sessionId,
  onClose,
}: {
  sessionId: string;
  onClose: () => void;
}) {
  const detailQuery = useQuery({
    queryKey: ["session", sessionId],
    queryFn: () => fetchSessionDetail(sessionId),
  });

  if (detailQuery.isPending) {
    return (
      <div className="session-inspector">
        <p role="status">Loading session details…</p>
      </div>
    );
  }

  if (detailQuery.isError) {
    return (
      <div className="session-inspector">
        <p role="alert" className="error">
          Failed to load session: {detailQuery.error.message}
        </p>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </div>
    );
  }

  const { session, findings, forward_secrecy, certificate_state } =
    detailQuery.data;
  const capture = session.capture;

  return (
    <div className="session-inspector">
      <div className="inspector-header">
        <div>
          <div className="eyebrow">SESSION EVIDENCE & FORENSICS</div>
          <h2>
            {session.protocol.toUpperCase()} · {session.flow.src_ip}:
            {session.flow.src_port} → {session.flow.dst_ip}:
            {session.flow.dst_port}
          </h2>
          <p className="mono">ID: {session.session_id}</p>
        </div>
        <button type="button" className="close-btn" onClick={onClose}>
          × Close
        </button>
      </div>

      <div className="inspector-meta">
        <div className="meta-card">
          <span className="meta-label">Protocol</span>
          <span className="meta-value">{session.protocol.toUpperCase()}</span>
        </div>
        <div className="meta-card">
          <span className="meta-label">STARTTLS State</span>
          <span className="meta-value">
            {session.starttls_state ?? "Unknown / not observed"}
          </span>
        </div>
        <div className="meta-card">
          <span className="meta-label">TLS Version</span>
          <span className="meta-value">
            {session.tls_version ?? "Unavailable"}
          </span>
        </div>
        <div className="meta-card">
          <span className="meta-label">Forward Secrecy</span>
          <span className={`badge ${forward_secrecy}`}>
            {forward_secrecy.replace("_", " ")}
          </span>
        </div>
        <div className="meta-card">
          <span className="meta-label">Certificate State</span>
          <span className={`badge ${certificate_state}`}>
            {certificate_state}
          </span>
        </div>
        <div className="meta-card">
          <span className="meta-label">Sensor / Provenance</span>
          <span className="meta-value mono">
            {session.sensor_id} ({session.provenance.parser}{" "}
            {session.provenance.parser_version})
          </span>
        </div>
      </div>

      {session.cipher_suite && (
        <div className="meta-row">
          <strong>Cipher Suite:</strong>{" "}
          <code>{session.cipher_suite.name}</code>
          {session.cipher_suite.id != null && (
            <span className="mono"> (ID: {session.cipher_suite.id})</span>
          )}
        </div>
      )}

      {session.certificate && (
        <div className="cert-card">
          <h3 className="section-title">Presented X.509 Certificate</h3>
          <dl className="cert-dl">
            <dt>Subject</dt>
            <dd className="mono">{session.certificate.reference.subject}</dd>
            <dt>Issuer</dt>
            <dd className="mono">{session.certificate.reference.issuer}</dd>
            <dt>Fingerprint (SHA-256)</dt>
            <dd className="mono">
              {session.certificate.reference.sha256_fingerprint}
            </dd>
            <dt>Validity</dt>
            <dd className="mono">
              {session.certificate.validity.not_before} →{" "}
              {session.certificate.validity.not_after}
            </dd>
            {session.certificate.san.length > 0 && (
              <>
                <dt>SANs</dt>
                <dd className="mono">{session.certificate.san.join(", ")}</dd>
              </>
            )}
          </dl>
        </div>
      )}

      {capture && capture.gaps.length > 0 && (
        <div className="gaps-card">
          <h3 className="section-title">Capture Observations & Gaps</h3>
          <ul>
            {capture.gaps.map((gap, i) => (
              <li key={`${gap}:${i}`}>{gap}</li>
            ))}
          </ul>
        </div>
      )}

      <SessionTimeline timeline={capture?.timeline ?? []} />

      <div className="findings-section">
        <h3 className="section-title">Policy Findings ({findings.length})</h3>
        {findings.length === 0 ? (
          <p className="notice">
            No deterministic policy violations identified for this session.
          </p>
        ) : (
          findings.map((f) => <FindingCard key={f.id} finding={f} />)
        )}
      </div>
    </div>
  );
}

function AssetDetailView({
  assetId,
  onBack,
  onInspectSession,
}: {
  assetId: string;
  onBack: () => void;
  onInspectSession: (sessionId: string) => void;
}) {
  const assetQuery = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () => fetchAsset(assetId),
  });
  const driftQuery = useQuery({
    queryKey: ["asset-drift", assetId],
    queryFn: () => fetchAssetDrift(assetId),
  });
  const certsQuery = useQuery({
    queryKey: ["asset-certs", assetId],
    queryFn: () => fetchAssetCertificates(assetId),
  });
  const findingsQuery = useQuery({
    queryKey: ["asset-findings", assetId],
    queryFn: () => fetchAssetFindings(assetId),
  });
  const sessionsQuery = useQuery({
    queryKey: ["asset-sessions", assetId],
    queryFn: () => fetchAssetSessions(assetId),
  });

  if (assetQuery.isPending) {
    return <p role="status">Loading asset profile…</p>;
  }
  if (assetQuery.isError) {
    return (
      <div className="error" role="alert">
        Failed to load asset: {assetQuery.error.message}
        <button type="button" onClick={onBack}>
          Back to Assets
        </button>
      </div>
    );
  }

  const asset = assetQuery.data;
  const driftEvents = driftQuery.data ?? [];
  const certs = certsQuery.data ?? [];
  const findings = findingsQuery.data ?? [];
  const sessions = sessionsQuery.data ?? [];

  return (
    <div className="asset-detail-view">
      <button type="button" className="back-btn" onClick={onBack}>
        ← Back to Assets
      </button>

      <div className="inspector-header">
        <div>
          <div className="eyebrow">PERSISTENT ASSET IDENTITY & POSTURE</div>
          <h2>{asset.primary_name ?? asset.addresses[0] ?? "Unnamed Asset"}</h2>
          <p className="mono">Asset ID: {asset.id}</p>
        </div>
      </div>

      <div className="inspector-meta card-grid">
        <div className="meta-card">
          <span className="meta-label">IP Addresses</span>
          <span className="meta-value mono">
            {asset.addresses.join(", ") || "None"}
          </span>
        </div>
        <div className="meta-card">
          <span className="meta-label">Hostnames</span>
          <span className="meta-value mono">
            {asset.hostnames.join(", ") || "None"}
          </span>
        </div>
        <div className="meta-card">
          <span className="meta-label">TLS Versions</span>
          <span className="meta-value">
            {asset.tls_versions.join(", ") || "None observed"}
          </span>
        </div>
        <div className="meta-card">
          <span className="meta-label">Active Findings</span>
          <span
            className={`badge ${asset.active_findings_count > 0 ? "high" : "low"}`}
          >
            {asset.active_findings_count}
          </span>
        </div>
        <div className="meta-card">
          <span className="meta-label">First Seen</span>
          <time className="meta-value mono">{asset.first_seen}</time>
        </div>
        <div className="meta-card">
          <span className="meta-label">Last Seen</span>
          <time className="meta-value mono">{asset.last_seen}</time>
        </div>
      </div>

      <ProbePanel asset={asset} />
      {/* Configuration Drift Events */}
      <section
        className="drift-section"
        aria-label="Configuration Drift Events"
      >
        <h3 className="section-title">
          Configuration Drift History ({driftEvents.length})
        </h3>
        {driftEvents.length === 0 ? (
          <p className="notice">
            No configuration drift detected. Service parameters remain
            baseline-stable.
          </p>
        ) : (
          <div className="drift-list">
            {driftEvents.map((drift) => (
              <div key={drift.id} className="drift-card">
                <div className="drift-header">
                  <span className="drift-title">{drift.title}</span>
                  <span className="badge drift">{drift.kind}</span>
                </div>
                <p>{drift.description}</p>
                <div className="drift-change">
                  {drift.previous_value && (
                    <>
                      <code>{drift.previous_value}</code>
                      <span className="drift-arrow">→</span>
                    </>
                  )}
                  <code>{drift.new_value}</code>
                </div>
                <time
                  className="timeline-time mono"
                  style={{ marginTop: "0.5rem" }}
                >
                  {drift.observed_at}
                </time>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Certificate History */}
      <section className="certs-section" aria-label="Certificate History">
        <h3 className="section-title">
          Presented X.509 Certificate History ({certs.length})
        </h3>
        {certs.length === 0 ? (
          <p className="notice">No certificates recorded for this asset.</p>
        ) : (
          certs.map((c) => (
            <div
              key={c.sha256_fingerprint}
              className="cert-card"
              style={{ marginBottom: "1rem" }}
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
      </section>

      {/* Active Findings */}
      <section className="findings-section">
        <h3 className="section-title">
          Active Policy Findings ({findings.length})
        </h3>
        {findings.length === 0 ? (
          <p className="notice">
            No policy findings currently active for this asset.
          </p>
        ) : (
          findings.map((f) => <FindingCard key={f.id} finding={f} />)
        )}
      </section>

      {/* Associated Sessions */}
      <section className="sessions-section">
        <h3 className="section-title">
          Recent Network Sessions ({sessions.length})
        </h3>
        {sessions.length === 0 ? (
          <p className="notice">No sessions recorded.</p>
        ) : (
          <div className="table-responsive">
            <table className="sessions-table">
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Client</th>
                  <th>Server</th>
                  <th>TLS</th>
                  <th>Cipher</th>
                  <th>Observed</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <tr key={s.session_id}>
                    <td>
                      <span className="proto-badge">
                        {s.protocol.toUpperCase()}
                      </span>
                    </td>
                    <td className="mono">
                      {s.flow.src_ip}:{s.flow.src_port}
                    </td>
                    <td className="mono">
                      {s.flow.dst_ip}:{s.flow.dst_port}
                    </td>
                    <td>{s.tls_version ?? "None"}</td>
                    <td className="mono">
                      {s.cipher_suite?.name ?? "Unavailable"}
                    </td>
                    <td className="mono">{s.last_seen}</td>
                    <td>
                      <button
                        type="button"
                        className="inspect-btn"
                        onClick={() => onInspectSession(s.session_id)}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export function App({
  initialView = "sessions",
}: {
  initialView?: "assets" | "sessions" | "findings" | "sensors" | "evaluator";
}) {
  const [view, setView] = useState<
    "assets" | "sessions" | "findings" | "sensors" | "evaluator"
  >(initialView);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    null,
  );
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [input, setInput] = useState(JSON.stringify(legacy, null, 2));
  const [sample, setSample] = useState("legacy");

  const readiness = useQuery({
    queryKey: ["readiness"],
    queryFn: readReadiness,
    retry: false,
    refetchInterval: 30000,
  });

  const assetsQuery = useQuery({
    queryKey: ["assets"],
    queryFn: fetchAssets,
    enabled: view === "assets",
    refetchInterval: 5000,
  });

  const sessionsQuery = useQuery({
    queryKey: ["sessions"],
    queryFn: fetchSessions,
    enabled: view === "sessions",
    refetchInterval: 5000,
  });

  const findingsQuery = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
    enabled: view === "findings",
    refetchInterval: 5000,
  });

  const sensorsQuery = useQuery({
    queryKey: ["sensors"],
    queryFn: fetchSensors,
    enabled: view === "sensors",
    refetchInterval: 5000,
  });

  const evaluation = useMutation({ mutationFn: evaluateObservation });
  const result = evaluation.data;

  const assets = assetsQuery.data ?? [];
  const sessions = sessionsQuery.data ?? [];
  const allFindings = findingsQuery.data ?? [];
  const sensors = sensorsQuery.data ?? [];

  return (
    <div className="app">
      <header>
        <a className="brand" href="/">
          MAILENT<span> / CONTINUOUS SECURITY</span>
        </a>
        <span className="environment">PERSISTENT PASSIVE OBSERVABILITY</span>
      </header>

      <main>
        <div className="intro">
          <div className="eyebrow">MONITORING → POSTURE → FORENSICS</div>
          <h1>Cryptographic Posture & Asset Intelligence</h1>
          <p>
            Continuous transport security monitoring across SMTP, IMAP, and POP3
            network flows.
          </p>
        </div>

        <section className="status" aria-label="Core status">
          {readiness.isPending ? (
            <p role="status">Connecting to core…</p>
          ) : readiness.isError ? (
            <p role="alert">Core unavailable. {readiness.error.message}</p>
          ) : (
            <p>
              <strong>
                {readiness.data.ready ? "Core ready" : "Core not ready"}
              </strong>{" "}
              · {readiness.data.policy_name} v{readiness.data.policy_version} ·{" "}
              {readiness.data.rule_count} rules · Storage:{" "}
              {readiness.data.storage} · Decisions:{" "}
              {readiness.data.decision_provider}
            </p>
          )}
        </section>

        <nav className="tab-nav" role="tablist" aria-label="Views">
          <button
            type="button"
            role="tab"
            aria-selected={view === "assets"}
            className={view === "assets" ? "active" : ""}
            onClick={() => {
              setSelectedAssetId(null);
              setView("assets");
            }}
          >
            Assets ({assets.length})
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={view === "sessions"}
            className={view === "sessions" ? "active" : ""}
            onClick={() => setView("sessions")}
          >
            Sessions ({sessions.length})
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={view === "findings"}
            className={view === "findings" ? "active" : ""}
            onClick={() => setView("findings")}
          >
            Findings ({allFindings.length})
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={view === "sensors"}
            className={view === "sensors" ? "active" : ""}
            onClick={() => setView("sensors")}
          >
            Sensors ({sensors.length})
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={view === "evaluator"}
            className={view === "evaluator" ? "active" : ""}
            onClick={() => setView("evaluator")}
          >
            Observation Evaluator
          </button>
        </nav>

        {view === "assets" && (
          <section className="assets-view" aria-label="Monitored Assets">
            {selectedAssetId ? (
              <AssetDetailView
                assetId={selectedAssetId}
                onBack={() => setSelectedAssetId(null)}
                onInspectSession={(sid) => {
                  setSelectedSessionId(sid);
                  setView("sessions");
                }}
              />
            ) : (
              <>
                <div className="view-header">
                  <h2>Discovered Mail Assets</h2>
                  <p className="notice">
                    Correlated servers, endpoints, certificates, and
                    configuration posture tracked in persistent storage.
                  </p>
                </div>

                {assetsQuery.isPending && <p role="status">Loading assets…</p>}
                {assetsQuery.isError && (
                  <p role="alert" className="error">
                    Failed to load assets: {assetsQuery.error.message}
                  </p>
                )}

                {!assetsQuery.isPending && assets.length === 0 && (
                  <div className="empty">
                    <h3>No assets discovered yet</h3>
                    <p>
                      Run{" "}
                      <code>mailent-sensor listen -i &lt;interface&gt;</code> or{" "}
                      <code>mailent-sensor analyze &lt;capture.pcap&gt;</code>{" "}
                      to begin passive discovery.
                    </p>
                  </div>
                )}

                {assets.length > 0 && (
                  <div className="table-responsive">
                    <table className="sessions-table">
                      <thead>
                        <tr>
                          <th>Primary Name</th>
                          <th>IP Addresses</th>
                          <th>Protocols</th>
                          <th>TLS Versions</th>
                          <th>Certificates</th>
                          <th>Active Findings</th>
                          <th>Last Seen</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {assets.map((asset) => (
                          <tr key={asset.id}>
                            <td>
                              <strong>{asset.primary_name ?? "Unnamed"}</strong>
                            </td>
                            <td className="mono">
                              {asset.addresses.join(", ") || "—"}
                            </td>
                            <td>
                              {asset.endpoints.map((ep) => (
                                <span
                                  key={`${ep.protocol}:${ep.port}`}
                                  className="proto-badge"
                                  style={{ marginRight: "4px" }}
                                >
                                  {ep.protocol.toUpperCase()}:{ep.port}
                                </span>
                              ))}
                            </td>
                            <td>{asset.tls_versions.join(", ") || "None"}</td>
                            <td className="mono">
                              {asset.certificate_fingerprints.length > 0
                                ? `${asset.certificate_fingerprints.length} cert(s)`
                                : "None"}
                            </td>
                            <td>
                              <span
                                className={`badge ${asset.active_findings_count > 0 ? "high" : "low"}`}
                              >
                                {asset.active_findings_count}
                              </span>
                            </td>
                            <td className="mono">{asset.last_seen}</td>
                            <td>
                              <button
                                type="button"
                                className="inspect-btn"
                                onClick={() => setSelectedAssetId(asset.id)}
                              >
                                View Asset
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </section>
        )}

        {view === "sessions" && (
          <section className="sessions-view" aria-label="Captured Sessions">
            <div className="view-header">
              <h2>Analyzed Mail Sessions</h2>
              <p className="notice">
                Sessions analyzed from live interface capture or PCAPs via Zeek
                and Mailent Sensor.
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

            {!sessionsQuery.isPending && sessions.length === 0 && (
              <div className="empty">
                <h3>No sessions analyzed yet</h3>
                <p>
                  Run <code>mailent-sensor analyze &lt;capture.pcap&gt;</code>{" "}
                  or <code>mailent-sensor listen -i &lt;interface&gt;</code> to
                  stream traffic.
                </p>
                <button type="button" onClick={() => setView("evaluator")}>
                  Open Observation Evaluator
                </button>
              </div>
            )}

            {sessions.length > 0 && (
              <div className="table-responsive">
                <table className="sessions-table">
                  <thead>
                    <tr>
                      <th>Protocol</th>
                      <th>Client</th>
                      <th>Server</th>
                      <th>STARTTLS</th>
                      <th>TLS Version</th>
                      <th>Cipher Suite</th>
                      <th>Forward Secrecy</th>
                      <th>Certificate</th>
                      <th>Findings</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map((item: SessionListItem) => (
                      <tr
                        key={item.session_id}
                        className={
                          selectedSessionId === item.session_id
                            ? "selected-row"
                            : ""
                        }
                      >
                        <td>
                          <span className="proto-badge">
                            {item.protocol.toUpperCase()}
                          </span>
                        </td>
                        <td className="mono">{item.client}</td>
                        <td className="mono">{item.server}</td>
                        <td>
                          <span className="state-badge">
                            {item.starttls_state ?? "None"}
                          </span>
                        </td>
                        <td>
                          <span
                            className={
                              item.tls_version?.includes("1.0") ||
                              item.tls_version?.includes("1.1")
                                ? "tls-legacy"
                                : ""
                            }
                          >
                            {item.tls_version ?? "Unavailable"}
                          </span>
                        </td>
                        <td className="cipher-cell mono">
                          {item.cipher_suite ?? "Unavailable"}
                        </td>
                        <td>
                          <span className={`badge ${item.forward_secrecy}`}>
                            {item.forward_secrecy.replace("_", " ")}
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${item.certificate_state}`}>
                            {item.certificate_state}
                          </span>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              item.findings_count > 0 ? "high" : "low"
                            }`}
                          >
                            {item.findings_count}
                          </span>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="inspect-btn"
                            onClick={() =>
                              setSelectedSessionId(
                                selectedSessionId === item.session_id
                                  ? null
                                  : item.session_id,
                              )
                            }
                          >
                            {selectedSessionId === item.session_id
                              ? "Hide"
                              : "Inspect"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {selectedSessionId && (
              <SessionInspector
                sessionId={selectedSessionId}
                onClose={() => setSelectedSessionId(null)}
              />
            )}
          </section>
        )}

        {view === "findings" && (
          <section className="findings-view" aria-label="Policy Findings">
            <div className="view-header">
              <h2>Deterministic Security Findings</h2>
              <p className="notice">
                Cryptographic findings evaluated by the Mailent deterministic
                policy engine.
              </p>
            </div>

            {findingsQuery.isPending && <p role="status">Loading findings…</p>}
            {findingsQuery.isError && (
              <p role="alert" className="error">
                Failed to load findings: {findingsQuery.error.message}
              </p>
            )}

            {!findingsQuery.isPending && allFindings.length === 0 && (
              <div className="empty">
                <h3>No findings recorded</h3>
                <p>
                  No policy violations were found in the current session store.
                </p>
              </div>
            )}

            {allFindings.length > 0 && (
              <div className="findings-list">
                {allFindings.map((f) => (
                  <FindingCard key={f.id} finding={f} />
                ))}
              </div>
            )}
          </section>
        )}

        {view === "sensors" && (
          <section className="sensors-view" aria-label="Sensor Fleet">
            <div className="view-header">
              <h2>Sensor Fleet & Ingestion Telemetry</h2>
              <p className="notice">
                Continuous telemetry, heartbeats, and bounded spooling status
                across active network sensors.
              </p>
            </div>

            {sensorsQuery.isPending && <p role="status">Loading sensors…</p>}
            {sensorsQuery.isError && (
              <p role="alert" className="error">
                Failed to load sensors: {sensorsQuery.error.message}
              </p>
            )}

            {!sensorsQuery.isPending && sensors.length === 0 && (
              <div className="empty">
                <h3>No sensors registered</h3>
                <p>
                  Start a sensor using{" "}
                  <code>mailent-sensor listen -i &lt;interface&gt;</code> to
                  stream observations.
                </p>
              </div>
            )}

            {sensors.length > 0 && (
              <div className="table-responsive">
                <table className="sessions-table">
                  <thead>
                    <tr>
                      <th>Sensor ID</th>
                      <th>Site</th>
                      <th>Hostname</th>
                      <th>Status</th>
                      <th>Mode</th>
                      <th>Interface</th>
                      <th>Version</th>
                      <th>Last Heartbeat</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sensors.map((sensor) => {
                      const statusClass =
                        sensor.status === "Online"
                          ? "online"
                          : sensor.status === "Stale"
                            ? "stale"
                            : "offline";
                      return (
                        <tr key={sensor.sensor_id}>
                          <td>
                            <strong>{sensor.sensor_id}</strong>
                          </td>
                          <td>{sensor.site_id}</td>
                          <td className="mono">{sensor.hostname}</td>
                          <td>
                            <span className={`badge ${statusClass}`}>
                              {sensor.status}
                            </span>
                          </td>
                          <td>
                            <code>{sensor.mode}</code>
                          </td>
                          <td>
                            <code>{sensor.interface ?? "none"}</code>
                          </td>
                          <td className="mono">{sensor.version}</td>
                          <td className="mono">{sensor.last_seen}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {view === "evaluator" && (
          <div className="workspace">
            <section className="input-panel" aria-labelledby="input-title">
              <h2 id="input-title">01 / Observation</h2>
              <label htmlFor="sample">Synthetic fixture</label>
              <select
                id="sample"
                value={sample}
                disabled={evaluation.isPending}
                onChange={(event) => {
                  const key = event.target.value as keyof typeof samples;
                  setSample(key);
                  setInput(JSON.stringify(samples[key].observation, null, 2));
                  evaluation.reset();
                }}
              >
                {Object.entries(samples).map(([key, value]) => (
                  <option key={key} value={key}>
                    {value.label}
                  </option>
                ))}
              </select>
              <label htmlFor="observation">Normalized observation JSON</label>
              <textarea
                id="observation"
                spellCheck={false}
                value={input}
                disabled={evaluation.isPending}
                onChange={(event) => {
                  setInput(event.target.value);
                  evaluation.reset();
                }}
              />
              <button
                type="button"
                disabled={
                  evaluation.isPending ||
                  !readiness.data?.ready ||
                  readiness.isError
                }
                onClick={() => {
                  evaluation.reset();
                  evaluation.mutate(input);
                }}
              >
                {evaluation.isPending ? "Evaluating…" : "Evaluate observation"}
              </button>
            </section>
            <section
              className="results"
              aria-labelledby="results-title"
              aria-live="polite"
            >
              <h2 id="results-title">02 / Findings</h2>
              {evaluation.isPending && (
                <p role="status">Evaluating observation in core…</p>
              )}
              {evaluation.isError && (
                <p role="alert" className="error">
                  Evaluation failed. {evaluation.error.message}
                </p>
              )}
              {!result && !evaluation.isPending && !evaluation.isError && (
                <div className="empty">
                  <h3>No observation evaluated</h3>
                  <p>
                    Select a fixture or supply normalized metadata, then run the
                    policy checks.
                  </p>
                </div>
              )}
              {result && (
                <>
                  <div className="result-summary">
                    <strong>
                      {result.findings.length}{" "}
                      {result.findings.length === 1 ? "finding" : "findings"}
                    </strong>
                    <p>
                      {result.observation.protocol.toUpperCase()} ·{" "}
                      {result.observation.tls_version ?? "TLS unknown"} ·{" "}
                      {result.observation.flow.dst_ip}:
                      {result.observation.flow.dst_port}
                    </p>
                    <p>
                      STARTTLS:{" "}
                      {result.observation.starttls_state ??
                        "Unknown / not observed"}
                    </p>
                    <p>
                      Source: {result.observation.provenance.source} ·{" "}
                      {result.observation.sensor_id} ·{" "}
                      {result.observation.provenance.parser} v
                      {result.observation.provenance.parser_version}
                    </p>
                    <p className="mono">Session: {result.session_id}</p>
                  </div>
                  {result.findings.length === 0 ? (
                    <div className="empty">
                      <h3>No violations found by the evaluated rules</h3>
                      <p>
                        This is not a complete security assessment. Missing
                        evidence remains unknown.
                      </p>
                    </div>
                  ) : (
                    result.findings.map((finding) => (
                      <FindingCard key={finding.id} finding={finding} />
                    ))
                  )}
                </>
              )}
            </section>
          </div>
        )}
      </main>

      <footer>
        Mailent / Continuous Cryptographic Observability · Deterministic policy
        · Persistent Storage · Real Network Captures
      </footer>
    </div>
  );
}
