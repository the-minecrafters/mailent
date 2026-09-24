import type { EmailSession } from "../api";

export interface ConnectionStage {
  id: string;
  name: string;
  status: "observed" | "warning" | "failed" | "unknown";
  detail: string;
}

/** Describe captured evidence; ports and hello messages cannot prove TLS completion. */
export function connectionStages(session: EmailSession): ConnectionStage[] {
  const events = new Set((session.capture?.timeline ?? []).map((event) => event.kind));
  const has = (kind: string) => events.has(kind);
  const established = session.capture?.tls_established === true || has("tls_established") || session.starttls_state === "tls_established";
  const rejected = has("starttls_rejected") || session.starttls_state === "rejected";
  const accepted = has("starttls_accepted") || session.starttls_state === "advertised_and_used";
  const stages: ConnectionStage[] = [
    { id: "tcp", name: "TCP connection", status: has("tcp_connected") ? "observed" : "unknown", detail: has("tcp_connected") ? `Connection established on port ${session.flow.dst_port}` : "Connection handshake not captured" },
    { id: "greeting", name: "Mail protocol", status: has("smtp_greeting") || has("protocol_identified") ? "observed" : "unknown", detail: has("smtp_greeting") ? "SMTP greeting captured" : has("protocol_identified") ? `${session.protocol.toUpperCase()} identified; greeting not confirmed` : "Protocol greeting not captured" },
    { id: "starttls", name: session.protocol.toLowerCase() === "pop3" ? "STLS upgrade" : "STARTTLS upgrade", status: rejected ? "failed" : accepted ? "observed" : "unknown", detail: rejected ? "Server rejected the upgrade" : accepted ? "Server accepted the upgrade; TLS completion is checked separately" : has("starttls_requested") ? "Upgrade requested; response not captured" : has("starttls_advertised") ? "Upgrade advertised; use not confirmed" : session.starttls_state === "not_advertised" ? "Upgrade was not advertised" : "No upgrade observed; the connection may use direct TLS" },
    { id: "handshake", name: "TLS negotiation", status: has("tls_server_hello") ? "observed" : "unknown", detail: has("tls_server_hello") ? [session.tls_version?.toUpperCase(), session.cipher_suite?.name].filter(Boolean).join(" · ") || "ServerHello captured" : has("tls_client_hello") ? "ClientHello captured; server response not confirmed" : "TLS negotiation not captured" },
  ];
  const certificate = session.certificate;
  const observedAt = Date.parse(session.first_seen);
  const expired = certificate && Number.isFinite(observedAt) && Date.parse(certificate.validity.not_after) < observedAt;
  const premature = certificate && Number.isFinite(observedAt) && Date.parse(certificate.validity.not_before) > observedAt;
  stages.push({ id: "certificate", name: "Certificate", status: expired || premature ? "warning" : certificate || has("certificate_observed") ? "observed" : "unknown", detail: expired ? "Certificate was expired when this connection was captured" : premature ? "Certificate was not yet valid when this connection was captured" : certificate ? `${certificate.reference.subject} — captured; see certificate checks for trust validation` : has("certificate_observed") ? "Certificate message observed; certificate details unavailable" : "Certificate not available in this capture" });
  stages.push({ id: "established", name: "TLS connection", status: established ? "observed" : "unknown", detail: established ? "TLS established for this connection" : "TLS completion not confirmed by the capture" });
  return stages;
}

export function ProtocolLadder({ session }: { session: EmailSession }) {
  return (
    <section aria-label="Connection timeline" style={{ border: "1px solid var(--border)", borderRadius: 12, padding: "1.25rem", marginBottom: "1.25rem" }}>
      <h3 style={{ margin: "0 0 .5rem", fontSize: "1.125rem" }}>Connection timeline</h3>
      <p className="secondary-text" style={{ margin: "0 0 1rem" }}>What this capture confirms. Missing steps do not prove that encryption failed.</p>
      <ol style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 230px), 1fr))", gap: ".75rem", listStyle: "none", padding: 0, margin: 0 }}>
        {connectionStages(session).map((stage, index) => (
          <li key={stage.id} style={{ minWidth: 0, overflowWrap: "anywhere", padding: "1rem", border: "1px solid var(--border)", borderRadius: 8, background: "var(--canvas-sunken)" }}>
            <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", gap: ".5rem", marginBottom: ".75rem" }}>
              <span className="secondary-text">Step {index + 1}</span>
              <span className={`badge ${stage.status === "observed" ? "fresh" : stage.status === "failed" ? "critical" : stage.status === "warning" ? "high" : ""}`}>
                {stage.status === "unknown" ? "Not confirmed" : stage.status === "observed" ? "Observed" : stage.status === "failed" ? "Rejected" : "Needs attention"}
              </span>
            </div>
            <h4 style={{ margin: "0 0 .5rem", fontSize: "1rem" }}>{stage.name}</h4>
            <p className="secondary-text" style={{ margin: 0, fontSize: "1rem", lineHeight: 1.5 }}>{stage.detail}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
