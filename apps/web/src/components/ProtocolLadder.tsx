import React from "react";
import type { EmailSession } from "../api";
import { Icon } from "./Icon";

interface ProtocolLadderProps {
  session: EmailSession;
}

interface StageStep {
  id: string;
  name: string;
  layer: string;
  isEncrypted: boolean;
  status: "completed" | "warning" | "failed" | "skipped";
  detail: string;
  timestamp?: string;
}

export function ProtocolLadder({ session }: ProtocolLadderProps) {
  const timeline = session.capture?.timeline || [];
  const events = new Set(timeline.map((e) => e.kind));

  const hasEvent = (kind: string) => events.has(kind);
  const getEventTime = (kind: string) =>
    timeline.find((e) => e.kind === kind)?.timestamp;

  const hasTcp = hasEvent("tcp_connected") || true;
  const isDirectTls =
    session.flow.dst_port === 465 ||
    session.flow.dst_port === 993 ||
    session.flow.dst_port === 995;

  const steps: StageStep[] = [];

  // Step 1: TCP Handshake
  steps.push({
    id: "tcp",
    name: "TCP Handshake",
    layer: "Layer 4 Transport",
    isEncrypted: false,
    status: hasTcp ? "completed" : "completed",
    detail: `Port ${session.flow.dst_port} connected`,
    timestamp: getEventTime("tcp_connected"),
  });

  if (!isDirectTls) {
    // Step 2: Plaintext Greeting & Capabilities
    const hasGreeting =
      hasEvent("smtp_greeting") ||
      hasEvent("ehlo") ||
      hasEvent("protocol_identified");
    steps.push({
      id: "greeting",
      name: "Plaintext Capabilities",
      layer: `Layer 7 (${session.protocol.toUpperCase()})`,
      isEncrypted: false,
      status: hasGreeting ? "completed" : "completed",
      detail: hasEvent("ehlo")
        ? "EHLO exchange & capability discovery"
        : `${session.protocol.toUpperCase()} banner received`,
      timestamp: getEventTime("ehlo") || getEventTime("smtp_greeting"),
    });

    // Step 3: STARTTLS Negotiation Transition
    const isStarttlsUsed =
      session.starttls_state === "tls_established" ||
      session.starttls_state === "advertised_and_used" ||
      hasEvent("starttls_accepted");
    const isStarttlsRejected =
      session.starttls_state === "rejected" || hasEvent("starttls_rejected");
    const isStarttlsNotAdvertised =
      session.starttls_state === "not_advertised" ||
      hasEvent("starttls_not_advertised");

    steps.push({
      id: "starttls",
      name: "STARTTLS Upgrade",
      layer: "Cryptographic Transition Boundary",
      isEncrypted: false,
      status: isStarttlsUsed
        ? "completed"
        : isStarttlsRejected
          ? "failed"
          : isStarttlsNotAdvertised
            ? "warning"
            : "skipped",
      detail: isStarttlsUsed
        ? "Upgrade requested & 220 OK accepted"
        : isStarttlsRejected
          ? "STARTTLS rejected by server"
          : isStarttlsNotAdvertised
            ? "STARTTLS not advertised by server"
            : "No in-flight upgrade",
      timestamp:
        getEventTime("starttls_accepted") || getEventTime("starttls_requested"),
    });
  }

  // Step 4: TLS Handshake (ClientHello / ServerHello)
  const hasHello =
    hasEvent("tls_client_hello") ||
    hasEvent("tls_server_hello") ||
    Boolean(session.tls_version);
  const tlsVerStr = session.tls_version
    ? session.tls_version.toUpperCase()
    : "TLS";
  const isLegacyTls =
    session.tls_version === "tls10" || session.tls_version === "tls11";

  steps.push({
    id: "handshake",
    name: "TLS Handshake",
    layer: "Cryptographic Negotiation",
    isEncrypted: true,
    status: isLegacyTls ? "warning" : hasHello ? "completed" : "skipped",
    detail: session.cipher_suite
      ? `${tlsVerStr} · ${session.cipher_suite.name}`
      : hasHello
        ? `${tlsVerStr} Handshake negotiated`
        : "No TLS handshake observed",
    timestamp:
      getEventTime("tls_server_hello") || getEventTime("tls_client_hello"),
  });

  // Step 5: X.509 Certificate Validation
  const hasCert = Boolean(session.certificate) || hasEvent("certificate_observed");
  const isExpired = session.certificate?.validity?.not_after
    ? new Date(session.certificate.validity.not_after).getTime() < Date.now()
    : false;

  steps.push({
    id: "cert",
    name: "X.509 Certificate",
    layer: "Identity & Key Material",
    isEncrypted: true,
    status: isExpired ? "warning" : hasCert ? "completed" : "skipped",
    detail: session.certificate
      ? `${session.certificate.reference.subject.replace(/^[A-Z]+=/, "")} (${session.certificate.crypto_details?.public_key?.algorithm || "PKI"} ${session.certificate.crypto_details?.public_key?.rsa_bits || ""})`
      : hasCert
        ? "Certificate presented"
        : "No certificate observed",
    timestamp: getEventTime("certificate_observed"),
  });

  // Step 6: Encrypted Session Established
  const isTlsEstablished =
    session.capture?.tls_established === true ||
    session.starttls_state === "tls_established" ||
    hasEvent("tls_established") ||
    Boolean(session.tls_version);

  steps.push({
    id: "established",
    name: "Secured Channel",
    layer: "Encrypted Application Stream",
    isEncrypted: true,
    status: isTlsEstablished ? "completed" : "skipped",
    detail: isTlsEstablished
      ? `End-to-end encrypted ${session.protocol.toUpperCase()} stream active`
      : "Session remained in plaintext",
    timestamp: getEventTime("tls_established"),
  });

  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: "8px",
        background: "var(--canvas-sunken)",
        padding: "1.25rem",
        marginBottom: "1.25rem",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "1rem",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <span
            style={{
              fontWeight: 700,
              fontSize: "0.9375rem",
              letterSpacing: "-0.01em",
            }}
          >
            Protocol State Machine & Transition Diagram
          </span>
          <span className="badge fresh" style={{ fontSize: "0.75rem" }}>
            {isDirectTls ? "Direct TLS (Port-Implicit)" : "Opportunistic Upgrade (STARTTLS)"}
          </span>
        </div>
        <div style={{ fontSize: "0.8125rem", color: "var(--ink-secondary)" }}>
          Session UID: <code className="mono">{session.session_id.slice(0, 8)}</code>
        </div>
      </div>

      {/* Ladder Progression Flow */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: `repeat(${steps.length}, minmax(0, 1fr))`,
          gap: "0.5rem",
          position: "relative",
        }}
      >
        {steps.map((step, idx) => {
          const isBorderTransition = !isDirectTls && step.id === "starttls";
          const statusBg =
            step.status === "completed"
              ? "var(--status-success-bg, #ecfdf5)"
              : step.status === "warning"
                ? "var(--status-warning-bg, #fffbeb)"
                : step.status === "failed"
                  ? "var(--status-critical-bg, #fef2f2)"
                  : "var(--canvas, #ffffff)";
          const statusBorder =
            step.status === "completed"
              ? "var(--status-success-border, #a7f3d0)"
              : step.status === "warning"
                ? "var(--status-warning-border, #fde68a)"
                : step.status === "failed"
                  ? "var(--status-critical-border, #fecaca)"
                  : "var(--border, #e5e7eb)";
          const statusInk =
            step.status === "completed"
              ? "var(--status-success-ink, #065f46)"
              : step.status === "warning"
                ? "var(--status-warning-ink, #92400e)"
                : step.status === "failed"
                  ? "var(--status-critical-ink, #991b1b)"
                  : "var(--ink-secondary, #6b7280)";

          return (
            <div
              key={step.id}
              style={{
                display: "flex",
                flexDirection: "column",
                border: `1px solid ${statusBorder}`,
                borderRadius: "6px",
                background: statusBg,
                padding: "0.75rem 0.6rem",
                position: "relative",
              }}
            >
              {/* Transition Boundary Tag */}
              {isBorderTransition && (
                <div
                  style={{
                    position: "absolute",
                    top: "-10px",
                    left: "50%",
                    transform: "translateX(-50%)",
                    background: "#4f46e5",
                    color: "#ffffff",
                    fontSize: "0.625rem",
                    fontWeight: 700,
                    padding: "1px 6px",
                    borderRadius: "10px",
                    whiteSpace: "nowrap",
                    zIndex: 2,
                    letterSpacing: "0.03em",
                  }}
                >
                  UPGRADE BOUNDARY
                </div>
              )}

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: "0.35rem",
                }}
              >
                <span
                  style={{
                    fontSize: "0.6875rem",
                    fontWeight: 700,
                    color: statusInk,
                    textTransform: "uppercase",
                  }}
                >
                  Step {idx + 1}
                </span>
                <span
                  style={{
                    fontSize: "0.6875rem",
                    padding: "1px 5px",
                    borderRadius: "4px",
                    background: step.isEncrypted ? "#dbeafe" : "#f3f4f6",
                    color: step.isEncrypted ? "#1e40af" : "#4b5563",
                    fontWeight: 600,
                  }}
                >
                  {step.isEncrypted ? "Encrypted" : "Plaintext"}
                </span>
              </div>

              <div
                style={{
                  fontWeight: 700,
                  fontSize: "0.8125rem",
                  marginBottom: "0.25rem",
                  lineHeight: 1.2,
                }}
              >
                {step.name}
              </div>

              <div
                style={{
                  fontSize: "0.6875rem",
                  color: "var(--ink-secondary)",
                  lineHeight: 1.3,
                  flex: 1,
                }}
              >
                {step.detail}
              </div>

              {step.timestamp && (
                <div
                  className="mono"
                  style={{
                    fontSize: "0.6875rem",
                    color: "var(--ink-secondary)",
                    marginTop: "0.5rem",
                    borderTop: "1px dashed var(--border)",
                    paddingTop: "0.25rem",
                  }}
                >
                  {new Date(step.timestamp).toISOString().slice(11, 23)}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
