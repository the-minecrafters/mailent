import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  applyRemediation,
  fetchRemediation,
  type RemediationGuidance,
  type RemediationRecord,
  startRemediation,
  verifyRemediation,
} from "./api";
import { ProbeEvidence } from "./ProbePanel";

export function RemediationWorkflow({
  assetId,
  guidance,
  initial,
  sessionId,
}: {
  assetId: string;
  guidance: RemediationGuidance;
  initial?: RemediationRecord;
  sessionId?: string;
}) {
  const client = useQueryClient();
  const [created, setCreated] = useState<RemediationRecord>();
  const [note, setNote] = useState("");
  const [selectedSession, setSelectedSession] = useState(
    sessionId ?? initial?.before.session_id ?? "",
  );
  // Retain the idempotency key through network errors/retries; a new completed attempt gets a new key.
  const [requestId, setRequestId] = useState(() => crypto.randomUUID());
  const base = created ?? initial;
  const query = useQuery({
    queryKey: ["remediation", base?.id],
    enabled: !!base,
    queryFn: () => fetchRemediation(base?.id ?? ""),
    initialData: base,
    refetchInterval: (q) =>
      q.state.data?.state === "verifying" ? 1000 : false,
  });
  const record = query.data ?? base;
  const mutation = useMutation({
    mutationFn: async (action: "start" | "apply" | "verify") => {
      if (action === "start")
        return startRemediation(
          assetId,
          guidance.finding_id ?? "",
          selectedSession || undefined,
        );
      if (!record) throw new Error("Start remediation first");
      if (action === "apply") return applyRemediation(record.id, note);
      return verifyRemediation(record.id, requestId);
    },
    onSuccess: (value, action) => {
      setCreated(value);
      client.setQueryData(["remediation", value.id], value);
      if (action === "verify") setRequestId(crypto.randomUUID());
      void client.invalidateQueries({ queryKey: ["asset-posture", assetId] });
      void client.invalidateQueries({ queryKey: ["session-posture"] });
    },
    onError: () => {
      void query.refetch();
    },
  });
  const sessions = [
    ...new Set(
      guidance.evidence.flatMap((e) => (e.session_id ? [e.session_id] : [])),
    ),
  ];
  const stateClass =
    record?.state === "verified_fixed"
      ? "fresh"
      : record?.state === "still_present"
        ? "critical"
        : record?.state === "applied"
          ? "aging"
          : "low";

  const isAdvisoryOnly = !guidance.finding_id || guidance.kind === "best_practice";

  const statusLabel = !record
    ? "Ready to fix"
    : record.state === "verified_fixed"
      ? "Verified fixed!"
      : record.state === "still_present"
        ? "Issue still detected"
        : record.state === "applied"
          ? "Marked as fixed (ready to test)"
          : record.state === "verifying"
            ? "Testing live server…"
            : record.state === "inconclusive"
              ? "Test inconclusive"
              : record.state.replaceAll("_", " ");

  return (
    <section
      aria-label={`Fix workflow for ${guidance.title || guidance.rule_id}`}
      className="remediation-workflow-card"
      style={{
        marginTop: "1rem",
        padding: "1.25rem",
        background: "var(--surface-subtle)",
        borderRadius: "8px",
        border: "1px solid var(--hairline)",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "0.5rem",
        }}
      >
        <p style={{ margin: 0 }}>
          <strong>Status: {statusLabel}</strong>
        </p>
        {record && (
          <span className={`badge ${stateClass}`}>
            {statusLabel}
          </span>
        )}
      </div>
      <p
        className="secondary-text"
        style={{ fontSize: "0.8125rem", margin: "0 0 1rem" }}
      >
        When you test your fix, Mailent connects to your live mail server to confirm
        the issue is solved. Your test history is saved for your records.
      </p>
      {isAdvisoryOnly && (
        <div
          style={{
            padding: "0.75rem 1rem",
            background: "var(--surface-card-solid)",
            borderRadius: "6px",
            border: "1px solid var(--hairline)",
            fontSize: "0.875rem",
          }}
        >
          <p style={{ margin: 0 }}>
            <strong>Optional Security Tip:</strong> This recommendation does not require an active test. Update your server settings and Mailent will detect the improvement on the next scan.
          </p>
        </div>
      )}
      {!record && !isAdvisoryOnly && sessions.length > 1 && (
        <div className="form-group" style={{ marginBottom: "1rem" }}>
          <label className="form-label">
            Affected mail session
            <select
              value={selectedSession}
              onChange={(e) => setSelectedSession(e.target.value)}
              style={{ marginTop: "0.35rem" }}
            >
              <option value="">Select a captured session</option>
              {sessions.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
          </label>
        </div>
      )}
      {!record && !isAdvisoryOnly && (
        <button
          type="button"
          className="btn-primary"
          disabled={
            mutation.isPending || (sessions.length > 1 && !selectedSession)
          }
          onClick={() => mutation.mutate("start")}
        >
          {mutation.isPending ? "Starting…" : "Start fix workflow"}
        </button>
      )}
      {record && (
        <>
          {record.state !== "verifying" && (
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "flex-end",
                gap: "0.75rem",
                marginBottom: "1rem",
                padding: "1rem",
                background: "var(--surface-card-solid)",
                borderRadius: "8px",
                border: "1px solid var(--hairline)",
              }}
            >
              <div style={{ flex: 1, minWidth: "240px" }}>
                <label
                  className="form-label"
                  style={{ marginBottom: "0.35rem" }}
                >
                  What changes did you make?
                </label>
                <input
                  value={note}
                  maxLength={4096}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="e.g. Disabled TLS 1.0/1.1 or renewed the SSL certificate"
                  style={{ width: "100%" }}
                />
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <button
                  type="button"
                  className="btn"
                  disabled={mutation.isPending}
                  onClick={() => mutation.mutate("apply")}
                >
                  Mark as fixed
                </button>
                {record.applied_at && (
                  <button
                    type="button"
                    className="btn-primary"
                    disabled={mutation.isPending}
                    onClick={() => mutation.mutate("verify")}
                  >
                    Test fix now
                  </button>
                )}
              </div>
            </div>
          )}
          <details
            style={{
              padding: "0.75rem 1rem",
              background: "var(--surface-card-solid)",
              borderRadius: "6px",
              border: "1px solid var(--hairline)",
              marginBottom: "0.75rem",
            }}
          >
            <summary
              style={{
                cursor: "pointer",
                fontWeight: 600,
                fontSize: "0.8125rem",
              }}
            >
              View original issue and evidence
            </summary>
            <div style={{ marginTop: "0.75rem", fontSize: "0.8125rem" }}>
              <p style={{ margin: "0.25rem 0" }}>
                {record.finding.description}
              </p>
              <p
                className="mono secondary-text"
                style={{ margin: "0.25rem 0" }}
              >
                Session {record.before.session_id} · {record.before.flow.dst_ip}
                :{record.before.flow.dst_port} · TLS{" "}
                {record.before.tls_version ?? "Unknown"}
              </p>
              <p
                className="mono secondary-text"
                style={{ margin: "0.25rem 0" }}
              >
                Certificate{" "}
                {record.before.certificate?.reference.sha256_fingerprint ??
                  "Unavailable"}
              </p>
            </div>
          </details>
          {record.attempts.map((attempt) => (
            <div
              key={attempt.request_id}
              style={{
                padding: "0.875rem",
                borderRadius: "6px",
                border: "1px solid var(--hairline)",
                background: "var(--surface-card-solid)",
                marginBottom: "0.75rem",
              }}
            >
              <p
                role="status"
                style={{
                  fontWeight: 600,
                  fontSize: "0.875rem",
                  margin: "0 0 0.25rem",
                }}
              >
                {attempt.outcome === "verified_fixed"
                  ? "Verified fixed!"
                  : attempt.outcome === "still_present"
                    ? "Issue still detected"
                    : attempt.outcome === "inconclusive"
                      ? "Test inconclusive"
                      : (attempt.outcome?.replaceAll("_", " ") ?? "Testing…")}:{" "}
                {attempt.explanation.replace(/use SMTP STARTTLS or an implicit TLS endpoint.*; /i, "")}
              </p>
              <p
                className="mono secondary-text"
                style={{ fontSize: "0.75rem", margin: "0 0 0.5rem" }}
              >
                Tested at: {attempt.completed_at ? new Date(attempt.completed_at).toLocaleString() : "In progress"}
              </p>
              {attempt.after && (
                <details style={{ marginTop: "0.5rem" }}>
                  <summary
                    style={{
                      cursor: "pointer",
                      fontSize: "0.75rem",
                      fontWeight: 600,
                    }}
                  >
                    Live test details and evidence
                  </summary>
                  <div style={{ marginTop: "0.5rem" }}>
                    <ProbeEvidence run={attempt.after} />
                  </div>
                </details>
              )}
            </div>
          ))}
        </>
      )}
      {mutation.isError && (
        <p
          role="alert"
          className="alert-banner danger"
          style={{ marginTop: "0.75rem" }}
        >
          {mutation.error.message}
        </p>
      )}
      {query.isError && (
        <p
          role="alert"
          className="alert-banner danger"
          style={{ marginTop: "0.75rem" }}
        >
          {query.error.message}
        </p>
      )}
    </section>
  );
}
