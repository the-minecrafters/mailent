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
  return (
    <section aria-label={`Remediation workflow ${guidance.rule_id}`}>
      <p>
        <strong>
          Remediation: {record?.state.replaceAll("_", " ") ?? "not started"}
        </strong>
      </p>
      <p>
        Verification applies to the affected endpoint at the probe time.
        Original findings and historical posture remain visible; investigation
        status stays analyst controlled.
      </p>
      {!record && sessions.length > 1 && (
        <label>
          Affected session{" "}
          <select
            value={selectedSession}
            onChange={(e) => setSelectedSession(e.target.value)}
          >
            <option value="">Select a captured session</option>
            {sessions.map((id) => (
              <option key={id}>{id}</option>
            ))}
          </select>
        </label>
      )}
      {!record ? (
        <button
          type="button"
          disabled={
            mutation.isPending || (sessions.length > 1 && !selectedSession)
          }
          onClick={() => mutation.mutate("start")}
        >
          Start remediation
        </button>
      ) : (
        <>
          {record.state !== "verifying" && (
            <>
              <label>
                Change note{" "}
                <input
                  value={note}
                  maxLength={4096}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Describe the applied configuration change"
                />
              </label>
              <button
                type="button"
                disabled={mutation.isPending}
                onClick={() => mutation.mutate("apply")}
              >
                Mark change applied
              </button>
              {record.applied_at && (
                <button
                  type="button"
                  disabled={mutation.isPending}
                  onClick={() => mutation.mutate("verify")}
                >
                  Verify fix
                </button>
              )}
            </>
          )}
          <details>
            <summary>Original policy and passive evidence</summary>
            <p>{record.finding.description}</p>
            <p>
              Session {record.before.session_id} · {record.before.flow.dst_ip}:
              {record.before.flow.dst_port} · TLS{" "}
              {record.before.tls_version ?? "Unknown"}
            </p>
            <p>
              Certificate{" "}
              {record.before.certificate?.reference.sha256_fingerprint ??
                "Unavailable"}
            </p>
          </details>
          {record.attempts.map((attempt) => (
            <div key={attempt.request_id}>
              <p role="status">
                {attempt.outcome?.replaceAll("_", " ") ?? "verifying"}:{" "}
                {attempt.explanation}
              </p>
              <p>Verified at {attempt.completed_at ?? "Pending"}</p>
              {attempt.after && (
                <details>
                  <summary>Active verification evidence</summary>
                  <ProbeEvidence run={attempt.after} />
                </details>
              )}
            </div>
          ))}
        </>
      )}
      {mutation.isError && <p role="alert">{mutation.error.message}</p>}
      {query.isError && <p role="alert">{query.error.message}</p>}
    </section>
  );
}
