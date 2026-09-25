import { reviewSummary, reviewTitle, liveCheckMessage } from "./display-copy";
import { useQuery } from "@tanstack/react-query";
import { CliWorkflowInstructions } from "./components/CliWorkflow";
import {
  type Asset,
  fetchAssetProbes,
  fetchInvestigation,
  fetchInvestigations,
  type ProbeRun,
} from "./api";

export function ProbeEvidence({ run }: { run: ProbeRun }) {
  const r = run.result;
  return (
    <article className="drift-card">
      <h4>
        Live check · {run.target}:{run.port}
      </h4>
      <p>
        {run.finished_at ? run.outcome : "Running"} · {run.trigger} ·{" "}
        <time>{run.finished_at ?? run.started_at}</time>
      </p>
      {r && (
        <>
          <p>
            STARTTLS: {r.starttls} · TLS: {r.tls_version ?? "Unavailable"} ·
            Cipher: {r.cipher_suite?.name ?? "Unavailable"} · Forward Secrecy:{" "}
            {r.forward_secrecy}
          </p>
          <p>
            Connected IP: {r.resolved_ip ?? "Unavailable"} · Duration:{" "}
            {r.latency_ms} ms
          </p>
          <p>SMTP greeting: {r.smtp_greeting ?? "Unavailable"}</p>
          <p>EHLO: {r.ehlo_capabilities.join(" · ") || "Unavailable"}</p>
          {r.certificate && (
            <details>
              <summary>Certificate evidence</summary>
              <p>
                {r.certificate.reference.subject} · Issuer:{" "}
                {r.certificate.reference.issuer}
              </p>
              <p className="mono">
                SHA-256: {r.certificate.reference.sha256_fingerprint}
              </p>
              <p>
                Valid: {r.certificate.validity.not_before} to{" "}
                {r.certificate.validity.not_after}
              </p>
              <p>
                Hostname valid:{" "}
                {String(r.certificate_hostname_valid ?? "Unknown")} · Trust and
                validity: {String(r.certificate_trusted ?? "Unknown")}
              </p>
            </details>
          )}
          {r.tls_challenges?.map((c) => (
            <p key={c.version}>
              Protocol check {c.version}: {c.outcome} · {c.detail}
            </p>
          ))}
          <p>MTA-STS: {r.mta_sts_result ?? "Unavailable"}</p>
          <p>DANE: {r.dane_result ?? "Unavailable"}</p>
          {r.error && <p role="alert">{r.error}</p>}
          {r.warnings.map((w) => (
            <p key={w}>{w}</p>
          ))}
          <h4>Captured traffic and live check</h4>
          <p>
            Verification confidence:{" "}
            {r.verification?.confidence ?? "Incomplete"}
          </p>
          <p>
            Captured session:{" "}
            {r.verification?.passive_session_id ?? "No comparable session"}
          </p>
          {run.perspective_mismatches.map((m) => (
            <p key={m.kind}>
              {m.kind}: {m.passive_value} → {m.active_value}. {liveCheckMessage(m.description)}
            </p>
          ))}
          {r.verification?.passive_session_id && !run.has_mismatch && (
            <p>
              The available details match the captured connection.
            </p>
          )}
          {r.verification?.drift.map((d) => (
            <p key={d.drift_id}>
              Change {d.drift_id}:{" "}
              {d.confirmed
                ? "Confirmed by live check"
                : "Results differ; not confirmed"}{" "}
              · {d.active_value}
            </p>
          ))}
          {r.verification?.anomalies?.map((a) => (
            <p key={a.anomaly_id}>
              Unusual change {a.anomaly_id}: {a.conclusion} · {a.active_value}
            </p>
          ))}
          <p>
            Related changes:{" "}
            {r.verification?.anomaly_ids.join(", ") || "None linked"}
          </p>
        </>
      )}
    </article>
  );
}

function InvestigationRemediationContext({ id }: { id: string }) {
  const query = useQuery({
    queryKey: ["investigation", id],
    queryFn: () => fetchInvestigation(id),
    refetchInterval: 3000,
  });
  return (
    <>
      {query.data?.remediations.map((r) => (
        <div key={r.id}>
          <p>
            Fix {r.finding.rule_id}: {r.state.replaceAll("_", " ")}
          </p>
          {r.attempts.map((a) => (
            <p key={a.request_id}>
              {liveCheckMessage(a.explanation)} · {a.completed_at ?? "Pending"}
            </p>
          ))}
        </div>
      ))}
      {query.isError && <p role="alert">{query.error.message}</p>}
    </>
  );
}

export function ProbePanel({ asset }: { asset: Asset }) {
  const probes = useQuery({
    queryKey: ["asset-probes", asset.id],
    queryFn: () => fetchAssetProbes(asset.id),
    refetchInterval: 2000,
  });
  const investigations = useQuery({
    queryKey: ["investigations"],
    queryFn: fetchInvestigations,
    refetchInterval: 3000,
  });
  const related =
    investigations.data?.filter((i) => i.asset_id === asset.id) ?? [];
  return (
    <section aria-label="Infrastructure scan results">
      <h3>Check current infrastructure</h3>
      <CliWorkflowInstructions workflow="scan" />
      <h3>Saved connection checks</h3>
      {probes.isError && <p role="alert">{probes.error.message}</p>}
      {probes.data?.map((run) => (
        <ProbeEvidence key={run.id} run={run} />
      ))}
      <h3>Related reviews</h3>
      {investigations.isError && (
        <p role="alert">{investigations.error.message}</p>
      )}
      {related.map((i) => (
        <details key={i.id}>
          <summary>
            {reviewTitle(i.title)} · {i.status}
          </summary>
          <p>{reviewSummary(i.summary)}</p>
          <InvestigationRemediationContext id={i.id} />
          <p>Unusual changes: {i.anomaly_ids.join(", ") || "None"}</p>

          {Object.values(
            i.external_intelligence.active_verifications ?? {},
          ).map((run) => (
            <ProbeEvidence key={run.id} run={run} />
          ))}
        </details>
      ))}
    </section>
  );
}
