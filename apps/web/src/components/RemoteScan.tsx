import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { type Device, fetchDeviceScanJob, scanOnDevice } from "../api";
import { Button, ErrorState } from "./ui";

/** Optional remote scans; a saved login alone never makes an installation eligible. */
export function RemoteScan({
  installations,
  initialDomain = "",
}: {
  installations: Device[];
  initialDomain?: string;
}) {
  const client = useQueryClient();
  const online = installations.filter((i) => !i.revoked_at && i.remote_online);
  const [domain, setDomain] = useState(initialDomain);
  const [selected, setSelected] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const installation = online.find((i) => i.id === selected) ?? online[0];
  const scan = useMutation({
    mutationFn: () => scanOnDevice(domain.trim(), installation!.id),
    onSuccess: (job) => setJobId(job.id),
  });
  const job = useQuery({
    queryKey: ["scan-job", jobId],
    queryFn: () => fetchDeviceScanJob(jobId!),
    enabled: !!jobId,
    refetchInterval: (query) =>
      ["pending", "leased", "running"].includes(
        query.state.data?.state ?? "pending",
      )
        ? 2000
        : false,
  });
  const busy =
    scan.isPending ||
    (!!jobId &&
      (!job.data || ["pending", "leased", "running"].includes(job.data.state)));
  return (
    <details>
      <summary>Scan from an online installation</summary>
      <p>
        Optional: keep <code>mailent agent run</code> open on your machine to
        accept remote scans. A connected login alone does not enable remote
        execution.
      </p>
      {online.length === 0 ? (
        <p>No CLI installation is online and accepting scans.</p>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (installation && !busy && domain.trim()) scan.mutate();
          }}
        >
          <label className="form-label">
            Domain
            <input
              className="text-input"
              required
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="Your mail domain"
            />
          </label>
          <label className="form-label">
            Online installation
            <select
              className="select-input"
              value={installation?.id ?? ""}
              onChange={(e) => setSelected(e.target.value)}
            >
              {online.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.hostname}
                </option>
              ))}
            </select>
          </label>
          <Button
            variant="secondary"
            type="submit"
            disabled={busy || !domain.trim()}
          >
            {busy ? "Scan requested…" : "Run remote scan"}
          </Button>
        </form>
      )}
      {scan.isError && (
        <ErrorState
          title="Scan could not start"
          description={scan.error.message}
        />
      )}
      {job.isError && (
        <ErrorState
          title="Scan status unavailable"
          description="The scan may still be running. Check its status before starting another."
          onRetry={() => void job.refetch()}
        />
      )}
      {job.data?.state === "completed" && job.data.result_assessment_id && (
        <Link
          to={`/workspace/captures/${job.data.result_assessment_id}`}
          onClick={() =>
            void client.invalidateQueries({ queryKey: ["assessments"] })
          }
        >
          Open synced assessment
        </Link>
      )}
      {job.data && ["failed", "canceled"].includes(job.data.state) && (
        <p role="alert">
          {job.data.last_error ??
            "Scan did not finish. Start it again when the installation is online."}
        </p>
      )}
    </details>
  );
}
