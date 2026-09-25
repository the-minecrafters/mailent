import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  fetchDeviceScanJob,
  fetchDevices,
  scanOnDevice,
  type Device,
} from "./api";
import { useAuth } from "./auth";
import { Icon } from "./components/Icon";
import { InstallCommand } from "./components/InstallCommand";
import { Button, ErrorState, LoadingState } from "./components/ui";

export function ScanInfrastructureModal({
  isOpen,
  onClose,
  initialDomain = "",
}: {
  isOpen: boolean;
  onClose: () => void;
  initialDomain?: string;
}) {
  const { user, openSignIn } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [domain, setDomain] = useState(initialDomain);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const installations = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
    enabled: !!user && isOpen,
    refetchInterval: user && isOpen ? 3000 : false,
  });

  const activeDevices = (installations.data ?? []).filter(
    (installation) => !installation.revoked_at,
  );
  const connected = activeDevices.length > 0;
  const onlineDevices = activeDevices.filter((i) => i.remote_online);

  const targetDevice: Device | undefined =
    onlineDevices.find((i) => i.id === selectedDeviceId) ?? onlineDevices[0];

  const scanMutation = useMutation({
    mutationFn: () => {
      if (!targetDevice) throw new Error("No online installation selected.");
      return scanOnDevice(domain.trim(), targetDevice.id);
    },
    onSuccess: (job) => {
      setJobId(job.id);
    },
  });

  const jobQuery = useQuery({
    queryKey: ["scan-job", jobId],
    queryFn: () => fetchDeviceScanJob(jobId!),
    enabled: !!jobId && isOpen,
    refetchInterval: (query) =>
      ["pending", "leased", "running"].includes(
        query.state.data?.state ?? "pending",
      )
        ? 1500
        : false,
  });

  const isJobRunning =
    scanMutation.isPending ||
    (!!jobId &&
      (!jobQuery.data ||
        ["pending", "leased", "running"].includes(jobQuery.data.state)));

  useEffect(() => {
    if (
      jobQuery.data?.state === "completed" &&
      jobQuery.data.result_assessment_id
    ) {
      const assessmentId = jobQuery.data.result_assessment_id;
      void queryClient.invalidateQueries({ queryKey: ["assessments"] });
      onClose();
      navigate(`/workspace/captures/${assessmentId}`);
    }
  }, [
    jobQuery.data?.state,
    jobQuery.data?.result_assessment_id,
    queryClient,
    onClose,
    navigate,
  ]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!domain.trim() || isJobRunning || !targetDevice) return;
    scanMutation.mutate();
  }

  function copyCompanionCommand() {
    navigator.clipboard.writeText("mailent companion start").then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const safeDomainCommand =
    domain &&
    /^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$/i.test(domain.trim())
      ? `mailent scan ${domain.trim()} --sync`
      : "mailent scan <domain> --sync";

  return (
    <Dialog.Root
      open={isOpen}
      onOpenChange={(open) => {
        if (!open) {
          setJobId(null);
          onClose();
        }
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content
          className="capture-dialog"
          style={{
            width: "min(680px, calc(100vw - 2rem))",
            maxHeight: "85vh",
            overflowY: "auto",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "1rem",
              marginBottom: "0.5rem",
            }}
          >
            <Dialog.Title style={{ margin: 0 }}>Scan mail infrastructure</Dialog.Title>
            <Dialog.Close asChild>
              <Button aria-label="Close dialog">Close</Button>
            </Dialog.Close>
          </div>
          <Dialog.Description>
            Check mail infrastructure from your own network, then sync the assessment to this workspace.
          </Dialog.Description>

          {!user ? (
            <div className="cli-workflow-content" style={{ marginTop: "1rem" }}>
              <p>
                Sign in to connect Mailent CLI and keep your results in this
                workspace.
              </p>
              <Button variant="primary" onClick={openSignIn}>
                Sign in
              </Button>
            </div>
          ) : installations.isPending ? (
            <div style={{ padding: "2rem 0" }}>
              <LoadingState label="Checking Mailent installations…" />
            </div>
          ) : installations.isError ? (
            <div style={{ marginTop: "1rem" }}>
              <ErrorState
                title="Could not check your installations"
                description="Try again before starting a new analysis."
                onRetry={() => void installations.refetch()}
              />
            </div>
          ) : !connected ? (
            <div className="cli-workflow-content" style={{ marginTop: "1rem" }}>
              <h3>Install and connect Mailent CLI</h3>
              <p>
                Analysis runs on your machine. Connect the CLI before adding results
                to this workspace.
              </p>
              <InstallCommand />
              <pre className="device-login-command">
                <code>mailent login --server {window.location.origin}</code>
              </pre>
              <Link className="btn btn-primary" to="/workspace/installations">
                Connect installation
              </Link>
            </div>
          ) : onlineDevices.length === 0 ? (
            <div className="cli-workflow-content" style={{ marginTop: "1rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
                <span className="badge fresh">CLI connected</span>
                <span className="badge" style={{ background: "var(--hairline)", color: "var(--ink-secondary)" }}>
                  Local companion offline
                </span>
              </div>
              <p style={{ margin: "0.5rem 0" }}>
                Local companion service is offline. Start the service to enable scans on this machine:
              </p>
              <div style={{ position: "relative" }}>
                <pre className="device-login-command" style={{ margin: "0.75rem 0" }}>
                  <code>mailent companion start</code>
                </pre>
                <Button
                  variant="secondary"
                  onClick={copyCompanionCommand}
                  style={{
                    position: "absolute",
                    right: "8px",
                    top: "50%",
                    transform: "translateY(-50%)",
                    padding: "0.3rem 0.6rem",
                    fontSize: "0.8rem",
                  }}
                >
                  <Icon name={copied ? "check_circle" : "copy"} size={14} />
                  <span>{copied ? "Copied" : "Copy"}</span>
                </Button>
              </div>
              <p className="secondary-text" style={{ margin: "0.25rem 0 0.5rem", fontSize: "0.82rem" }}>
                Runs as a background service. Use <code>mailent companion run</code> for foreground debugging.
              </p>
              <div
                className="secondary-text"
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "0.5rem",
                  marginTop: "0.5rem",
                  padding: "0.5rem 0.75rem",
                  background: "var(--surface-alt)",
                  borderRadius: "6px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <Icon name="refresh" className="spin" size={14} />
                  <span>Waiting for companion to come online…</span>
                </div>
                <Button
                  variant="secondary"
                  onClick={() => void installations.refetch()}
                  style={{ padding: "0.2rem 0.5rem", fontSize: "0.75rem" }}
                >
                  Check now
                </Button>
              </div>
              <div
                style={{
                  marginTop: "1.5rem",
                  paddingTop: "1rem",
                  borderTop: "1px solid var(--hairline)",
                }}
              >
                <p className="secondary-text" style={{ margin: 0, fontSize: "0.85rem" }}>
                  Terminal alternative: <code>{safeDomainCommand}</code>
                </p>
              </div>
            </div>
          ) : (
            <div style={{ marginTop: "1rem" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: "1rem",
                }}
              >
                <span className="badge fresh" style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                  <span
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      backgroundColor: "currentColor",
                    }}
                  />
                  Local companion online
                </span>
                <span className="secondary-text" style={{ fontSize: "0.85rem" }}>
                  {targetDevice?.hostname || "Local machine"}
                </span>
              </div>

              {isJobRunning ? (
                <div className="analysis-progress" role="status">
                  <Icon name="refresh" className="spin" size={32} />
                  <h3 style={{ margin: "1rem 0 0.5rem" }}>
                    Checking mail infrastructure for {domain}…
                  </h3>
                  <p style={{ margin: 0 }}>
                    Executing DNS, MX, SPF, DMARC, and STARTTLS cipher suite probes.
                  </p>
                  <span className="secondary-text" style={{ display: "block", marginTop: "0.5rem" }}>
                    Scanning from {targetDevice?.hostname || "connected device"}
                  </span>
                </div>
              ) : (
                <form onSubmit={handleSubmit}>
                  <label className="form-label" style={{ display: "block", marginBottom: "0.5rem" }}>
                    Mail Domain
                    <input
                      className="text-input"
                      type="text"
                      required
                      autoFocus
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      placeholder="e.g. example.com or mail.example.com"
                      style={{ width: "100%", marginTop: "0.25rem" }}
                    />
                  </label>

                  {onlineDevices.length > 1 ? (
                    <label className="form-label" style={{ display: "block", marginTop: "0.75rem", marginBottom: "0.5rem" }}>
                      Online machine
                      <select
                        className="select-input"
                        value={targetDevice?.id ?? ""}
                        onChange={(e) => setSelectedDeviceId(e.target.value)}
                        style={{ width: "100%", marginTop: "0.25rem" }}
                      >
                        {onlineDevices.map((i) => (
                          <option key={i.id} value={i.id}>
                            {i.hostname || i.name} ({i.platform})
                          </option>
                        ))}
                      </select>
                    </label>
                  ) : (
                    <p className="secondary-text" style={{ margin: "0.5rem 0 1rem", fontSize: "0.85rem" }}>
                      Probing from: <strong>{targetDevice?.hostname || "your machine"}</strong> ({targetDevice?.platform})
                    </p>
                  )}

                  <Button
                    variant="primary"
                    type="submit"
                    disabled={!domain.trim() || isJobRunning}
                    style={{ width: "100%", marginTop: "0.75rem" }}
                  >
                    Run check
                  </Button>
                </form>
              )}

              {scanMutation.isError && (
                <div style={{ marginTop: "1rem" }}>
                  <ErrorState
                    title="Scan could not start"
                    description={scanMutation.error.message}
                    onRetry={() => scanMutation.reset()}
                  />
                </div>
              )}

              {jobQuery.isError && (
                <div style={{ marginTop: "1rem" }}>
                  <ErrorState
                    title="Scan status unavailable"
                    description="The scan may still be running. Check its status before starting another."
                    onRetry={() => void jobQuery.refetch()}
                  />
                </div>
              )}

              {jobQuery.data &&
                ["failed", "canceled"].includes(jobQuery.data.state) && (
                  <div style={{ marginTop: "1rem" }}>
                    <ErrorState
                      title="Scan did not finish"
                      description={
                        jobQuery.data.last_error ??
                        "Scan did not complete. Please verify the domain and ensure the companion is running."
                      }
                      onRetry={() => setJobId(null)}
                    />
                  </div>
                )}

              {!isJobRunning && (
                <div
                  style={{
                    marginTop: "1.5rem",
                    paddingTop: "1rem",
                    borderTop: "1px solid var(--hairline)",
                  }}
                >
                  <p className="secondary-text" style={{ margin: 0, fontSize: "0.85rem" }}>
                    Terminal alternative: <code>{safeDomainCommand}</code>
                  </p>
                </div>
              )}
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
