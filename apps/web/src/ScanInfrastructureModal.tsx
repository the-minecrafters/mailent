import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  type AssessmentRecord,
  readReadiness,
  scanInfrastructure,
  fetchDevices,
  scanOnDevice,
  fetchDeviceScanJob,
  fetchAssessment,
} from "./api";
import { useAuth } from "./auth";
import { Link } from "react-router-dom";
import { Icon } from "./components/Icon";
import { Button, ErrorState } from "./components/ui";

interface ScanInfrastructureModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (assessment: AssessmentRecord) => void;
}

export function ScanInfrastructureModal({
  isOpen,
  onClose,
  onCreated,
}: ScanInfrastructureModalProps) {
  const [domain, setDomain] = useState("");
  const [scanning, setScanning] = useState(false);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();
  const [executionTarget, setExecutionTarget] = useState("cloud");
  const selectedDeviceId = executionTarget === "cloud" ? null : executionTarget;
  const [jobId, setJobId] = useState<string | null>(null);
  const devices = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
    enabled: isOpen && !!user,
  });
  const availableDevices = (devices.data ?? []).filter(
    (device) =>
      !device.revoked_at &&
      device.agent_enabled &&
      device.capabilities.includes("infrastructure_scan") &&
      Date.now() - Date.parse(device.last_seen_at) < 300000,
  );
  const job = useQuery({
    queryKey: ["scan-job", jobId],
    queryFn: () => fetchDeviceScanJob(jobId!),
    enabled: isOpen && !!jobId,
    refetchInterval: 2000,
    retry: 1,
  });
  const readiness = useQuery({
    queryKey: ["readiness"],
    queryFn: readReadiness,
    enabled: isOpen,
  });
  const blockedPorts = readiness.data?.blocked_mail_ports ?? [];

  const close = () => {
    setJobId(null);
    setScanning(false);
    onClose();
  };

  useEffect(() => {
    if (!isOpen || !jobId) return;
    let alive = true;
    const result = job.data;
    if (result?.state === "completed" && result.result_assessment_id) {
      fetchAssessment(result.result_assessment_id)
        .then((assessment) => {
          if (!alive) return;
          setJobId(null);
          setScanning(false);
          onCreated(assessment);
          onClose();
        })
        .catch((err) => {
          if (alive) {
            setError(String(err));
            setJobId(null);
            setScanning(false);
          }
        });
    } else if (
      result?.state === "failed" ||
      result?.state === "canceled" ||
      job.error
    ) {
      setError(
        result?.last_error ||
          job.error?.message ||
          "The device check did not finish. Check that the CLI is running and try again.",
      );
      setJobId(null);
      setScanning(false);
    }
    return () => {
      alive = false;
    };
  }, [isOpen, jobId, job.data, job.error, onCreated, onClose]);

  useEffect(() => {
    if (!scanning) return;
    const timer = window.setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => window.clearInterval(timer);
  }, [scanning]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const target = domain.trim().toLowerCase();
    if (!target) {
      setError("Please enter a domain name to scan.");
      return;
    }

    setError(null);
    setScanning(true);
    setSeconds(0);

    try {
      if (selectedDeviceId) {
        const queued = await scanOnDevice(target, selectedDeviceId);
        setJobId(queued.id);
        return;
      }
      const result = await scanInfrastructure(target);
      setScanning(false);
      onCreated(result.assessment);
      onClose();
    } catch (err: any) {
      setError(
        err?.message ||
          "Infrastructure scan failed. Check the domain and try again.",
      );
      setScanning(false);
    }
  };

  return (
    <Dialog.Root
      open={isOpen}
      onOpenChange={(open) => !open && (!scanning || !!jobId) && close()}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content className="modal-content">
          <div className="modal-header">
            <div className="modal-header-content">
              <Dialog.Title className="modal-title">
                <Icon name="search" size={20} />
                <span>Check a domain</span>
              </Dialog.Title>
              <Dialog.Description className="modal-description">
                Find mail servers and check their encryption, certificates, and
                email security settings.
              </Dialog.Description>
            </div>
            <Dialog.Close asChild disabled={scanning && !jobId}>
              <button
                className="icon-button modal-close"
                aria-label="Close dialog"
              >
                <Icon name="close" />
              </button>
            </Dialog.Close>
          </div>

          <form onSubmit={handleScan} className="modal-body">
            {error && <ErrorState title="Scan failed" description={error} />}

            {!selectedDeviceId && blockedPorts.length > 0 && (
              <div
                style={{
                  background: "var(--status-warning-bg)",
                  border: "1px solid var(--status-warning-border)",
                  borderRadius: "6px",
                  padding: "0.75rem 1rem",
                  marginBottom: "1rem",
                  fontSize: "0.875rem",
                  lineHeight: 1.45,
                  color: "var(--status-warning-ink)",
                }}
              >
                <strong>Some ports are disabled</strong>
                <p style={{ margin: "0.25rem 0 0 0" }}>
                  Ports {blockedPorts.join(", ")} are disabled in this
                  workspace. Run the CLI on a network that allows these
                  connections to check those services.
                </p>
              </div>
            )}

            <div className="form-group" style={{ marginBottom: "1rem" }}>
              <label htmlFor="scan-domain-input" className="form-label">
                Domain
              </label>
              <input
                id="scan-domain-input"
                type="text"
                className="input text-input"
                placeholder="company.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={scanning}
                autoFocus
                required
              />
              <span
                className="secondary-text"
                style={{
                  fontSize: "0.875rem",
                  marginTop: "0.35rem",
                  display: "block",
                }}
              >
                Use a domain you own or have permission to check.
              </span>
            </div>

            <div className="form-group" style={{ marginBottom: "1rem" }}>
              <label htmlFor="scan-execution-target" className="form-label">
                Run on
              </label>
              <select
                id="scan-execution-target"
                className="input"
                value={executionTarget}
                onChange={(event) => setExecutionTarget(event.target.value)}
                disabled={scanning}
              >
                <option value="cloud">This workspace</option>
                {availableDevices.map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.name}
                  </option>
                ))}
              </select>
              <p className="secondary-text">
                A connected device runs the check from its own network and sends
                results back securely. This avoids the cloud host’s mail-port
                restrictions without a paid server.
              </p>
              {availableDevices.length === 0 && (
                <div className="callout">
                  <strong>Use your own computer</strong>
                  <p>
                    <Link to="/workspace/devices" onClick={close}>
                      Connect a device
                    </Link>
                    , then run <code>mailent agent run</code> on it. Keep it
                    running while checks are in progress. Its network must allow
                    connections to the mail servers.
                  </p>
                </div>
              )}
              {devices.isError && (
                <ErrorState
                  title="Devices could not be loaded"
                  description={devices.error.message}
                />
              )}
            </div>

            {jobId && (
              <p role="status">
                {job.data?.state === "pending"
                  ? "Waiting for your device…"
                  : "Your device is checking the domain…"}{" "}
                You can leave this open or continue in the background. The
                result will appear in Captures.
              </p>
            )}

            <div
              style={{
                background: "var(--canvas-sunken)",
                border: "1px solid var(--border)",
                borderRadius: "6px",
                padding: "0.85rem 1rem",
                marginBottom: "1.25rem",
                fontSize: "0.875rem",
                lineHeight: 1.5,
              }}
            >
              <strong style={{ display: "block", marginBottom: "0.25rem" }}>
                Included in this check
              </strong>
              <ul style={{ margin: 0, paddingLeft: "1.2rem" }}>
                <li>Mail server records and DNS security</li>
                <li>
                  SMTP STARTTLS (port 25 &amp; 587) and IMAP/POP3 (port 993,
                  143, 995)
                </li>
                <li>Certificate names, expiry, and trust</li>
                <li>MTA-STS, TLS reporting, and DANE policies</li>
              </ul>
            </div>

            <div
              className="modal-actions"
              style={{
                display: "flex",
                justifyContent: "flex-end",
                gap: "0.5rem",
              }}
            >
              <Button
                variant="secondary"
                type="button"
                onClick={close}
                disabled={scanning && !jobId}
              >
                {jobId ? "Continue in background" : "Cancel"}
              </Button>
              <Button
                variant="primary"
                type="submit"
                disabled={scanning || !domain.trim()}
              >
                {scanning ? (
                  <>
                    <Icon name="refresh" className="spin" size={16} />
                    <span>Checking ({seconds}s)…</span>
                  </>
                ) : (
                  <>
                    <Icon name="search" size={16} />
                    <span>Run check</span>
                  </>
                )}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
