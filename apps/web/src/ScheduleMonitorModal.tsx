import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  createMonitor,
  fetchDevices,
  type InfrastructureMonitor,
  type MonitorCadence,
  type MonitorExecutionTarget,
} from "./api";
import { Icon } from "./components/Icon";
import { Button, ErrorState } from "./components/ui";

interface ScheduleMonitorModalProps {
  isOpen: boolean;
  domain: string;
  onClose: () => void;
  onCreated: (monitor: InfrastructureMonitor) => void;
}

export function ScheduleMonitorModal({
  isOpen,
  domain,
  onClose,
  onCreated,
}: ScheduleMonitorModalProps) {
  const [cadence, setCadence] = useState<MonitorCadence>("daily");
  const [targetType, setTargetType] = useState<"cloud" | "agent">("cloud");
  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const devicesQuery = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
    enabled: isOpen,
  });

  const devices = devicesQuery.data?.filter((d) => !d.revoked_at) ?? [];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    let target: MonitorExecutionTarget = { type: "cloud" };
    if (targetType === "agent") {
      if (!selectedAgentId) {
        setError("Please select a registered agent to execute this scan.");
        setLoading(false);
        return;
      }
      target = { type: "agent", agent_id: selectedAgentId };
    }

    try {
      const monitor = await createMonitor({
        domain: domain.trim().toLowerCase(),
        cadence,
        target,
      });
      onCreated(monitor);
      onClose();
    } catch (err: any) {
      setError(err?.message || "Failed to schedule monitor.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog.Root
      open={isOpen}
      onOpenChange={(open) => !open && !loading && onClose()}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content className="modal-content">
          <div className="modal-header">
            <div className="modal-header-content">
              <Dialog.Title className="modal-title">
                <Icon name="schedule" size={20} />
                <span>Schedule Infrastructure Monitoring</span>
              </Dialog.Title>
              <Dialog.Description className="modal-description">
                Continuously monitor {domain} for configuration drift and security
                regressions.
              </Dialog.Description>
            </div>
            <Dialog.Close asChild disabled={loading}>
              <button
                className="icon-button modal-close"
                aria-label="Close dialog"
              >
                <Icon name="close" />
              </button>
            </Dialog.Close>
          </div>

          <form onSubmit={handleSubmit} className="modal-body">
            {error && (
              <ErrorState title="Scheduling failed" description={error} />
            )}

            <div className="form-group" style={{ marginBottom: "1rem" }}>
              <label className="form-label">Target Domain</label>
              <input
                type="text"
                className="input text-input"
                value={domain}
                disabled
                style={{ opacity: 0.8, cursor: "not-allowed" }}
              />
            </div>

            <div className="form-group" style={{ marginBottom: "1rem" }}>
              <label htmlFor="monitor-cadence-select" className="form-label">
                Scan Cadence
              </label>
              <select
                id="monitor-cadence-select"
                className="input select-input"
                value={cadence}
                onChange={(e) => setCadence(e.target.value as MonitorCadence)}
                disabled={loading}
              >
                <option value="hourly">Hourly (Every 1 hour)</option>
                <option value="every_6_hours">Every 6 Hours</option>
                <option value="every_12_hours">Every 12 Hours</option>
                <option value="daily">
                  Daily (Once per day - recommended)
                </option>
                <option value="weekly">Weekly (Once per week)</option>
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: "1.25rem" }}>
              <label htmlFor="monitor-target-select" className="form-label">
                Execution Target
              </label>
              <select
                id="monitor-target-select"
                className="input select-input"
                value={targetType}
                onChange={(e) => {
                  const val = e.target.value as "cloud" | "agent";
                  setTargetType(val);
                  if (
                    val === "agent" &&
                    devices.length > 0 &&
                    !selectedAgentId
                  ) {
                    setSelectedAgentId(devices[0].id);
                  }
                }}
                disabled={loading}
              >
                <option value="cloud">Cloud Core Worker (Default)</option>
                <option value="agent" disabled={devices.length === 0}>
                  Registered Scanning Agent{" "}
                  {devices.length === 0
                    ? "(No active agents)"
                    : `(${devices.length} available)`}
                </option>
              </select>
              <span
                className="secondary-text"
                style={{
                  fontSize: "0.8125rem",
                  marginTop: "0.35rem",
                  display: "block",
                }}
              >
                {targetType === "cloud"
                  ? "Scan will be executed by Mailent's cloud infrastructure worker pool."
                  : "Scan job will be dispatched to an on-premises or registered host running the Mailent agent."}
              </span>
            </div>

            {targetType === "agent" && (
              <div className="form-group" style={{ marginBottom: "1.25rem" }}>
                <label htmlFor="agent-device-select" className="form-label">
                  Select Agent Machine
                </label>
                <select
                  id="agent-device-select"
                  className="input select-input"
                  value={selectedAgentId}
                  onChange={(e) => setSelectedAgentId(e.target.value)}
                  disabled={loading}
                  required
                >
                  <option value="" disabled>
                    Choose an agent…
                  </option>
                  {devices.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name} ({d.hostname} - {d.platform} {d.architecture})
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div
              style={{
                background: "var(--canvas-sunken)",
                border: "1px solid var(--border)",
                borderRadius: "6px",
                padding: "0.85rem 1rem",
                marginBottom: "1.25rem",
                fontSize: "0.8125rem",
                display: "flex",
                flexDirection: "column",
                gap: "0.4rem",
              }}
            >
              <div style={{ fontWeight: 600, color: "var(--text)" }}>
                Automated Security Actions
              </div>
              <div className="secondary-text">
                • Historical baseline diffing on consecutive scans (Change !=
                Finding)
              </div>
              <div className="secondary-text">
                • Immediate alerting on security regressions (STARTTLS lost,
                weak ciphers, expired certs)
              </div>
              <div className="secondary-text">
                • Webhook and SIEM notification dispatch on detected changes
              </div>
            </div>

            <div
              className="modal-footer"
              style={{
                display: "flex",
                justifyContent: "flex-end",
                gap: "0.5rem",
              }}
            >
              <Button
                type="button"
                variant="secondary"
                onClick={onClose}
                disabled={loading}
              >
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={loading}>
                {loading ? "Scheduling…" : "Enable Monitor"}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
