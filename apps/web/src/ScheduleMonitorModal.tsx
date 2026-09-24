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
  const [cadence, setFrequency] = useState<MonitorCadence>("daily");
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
        setError("Choose a connected device to run this check.");
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
                <span>Schedule checks</span>
              </Dialog.Title>
              <Dialog.Description className="modal-description">
                Continuously monitor {domain} for changes and new issues.
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
                Frequency
              </label>
              <select
                id="monitor-cadence-select"
                className="input select-input"
                value={cadence}
                onChange={(e) => setFrequency(e.target.value as MonitorCadence)}
                disabled={loading}
              >
                <option value="hourly">Every hour</option>
                <option value="every_6_hours">Every 6 Hours</option>
                <option value="every_12_hours">Every 12 Hours</option>
                <option value="daily">
                  Daily
                </option>
                <option value="weekly">Weekly</option>
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: "1.25rem" }}>
              <label htmlFor="monitor-target-select" className="form-label">
                Run checks from
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
                <option value="cloud">Mailent cloud</option>
                <option value="agent" disabled={devices.length === 0}>
                  Connected device{" "}
                  {devices.length === 0
                    ? "(No devices available)"
                    : `(${devices.length} available)`}
                </option>
              </select>
              <span
                className="secondary-text"
                style={{
                  fontSize: "0.875rem",
                  marginTop: "0.35rem",
                  display: "block",
                }}
              >
                {targetType === "cloud"
                  ? "Runs from your hosted Mailent workspace."
                  : "Runs from the connected device you choose."}
              </span>
            </div>

            {targetType === "agent" && (
              <div className="form-group" style={{ marginBottom: "1.25rem" }}>
                <label htmlFor="agent-device-select" className="form-label">
                  Choose a device
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
                    Choose a device…
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
                fontSize: "0.875rem",
                display: "flex",
                flexDirection: "column",
                gap: "0.4rem",
              }}
            >
              <div style={{ fontWeight: 600, color: "var(--text)" }}>
                Each scheduled check
              </div>
              <div className="secondary-text">
                Compares results with the previous check
              </div>
              <div className="secondary-text">
                Flags new issues with encryption and certificates
              </div>
              <div className="secondary-text">
                Sends updates to your configured integrations
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
                {loading ? "Scheduling…" : "Schedule checks"}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
