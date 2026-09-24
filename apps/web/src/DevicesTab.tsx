import { InstallCommand } from "./components/InstallCommand";
import { useAuth } from "./auth";
import { workspaceName } from "./display-copy";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  approveDeviceChallenge,
  type Device,
  fetchCurrentOrganization,
  fetchDevices,
  revokeDevice,
} from "./api";
import { Icon } from "./components/Icon";
import {
  Button,
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
} from "./components/ui";

export function DevicesTab() {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const urlCode = params.get("code") || "";
  const [challengeCode, setChallengeCode] = useState(urlCode);
  const [approvalMessage, setApprovalMessage] = useState<string | null>(null);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  useEffect(() => {
    if (urlCode) {
      setChallengeCode(urlCode);
    }
  }, [urlCode]);

  const orgQuery = useQuery({
    queryKey: ["organization", "current"],
    queryFn: fetchCurrentOrganization,
    enabled: !!user,
  });

  const devicesQuery = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
  });

  const approveMutation = useMutation({
    mutationFn: (code: string) =>
      approveDeviceChallenge(code.trim().toUpperCase()),
    onSuccess: (data) => {
      setApprovalMessage(
        `Device "${data.device.name}" authorized successfully.`,
      );
      setApprovalError(null);
      setChallengeCode("");
      if (params.has("code")) {
        params.delete("code");
        setParams(params);
      }
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err: any) => {
      setApprovalError(
        err?.message ||
          "Failed to approve device. Check the code and try again.",
      );
      setApprovalMessage(null);
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => revokeDevice(id),
    onSuccess: () => {
      setRevokingId(null);
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err: any) => {
      setApprovalError(err?.message || "Failed to revoke device.");
      setRevokingId(null);
    },
  });

  const handleApprove = (e: React.FormEvent) => {
    e.preventDefault();
    if (!challengeCode.trim()) return;
    setApprovalMessage(null);
    setApprovalError(null);
    approveMutation.mutate(challengeCode);
  };

  const handleRevoke = (id: string, name: string) => {
    if (
      window.confirm(
        `Are you sure you want to revoke credentials for device "${name}"? It will immediately lose access.`,
      )
    ) {
      setRevokingId(id);
      revokeMutation.mutate(id);
    }
  };

  const devices = devicesQuery.data ?? [];
  const orgName = user ? workspaceName(orgQuery.data) : "your workspace";

  return (
    <div className="tab-page">
      <PageHeader
        title="Devices"
        description={`Manage devices connected to ${orgName}.`}
      />

      {/* Authorize New Device Card */}
      <div
        className="card"
        style={{ marginBottom: "1.5rem", padding: "1.25rem 1.5rem" }}
      >
        <h3
          className="card-title"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            marginBottom: "0.5rem",
          }}
        >
          <Icon name="phonelink_lock" size={20} />
          <span>Connect a device</span>
        </h3>
        <p
          className="secondary-text"
          style={{ fontSize: "0.875rem", margin: "0 0 1rem 0" }}
        >
          Install the CLI, then run <code className="mono">mailent login --server {window.location.origin}</code> and enter the device code below.
        </p>

        <InstallCommand />

        {approvalMessage && (
          <div
            className="badge fresh"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
              padding: "0.6rem 0.85rem",
              marginBottom: "1rem",
              borderRadius: "4px",
            }}
          >
            <Icon name="check_circle" size={16} />
            <span>{approvalMessage}</span>
          </div>
        )}

        {approvalError && (
          <ErrorState title="Authorization error" description={approvalError} />
        )}

        <form
          onSubmit={handleApprove}
          style={{
            display: "flex",
            gap: "0.75rem",
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          <input
            type="text"
            className="input text-input mono"
            placeholder="MLT-XXXXXXXX"
            value={challengeCode}
            onChange={(e) => setChallengeCode(e.target.value.toUpperCase())}
            style={{
              width: "240px",
              textTransform: "uppercase",
              letterSpacing: "1px",
              fontWeight: 600,
            }}
            required
          />
          <Button
            variant="primary"
            type="submit"
            disabled={approveMutation.isPending || !challengeCode.trim()}
          >
            {approveMutation.isPending ? "Approving…" : "Connect device"}
          </Button>
        </form>
      </div>

      {/* Devices List Table */}
      <div className="card" style={{ padding: "1.25rem 1.5rem" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "1rem",
          }}
        >
          <h3 className="card-title" style={{ margin: 0 }}>
            Connected devices
          </h3>
          <span className="secondary-text" style={{ fontSize: "0.875rem" }}>
            {devices.length} registered{" "}
            {devices.length === 1 ? "device" : "devices"}
          </span>
        </div>

        {devicesQuery.isLoading ? (
          <LoadingState label="Loading registered devices…" />
        ) : devicesQuery.isError ? (
          <ErrorState
            title="Could not load devices"
            description={
              devicesQuery.error?.message ||
              "Failed to fetch registered devices."
            }
            onRetry={() => void devicesQuery.refetch()}
          />
        ) : devices.length === 0 ? (
          <EmptyState
            icon="devices"
            title="No devices registered"
            description="Install the Mailent CLI locally and run 'mailent login' to register your machine."
          />
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Device Name</th>
                  <th>System</th>
                  <th>Activity</th>
                  <th>Last Seen</th>
                  <th>Status</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => {
                  const isRevoked = !!device.revoked_at;
                  return (
                    <tr key={device.id}>
                      <td>
                        <strong>{device.name}</strong>
                        <div
                          className="mono secondary-text"
                          style={{ fontSize: "0.875rem" }}
                        >
                          ID: {device.id.slice(0, 8)}…
                        </div>
                      </td>
                      <td>
                        <span className="mono">{device.hostname}</span>
                        <div
                          className="secondary-text"
                          style={{ fontSize: "0.875rem" }}
                        >
                          {device.platform} ({device.architecture})
                        </div>
                      </td>
                      <td>
                        {device.agent_enabled || device.agent_status ? (
                          <div>
                            <div
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "0.4rem",
                              }}
                            >
                              <span
                                className={`badge ${
                                  device.agent_status === "busy"
                                    ? "high"
                                    : device.agent_status === "idle" ||
                                        device.agent_status === "online"
                                      ? "fresh"
                                      : ""
                                }`}
                                style={{
                                  fontSize: "0.875rem",
                                  padding: "0.15rem 0.4rem",
                                }}
                              >
                                Agent: {device.agent_status ?? "online"}
                              </span>
                              {device.version && (
                                <span
                                  className="secondary-text mono"
                                  style={{ fontSize: "0.875rem" }}
                                >
                                  v{device.version}
                                </span>
                              )}
                            </div>
                            <div
                              className="secondary-text"
                              style={{
                                fontSize: "0.875rem",
                                marginTop: "0.2rem",
                              }}
                            >
                              {device.completed_jobs_count ?? 0} jobs completed
                              {device.current_job_id && (
                                <span
                                  className="mono"
                                  style={{ marginLeft: "0.3rem" }}
                                >
                                  (active: {device.current_job_id.slice(0, 8)}…)
                                </span>
                              )}
                            </div>
                          </div>
                        ) : (
                          <div>
                            <span
                              className="secondary-text"
                              style={{ fontSize: "0.875rem" }}
                            >
                              CLI instance
                            </span>
                            <div
                              className="secondary-text"
                              style={{ fontSize: "0.875rem" }}
                            >
                              Run &lsquo;mailent agent install&rsquo; to enable
                            </div>
                          </div>
                        )}
                      </td>
                      <td
                        className="secondary-text"
                        style={{ fontSize: "0.875rem" }}
                      >
                        {new Date(device.last_seen_at).toLocaleString()}
                      </td>
                      <td>
                        {isRevoked ? (
                          <span className="badge critical">Revoked</span>
                        ) : (
                          <span className="badge fresh">Active</span>
                        )}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        {!isRevoked && (
                          <Button
                            variant="secondary"
                            onClick={() => handleRevoke(device.id, device.name)}
                            disabled={revokingId === device.id}
                            title="Revoke device access"
                            style={{ color: "var(--status-danger-ink)" }}
                          >
                            <Icon name="block" size={15} />
                            <span>
                              {revokingId === device.id
                                ? "Revoking…"
                                : "Revoke"}
                            </span>
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
