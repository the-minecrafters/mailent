import { InstallCommand } from "./components/InstallCommand";
import { useAuth } from "./auth";
import { workspaceName } from "./display-copy";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useState } from "react";
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

function InstallationReadiness({ installation }: { installation: Device }) {
  if (installation.revoked_at || installation.readiness === "revoked") {
    return <span className="badge critical">Access revoked</span>;
  }
  if (installation.readiness === "ready") {
    return <span className="badge fresh">Ready</span>;
  }
  return (
    <div>
      <span className="badge">
        {installation.readiness === "setup_required"
          ? "Setup required"
          : "Not checked yet"}
      </span>
      <p className="secondary-text" style={{ margin: "0.4rem 0 0" }}>
        Run <code>mailent doctor</code> on this machine.
      </p>
    </div>
  );
}

export function DevicesTab() {
  const { user, openSignIn } = useAuth();
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const urlCode = params.get("code") || "";
  const [challengeCode, setChallengeCode] = useState(urlCode);
  const [approvalMessage, setApprovalMessage] = useState<string | null>(null);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  useEffect(() => {
    if (urlCode) setChallengeCode(urlCode);
  }, [urlCode]);

  const orgQuery = useQuery({
    queryKey: ["organization", "current"],
    queryFn: fetchCurrentOrganization,
    enabled: !!user,
  });
  const devicesQuery = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
    enabled: !!user,
    refetchInterval: user ? 10000 : false,
  });
  const approveMutation = useMutation({
    mutationFn: (code: string) =>
      approveDeviceChallenge(code.trim().toUpperCase()),
    onSuccess: (data) => {
      setApprovalMessage(
        `“${data.device.hostname}” is connected. Run mailent doctor to check this installation.`,
      );
      setApprovalError(null);
      setChallengeCode("");
      if (params.has("code")) {
        const next = new URLSearchParams(params);
        next.delete("code");
        setParams(next);
      }
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (error: Error) => {
      setApprovalError(
        error.message ||
          "Could not connect this installation. Check the code and try again.",
      );
      setApprovalMessage(null);
    },
  });
  const revokeMutation = useMutation({
    mutationFn: revokeDevice,
    onSuccess: () => {
      setRevokingId(null);
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (error: Error) => {
      setApprovalError(
        error.message || "Could not revoke access. Please try again.",
      );
      setRevokingId(null);
    },
  });

  function handleApprove(event: FormEvent) {
    event.preventDefault();
    if (!user || !challengeCode.trim()) return;
    setApprovalMessage(null);
    setApprovalError(null);
    approveMutation.mutate(challengeCode);
  }
  function handleRevoke(installation: Device) {
    if (
      window.confirm(
        `Revoke workspace access for “${installation.hostname}”? This installation will need to sign in again before it can sync results.`,
      )
    ) {
      setApprovalMessage(null);
      setApprovalError(null);
      setRevokingId(installation.id);
      revokeMutation.mutate(installation.id);
    }
  }

  const installations = devicesQuery.data ?? [];
  const activeCount = installations.filter(
    (installation) => !installation.revoked_at,
  ).length;
  const orgName = user ? workspaceName(orgQuery.data) : "your workspace";

  if (!user) {
    return (
      <div className="tab-page">
        <PageHeader
          title="Mailent installations"
          description="Connect your CLI to sync results into the workspace."
        />
        <section className="card device-sign-in">
          <Icon name="phonelink_lock" size={28} />
          <h2>Sign in to connect Mailent CLI</h2>
          <p className="secondary-text">
            Analyze captures, scan mail infrastructure, and monitor traffic on
            your machine. Sign in to review synced results here.
          </p>
          {urlCode && (
            <p>
              Your connection code is saved here. You can approve it after
              signing in.
            </p>
          )}
          <Button variant="primary" onClick={openSignIn}>
            Sign in
          </Button>
        </section>
      </div>
    );
  }

  return (
    <div className="tab-page">
      <PageHeader
        title="Mailent installations"
        description={`Manage CLI access to ${orgName}. Analysis runs on your machine; structured results sync here.`}
      />
      <section
        className="card"
        style={{ marginBottom: "1.5rem", padding: "1.5rem" }}
      >
        <h2 className="card-title">
          <Icon name="phonelink_lock" size={20} /> Connect Mailent CLI
        </h2>
        <p className="secondary-text">
          Install the CLI with Zeek, sign in from your terminal, then enter the
          connection code below.
        </p>
        <InstallCommand />
        <pre className="device-login-command">
          <code>mailent login --server {window.location.origin}</code>
        </pre>
        {approvalMessage && (
          <p
            className="badge fresh"
            role="status"
            style={{
              display: "block",
              whiteSpace: "normal",
              padding: "0.8rem",
            }}
          >
            {approvalMessage}
          </p>
        )}
        {approvalError && (
          <ErrorState title="Connection error" description={approvalError} />
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
            aria-label="Connection code"
            value={challengeCode}
            onChange={(event) =>
              setChallengeCode(event.target.value.toUpperCase())
            }
            style={{
              width: "240px",
              maxWidth: "100%",
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
            {approveMutation.isPending ? "Connecting…" : "Connect CLI"}
          </Button>
        </form>
      </section>

      {activeCount > 0 && (
        <section
          className="card"
          style={{ marginBottom: "1.5rem", padding: "1.5rem" }}
        >
          <h2 className="card-title">Run locally. Review here.</h2>
          <p className="secondary-text">
            Use your terminal to collect evidence. Add <code>--sync</code> for
            capture and infrastructure assessments; monitoring sends
            observations while it runs.
          </p>
          <pre
            className="device-login-command"
            style={{ marginBottom: "0.75rem" }}
          >
            <code>
              {
                "mailent analyze <capture.pcap> --sync\nmailent scan <domain> --sync\nmailent monitor --interface <iface>"
              }
            </code>
          </pre>
          <p className="secondary-text" style={{ marginBottom: 0 }}>
            Review results in assessment history, compare changes, investigate
            findings, and track fixes in this workspace.
          </p>
        </section>
      )}

      <section className="card" style={{ padding: "1.5rem" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "0.75rem",
            marginBottom: "1rem",
          }}
        >
          <h2 className="card-title" style={{ margin: 0 }}>
            Your installations
          </h2>
          <span className="secondary-text">{activeCount} connected</span>
        </div>
        {devicesQuery.isLoading ? (
          <LoadingState label="Loading installations…" />
        ) : devicesQuery.isError ? (
          <ErrorState
            title="Could not load installations"
            description={devicesQuery.error.message}
            onRetry={() => void devicesQuery.refetch()}
          />
        ) : installations.length === 0 ? (
          <EmptyState
            icon="devices"
            title="Connect your first installation"
            description="Install Mailent CLI and sign in above. Your machine will appear here once connected."
          />
        ) : (
          <div
            className="table-container device-table-scroll"
            role="region"
            aria-label="Mailent installations"
            tabIndex={0}
          >
            <table className="data-table devices-table">
              <thead>
                <tr>
                  <th>Installation</th>
                  <th>Software</th>
                  <th>Readiness</th>
                  <th>Last assessment sync</th>
                  <th style={{ textAlign: "right" }}>Access</th>
                </tr>
              </thead>
              <tbody>
                {installations.map((installation) => (
                  <tr key={installation.id}>
                    <td>
                      <strong>
                        {installation.hostname || installation.name}
                      </strong>
                      <div className="secondary-text">
                        {installation.platform} · {installation.architecture}
                      </div>
                    </td>
                    <td>
                      <div>
                        CLI{" "}
                        <span className="mono device-version">
                          {installation.version || "Not reported"}
                        </span>
                      </div>
                      <div>
                        Zeek{" "}
                        <span className="mono device-version">
                          {installation.zeek_version || "Not reported"}
                        </span>
                      </div>
                    </td>
                    <td>
                      <InstallationReadiness installation={installation} />
                      {installation.remote_online && <span className="badge fresh">Online for remote scans</span>}
                    </td>
                    <td>
                      {installation.last_sync_at ? (
                        <time dateTime={installation.last_sync_at}>
                          <span>
                            {new Date(
                              installation.last_sync_at,
                            ).toLocaleDateString()}
                          </span>
                          <span>
                            {new Date(
                              installation.last_sync_at,
                            ).toLocaleTimeString()}
                          </span>
                        </time>
                      ) : (
                        <span className="secondary-text">No sync recorded</span>
                      )}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      {!installation.revoked_at &&
                        installation.readiness !== "revoked" && (
                          <Button
                            variant="secondary"
                            onClick={() => handleRevoke(installation)}
                            disabled={revokingId === installation.id}
                            title={`Revoke access for ${installation.hostname}`}
                            style={{ color: "var(--status-danger-ink)" }}
                          >
                            <Icon name="block" size={15} />
                            {revokingId === installation.id
                              ? "Revoking…"
                              : "Revoke access"}
                          </Button>
                        )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
