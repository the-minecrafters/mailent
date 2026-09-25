import * as Dialog from "@radix-ui/react-dialog";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { fetchDevices } from "../api";
import { useAuth } from "../auth";
import { RemoteScan } from "./RemoteScan";
import { InstallCommand } from "./InstallCommand";
import { Button, ErrorState, LoadingState } from "./ui";

export type CliWorkflow = "analyze" | "scan" | "monitor";
const workflows = {
  analyze: {
    title: "Analyze captures",
    description:
      "Run Zeek against a PCAP on your machine, then sync the assessment and evidence for review.",
    command: "mailent analyze <capture.pcap> --sync",
  },
  scan: {
    title: "Scan mail infrastructure",
    description:
      "Check mail infrastructure from your own network, then sync the assessment to this workspace.",
    command: "mailent scan <domain> --sync",
  },
  monitor: {
    title: "Monitor live traffic",
    description:
      "Observe mail traffic with Zeek on your machine. Keep the CLI running to send connection evidence to the workspace.",
    command: "mailent monitor --interface <iface>",
  },
};

export function CliWorkflowInstructions({
  workflow,
  domain,
}: {
  workflow: CliWorkflow;
  domain?: string;
}) {
  const { user, openSignIn } = useAuth();
  const installations = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
    enabled: !!user,
    refetchInterval: user ? 10000 : false,
  });
  const connected = (installations.data ?? []).some(
    (installation) => !installation.revoked_at,
  );
  const details = workflows[workflow];
  // Display only a DNS name as an argument, never arbitrary server-supplied shell text.
  const command =
    workflow === "scan" &&
    domain &&
    /^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$/i.test(domain)
      ? `mailent scan ${domain} --sync`
      : details.command;
  if (!user)
    return (
      <div className="cli-workflow-content">
        <p>
          Sign in to connect Mailent CLI and keep your results in this
          workspace.
        </p>
        <Button variant="primary" onClick={openSignIn}>
          Sign in
        </Button>
      </div>
    );
  if (installations.isPending)
    return <LoadingState label="Checking Mailent installations…" />;
  if (installations.isError)
    return (
      <ErrorState
        title="Could not check your installations"
        description="Try again before starting a new analysis."
        onRetry={() => void installations.refetch()}
      />
    );
  if (!connected)
    return (
      <div className="cli-workflow-content">
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
    );
  return (
    <div className="cli-workflow-content">
      <span className="badge fresh">CLI connected</span>
      <p>{details.description}</p>
      <pre className="device-login-command">
        <code>{command}</code>
      </pre>
      <p className="secondary-text">
        Run this in your terminal. Zeek 8+ is required;{" "}
        <code>mailent doctor</code> checks your local setup. Replace values in
        angle brackets with your own.
      </p>
      {workflow === "monitor" && (
        <p className="secondary-text">
          Your operating system must allow packet capture on the selected
          interface.
        </p>
      )}
      <p>
        Synced results appear here for AI-assisted review, history, comparisons,
        investigations, remediation tracking, and reports.
      </p>
      {workflow === "scan" && (
        <RemoteScan
          installations={installations.data ?? []}
          initialDomain={domain}
        />
      )}
      <Link to="/workspace/installations">Manage Mailent installations</Link>
    </div>
  );
}

export function CliWorkflowDialog({
  workflow,
  domain,
  isOpen,
  onClose,
}: {
  workflow: CliWorkflow;
  domain?: string;
  isOpen: boolean;
  onClose: () => void;
}) {
  return (
    <Dialog.Root
      open={isOpen}
      onOpenChange={(open) => {
        if (!open) onClose();
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
            }}
          >
            <Dialog.Title>{workflows[workflow].title}</Dialog.Title>
            <Dialog.Close asChild>
              <Button aria-label="Close CLI instructions">Close</Button>
            </Dialog.Close>
          </div>
          <Dialog.Description>
            Mailent CLI runs the analysis. Mailent Workspace brings the results
            together.
          </Dialog.Description>
          <CliWorkflowInstructions workflow={workflow} domain={domain} />
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
