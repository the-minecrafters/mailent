import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchDeviceScanJob,
  fetchDevices,
  scanOnDevice,
  type Device,
  type DeviceScanJob,
} from "./api";
import { ScanInfrastructureModal } from "./ScanInfrastructureModal";

const auth = vi.hoisted(() => ({
  user: null as object | null,
  openSignIn: vi.fn(),
}));

vi.mock("./auth", () => ({
  useAuth: () => auth,
  authenticatedFetch: vi.fn(),
}));

vi.mock("./api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./api")>()),
  fetchDevices: vi.fn(),
  scanOnDevice: vi.fn(),
  fetchDeviceScanJob: vi.fn(),
}));

const mockDevice: Device = {
  id: "dev-scan-1",
  organization_id: "org-1",
  name: "Server",
  hostname: "server-alpha",
  platform: "linux",
  architecture: "x86_64",
  created_at: "2026-09-25T10:00:00Z",
  last_seen_at: "2026-09-25T10:00:00Z",
  capabilities: [],
  remote_online: false,
  agent_enabled: true,
  agent_status: "idle",
  completed_jobs_count: 0,
};

const clients: QueryClient[] = [];

function mount(isOpen = true, initialDomain = "", onClose = vi.fn()) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  clients.push(client);

  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/workspace/overview"]}>
        <Routes>
          <Route
            path="/workspace/overview"
            element={
              <ScanInfrastructureModal
                isOpen={isOpen}
                onClose={onClose}
                initialDomain={initialDomain}
              />
            }
          />
          <Route
            path="/workspace/captures/:id"
            element={<div>Assessment View Target</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );

  return { user: userEvent.setup(), onClose };
}

beforeEach(() => {
  vi.clearAllMocks();
  auth.user = { email: "analyst@example.com" };
});

afterEach(() => {
  for (const client of clients.splice(0)) client.clear();
});

describe("ScanInfrastructureModal - Local Companion Workflow", () => {
  it("gates guest users with sign-in prompt", async () => {
    auth.user = null;
    const { user } = mount();

    expect(
      screen.getByRole("heading", { name: "Scan mail infrastructure" }),
    ).toBeVisible();
    const signInBtn = screen.getByRole("button", { name: "Sign in" });
    expect(signInBtn).toBeVisible();
    await user.click(signInBtn);
    expect(auth.openSignIn).toHaveBeenCalledOnce();
  });

  it("renders State 1 (CLI unavailable setup) when no devices are registered", async () => {
    vi.mocked(fetchDevices).mockResolvedValue([]);
    mount();

    expect(
      await screen.findByRole("heading", {
        name: "Install and connect Mailent CLI",
      }),
    ).toBeVisible();
    expect(screen.getByText(/^mailent login --server /)).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Connect installation" }),
    ).toHaveAttribute("href", "/workspace/installations");
  });

  it("renders State 2 (Companion offline prompt) when connected device is offline", async () => {
    vi.mocked(fetchDevices).mockResolvedValue([mockDevice]);
    mount();

    expect(await screen.findByText("CLI connected")).toBeVisible();
    expect(screen.getByText("Local companion offline")).toBeVisible();
    expect(
      screen.getByText(/Local companion is offline\. Run this in your terminal/i),
    ).toBeVisible();
    expect(screen.getByText("mailent companion run")).toBeVisible();
    expect(
      screen.getByText(/Waiting for companion to come online…/i),
    ).toBeVisible();
    expect(screen.getByText(/mailent scan <domain> --sync/)).toBeVisible();
  });

  it("renders State 3 (Companion online) and executes domain scan", async () => {
    const onlineDevice = { ...mockDevice, remote_online: true };
    vi.mocked(fetchDevices).mockResolvedValue([onlineDevice]);

    const pendingJob: DeviceScanJob = {
      id: "job-101",
      state: "running",
      result_assessment_id: null,
      last_error: null,
    };
    const completedJob: DeviceScanJob = {
      id: "job-101",
      state: "completed",
      result_assessment_id: "asmt-scan-999",
      last_error: null,
    };

    vi.mocked(scanOnDevice).mockResolvedValue(pendingJob);
    vi.mocked(fetchDeviceScanJob).mockResolvedValue(completedJob);

    const onClose = vi.fn();
    const { user } = mount(true, "", onClose);

    expect(await screen.findByText("Local companion online")).toBeVisible();
    expect(screen.getAllByText(/server-alpha/)[0]).toBeVisible();

    const domainInput = screen.getByLabelText(/Mail Domain/i);
    await user.type(domainInput, "mail.example.org");

    const submitBtn = screen.getByRole("button", { name: "Run check" });
    await user.click(submitBtn);

    expect(scanOnDevice).toHaveBeenCalledWith(
      "mail.example.org",
      onlineDevice.id,
    );

    // On completion, automatically navigates to assessment target
    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
      expect(screen.getByText("Assessment View Target")).toBeVisible();
    });
  });

  it("safely handles scan submission failures", async () => {
    const onlineDevice = { ...mockDevice, remote_online: true };
    vi.mocked(fetchDevices).mockResolvedValue([onlineDevice]);
    vi.mocked(scanOnDevice).mockRejectedValue(
      new Error("Network unreachable on port 25/587"),
    );

    const { user } = mount(true, "invalid.test");

    expect(await screen.findByText("Local companion online")).toBeVisible();

    await user.click(screen.getByRole("button", { name: "Run check" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Network unreachable on port 25/587",
    );
  });
});
