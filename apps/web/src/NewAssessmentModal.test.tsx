import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  analyzeCaptureOnCompanion,
  fetchCompanionStatus,
  fetchDevices,
  type Device,
} from "./api";
import { NewAssessmentModal } from "./NewAssessmentModal";

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
  fetchCompanionStatus: vi.fn(),
  analyzeCaptureOnCompanion: vi.fn(),
}));

const mockDevice: Device = {
  id: "dev-1",
  organization_id: "org-1",
  name: "Workstation",
  hostname: "workstation",
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

function mount(isOpen = true, onClose = vi.fn()) {
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
            element={<NewAssessmentModal isOpen={isOpen} onClose={onClose} />}
          />
          <Route
            path="/workspace/captures/:id"
            element={<div>Assessment Details Page</div>}
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

describe("NewAssessmentModal - Local Companion Workflow", () => {
  it("gates guest users to sign in without exposing file upload", async () => {
    auth.user = null;
    const { user } = mount();

    expect(
      screen.getByRole("heading", { name: "Analyze captures" }),
    ).toBeVisible();
    const signInBtn = screen.getByRole("button", { name: "Sign in" });
    expect(signInBtn).toBeVisible();
    await user.click(signInBtn);
    expect(auth.openSignIn).toHaveBeenCalledOnce();
    expect(screen.queryByLabelText(/file/i)).not.toBeInTheDocument();
  });

  it("renders State 1 (CLI unavailable setup) when no devices are connected", async () => {
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

  it("renders State 2 (Companion offline prompt) when device exists but bridge is unreachable", async () => {
    vi.mocked(fetchDevices).mockResolvedValue([mockDevice]);
    vi.mocked(fetchCompanionStatus).mockResolvedValue(null);
    mount();

    expect(await screen.findByText("CLI connected")).toBeVisible();
    expect(screen.getByText("Local companion offline")).toBeVisible();
    expect(
      screen.getByText(/Start the local companion service on your machine/i),
    ).toBeVisible();
    expect(screen.getByText("mailent companion start")).toBeVisible();
    expect(
      screen.getByText(/Waiting for companion on 127.0.0.1:15488…/i),
    ).toBeVisible();
    expect(
      screen.getByText(/mailent analyze <capture\.pcap> --sync/),
    ).toBeVisible();
  });

  it("renders State 3 (Companion ready) with interactive dropzone", async () => {
    vi.mocked(fetchDevices).mockResolvedValue([mockDevice]);
    vi.mocked(fetchCompanionStatus).mockResolvedValue({
      status: "ready",
      version: "0.1.4",
      device_name: "test-laptop",
      device_id: "dev-1",
      server_url: "https://mailent.onrender.com",
      zeek_available: true,
    });

    mount();

    expect(
      await screen.findByText(/Companion ready \(v0\.1\.4\)/i),
    ).toBeVisible();
    expect(
      screen.getByText("Choose a capture file or drag and drop"),
    ).toBeVisible();
    expect(
      screen.getByText(/Supports \.pcap, \.pcapng, and \.cap/i),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Browse files" }),
    ).toBeVisible();
  });

  it("uploads capture to local companion bridge and navigates to the result assessment", async () => {
    vi.mocked(fetchDevices).mockResolvedValue([mockDevice]);
    vi.mocked(fetchCompanionStatus).mockResolvedValue({
      status: "ready",
      version: "0.1.4",
      device_name: "test-laptop",
      device_id: "dev-1",
      server_url: "https://mailent.onrender.com",
      zeek_available: true,
    });
    vi.mocked(analyzeCaptureOnCompanion).mockResolvedValue({
      status: "ok",
      assessment_id: "asmt-456",
      assessment: {} as any,
      findings_count: 2,
      sessions_count: 10,
      posture_score: 85,
      posture_grade: "B",
    });

    const onClose = vi.fn();
    const { user } = mount(true, onClose);

    await screen.findByText(/Companion ready/i);

    // Provide a file to the hidden file input
    const file = new File(["dummy pcap data"], "sample_traffic.pcap", {
      type: "application/vnd.tcpdump.pcap",
    });
    const hiddenInput = document.querySelector(
      'input[type="file"]',
    ) as HTMLInputElement;
    expect(hiddenInput).toBeInTheDocument();

    await user.upload(hiddenInput, file);

    // Selected file details must now be visible
    expect(screen.getByText("sample_traffic.pcap")).toBeVisible();
    expect(
      screen.getByPlaceholderText(/e\.g\. Inbound SMTP Security Review/i),
    ).toBeVisible();

    const analyzeBtn = screen.getByRole("button", {
      name: "Analyze capture",
    });
    await user.click(analyzeBtn);

    await waitFor(() => {
      expect(analyzeCaptureOnCompanion).toHaveBeenCalledWith(
        expect.objectContaining({ name: "sample_traffic.pcap" }),
        "",
      );
    });

    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
      expect(screen.getByText("Assessment Details Page")).toBeVisible();
    });
  });

  it("displays local analysis error if bridge returns failure", async () => {
    vi.mocked(fetchDevices).mockResolvedValue([mockDevice]);
    vi.mocked(fetchCompanionStatus).mockResolvedValue({
      status: "ready",
      version: "0.1.4",
      device_name: "test-laptop",
      device_id: "dev-1",
      server_url: "https://mailent.onrender.com",
      zeek_available: true,
    });
    vi.mocked(analyzeCaptureOnCompanion).mockRejectedValue(
      new Error("Zeek binary not found or timed out"),
    );

    const { user } = mount();

    await screen.findByText(/Companion ready/i);

    const file = new File(["dummy"], "test.pcap");
    const hiddenInput = document.querySelector(
      'input[type="file"]',
    ) as HTMLInputElement;
    await user.upload(hiddenInput, file);

    await user.click(screen.getByRole("button", { name: "Analyze capture" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Zeek binary not found or timed out",
    );
  });
});
