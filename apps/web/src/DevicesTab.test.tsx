import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DevicesTab } from "./DevicesTab";
import { fetchCurrentOrganization, fetchDevices, revokeDevice } from "./api";

const auth = vi.hoisted(() => ({
  user: null as object | null,
  openSignIn: vi.fn(),
}));
vi.mock("./auth", () => ({ useAuth: () => auth, authenticatedFetch: vi.fn() }));
vi.mock("./api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./api")>()),
  fetchCurrentOrganization: vi.fn(),
  fetchDevices: vi.fn(),
  revokeDevice: vi.fn(),
}));

const installation = {
  id: "installation-id",
  organization_id: "org-id",
  name: "Mailent CLI",
  hostname: "workstation",
  platform: "linux",
  architecture: "x86_64",
  created_at: "2026-09-25T10:00:00Z",
  last_seen_at: "2026-09-25T10:00:00Z",
  capabilities: [],
  remote_online: false,
  agent_enabled: true,
  agent_status: "idle",
  completed_jobs_count: 3,
};

function mount() {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter
        initialEntries={["/workspace/installations?code=MLT-TEST1234"]}
      >
        <DevicesTab />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  auth.user = { id: "user" };
  vi.mocked(fetchCurrentOrganization).mockResolvedValue({
    id: "org-id",
    name: "Workspace",
    slug: "workspace",
    created_at: "2026-09-25T10:00:00Z",
  });
  vi.mocked(fetchDevices).mockResolvedValue([installation]);
});

describe("Mailent installations", () => {
  it("gates guest connections before making account requests and preserves the connection code", async () => {
    auth.user = null;
    mount();
    expect(screen.getByText(/Your connection code is saved/)).toBeVisible();
    expect(
      screen.queryByRole("textbox", { name: "Connection code" }),
    ).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(auth.openSignIn).toHaveBeenCalledOnce();
    expect(fetchDevices).not.toHaveBeenCalled();
    expect(fetchCurrentOrganization).not.toHaveBeenCalled();
  });

  it("does not treat legacy agent activity or login time as readiness or a sync", async () => {
    mount();
    expect(await screen.findByText("Not checked yet")).toBeVisible();
    expect(screen.getByText("No sync recorded")).toBeVisible();
    expect(
      screen.queryByText("Ready", { exact: true }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/jobs completed/)).not.toBeInTheDocument();
    expect(
      screen.getByRole("textbox", { name: "Connection code" }),
    ).toHaveValue("MLT-TEST1234");
  });

  it("shows reported versions, readiness and sync time, and retains revoke access", async () => {
    vi.mocked(fetchDevices).mockResolvedValue([
      {
        ...installation,
        version: "0.1.4",
        zeek_version: "8.0.4",
        readiness: "ready",
        last_sync_at: "2026-09-25T11:00:00Z",
      },
    ]);
    vi.stubGlobal(
      "confirm",
      vi.fn(() => true),
    );
    mount();
    const row = (await screen.findByText("workstation")).closest("tr")!;
    expect(within(row).getByText("Ready")).toBeVisible();
    expect(within(row).getByText("0.1.4")).toBeVisible();
    expect(within(row).getByText("8.0.4")).toBeVisible();
    expect(row.querySelector("time")).toHaveAttribute(
      "datetime",
      "2026-09-25T11:00:00Z",
    );
    await userEvent.click(
      within(row).getByRole("button", { name: "Revoke access" }),
    );
    expect(revokeDevice).toHaveBeenCalledWith(
      "installation-id",
      expect.anything(),
    );
  });
});
