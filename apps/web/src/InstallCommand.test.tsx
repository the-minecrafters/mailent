import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { INSTALL_COMMAND, InstallCommand } from "./components/InstallCommand";

describe("CLI install command", () => {
  it("copies the actual website installer command and confirms it", async () => {
    const user = userEvent.setup();
    const write = vi
      .spyOn(navigator.clipboard, "writeText")
      .mockResolvedValue();
    render(<InstallCommand />);
    await user.click(
      screen.getByRole("button", { name: "Copy install command" }),
    );
    expect(write).toHaveBeenCalledWith(INSTALL_COMMAND);
    expect(screen.getByRole("status")).toHaveTextContent(
      "Install command copied.",
    );
    write.mockRestore();
  });
  it("keeps the command readable when clipboard permission is unavailable", async () => {
    const user = userEvent.setup();
    const write = vi
      .spyOn(navigator.clipboard, "writeText")
      .mockRejectedValue(new Error("denied"));
    render(<InstallCommand />);
    await user.click(
      screen.getByRole("button", { name: "Copy install command" }),
    );
    expect(screen.getByRole("status")).toHaveTextContent("Could not copy.");
    expect(screen.getByText(INSTALL_COMMAND)).toBeVisible();
    write.mockRestore();
  });
  it("switches between Linux and Windows install commands via the platform selector", async () => {
    const user = userEvent.setup();
    const write = vi
      .spyOn(navigator.clipboard, "writeText")
      .mockResolvedValue();
    render(<InstallCommand />);
    expect(screen.getByText(INSTALL_COMMAND)).toBeVisible();
    const winTab = screen.getByRole("tab", { name: /Windows/i });
    await user.click(winTab);
    expect(screen.getByRole("button", { name: "Copy install command" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Copy install command" }));
    expect(write).toHaveBeenCalledWith(expect.stringContaining("install.ps1"));
    const linuxTab = screen.getByRole("tab", { name: /Linux/i });
    await user.click(linuxTab);
    await user.click(screen.getByRole("button", { name: "Copy install command" }));
    expect(write).toHaveBeenCalledWith(INSTALL_COMMAND);
    write.mockRestore();
  });
});
