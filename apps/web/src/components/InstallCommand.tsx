import { Check, Copy, Terminal } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "./ui";

export const INSTALL_COMMAND =
  "curl -fsSL https://mailent.onrender.com/install.sh | bash";
export const INSTALL_COMMAND_WINDOWS =
  "irm https://mailent.onrender.com/install.ps1 | iex";
export const CLI_RELEASE_URL =
  "https://github.com/the-minecrafters/mailent/releases/latest";

export function InstallCommand() {
  const [platform, setPlatform] = useState<"linux" | "windows">("linux");
  const [status, setStatus] = useState<"idle" | "copied" | "error">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    if (
      typeof window !== "undefined" &&
      navigator.userAgent.toLowerCase().includes("win")
    ) {
      setPlatform("windows");
    }
  }, []);

  useEffect(() => () => clearTimeout(timer.current), []);

  const activeCommand =
    platform === "windows" ? INSTALL_COMMAND_WINDOWS : INSTALL_COMMAND;

  async function copy() {
    clearTimeout(timer.current);
    try {
      await navigator.clipboard.writeText(activeCommand);
      setStatus("copied");
      timer.current = setTimeout(() => setStatus("idle"), 2500);
    } catch {
      setStatus("error");
    }
  }
  return (
    <div className="install-command-group">
      <div style={{ display: "flex", gap: "8px", marginBottom: "8px" }}>
        <button
          type="button"
          onClick={() => setPlatform("linux")}
          className={platform === "linux" ? "badge badge-neutral" : "badge badge-outline"}
          style={{ cursor: "pointer", fontSize: "12px", padding: "4px 10px", borderRadius: "14px" }}
        >
          Linux / macOS
        </button>
        <button
          type="button"
          onClick={() => setPlatform("windows")}
          className={platform === "windows" ? "badge badge-neutral" : "badge badge-outline"}
          style={{ cursor: "pointer", fontSize: "12px", padding: "4px 10px", borderRadius: "14px" }}
        >
          Windows (PowerShell)
        </button>
      </div>
      <div className="install-command">
        <Terminal size={20} aria-hidden="true" />
        <code>{activeCommand}</code>
        <Button onClick={copy} aria-label="Copy install command">
          {status === "copied" ? <Check size={18} /> : <Copy size={18} />}
          {status === "copied" ? "Copied" : "Copy"}
        </Button>
      </div>
      <p className="install-copy-status" role="status">
        {status === "error"
          ? "Could not copy. Select the command above to copy it manually."
          : status === "copied"
            ? "Install command copied."
            : ""}
      </p>
    </div>
  );
}
