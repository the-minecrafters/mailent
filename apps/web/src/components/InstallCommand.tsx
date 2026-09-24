import { Check, Copy, Terminal } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "./ui";

export const INSTALL_COMMAND =
  "curl -fsSL https://mailent.onrender.com/install.sh | bash";
export const CLI_RELEASE_URL =
  "https://github.com/the-minecrafters/mailent/releases/latest";

export function InstallCommand() {
  const [status, setStatus] = useState<"idle" | "copied" | "error">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  async function copy() {
    clearTimeout(timer.current);
    try {
      await navigator.clipboard.writeText(INSTALL_COMMAND);
      setStatus("copied");
      timer.current = setTimeout(() => setStatus("idle"), 2500);
    } catch {
      setStatus("error");
    }
  }
  return (
    <div className="install-command-group">
      <div className="install-command">
        <Terminal size={20} aria-hidden="true" />
        <code>{INSTALL_COMMAND}</code>
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
