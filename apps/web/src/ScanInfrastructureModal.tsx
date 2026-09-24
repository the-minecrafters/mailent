import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useState } from "react";
import { type AssessmentRecord, scanInfrastructure } from "./api";
import { Icon } from "./components/Icon";
import { Button, ErrorState } from "./components/ui";

interface ScanInfrastructureModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (assessment: AssessmentRecord) => void;
}

export function ScanInfrastructureModal({
  isOpen,
  onClose,
  onCreated,
}: ScanInfrastructureModalProps) {
  const [domain, setDomain] = useState("");
  const [scanning, setScanning] = useState(false);
  const [seconds, setSeconds] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanning) return;
    const timer = window.setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => window.clearInterval(timer);
  }, [scanning]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const target = domain.trim().toLowerCase();
    if (!target) {
      setError("Please enter a domain name to scan.");
      return;
    }

    setError(null);
    setScanning(true);
    setSeconds(0);

    try {
      const result = await scanInfrastructure(target);
      onCreated(result.assessment);
      onClose();
    } catch (err: any) {
      setError(
        err?.message ||
          "Infrastructure scan failed. Check the domain and try again.",
      );
    } finally {
      setScanning(false);
    }
  };

  return (
    <Dialog.Root
      open={isOpen}
      onOpenChange={(open) => !open && !scanning && onClose()}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content className="modal-content">
          <div className="modal-header">
            <div className="modal-header-content">
              <Dialog.Title className="modal-title">
                <Icon name="search" size={20} />
                <span>Check a domain</span>
              </Dialog.Title>
              <Dialog.Description className="modal-description">
                Find mail servers and check their encryption, certificates, and email security settings.
              </Dialog.Description>
            </div>
            <Dialog.Close asChild disabled={scanning}>
              <button
                className="icon-button modal-close"
                aria-label="Close dialog"
              >
                <Icon name="close" />
              </button>
            </Dialog.Close>
          </div>

          <form onSubmit={handleScan} className="modal-body">
            {error && <ErrorState title="Scan failed" description={error} />}

            <div
              style={{
                background: "var(--status-warning-bg)",
                border: "1px solid var(--status-warning-border)",
                borderRadius: "6px",
                padding: "0.75rem 1rem",
                marginBottom: "1rem",
                fontSize: "0.875rem",
                lineHeight: 1.45,
                color: "var(--status-warning-ink)",
              }}
            >
              <strong>Some connections may be unavailable</strong>
              <p style={{ margin: "0.25rem 0 0 0" }}>
                This hosted workspace cannot connect on port 25. Those results will be marked unavailable. Upload a capture to review traffic from those servers.
              </p>
            </div>

            <div className="form-group" style={{ marginBottom: "1rem" }}>
              <label htmlFor="scan-domain-input" className="form-label">
                Domain
              </label>
              <input
                id="scan-domain-input"
                type="text"
                className="input text-input"
                placeholder="company.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={scanning}
                autoFocus
                required
              />
              <span
                className="secondary-text"
                style={{
                  fontSize: "0.875rem",
                  marginTop: "0.35rem",
                  display: "block",
                }}
              >
                Use a domain you own or have permission to check.
              </span>
            </div>

            <div
              style={{
                background: "var(--canvas-sunken)",
                border: "1px solid var(--border)",
                borderRadius: "6px",
                padding: "0.85rem 1rem",
                marginBottom: "1.25rem",
                fontSize: "0.875rem",
                lineHeight: 1.5,
              }}
            >
              <strong style={{ display: "block", marginBottom: "0.25rem" }}>
                Included in this check
              </strong>
              <ul style={{ margin: 0, paddingLeft: "1.2rem" }}>
                <li>Mail server records and DNS security</li>
                <li>
                  SMTP STARTTLS (port 25 &amp; 587) and IMAP/POP3 (port 993,
                  143, 995)
                </li>
                <li>
                  Certificate names, expiry, and trust
                </li>
                <li>
                  MTA-STS, TLS reporting, and DANE policies
                </li>
              </ul>
            </div>

            <div
              className="modal-actions"
              style={{
                display: "flex",
                justifyContent: "flex-end",
                gap: "0.5rem",
              }}
            >
              <Button
                variant="secondary"
                type="button"
                onClick={onClose}
                disabled={scanning}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                type="submit"
                disabled={scanning || !domain.trim()}
              >
                {scanning ? (
                  <>
                    <Icon name="refresh" className="spin" size={16} />
                    <span>Checking ({seconds}s)…</span>
                  </>
                ) : (
                  <>
                    <Icon name="search" size={16} />
                    <span>Run check</span>
                  </>
                )}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
