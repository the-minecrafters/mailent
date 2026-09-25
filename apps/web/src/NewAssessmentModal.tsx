import * as Dialog from "@radix-ui/react-dialog";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type DragEvent, type ChangeEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  analyzeCaptureOnCompanion,
  fetchCompanionStatus,
  fetchDevices,
} from "./api";
import { useAuth } from "./auth";
import { Icon } from "./components/Icon";
import { InstallCommand } from "./components/InstallCommand";
import { Button, ErrorState, LoadingState } from "./components/ui";

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function NewAssessmentModal({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const { user, openSignIn } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const installations = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
    enabled: !!user && isOpen,
    refetchInterval: user && isOpen ? 10000 : false,
  });

  const connected = (installations.data ?? []).some(
    (installation) => !installation.revoked_at,
  );

  const companionQuery = useQuery({
    queryKey: ["companion-status"],
    queryFn: () => fetchCompanionStatus(),
    enabled: !!user && connected && isOpen,
    refetchInterval: (query) =>
      !query.state.data || query.state.data.status !== "ready" ? 2500 : 15000,
  });

  const isCompanionReady =
    companionQuery.data?.status === "ready" &&
    companionQuery.data?.zeek_available;

  function handleFileSelected(selectedFile: File) {
    const validExtensions = [".pcap", ".pcapng", ".cap"];
    const ext = selectedFile.name.toLowerCase();
    const isValid = validExtensions.some((e) => ext.endsWith(e));
    if (!isValid) {
      setAnalysisError(
        "Please select a valid packet capture file (.pcap, .pcapng, or .cap).",
      );
      return;
    }
    setFile(selectedFile);
    setAnalysisError(null);
  }

  function handleDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  }

  function handleInputChange(e: ChangeEvent<HTMLInputElement>) {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  }

  async function handleAnalyze() {
    if (!file) return;
    setAnalyzing(true);
    setAnalysisError(null);
    try {
      const outcome = await analyzeCaptureOnCompanion(file, title.trim());
      await queryClient.invalidateQueries({ queryKey: ["assessments"] });
      onClose();
      navigate(`/workspace/captures/${outcome.assessment_id}`);
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Failed to analyze capture on local companion.";
      setAnalysisError(message);
    } finally {
      setAnalyzing(false);
    }
  }

  function copyCompanionCommand() {
    navigator.clipboard.writeText("mailent companion start").then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <Dialog.Root
      open={isOpen}
      onOpenChange={(open) => {
        if (!open) {
          setFile(null);
          setTitle("");
          setAnalysisError(null);
          onClose();
        }
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
              marginBottom: "0.5rem",
            }}
          >
            <Dialog.Title style={{ margin: 0 }}>Analyze captures</Dialog.Title>
            <Dialog.Close asChild>
              <Button aria-label="Close dialog">Close</Button>
            </Dialog.Close>
          </div>
          <Dialog.Description>
            Mailent CLI runs the analysis locally. Mailent Workspace brings the results together.
          </Dialog.Description>

          {!user ? (
            <div className="cli-workflow-content" style={{ marginTop: "1rem" }}>
              <p>
                Sign in to connect Mailent CLI and keep your results in this
                workspace.
              </p>
              <Button variant="primary" onClick={openSignIn}>
                Sign in
              </Button>
            </div>
          ) : installations.isPending ? (
            <div style={{ padding: "2rem 0" }}>
              <LoadingState label="Checking Mailent installations…" />
            </div>
          ) : installations.isError ? (
            <div style={{ marginTop: "1rem" }}>
              <ErrorState
                title="Could not check your installations"
                description="Try again before starting a new analysis."
                onRetry={() => void installations.refetch()}
              />
            </div>
          ) : !connected ? (
            <div className="cli-workflow-content" style={{ marginTop: "1rem" }}>
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
          ) : !isCompanionReady ? (
            <div className="cli-workflow-content" style={{ marginTop: "1rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
                <span className="badge fresh">CLI connected</span>
                <span className="badge" style={{ background: "var(--hairline)", color: "var(--ink-secondary)" }}>
                  Local companion offline
                </span>
              </div>
              <p style={{ margin: "0.5rem 0" }}>
                Start the local companion service on your machine to analyze captures directly from this workspace:
              </p>
              <div style={{ position: "relative" }}>
                <pre className="device-login-command" style={{ margin: "0.75rem 0" }}>
                  <code>mailent companion start</code>
                </pre>
                <Button
                  variant="secondary"
                  onClick={copyCompanionCommand}
                  style={{
                    position: "absolute",
                    right: "8px",
                    top: "50%",
                    transform: "translateY(-50%)",
                    padding: "0.3rem 0.6rem",
                    fontSize: "0.8rem",
                  }}
                >
                  <Icon name={copied ? "check_circle" : "copy"} size={14} />
                  <span>{copied ? "Copied" : "Copy"}</span>
                </Button>
              </div>
              <p className="secondary-text" style={{ margin: "0.25rem 0 0.5rem", fontSize: "0.82rem" }}>
                Runs as a background service. Use <code>mailent companion run</code> for foreground debugging.
              </p>
              <div
                className="secondary-text"
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "0.5rem",
                  marginTop: "0.5rem",
                  padding: "0.5rem 0.75rem",
                  background: "var(--surface-alt)",
                  borderRadius: "6px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <Icon name="refresh" className="spin" size={14} />
                  <span>Waiting for companion on 127.0.0.1:15488…</span>
                </div>
                <Button
                  variant="secondary"
                  onClick={() => void companionQuery.refetch()}
                  style={{ padding: "0.2rem 0.5rem", fontSize: "0.75rem" }}
                >
                  Check now
                </Button>
              </div>
              <div
                style={{
                  marginTop: "1.5rem",
                  paddingTop: "1rem",
                  borderTop: "1px solid var(--hairline)",
                }}
              >
                <p className="secondary-text" style={{ margin: 0, fontSize: "0.85rem" }}>
                  Terminal alternative: <code>mailent analyze &lt;capture.pcap&gt; --sync</code>
                </p>
              </div>
            </div>
          ) : (
            <div style={{ marginTop: "1rem" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: "1rem",
                }}
              >
                <span className="badge fresh" style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                  <span
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      backgroundColor: "currentColor",
                    }}
                  />
                  Companion ready (v{companionQuery.data?.version})
                </span>
                <span className="secondary-text" style={{ fontSize: "0.85rem" }}>
                  {companionQuery.data?.device_name || "Local machine"}
                </span>
              </div>

              {analyzing ? (
                <div className="analysis-progress" role="status">
                  <Icon name="refresh" className="spin" size={32} />
                  <h3 style={{ margin: "1rem 0 0.5rem" }}>Analyzing capture locally…</h3>
                  <p style={{ margin: 0 }}>
                    Running Zeek passive forensics and generating security findings.
                  </p>
                  <span className="secondary-text" style={{ display: "block", marginTop: "0.5rem" }}>
                    Raw capture remains on your machine; only structured assessments sync.
                  </span>
                </div>
              ) : (
                <>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pcap,.pcapng,.cap"
                    style={{ display: "none" }}
                    onChange={handleInputChange}
                  />

                  {!file ? (
                    <div
                      className={`upload-dropzone ${isDragging ? "dragging" : ""}`}
                      onDragOver={(e) => {
                        e.preventDefault();
                        setIsDragging(true);
                      }}
                      onDragLeave={() => setIsDragging(false)}
                      onDrop={handleDrop}
                      onClick={() => fileInputRef.current?.click()}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          fileInputRef.current?.click();
                        }
                      }}
                      style={{ cursor: "pointer", minHeight: "160px" }}
                    >
                      <Icon name="upload_file" size={36} />
                      <strong>Choose a capture file or drag and drop</strong>
                      <p>Supports .pcap, .pcapng, and .cap</p>
                      <Button variant="secondary" style={{ marginTop: "0.25rem" }}>
                        Browse files
                      </Button>
                    </div>
                  ) : (
                    <div
                      style={{
                        border: "1px solid var(--hairline)",
                        borderRadius: "8px",
                        padding: "1rem",
                        background: "var(--surface-alt)",
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
                        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", minWidth: 0 }}>
                          <Icon name="description" size={24} />
                          <div style={{ minWidth: 0 }}>
                            <strong
                              style={{
                                display: "block",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {file.name}
                            </strong>
                            <span className="secondary-text" style={{ fontSize: "0.85rem" }}>
                              {formatFileSize(file.size)}
                            </span>
                          </div>
                        </div>
                        <Button
                          variant="secondary"
                          onClick={() => {
                            setFile(null);
                            if (fileInputRef.current) fileInputRef.current.value = "";
                          }}
                          style={{ padding: "0.3rem 0.6rem", fontSize: "0.8rem" }}
                        >
                          Change file
                        </Button>
                      </div>

                      <div style={{ marginTop: "1rem" }}>
                        <label className="form-label" style={{ display: "block", marginBottom: "0.25rem" }}>
                          Assessment title (optional)
                        </label>
                        <input
                          type="text"
                          className="text-input"
                          value={title}
                          onChange={(e) => setTitle(e.target.value)}
                          placeholder="e.g. Inbound SMTP Security Review"
                          style={{ width: "100%" }}
                        />
                      </div>

                      <Button
                        variant="primary"
                        onClick={handleAnalyze}
                        style={{ width: "100%", marginTop: "1rem" }}
                      >
                        Analyze capture
                      </Button>
                    </div>
                  )}

                  {analysisError && (
                    <div style={{ marginTop: "1rem" }}>
                      <ErrorState
                        title="Local analysis failed"
                        description={analysisError}
                        onRetry={() => setAnalysisError(null)}
                      />
                    </div>
                  )}

                  <div
                    style={{
                      marginTop: "1.5rem",
                      paddingTop: "1rem",
                      borderTop: "1px solid var(--hairline)",
                    }}
                  >
                    <p className="secondary-text" style={{ margin: 0, fontSize: "0.85rem" }}>
                      Terminal alternative: <code>mailent analyze &lt;capture.pcap&gt; --sync</code>
                    </p>
                  </div>
                </>
              )}
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
