import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useRef, useState } from "react";
import { type AssessmentRecord, analyzeCapture } from "./api";
import { Icon } from "./components/Icon";
import { Button, ErrorState } from "./components/ui";

interface NewAssessmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (assessment: AssessmentRecord) => void;
}

export function NewAssessmentModal({
  isOpen,
  onClose,
  onCreated,
}: NewAssessmentModalProps) {
  const [title, setTitle] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [base64, setBase64] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [seconds, setSeconds] = useState(0);
  const [dragging, setDragging] = useState(false);
  const readerRef = useRef<FileReader | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  useEffect(
    () => () => {
      readerRef.current?.abort();
    },
    [],
  );
  useEffect(() => {
    if (!analyzing) return;
    const timer = window.setInterval(() => setSeconds((s) => s + 1), 1000);
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    window.addEventListener("beforeunload", warn);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("beforeunload", warn);
    };
  }, [analyzing]);
  const select = (next: File) => {
    readerRef.current?.abort();
    setFile(null);
    setBase64(null);
    setError(null);
    setReading(false);
    if (!/\.(pcap|pcapng|cap)$/i.test(next.name)) {
      setError("Choose a PCAP, PCAPNG or CAP file.");
      return;
    }
    if (!next.size) {
      setError(
        "This file is empty. Choose a capture containing network traffic.",
      );
      return;
    }
    if (next.size > 50 * 1024 * 1024) {
      setError(
        "This file exceeds the 50 MB limit. Export a smaller capture and try again.",
      );
      return;
    }
    setFile(next);
    setReading(true);
    const reader = new FileReader();
    readerRef.current = reader;
    reader.onload = () => {
      if (readerRef.current !== reader) return;
      setBase64(String(reader.result).split(",")[1]);
      setReading(false);
    };
    reader.onerror = () => {
      if (readerRef.current !== reader) return;
      setError("Could not read this file. Please choose it again.");
      setFile(null);
      setReading(false);
    };
    reader.readAsDataURL(next);
  };
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!file || !base64 || analyzing) return;
    setError(null);
    setSeconds(0);
    setAnalyzing(true);
    try {
      const assessment = await analyzeCapture({
        pcap_base64: base64,
        file_name: file.name,
        title: title.trim() || undefined,
      });
      onCreated(assessment);
      onClose();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Analysis failed. Please try again.",
      );
    } finally {
      setAnalyzing(false);
    }
  };
  return (
    <Dialog.Root
      open={isOpen}
      onOpenChange={(open) => {
        if (!open && !analyzing) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content
          className="capture-dialog"
          onEscapeKeyDown={(e) => {
            if (analyzing) e.preventDefault();
          }}
          onInteractOutside={(e) => {
            if (analyzing) e.preventDefault();
          }}
        >
          <div className="dialog-heading">
            <span className="dialog-icon">
              <Icon name="upload_file" size={24} />
            </span>
            <Dialog.Close
              className="icon-button"
              disabled={analyzing}
              aria-label="Close upload"
            >
              <Icon name="close" />
            </Dialog.Close>
          </div>
          <Dialog.Title>Analyze a capture</Dialog.Title>
          <Dialog.Description>
            Upload a network recording to check email connections, encryption
            and certificates.
          </Dialog.Description>
          {analyzing ? (
            <div className="analysis-progress" role="status">
              <Icon name="refresh" size={32} className="spin" />
              <h3>Analyzing your capture</h3>
              <p>
                Checking connections and gathering evidence. Keep this window
                open until analysis finishes.
              </p>
              <span>{seconds}s elapsed</span>
            </div>
          ) : (
            <form onSubmit={submit}>
              <div className="form-group">
                <label htmlFor="capture-title">
                  Title <span className="secondary-text">(optional)</span>
                </label>
                <input
                  id="capture-title"
                  maxLength={160}
                  placeholder="Use the filename, or add a title"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                />
              </div>
              <div
                className={`upload-dropzone ${dragging ? "dragging" : ""} ${file ? "has-file" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragging(false);
                  const next = e.dataTransfer.files[0];
                  if (next) select(next);
                }}
              >
                <input
                  ref={fileRef}
                  className="sr-only"
                  id="pcap-file-input"
                  aria-label="Capture file"
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  onChange={(e) => {
                    const next = e.target.files?.[0];
                    if (next) select(next);
                    e.target.value = "";
                  }}
                />
                <Icon name={file ? "description" : "upload_file"} size={30} />
                <strong>{file ? file.name : "Drop your capture here"}</strong>
                <p>
                  {file
                    ? `${(file.size / 1024).toFixed(1)} KB · ${reading ? "Reading file…" : "Ready to analyze"}`
                    : "PCAP, PCAPNG or CAP · Up to 50 MB"}
                </p>
                <Button onClick={() => fileRef.current?.click()}>
                  {file ? "Choose another file" : "Choose file"}
                </Button>
              </div>
              {error && (
                <ErrorState
                  title="Cannot analyze this capture"
                  description={error}
                />
              )}
              <div className="dialog-footer">
                <Button onClick={onClose}>Cancel</Button>
                <Button
                  type="submit"
                  variant="primary"
                  disabled={!base64 || reading}
                >
                  <Icon name="shield" size={17} />
                  Analyze capture
                </Button>
              </div>
            </form>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
