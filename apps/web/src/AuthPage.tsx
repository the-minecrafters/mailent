import type { SupabaseClient } from "@supabase/supabase-js";
import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "./components/Icon";
import { Button } from "./components/ui";

export function AuthPage({
  client,
  allowSkip = true,
  onSkip,
}: {
  client: SupabaseClient;
  allowSkip?: boolean;
  onSkip?: () => void;
}) {
  const [mode, setMode] = useState<"password" | "otp">("password");
  const [email, setEmail] = useState("seadeepie@gmail.com");
  const [password, setPassword] = useState("Mailent2026!");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  async function handlePasswordSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const { error } = await client.auth.signInWithPassword({
        email: email.trim(),
        password,
      });
      if (error) throw error;
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Could not sign in with email. Check your credentials.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleOtpSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const { error } = await client.auth.signInWithOtp({
        email: email.trim(),
        options: {
          shouldCreateUser: false,
          emailRedirectTo: `${window.location.origin}/workspace/overview`,
        },
      });
      if (error) throw error;
      setSent(true);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Could not send a sign-in link. Try again.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="sign-in-page">
      <section className="sign-in-card">
        <div className="sign-in-brand">
          <span className="brand-mark">
            <Icon name="mail" size={24} />
          </span>
          <Link to="/">mailent</Link>
        </div>

        <span className="eyebrow">WORKSPACE ACCESS</span>
        <h1>{sent ? "Check your inbox" : "Sign in to workspace"}</h1>
        <p className="secondary-text">
          {sent
            ? `A secure sign-in link was sent to ${email}. Open it to continue.`
            : "Sign in with your workspace credentials to persist captures and forensic reports."}
        </p>

        {sent ? (
          <div style={{ marginTop: "1.5rem" }}>
            <p className="secondary-text" style={{ marginBottom: "1rem" }}>
              Links expire in one hour.
            </p>
            <Button variant="secondary" onClick={() => setSent(false)}>
              Back to password sign-in
            </Button>
          </div>
        ) : mode === "password" ? (
          <form onSubmit={handlePasswordSubmit} className="sign-in-form">
            <div className="form-group">
              <label htmlFor="sign-in-email">Email address</label>
              <input
                id="sign-in-email"
                type="email"
                autoComplete="email"
                placeholder="seadeepie@gmail.com"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={busy}
              />
            </div>

            <div className="form-group">
              <label htmlFor="sign-in-password">Password</label>
              <input
                id="sign-in-password"
                type="password"
                autoComplete="current-password"
                placeholder="Enter password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={busy}
              />
            </div>

            <Button type="submit" disabled={busy} style={{ width: "100%", marginTop: "0.5rem" }}>
              {busy ? "Signing in…" : "Sign in (Persistent Storage)"}
            </Button>

            <div style={{ marginTop: "0.75rem", display: "flex", justifyContent: "space-between", fontSize: "0.8125rem" }}>
              <button
                type="button"
                className="btn-link"
                style={{ background: "none", border: "none", color: "var(--ink-secondary)", cursor: "pointer", textDecoration: "underline", padding: 0 }}
                onClick={() => { setMode("otp"); setError(""); }}
              >
                Sign in with magic link
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleOtpSubmit} className="sign-in-form">
            <div className="form-group">
              <label htmlFor="sign-in-email">Email address</label>
              <input
                id="sign-in-email"
                type="email"
                autoComplete="email"
                placeholder="seadeepie@gmail.com"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={busy}
              />
            </div>

            <Button type="submit" disabled={busy} style={{ width: "100%", marginTop: "0.5rem" }}>
              {busy ? "Sending magic link…" : "Send sign-in link"}
            </Button>

            <div style={{ marginTop: "0.75rem", textAlign: "center", fontSize: "0.8125rem" }}>
              <button
                type="button"
                className="btn-link"
                style={{ background: "none", border: "none", color: "var(--ink-secondary)", cursor: "pointer", textDecoration: "underline", padding: 0 }}
                onClick={() => { setMode("password"); setError(""); }}
              >
                Back to password sign-in
              </button>
            </div>
          </form>
        )}

        {error && (
          <p role="alert" className="error-message" style={{ marginTop: "1rem" }}>
            {error}
          </p>
        )}

        {allowSkip && onSkip && (
          <div
            style={{
              marginTop: "2rem",
              paddingTop: "1.5rem",
              borderTop: "1px solid var(--hairline)",
              textAlign: "center",
            }}
          >
            <Button
              variant="secondary"
              onClick={onSkip}
              style={{ width: "100%", justifyContent: "center" }}
            >
              Skip sign in (use without persistence)
            </Button>
            <p
              className="secondary-text"
              style={{ marginTop: "0.5rem", fontSize: "0.75rem", lineHeight: 1.4 }}
            >
              Inspect sessions, evaluate rules, and analyze captures in-memory.
              Evidence is not persisted to PostgreSQL.
            </p>
          </div>
        )}
      </section>
    </main>
  );
}
