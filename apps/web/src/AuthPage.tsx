import type { SupabaseClient } from "@supabase/supabase-js";
import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { MailentLogo } from "./components/MailentLogo";
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
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
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
      <section className="sign-in-card" aria-labelledby="sign-in-title">
        <Link to="/" className="sign-in-brand" aria-label="Mailent home">
          <MailentLogo size={40} />
          <span>mailent</span>
        </Link>
        <h1 id="sign-in-title">
          {sent ? "Check your inbox" : "Welcome to Mailent"}
        </h1>
        <p className="sign-in-description">
          {sent
            ? `We sent a sign-in link to ${email}. Open it to continue.`
            : "Sign in to access your workspace."}
        </p>
        {sent ? (
          <div className="sign-in-sent">
            <p>Links expire in one hour.</p>
            <Button
              onClick={() => {
                setSent(false);
                setMode("password");
              }}
            >
              Back to sign in
            </Button>
          </div>
        ) : (
          <form
            onSubmit={
              mode === "password" ? handlePasswordSubmit : handleOtpSubmit
            }
            className="sign-in-form"
            autoComplete="off"
            data-form-type="other"
          >
            <div className="form-group">
              <label htmlFor="sign-in-email">Email address</label>
              <input
                id="sign-in-email"
                type="email"
                name="email"
                autoComplete="off"
                data-1p-ignore="true"
                data-lpignore="true"
                placeholder="you@company.com"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={busy}
              />
            </div>
            {mode === "password" && (
              <div className="form-group">
                <label htmlFor="sign-in-password">Password</label>
                <input
                  id="sign-in-password"
                  type="password"
                  name="password"
                  autoComplete="new-password"
                  data-1p-ignore="true"
                  data-lpignore="true"
                  placeholder="Enter your password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={busy}
                />
              </div>
            )}
            {error && (
              <p role="alert" className="error-message">
                {error}
              </p>
            )}
            <Button variant="primary" type="submit" disabled={busy}>
              {busy
                ? mode === "password"
                  ? "Signing in…"
                  : "Sending link…"
                : mode === "password"
                  ? "Sign in"
                  : "Send sign-in link"}
            </Button>
            <button
              type="button"
              className="auth-text-button"
              disabled={busy}
              onClick={() => {
                setMode(mode === "password" ? "otp" : "password");
                setError("");
              }}
            >
              {mode === "password"
                ? "Email me a sign-in link"
                : "Sign in with a password"}
            </button>
          </form>
        )}
        {allowSkip && onSkip && (
          <div className="sign-in-guest">
            <Button onClick={onSkip} disabled={busy}>
              Continue as guest
            </Button>
            <p>Guest results are temporary.</p>
          </div>
        )}
        <Link to="/privacy" className="sign-in-privacy">
          Privacy
        </Link>
      </section>
    </main>
  );
}
