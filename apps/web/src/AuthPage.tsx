import type { SupabaseClient } from "@supabase/supabase-js";
import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "./components/Icon";
import { Button } from "./components/ui";

export function AuthPage({ client }: { client: SupabaseClient }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
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
        <span className="eyebrow">PRIVATE WORKSPACE</span>
        <h1>{sent ? "Check your inbox" : "Welcome back"}</h1>
        <p>
          {sent
            ? `We sent a secure sign-in link to ${email}. Open it in this browser to continue.`
            : "Sign in to review your mail servers, captures, and security findings."}
        </p>
        {sent ? (
          <>
            <p className="secondary-text">
              Links expire after one hour. Check your spam folder if the message
              hasn’t arrived.
            </p>
            <Button variant="secondary" onClick={() => setSent(false)}>
              Use another email
            </Button>
          </>
        ) : (
          <form onSubmit={submit} className="sign-in-form">
            <label htmlFor="sign-in-email">Email address</label>
            <input
              id="sign-in-email"
              type="email"
              autoComplete="email"
              placeholder="Your workspace email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={busy}
            />
            <Button type="submit" disabled={busy}>
              {busy ? "Sending link…" : "Send sign-in link"}
            </Button>
            <p className="secondary-text">
              Access is limited to approved workspace members.
            </p>
          </form>
        )}
        {error && (
          <p role="alert" className="error-message">
            {error}
          </p>
        )}
      </section>
    </main>
  );
}
