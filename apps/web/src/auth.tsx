import {
  createClient,
  type SupabaseClient,
  type User,
} from "@supabase/supabase-js";
import { useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  type ReactNode,
  useContext,
  useEffect,
  useState,
} from "react";
import { AuthPage } from "./AuthPage";
import { Button } from "./components/ui";

let client: SupabaseClient | null = null;
export async function authenticatedFetch(path: string, init?: RequestInit) {
  const headers = new Headers(init?.headers);
  if (client) {
    const { data, error } = await client.auth.getSession();
    if (error || !data.session)
      throw new Error("Your session has expired. Please sign in again.");
    headers.set("Authorization", `Bearer ${data.session.access_token}`);
  }
  const response = await fetch(path, { ...init, headers });
  if (response.status === 401 && client) {
    await client.auth.signOut({ scope: "local" });
    throw new Error("Your session has expired. Please sign in again.");
  }
  return response;
}
const AuthContext = createContext<{
  user: User | null;
  signOut?: () => Promise<void>;
}>({ user: null });
export const useAuth = () => useContext(AuthContext);

export function AuthGate({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [ready, setReady] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let alive = true;
    let unsubscribe: (() => void) | undefined;
    setError("");
    setReady(false);
    async function initialize() {
      const response = await fetch("/auth/config", {
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok)
        throw new Error("Cannot connect to Mailent. Please try again.");
      const config = await response.json();
      if (!alive) return;
      if (config.enabled) {
        client ??= createClient(config.url, config.publishable_key);
        const { data } = client.auth.onAuthStateChange((_event, session) => {
          if (alive) {
            setUser(session?.user ?? null);
            queryClient.clear();
          }
        });
        unsubscribe = () => data.subscription.unsubscribe();
        const { data: session, error: sessionError } =
          await client.auth.getSession();
        if (sessionError) throw sessionError;
        if (alive) setUser(session.session?.user ?? null);
      }
      if (alive) setReady(true);
    }
    void initialize().catch((e) => {
      if (alive)
        setError(e instanceof Error ? e.message : "Could not start Mailent.");
    });
    return () => {
      alive = false;
      unsubscribe?.();
    };
  }, [queryClient, retry]);
  const signOut = async () => {
    const result = await client?.auth.signOut();
    if (result?.error) {
      setError(result.error.message);
      return;
    }
    setUser(null);
    queryClient.clear();
  };
  if (error)
    return (
      <main className="sign-in-page">
        <section className="sign-in-card">
          <h1>Connection needed</h1>
          <p role="alert">{error}</p>
          <Button onClick={() => setRetry((v) => v + 1)}>Try again</Button>
        </section>
      </main>
    );
  if (!ready)
    return (
      <main className="sign-in-page">
        <p role="status">Connecting to your workspace…</p>
      </main>
    );
  if (client && !user) return <AuthPage client={client} />;
  return (
    <AuthContext.Provider
      value={{ user, signOut: client ? signOut : undefined }}
    >
      {children}
    </AuthContext.Provider>
  );
}
