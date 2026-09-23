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
    const { data } = await client.auth.getSession();
    if (data.session?.access_token) {
      headers.set("Authorization", `Bearer ${data.session.access_token}`);
    } else {
      // Guest mode: bypass persistent storage
      headers.set("X-Mailent-Guest", "true");
    }
  } else {
    headers.set("X-Mailent-Guest", "true");
  }

  const response = await fetch(path, { ...init, headers });
  if (response.status === 401 && client) {
    const { data } = await client.auth.getSession();
    if (data.session) {
      await client.auth.signOut({ scope: "local" });
      throw new Error("Your session has expired. Please sign in again.");
    }
  }
  return response;
}

const AuthContext = createContext<{
  user: User | null;
  isGuest: boolean;
  signOut?: () => Promise<void>;
  enableGuest?: () => void;
  openSignIn?: () => void;
}>({ user: null, isGuest: false });

export const useAuth = () => useContext(AuthContext);

export function AuthGate({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [ready, setReady] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [isGuest, setIsGuest] = useState<boolean>(() => {
    return sessionStorage.getItem("mailent_guest_mode") === "true";
  });
  const [showSignInModal, setShowSignInModal] = useState(false);
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
            if (session?.user) {
              sessionStorage.removeItem("mailent_guest_mode");
              setIsGuest(false);
              setShowSignInModal(false);
            }
            queryClient.clear();
          }
        });
        unsubscribe = () => data.subscription.unsubscribe();
        const { data: session, error: sessionError } =
          await client.auth.getSession();
        if (sessionError) throw sessionError;
        if (alive) {
          setUser(session.session?.user ?? null);
          if (session.session?.user) {
            sessionStorage.removeItem("mailent_guest_mode");
            setIsGuest(false);
          }
        }
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
    sessionStorage.removeItem("mailent_guest_mode");
    setIsGuest(false);
    const result = await client?.auth.signOut();
    if (result?.error) {
      setError(result.error.message);
      return;
    }
    setUser(null);
    queryClient.clear();
  };

  const handleSkip = () => {
    sessionStorage.setItem("mailent_guest_mode", "true");
    setIsGuest(true);
    setShowSignInModal(false);
  };

  const openSignIn = () => {
    setShowSignInModal(true);
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
        <p role="status">Connecting to workspace…</p>
      </main>
    );

  // If user is not signed in and has not chosen guest mode, or explicitly clicked "Sign in":
  if (client && !user && (!isGuest || showSignInModal)) {
    return (
      <AuthPage
        client={client}
        allowSkip={!user}
        onSkip={handleSkip}
      />
    );
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isGuest: !user && (isGuest || !client),
        signOut: client ? signOut : undefined,
        enableGuest: handleSkip,
        openSignIn,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
