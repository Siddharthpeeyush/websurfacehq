/**
 * AuthContext — session state for the WebSurfaceHQ frontend.
 *
 * Token storage trade-off (MVP): the access token is kept in localStorage
 * (key `wshq_access_token`, see src/lib/api.ts) and mirrored in memory,
 * because the frontend and the API live on different origins with no shared
 * cookie domain, so an httpOnly cookie cannot be shared yet. CSP + no inline
 * scripts mitigate XSS; the token is never put in a URL or a log line.
 * When frontend + API share a domain, switch to an httpOnly cookie here and
 * in api.ts and delete the localStorage path.
 */
"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useRouter } from "next/navigation";
import {
  authCallback,
  clearToken,
  fetchMe,
  getToken,
  login as apiLogin,
  logout as apiLogout,
  requestPasswordReset,
  setToken,
  setUnauthorizedHandler,
  signup as apiSignup,
  type User,
} from "./api";

interface AuthContextValue {
  user: User | null;
  /** True while the initial session restore is running. */
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  resetPassword: (email: string) => Promise<void>;
  handleCallback: (code: string) => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // A 401 from any authenticated request clears the session and routes
  // here — the API client itself never navigates.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      router.push("/login");
    });
    return () => setUnauthorizedHandler(null);
  }, [router]);

  const refreshUser = useCallback(async () => {
    const me = await fetchMe();
    setUser(me);
  }, []);

  // Restore the session once on mount: token present -> verify via /auth/me.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!getToken()) {
        setLoading(false);
        return;
      }
      try {
        const me = await fetchMe();
        if (!cancelled) setUser(me);
      } catch {
        // Invalid/expired token: apiRequest already cleared it on 401.
        if (!cancelled) setUser(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const tokens = await apiLogin(email, password);
    setToken(tokens.access_token);
    setUser(tokens.user);
  }, []);

  const signup = useCallback(async (email: string, password: string) => {
    await apiSignup(email, password);
    // No session is created here: the user must verify their email first
    // (see /signup — it shows the "check your email" state).
  }, []);

  const logout = useCallback(async () => {
    // M2 review fix: log out server-side too — clearing localStorage
    // alone leaves the JWT valid until expiry. The local token is
    // cleared regardless of the result (a failed revocation must not
    // leave the user apparently signed in).
    try {
      await apiLogout();
    } catch {
      // Revocation failed (network / server): the token is still dropped
      // locally; the server-side session expires on its own.
    } finally {
      clearToken();
      setUser(null);
    }
  }, []);

  const resetPassword = useCallback(async (email: string) => {
    await requestPasswordReset(email);
  }, []);

  const handleCallback = useCallback(async (code: string) => {
    const tokens = await authCallback(code);
    setToken(tokens.access_token);
    setUser(tokens.user);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      login,
      signup,
      logout,
      resetPassword,
      handleCallback,
      refreshUser,
    }),
    [user, loading, login, signup, logout, resetPassword, handleCallback, refreshUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside <AuthProvider>");
  }
  return ctx;
}
