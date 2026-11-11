"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { SkeletonRows, ErrorState } from "@/components/ui/states";

function CallbackInner() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { handleCallback } = useAuth();
  // Derived during render, not set in an effect: a missing ?code= is a
  // render-time fact, not an external-system sync.
  const code = searchParams.get("code");
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const started = useRef(false);

  useEffect(() => {
    if (!code) return;
    if (started.current) return;
    started.current = true;
    (async () => {
      try {
        await handleCallback(code);
        router.push("/dashboard");
      } catch (err) {
        setError(
          err instanceof ApiError
            ? err.message
            : "Verification failed. Please try again.",
        );
      }
    })();
  }, [code, handleCallback, router, attempt]);

  if (!code) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
        <Card className="w-full max-w-md">
          <h1 className="text-xl font-bold">Verification failed</h1>
          <div className="mt-4">
            <ErrorState
              message="No verification code was provided. Start from the email link again."
              onRetry={() => router.push("/login")}
            />
          </div>
        </Card>
      </main>
    );
  }

  if (error) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
        <Card className="w-full max-w-md">
          <h1 className="text-xl font-bold">Verification failed</h1>
          <div className="mt-4">
            <ErrorState
              message={error}
              onRetry={() => {
                started.current = false;
                setError("");
                setAttempt((n) => n + 1);
              }}
            />
          </div>
          <div className="mt-4 text-center">
            <Button variant="ghost" size="sm" onClick={() => router.push("/login")}>
              Back to log in
            </Button>
          </div>
        </Card>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <Card className="w-full max-w-md">
        <h1 className="text-xl font-bold">Verifying your account…</h1>
        <div className="mt-4">
          <SkeletonRows rows={2} />
        </div>
      </Card>
    </main>
  );
}

export default function AuthCallbackPage() {
  return (
    <Suspense
      fallback={
        <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
          <Card className="w-full max-w-md">
            <h1 className="text-xl font-bold">Verifying your account…</h1>
            <div className="mt-4">
              <SkeletonRows rows={2} />
            </div>
          </Card>
        </main>
      }
    >
      <CallbackInner />
    </Suspense>
  );
}
