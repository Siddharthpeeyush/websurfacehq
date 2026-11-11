"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card } from "@/components/ui/Card";

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    setSubmitting(true);
    try {
      await login(email, password);
      router.push("/dashboard");
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429) {
          setFormError(
            err.retryAfter
              ? `Too many login attempts. Try again in ${err.retryAfter} seconds.`
              : "Too many login attempts. Please try again later.",
          );
        } else {
          // Show the API's own message (keyed by its stable code, never a
          // stack trace — the API only ever sends a safe one-liner).
          setFormError(err.message);
        }
      } else {
        setFormError("Something went wrong. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-8">
      <Card className="w-full max-w-md">
        <h1 className="text-xl font-bold">Log in</h1>
        <p className="mt-1 text-sm text-slate-400">
          Welcome back to WebSurfaceHQ.
        </p>
        <form onSubmit={onSubmit} noValidate className="mt-6 flex flex-col gap-4">
          <Input
            id="email"
            label="Email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
          />
          <Input
            id="password"
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {formError && (
            <p role="alert" className="text-sm text-[var(--danger)]">
              {formError}
            </p>
          )}
          <Button type="submit" loading={submitting} className="w-full">
            Log in
          </Button>
        </form>
        <p className="mt-4 text-center text-sm text-slate-400">
          <Link href="/reset" className="text-[var(--brand)] hover:underline">
            Forgot your password?
          </Link>
        </p>
        <p className="mt-2 text-center text-sm text-slate-400">
          No account yet?{" "}
          <Link href="/signup" className="text-[var(--brand)] hover:underline">
            Sign up
          </Link>
        </p>
      </Card>
    </main>
  );
}
