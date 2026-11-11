"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card } from "@/components/ui/Card";

/**
 * Password reset request. The API always returns 200 (no enumeration), so
 * this page ALWAYS shows the same success message — whether or not the
 * email has an account.
 */
export default function ResetPage() {
  const { resetPassword } = useAuth();
  const [email, setEmail] = useState("");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    setSubmitting(true);
    try {
      await resetPassword(email);
      setDone(true);
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setFormError(
          err.retryAfter
            ? `Too many reset requests. Try again in ${err.retryAfter} seconds.`
            : "Too many reset requests. Please try again later.",
        );
      } else {
        // Any other failure is a transport problem, not "no such account":
        // still show the same neutral message so nothing is enumerated.
        setDone(true);
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (done) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
        <Card className="w-full max-w-md text-center">
          <h1 className="text-xl font-bold">Check your email</h1>
          <p className="mt-3 text-sm text-slate-300">
            If an account exists for that email, a password-reset link is on
            its way. The link expires soon — request a new one if it lapses.
          </p>
          <p className="mt-4 text-sm text-slate-400">
            <Link href="/login" className="text-[var(--brand)] hover:underline">
              Back to log in
            </Link>
          </p>
        </Card>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-8">
      <Card className="w-full max-w-md">
        <h1 className="text-xl font-bold">Reset your password</h1>
        <p className="mt-1 text-sm text-slate-400">
          Enter the email you signed up with.
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
          {formError && (
            <p role="alert" className="text-sm text-[var(--danger)]">
              {formError}
            </p>
          )}
          <Button type="submit" loading={submitting} className="w-full">
            Send reset link
          </Button>
        </form>
        <p className="mt-4 text-center text-sm text-slate-400">
          <Link href="/login" className="text-[var(--brand)] hover:underline">
            Back to log in
          </Link>
        </p>
      </Card>
    </main>
  );
}
