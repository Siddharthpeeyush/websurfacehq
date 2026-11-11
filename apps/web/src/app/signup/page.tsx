"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { ApiError, fieldErrors } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card } from "@/components/ui/Card";

export default function SignupPage() {
  const router = useRouter();
  const { signup } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    const next: Record<string, string> = {};
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      next.email = "Enter a valid email address.";
    }
    if (password.length < 8) {
      next.password = "Password must be at least 8 characters.";
    }
    if (confirm !== password) {
      next.confirm = "Passwords do not match.";
    }
    setErrors(next);
    if (Object.keys(next).length > 0) return;

    setSubmitting(true);
    try {
      await signup(email, password);
      setDone(true);
    } catch (err) {
      if (err instanceof ApiError) {
        // 422 VALIDATION_ERROR carries per-field errors (Pydantic list
        // shape, parsed by fieldErrors in src/lib/api.ts).
        const fields = fieldErrors(err.details);
        if (Object.keys(fields).length > 0) {
          setErrors(fields);
        } else if (err.status === 429) {
          setFormError(
            err.retryAfter
              ? `Too many sign-up attempts. Try again in ${err.retryAfter} seconds.`
              : "Too many sign-up attempts. Please try again later.",
          );
        } else {
          setFormError(err.message);
        }
      } else {
        setFormError("Something went wrong. Please try again.");
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
            We sent a verification link to{" "}
            <span className="font-medium text-slate-100">{email}</span>.
            Click it to verify your account, then log in.
          </p>
          <div className="mt-6">
            <Button
              variant="secondary"
              onClick={() => router.push("/login")}
              className="w-full"
            >
              Go to log in
            </Button>
          </div>
        </Card>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-8">
      <Card className="w-full max-w-md">
        <h1 className="text-xl font-bold">Create your account</h1>
        <p className="mt-1 text-sm text-slate-400">
          Free plan: 1 domain, 3 scans a month.
        </p>
        <form onSubmit={onSubmit} noValidate className="mt-6 flex flex-col gap-4">
          <Input
            id="email"
            label="Email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            error={errors.email}
            placeholder="you@example.com"
          />
          <Input
            id="password"
            label="Password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={errors.password}
            hint="At least 8 characters."
          />
          <Input
            id="confirm"
            label="Confirm password"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            error={errors.confirm}
          />
          {formError && (
            <p role="alert" className="text-sm text-[var(--danger)]">
              {formError}
            </p>
          )}
          <Button type="submit" loading={submitting} className="w-full">
            Sign up
          </Button>
        </form>
        <p className="mt-4 text-center text-sm text-slate-400">
          Already have an account?{" "}
          <Link href="/login" className="text-[var(--brand)] hover:underline">
            Log in
          </Link>
        </p>
      </Card>
    </main>
  );
}
