"use client";

/**
 * Staff invite accept — the first step of staff onboarding.
 *
 * A new staff member arrives here from the one-time setup link the
 * Owner sent (single-use, 72h expiry). The page reads `?token=` from
 * the URL, asks for a password + confirmation, and calls
 * POST /staff/auth/invite/accept {token, password}.
 *
 * Design: same Kavora shell as the staff-login page
 * (~/workspace/websurfacehq-brand/kavora/staff-login.html) — canvas
 * #EBEBE8, surface #FFFFFF, ink #191919, dark #1B1B1B, coral #FF5C3D,
 * radii pills 99px / cards 28px. Urbanist is not bundled in this app,
 * so the stack falls back to the system sans, as on staff-login.
 *
 * Password validation is the same client-side rule as the customer
 * signup page: at least 8 characters, confirmation must match.
 *
 * NO ENUMERATION: an expired, used, or invalid token is
 * indistinguishable — every failure shows the SAME generic message
 * below, never which case it was. The server answers the same 404
 * for all three; this page does not reinterpret it.
 *
 * NO INVITE LOOKUP: there is no API to fetch an invite's email/role
 * before accepting, so the invited email + role are shown on the
 * SUCCESS state, from the accept response — not on the form.
 *
 * On success the account exists but MFA is not enrolled yet, and
 * invite-accept returns NO AAL1 token — enrollment starts at the
 * first sign-in, when /login returns `enroll_required` + the AAL1
 * token and routes on to /staff-mfa-setup. So success points at
 * staff sign-in, not straight at MFA setup.
 *
 * `useSearchParams` needs a Suspense boundary (Next prerenders this
 * page statically), so the form lives in its own component below.
 */

import { Suspense, useState, type FormEvent } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ApiError } from "@/lib/api";
import { staffInviteAccept, type StaffRole } from "@/lib/staff-api";

/** Shown for ANY accept failure — expired, used, or invalid token. */
const GENERIC_INVITE_ERROR =
  "This setup link is invalid or has expired. Ask the Owner for a new invite.";

function roleLabel(role: StaffRole): string {
  if (role === "owner") return "Owner";
  if (role === "admin") return "Admin";
  return "Support Staff";
}

function InviteForm() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [createdEmail, setCreatedEmail] = useState<string | null>(null);
  const [createdRole, setCreatedRole] = useState<StaffRole | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setFormError("");
    const next: Record<string, string> = {};
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
      const res = await staffInviteAccept(token, password);
      setCreatedEmail(res.user.email);
      setCreatedRole(res.user.role);
    } catch (err) {
      if (err instanceof ApiError && err.code === "RATE_LIMITED") {
        // Rate limit only (API code RATE_LIMITED) — says nothing about
        // the token or whether any account exists.
        setFormError("Too many attempts — try again shortly.");
      } else if (err instanceof ApiError) {
        // Every other API failure — expired/used/invalid token,
        // server error — shows the one generic message. Token states
        // must stay indistinguishable.
        setFormError(GENERIC_INVITE_ERROR);
      } else {
        setFormError("Something went wrong. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (!token) {
    return (
      <div role="alert" className="py-2 text-center">
        <p className="text-[15px] font-bold leading-relaxed">
          {GENERIC_INVITE_ERROR}
        </p>
        <p className="mt-2 text-sm leading-relaxed text-[#64635F]">
          Setup links come in the invite email from the Owner. If you
          already set your password, sign in instead.
        </p>
        <Link
          href="staff-login"
          className="mt-5 block w-full rounded-[99px] bg-[#1B1B1B] px-4 py-[15px] text-center text-[15px] font-extrabold text-[#FBFAF8] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
        >
          Go to staff sign-in →
        </Link>
      </div>
    );
  }

  if (createdEmail && createdRole) {
    return (
      <div role="status" className="py-2 text-center">
        <p className="text-lg font-extrabold">
          Account created — now set up your authenticator
        </p>
        <p className="mt-2 text-sm leading-relaxed text-[#64635F]">
          Account created for{" "}
          <span className="font-bold text-[#191919]">{createdEmail}</span>{" "}
          as {roleLabel(createdRole)}. Sign in with your new password —
          you will be asked to set up your authenticator app next.
        </p>
        <Link
          href="staff-login"
          className="mt-5 block w-full rounded-[99px] bg-[#1B1B1B] px-4 py-[15px] text-center text-[15px] font-extrabold text-[#FBFAF8] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
        >
          Continue to staff sign-in →
        </Link>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} noValidate>
      <div>
        <label
          htmlFor="invite-password"
          className="mb-[7px] block text-[11.5px] font-extrabold tracking-[0.07em] text-[#64635F]"
        >
          CHOOSE A PASSWORD
        </label>
        <input
          id="invite-password"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••••"
          required
          aria-describedby={errors.password ? "invite-password-error" : undefined}
          className="w-full rounded-[14px] border-[1.5px] border-[#E7E5E0] bg-[#F3F3F1] px-[15px] py-[13px] text-[15px] text-[#191919] outline-none placeholder:text-[#64635F] focus:border-[#191919] focus:bg-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
        />
        {errors.password ? (
          <p
            id="invite-password-error"
            role="alert"
            className="mt-2 text-[13px] font-bold text-[#B2421B]"
          >
            {errors.password}
          </p>
        ) : (
          <p className="mt-2 text-[13px] text-[#64635F]">
            At least 8 characters.
          </p>
        )}
      </div>
      <div className="mt-4">
        <label
          htmlFor="invite-confirm"
          className="mb-[7px] block text-[11.5px] font-extrabold tracking-[0.07em] text-[#64635F]"
        >
          CONFIRM PASSWORD
        </label>
        <input
          id="invite-confirm"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          placeholder="••••••••••"
          required
          aria-describedby={errors.confirm ? "invite-confirm-error" : undefined}
          className="w-full rounded-[14px] border-[1.5px] border-[#E7E5E0] bg-[#F3F3F1] px-[15px] py-[13px] text-[15px] text-[#191919] outline-none placeholder:text-[#64635F] focus:border-[#191919] focus:bg-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
        />
        {errors.confirm && (
          <p
            id="invite-confirm-error"
            role="alert"
            className="mt-2 text-[13px] font-bold text-[#B2421B]"
          >
            {errors.confirm}
          </p>
        )}
      </div>
      {formError && (
        <p role="alert" className="mt-4 text-sm font-bold text-[#B2421B]">
          {formError}
        </p>
      )}
      <button
        type="submit"
        disabled={submitting}
        className="mt-[22px] block w-full rounded-[99px] bg-[#1B1B1B] px-4 py-[15px] text-[15px] font-extrabold text-[#FBFAF8] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919] disabled:cursor-default disabled:opacity-40"
      >
        {submitting ? "Creating account…" : "Create account →"}
      </button>
    </form>
  );
}

export default function StaffInvitePage() {
  return (
    <main className="flex min-h-screen justify-center bg-[#EBEBE8] px-4 py-9 text-[#191919]">
      <div className="w-full max-w-[460px] min-w-0">
        <div className="text-center">
          <span className="text-2xl font-extrabold tracking-[-0.02em]">
            websurface<span className="text-[#FF5C3D]">hq</span>
          </span>
          <span className="ml-2 inline-block rounded-[99px] bg-[#1B1B1B] px-[11px] py-1 align-[3px] text-[11px] font-extrabold tracking-[0.08em] text-[#FBFAF8]">
            STAFF
          </span>
        </div>
        <h1 className="mt-[18px] text-center text-[27px] font-extrabold tracking-[-0.02em]">
          Set up your staff account
        </h1>
        <p className="mt-[5px] text-center text-sm text-[#64635F]">
          Choose your password to finish your invite.
        </p>

        <div className="mt-5 rounded-[28px] bg-white px-[22px] py-6">
          <Suspense
            fallback={
              <p role="status" className="py-2 text-center text-sm text-[#64635F]">
                Loading…
              </p>
            }
          >
            <InviteForm />
          </Suspense>
        </div>

        <p className="mt-5 text-center text-[13px] leading-relaxed text-[#64635F]">
          <b className="text-[#353431]">One-time link.</b> Your invite
          link works once and expires after 72 hours — after that, ask
          the Owner for a new one.
        </p>
        <p className="mt-[22px] text-center text-xs text-[#64635F]">
          WebSurfaceHQ staff setup · This page is not indexed and is not
          linked from the customer site.
        </p>
      </div>
    </main>
  );
}
