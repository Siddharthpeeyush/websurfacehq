"use client";

/**
 * Staff MFA setup — the second step of staff onboarding.
 *
 * Arrived at from staff sign-in: when /login returns
 * `enroll_required`, the login page stores the AAL1 token (tab-scoped,
 * sessionStorage — never in the URL) and links here. This page then:
 *
 *   1. POST /staff/auth/mfa/enroll (AAL1 token in Authorization) →
 *      {qr_uri, secret, factor_id} — enrollment material, shown ONCE.
 *   2. The staff member adds the secret to their authenticator app
 *      and enters the 6-digit code.
 *   3. POST /staff/auth/mfa/confirm {factor_id, code} (AAL1 token in
 *      Authorization) → the staff session. Sign-in completes here.
 *
 * Design: same Kavora shell as the staff-login page
 * (~/workspace/websurfacehq-brand/kavora/staff-login.html) — canvas
 * #EBEBE8, surface #FFFFFF, ink #191919, dark #1B1B1B, coral #FF5C3D,
 * radii pills 99px / cards 28px. Urbanist is not bundled in this app,
 * so the stack falls back to the system sans, as on staff-login.
 *
 * QR CODE: the app has no QR-code library (nothing in package.json /
 * node_modules) and no dependency was added — the secret is shown
 * ONCE in a copyable field with a clear warning, plus manual-entry
 * steps. The secret must never be sent to a third-party QR service:
 * that would leak the TOTP seed. If a QR library is added later, the
 * `qr_uri` from the enroll response is what to render.
 *
 * The secret is held in component state only — it is never written
 * to storage, and leaving the page drops it. If it is lost, the
 * staff member signs in again: login returns `enroll_required` and
 * enroll issues a fresh factor.
 *
 * On success the signed-in state mirrors the staff-login success
 * state (same pattern; the staff panel does not exist yet, so there
 * is no redirect target to invent).
 */

import { useEffect, useRef, useState, type FormEvent } from "react";
import Link from "next/link";
import { ApiError } from "@/lib/api";
import {
  clearStaffAal1Token,
  clearStaffToken,
  getStaffAal1Token,
  setStaffToken,
  staffLogout,
  staffMfaConfirm,
  staffMfaEnroll,
  type StaffRole,
} from "@/lib/staff-api";

function roleLabel(role: StaffRole): string {
  if (role === "owner") return "Owner";
  if (role === "admin") return "Admin";
  return "Support Staff";
}

/** The AAL1 token has not been read from storage yet. */
type Aal1State = "checking" | "missing" | "present";

export default function StaffMfaSetupPage() {
  const [aal1State, setAal1State] = useState<Aal1State>("checking");
  const [aal1Token, setAal1Token] = useState<string | null>(null);
  const [factorId, setFactorId] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [enrolling, setEnrolling] = useState(false);
  const [enrollError, setEnrollError] = useState("");
  const [code, setCode] = useState("");
  const [confirmError, setConfirmError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [signedInEmail, setSignedInEmail] = useState<string | null>(null);
  const [signedInRole, setSignedInRole] = useState<StaffRole | null>(null);
  /** Enroll exactly once per mount — a second call would mint a second
   * factor and strand the secret already shown. */
  const enrollStartedRef = useRef(false);

  // Restore the AAL1 token once on mount and enroll exactly once:
  // state updates live inside the async boot function (the
  // `lib/auth.tsx` session-restore pattern), never synchronously in
  // the effect body.
  useEffect(() => {
    (async () => {
      const token = getStaffAal1Token();
      if (!token) {
        setAal1State("missing");
        return;
      }
      setAal1Token(token);
      setAal1State("present");
      if (enrollStartedRef.current) return;
      enrollStartedRef.current = true;
      setEnrolling(true);
      setEnrollError("");
      try {
        const res = await staffMfaEnroll(token);
        setFactorId(res.factor_id);
        setSecret(res.secret);
      } catch (err: unknown) {
        if (err instanceof ApiError && err.status === 401) {
          // AAL1 expired/invalid: the setup link is spent — sign in
          // again for a fresh one. Clear the dead token.
          clearStaffAal1Token();
          setAal1Token(null);
          setAal1State("missing");
        } else if (err instanceof ApiError && err.status === 409) {
          // Already enrolled (API code MFA_ALREADY_ENROLLED): the
          // account already has an authenticator, so there is nothing
          // to set up here. Points at sign-in (the code works there)
          // or at the Owner for a reset. Says nothing about any other
          // account — the caller is already authenticated as this one.
          setEnrollError(
            "MFA is already set up for this account — sign in with your authenticator, or ask the Owner to reset it.",
          );
        } else if (err instanceof ApiError && err.status === 429) {
          setEnrollError(
            err.retryAfter
              ? `Too many attempts. Try again in ${err.retryAfter} seconds.`
              : "Too many attempts. Please try again later.",
          );
        } else {
          setEnrollError("Something went wrong. Please try again.");
        }
      } finally {
        setEnrolling(false);
      }
    })();
  }, []);

  async function onConfirm(e: FormEvent) {
    e.preventDefault();
    if (!factorId || !aal1Token || submitting) return;
    setConfirmError("");
    if (!/^\d{6}$/.test(code.trim())) {
      setConfirmError("Enter the 6-digit code from your authenticator app.");
      return;
    }
    setSubmitting(true);
    try {
      const session = await staffMfaConfirm(
        factorId,
        code.trim(),
        aal1Token,
      );
      setStaffToken(session.access_token);
      clearStaffAal1Token();
      setAal1Token(null);
      setSignedInEmail(session.user?.email ?? null);
      setSignedInRole(session.user?.role ?? null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        // Wrong code (or a factor mismatch, which the server also
        // answers 401) — the enrollment material stays on screen so
        // the code can be re-entered against it.
        setConfirmError(
          "That code didn't work. Check your authenticator app and try again.",
        );
      } else if (err instanceof ApiError && err.status === 429) {
        setConfirmError(
          err.retryAfter
            ? `Too many attempts. Try again in ${err.retryAfter} seconds.`
            : "Too many attempts. Please try again later.",
        );
      } else {
        setConfirmError("Something went wrong. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function onCopySecret() {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
    } catch {
      // Clipboard unavailable (permissions / non-secure context):
      // the secret stays visible in the field to copy by hand.
      setCopied(false);
    }
  }

  async function onSignOut() {
    try {
      await staffLogout();
    } catch {
      // Revocation failed (network / server): the token is still
      // dropped locally; the server-side session expires on its own.
    } finally {
      clearStaffToken();
      clearStaffAal1Token();
      setSignedInEmail(null);
      setSignedInRole(null);
      setAal1Token(null);
      setAal1State("missing");
      setFactorId(null);
      setSecret(null);
      setCode("");
      setConfirmError("");
      setEnrollError("");
    }
  }

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
          Set up your authenticator
        </h1>
        <p className="mt-[5px] text-center text-sm text-[#64635F]">
          MFA is required for every staff sign-in.
        </p>

        <div className="mt-5 rounded-[28px] bg-white px-[22px] py-6">
          {signedInRole ? (
            <div role="status" className="py-2 text-center">
              <p className="text-lg font-extrabold">
                Signed in as {roleLabel(signedInRole)}
              </p>
              <p className="mt-2 text-sm leading-relaxed text-[#64635F]">
                {signedInEmail ? (
                  <>
                    Authenticator set up for{" "}
                    <span className="font-bold text-[#191919]">
                      {signedInEmail}
                    </span>
                    .{" "}
                  </>
                ) : null}
                Your staff session is active. The staff panel opens here
                once it lands (Weeks 3–4) — for now this page only proves
                the sign-in works.
              </p>
              <button
                type="button"
                onClick={onSignOut}
                className="mt-5 w-full rounded-[99px] bg-[#1B1B1B] px-4 py-[15px] text-[15px] font-extrabold text-[#FBFAF8] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
              >
                Sign out
              </button>
            </div>
          ) : aal1State === "checking" ? (
            <p role="status" className="py-2 text-center text-sm text-[#64635F]">
              Loading…
            </p>
          ) : aal1State === "missing" ? (
            <div className="py-2 text-center">
              <p className="text-[15px] font-bold leading-relaxed">
                Sign in first to set up your authenticator.
              </p>
              <p className="mt-2 text-sm leading-relaxed text-[#64635F]">
                Open this page from staff sign-in, after entering your
                email and password — your sign-in hands you the setup
                link. If you have not set your password yet, use the
                setup link in your invite email.
              </p>
              <Link
                href="staff-login"
                className="mt-5 block w-full rounded-[99px] bg-[#1B1B1B] px-4 py-[15px] text-center text-[15px] font-extrabold text-[#FBFAF8] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
              >
                Go to staff sign-in →
              </Link>
            </div>
          ) : enrolling ? (
            <p role="status" className="py-2 text-center text-sm text-[#64635F]">
              Preparing your authenticator setup…
            </p>
          ) : enrollError ? (
            <div className="py-2 text-center">
              <p role="alert" className="text-[15px] font-bold leading-relaxed">
                {enrollError}
              </p>
              <Link
                href="staff-login"
                className="mt-5 block w-full rounded-[99px] bg-[#1B1B1B] px-4 py-[15px] text-center text-[15px] font-extrabold text-[#FBFAF8] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
              >
                Go to staff sign-in →
              </Link>
            </div>
          ) : (
            <form onSubmit={onConfirm} noValidate>
              <p className="rounded-[14px] bg-[#F3F3F1] px-[14px] py-3 text-[13px] leading-relaxed">
                <b>Your secret is shown once only.</b> Add it to your
                authenticator app now — it will never be shown again.
                If you lose it, sign in again to start setup over.
              </p>
              <div className="mt-4">
                <label
                  htmlFor="mfa-secret"
                  className="mb-[7px] block text-[11.5px] font-extrabold tracking-[0.07em] text-[#64635F]"
                >
                  YOUR SECRET KEY · SHOWN ONCE
                </label>
                <div className="flex gap-2">
                  <input
                    id="mfa-secret"
                    type="text"
                    readOnly
                    value={secret ?? ""}
                    autoComplete="off"
                    onFocus={(e) => e.target.select()}
                    className="min-w-0 flex-1 rounded-[14px] border-[1.5px] border-[#E7E5E0] bg-[#F3F3F1] px-[15px] py-[13px] font-mono text-[14px] text-[#191919] outline-none focus:border-[#191919] focus:bg-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
                  />
                  <button
                    type="button"
                    onClick={onCopySecret}
                    className="flex-none rounded-[99px] bg-[#1B1B1B] px-4 py-[13px] text-[14px] font-extrabold text-[#FBFAF8] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
                  >
                    {copied ? "Copied ✓" : "Copy"}
                  </button>
                </div>
              </div>
              <ol className="mt-4 list-decimal space-y-1 pl-5 text-[13px] leading-relaxed text-[#64635F]">
                <li>
                  Open your authenticator app (Google Authenticator,
                  Authy, 1Password, or similar).
                </li>
                <li>Add an account — choose manual / setup-key entry.</li>
                <li>
                  Paste the secret above. Account name: WebSurfaceHQ
                  staff. A QR scan is not available on this page yet —
                  enter the secret manually.
                </li>
              </ol>
              <div className="mt-4">
                <label
                  htmlFor="mfa-code"
                  className="mb-[7px] block text-[11.5px] font-extrabold tracking-[0.07em] text-[#64635F]"
                >
                  6-DIGIT CODE FROM YOUR AUTHENTICATOR APP
                </label>
                <input
                  id="mfa-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(e) =>
                    setCode(e.target.value.replace(/[^0-9]/g, ""))
                  }
                  placeholder="6 digits"
                  maxLength={6}
                  required
                  className="w-full rounded-[14px] border-[1.5px] border-[#E7E5E0] bg-[#F3F3F1] px-[15px] py-[13px] text-[15px] text-[#191919] outline-none placeholder:text-[#64635F] focus:border-[#191919] focus:bg-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
                />
              </div>
              {confirmError && (
                <p role="alert" className="mt-4 text-sm font-bold text-[#B2421B]">
                  {confirmError}
                </p>
              )}
              <button
                type="submit"
                disabled={submitting || !factorId}
                className="mt-[22px] block w-full rounded-[99px] bg-[#1B1B1B] px-4 py-[15px] text-[15px] font-extrabold text-[#FBFAF8] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919] disabled:cursor-default disabled:opacity-40"
              >
                {submitting ? "Verifying…" : "Verify & sign in →"}
              </button>
            </form>
          )}
        </div>

        <p className="mt-5 text-center text-[13px] leading-relaxed text-[#64635F]">
          <b className="text-[#353431]">Keep your secret private.</b>{" "}
          Anyone with it can generate your codes — never share it or
          paste it anywhere except your own authenticator app.
        </p>
        <p className="mt-[22px] text-center text-xs text-[#64635F]">
          WebSurfaceHQ staff setup · This page is not indexed and is not
          linked from the customer site.
        </p>
      </div>
    </main>
  );
}
