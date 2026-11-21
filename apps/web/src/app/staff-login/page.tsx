"use client";

/**
 * Staff sign-in — role-first, sign-in only (no self-registration).
 *
 * Design: ~/workspace/websurfacehq-brand/kavora/staff-login.html (approved
 * 15 Nov 2026) + DESIGN-LOCK.md "Staff login design" — three selectable
 * role cards above email + password + authenticator-code fields, no role
 * pre-selected, the Sign in button names the chosen role. Kavora tokens:
 * canvas #EBEBE8, surface #FFFFFF, ink #191919, dark #1B1B1B,
 * coral #FF5C3D, radii pills 99px / cards 28px. Urbanist is not bundled
 * in this app, so the stack falls back to the system sans — the tokens,
 * layout, and wording are copied from the approved design.
 *
 * Flow (real contract, Child C — staff_auth.py):
 *   1. POST /staff/auth/login {role, email, password} → always
 *      {mfa_required: true, enroll_required, supabase_access_token}
 *      (the AAL1 token). NO staff session exists before MFA verifies.
 *   2. Enrolled account → POST /staff/auth/mfa/verify {code} only
 *      (the challenge is created server-side), AAL1 token in the
 *      Authorization header. The code field is shown from the start,
 *      as in the design; if the user already typed a code it is
 *      verified immediately, otherwise they are asked for it.
 *      Unenrolled account (enroll_required) → MFA setup is not
 *      complete; the page says so (not an error) and does not
 *      attempt a verify.
 *   3. The staff panel does not exist yet (Weeks 3–4), so a successful
 *      sign-in shows an inline "signed in" state instead of navigating
 *      to a page that isn't built.
 *
 * NO ENUMERATION: every 401 — wrong password, wrong role, unknown email,
 * suspended account — shows the same fixed generic string below, never
 * the API's message, so the page cannot leak which check failed.
 */

import { useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import Link from "next/link";
import { ApiError } from "@/lib/api";
import {
  clearStaffAal1Token,
  clearStaffToken,
  setStaffAal1Token,
  setStaffToken,
  staffForgotPassword,
  staffLogin,
  staffLogout,
  staffMfaVerify,
  type StaffRole,
} from "@/lib/staff-api";

/** Shown for ANY 401, whatever the server's message says. */
const GENERIC_CREDENTIALS_ERROR =
  "Email, password, or role is incorrect. Please try again.";

const ROLES: { value: StaffRole; label: string; blurb: string }[] = [
  { value: "owner", label: "Owner", blurb: "Full control · Founder screen" },
  {
    value: "admin",
    label: "Admin",
    blurb: "Users, scans, billing, disputes",
  },
  {
    value: "support",
    label: "Support Staff",
    blurb: "Tickets & abuse reports only",
  },
];

function roleLabel(role: StaffRole): string {
  return ROLES.find((r) => r.value === role)?.label ?? role;
}

export default function StaffLoginPage() {
  const [role, setRole] = useState<StaffRole | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");
  const [formHint, setFormHint] = useState("");
  /** True when the hint must link on to authenticator setup (login
   * returned `enroll_required` and the AAL1 token is stored). */
  const [mfaSetupLink, setMfaSetupLink] = useState(false);
  const [forgotSent, setForgotSent] = useState(false);
  /** The AAL1 token from login — presented at /mfa/verify. Set once
   * login succeeds for an enrolled account; null otherwise. */
  const [aal1Token, setAal1Token] = useState<string | null>(null);
  const [signedInRole, setSignedInRole] = useState<StaffRole | null>(null);
  const codeInputRef = useRef<HTMLInputElement>(null);

  /** Arrow keys move between role cards, as a native radiogroup would. */
  function onRoleKeyDown(e: KeyboardEvent<HTMLButtonElement>) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const current = role ? ROLES.findIndex((r) => r.value === role) : -1;
    const next =
      e.key === "ArrowDown"
        ? (current + 1) % ROLES.length
        : (current - 1 + ROLES.length) % ROLES.length;
    const nextRole = ROLES[next];
    if (!nextRole) return;
    setRole(nextRole.value);
    setFormError("");
  }

  function pickRole(next: StaffRole) {
    setRole(next);
    setFormError("");
    setFormHint("");
    setMfaSetupLink(false);
  }

  function showError(err: unknown) {
    if (err instanceof ApiError) {
      if (err.status === 401) {
        setFormError(GENERIC_CREDENTIALS_ERROR);
      } else if (err.status === 429) {
        setFormError(
          err.retryAfter
            ? `Too many sign-in attempts. Try again in ${err.retryAfter} seconds.`
            : "Too many sign-in attempts. Please try again later.",
        );
      } else {
        setFormError("Something went wrong. Please try again.");
      }
    } else {
      setFormError("Something went wrong. Please try again.");
    }
  }

  async function verifyMfa(totpCode: string, aal1: string) {
    const session = await staffMfaVerify(totpCode, aal1);
    setStaffToken(session.access_token);
    clearStaffAal1Token();
    setSignedInRole(role);
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!role || submitting) return;
    setFormError("");
    setFormHint("");
    setMfaSetupLink(false);
    setForgotSent(false);
    setSubmitting(true);
    try {
      // Step 2 continuation: we already have the AAL1 token, only the
      // code was missing — verify it now.
      if (aal1Token) {
        if (!code.trim()) {
          setFormHint("Enter the 6-digit code from your authenticator app.");
          codeInputRef.current?.focus();
          return;
        }
        await verifyMfa(code.trim(), aal1Token);
        return;
      }

      const res = await staffLogin(role, email.trim(), password);
      if (res.enroll_required) {
        // MFA setup is not complete — not an error, and no verify is
        // attempted. The AAL1 token is stored (tab-scoped) so the
        // setup screen can call /mfa/enroll with it, and the hint
        // links on to authenticator setup — the next step of the
        // invite flow. (The invite token itself is already consumed:
        // accepting the invite is what created this account, so
        // linking back to invite-accept would only show the generic
        // expired-link error — a new dead end.)
        if (!res.supabase_access_token) {
          setFormError("Something went wrong. Please try again.");
          return;
        }
        setStaffAal1Token(res.supabase_access_token);
        setFormHint("MFA setup not complete —");
        setMfaSetupLink(true);
        return;
      }
      if (res.mfa_required) {
        if (!res.supabase_access_token) {
          setFormError("Something went wrong. Please try again.");
          return;
        }
        setAal1Token(res.supabase_access_token);
        if (code.trim()) {
          // Code already typed (the field is shown from the start, as in
          // the design) — verify it immediately.
          await verifyMfa(code.trim(), res.supabase_access_token);
        } else {
          setFormHint("Enter the 6-digit code from your authenticator app.");
          codeInputRef.current?.focus();
        }
        return;
      }
      setFormError("Something went wrong. Please try again.");
    } catch (err) {
      // A failed MFA verify must not drop the AAL1 token: the user
      // re-enters the code against it, so keep it. Any other failure
      // clears it so the next submit starts clean.
      if (!(err instanceof ApiError && aal1Token && err.status === 401)) {
        setAal1Token(null);
      }
      showError(err);
    } finally {
      setSubmitting(false);
    }
  }

  async function onForgotPassword() {
    setFormError("");
    setFormHint("");
    if (!email.trim()) {
      setFormError("Enter your email above, then choose Forgot password.");
      return;
    }
    // Always shows the same confirmation — the server always answers 200,
    // so this message reveals nothing about whether the email exists.
    try {
      await staffForgotPassword(email.trim());
    } catch {
      // Recovery must never leak whether the account exists.
    }
    setForgotSent(true);
  }

  async function onSignOut() {
    try {
      await staffLogout();
    } catch {
      // Revocation failed (network / server): the token is still dropped
      // locally; the server-side session expires on its own.
    } finally {
      clearStaffToken();
      clearStaffAal1Token();
      setSignedInRole(null);
      setAal1Token(null);
      setRole(null);
      setPassword("");
      setCode("");
      setFormError("");
      setFormHint("");
      setMfaSetupLink(false);
      setForgotSent(false);
    }
  }

  const buttonLabel = submitting
    ? "Signing in…"
    : role
      ? `Sign in as ${roleLabel(role)} →`
      : "Choose your role";

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
          Staff sign-in
        </h1>
        <p className="mt-[5px] text-center text-sm text-[#64635F]">
          Choose your role, then sign in.
        </p>

        <div className="mt-5 rounded-[28px] bg-white px-[22px] py-6">
          {signedInRole ? (
            <div role="status" className="py-2 text-center">
              <p className="text-lg font-extrabold">
                Signed in as {roleLabel(signedInRole)}
              </p>
              <p className="mt-2 text-sm leading-relaxed text-[#64635F]">
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
          ) : (
            <>
              <p
                id="role-label"
                className="text-[11.5px] font-extrabold tracking-[0.07em] text-[#64635F]"
              >
                I AM SIGNING IN AS…
              </p>
              <div
                role="radiogroup"
                aria-labelledby="role-label"
                className="mt-[10px] flex flex-col gap-2"
              >
                {ROLES.map((r) => {
                  const selected = role === r.value;
                  return (
                    <button
                      key={r.value}
                      type="button"
                      role="radio"
                      aria-checked={selected}
                      onClick={() => pickRole(r.value)}
                      onKeyDown={onRoleKeyDown}
                      className={`flex w-full min-w-0 items-center justify-between gap-3 rounded-[20px] border-2 px-4 py-[15px] text-left focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919] ${
                        selected
                          ? "border-[#1B1B1B] bg-[#1B1B1B] text-[#FBFAF8]"
                          : "border-transparent bg-[#F3F3F1] text-[#191919]"
                      }`}
                    >
                      <span className="min-w-0">
                        <span className="flex items-center gap-2 text-[15.5px] font-bold">
                          {r.value === "owner" && (
                            <svg
                              aria-hidden="true"
                              width="14"
                              height="14"
                              viewBox="0 0 24 24"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="2.5"
                              strokeLinecap="round"
                            >
                              <rect
                                x="4"
                                y="11"
                                width="16"
                                height="10"
                                rx="2"
                              />
                              <path d="M8 11V7a4 4 0 0 1 8 0v4" />
                            </svg>
                          )}
                          {r.label}
                        </span>
                        <span
                          className={`mt-[2px] block text-[12.5px] ${
                            selected ? "text-[#b9b6b0]" : "text-[#64635F]"
                          }`}
                        >
                          {r.blurb}
                        </span>
                      </span>
                      <span
                        aria-hidden="true"
                        className={`flex h-[22px] w-[22px] flex-none items-center justify-center rounded-full border-2 ${
                          selected ? "border-[#FBFAF8]" : "border-[#c9c6c0]"
                        }`}
                      >
                        <span
                          className={`block h-3 w-3 rounded-full ${
                            selected ? "bg-[#FBFAF8]" : "bg-transparent"
                          }`}
                        />
                      </span>
                    </button>
                  );
                })}
              </div>

              <form onSubmit={onSubmit} noValidate className="mt-4">
                <div>
                  <label
                    htmlFor="staff-email"
                    className="mb-[7px] block text-[11.5px] font-extrabold tracking-[0.07em] text-[#64635F]"
                  >
                    EMAIL
                  </label>
                  <input
                    id="staff-email"
                    type="email"
                    autoComplete="username"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com"
                    required
                    className="w-full rounded-[14px] border-[1.5px] border-[#E7E5E0] bg-[#F3F3F1] px-[15px] py-[13px] text-[15px] text-[#191919] outline-none placeholder:text-[#64635F] focus:border-[#191919] focus:bg-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
                  />
                </div>
                <div className="mt-4">
                  <label
                    htmlFor="staff-password"
                    className="mb-[7px] block text-[11.5px] font-extrabold tracking-[0.07em] text-[#64635F]"
                  >
                    PASSWORD
                  </label>
                  <input
                    id="staff-password"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••"
                    required
                    className="w-full rounded-[14px] border-[1.5px] border-[#E7E5E0] bg-[#F3F3F1] px-[15px] py-[13px] text-[15px] text-[#191919] outline-none placeholder:text-[#64635F] focus:border-[#191919] focus:bg-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
                  />
                </div>
                <div className="mt-4">
                  <label
                    htmlFor="staff-code"
                    className="mb-[7px] block text-[11.5px] font-extrabold tracking-[0.07em] text-[#64635F]"
                  >
                    AUTHENTICATOR CODE · MFA REQUIRED
                  </label>
                  <input
                    ref={codeInputRef}
                    id="staff-code"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    value={code}
                    onChange={(e) =>
                      setCode(e.target.value.replace(/[^0-9]/g, ""))
                    }
                    placeholder="6 digits"
                    maxLength={6}
                    aria-describedby={formHint ? "staff-code-hint" : undefined}
                    className="w-full rounded-[14px] border-[1.5px] border-[#E7E5E0] bg-[#F3F3F1] px-[15px] py-[13px] text-[15px] text-[#191919] outline-none placeholder:text-[#64635F] focus:border-[#191919] focus:bg-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
                  />
                  {formHint && (
                    <p
                      id="staff-code-hint"
                      className="mt-2 text-[13px] text-[#64635F]"
                    >
                      {formHint}{" "}
                      {mfaSetupLink && (
                        <Link
                          href="staff-mfa-setup"
                          className="font-bold text-[#191919] underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
                        >
                          continue to authenticator setup →
                        </Link>
                      )}
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
                  disabled={!role || submitting}
                  className="mt-[22px] block w-full rounded-[99px] bg-[#1B1B1B] px-4 py-[15px] text-[15px] font-extrabold text-[#FBFAF8] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919] disabled:cursor-default disabled:opacity-40"
                >
                  {buttonLabel}
                </button>
              </form>
              <button
                type="button"
                onClick={onForgotPassword}
                className="mx-auto mt-[14px] block bg-transparent text-[13.5px] font-bold text-[#64635F] underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#191919]"
              >
                Forgot password?
              </button>
              {forgotSent && (
                <p role="status" className="mt-[14px] rounded-[14px] bg-[#F3F3F1] px-[14px] py-3 text-[13px] leading-relaxed">
                  If an account exists for that email, a reset link has been
                  sent. Recovery only — there is no sign-up on the staff
                  site.
                </p>
              )}
            </>
          )}
        </div>

        <p className="mt-5 text-center text-[13px] leading-relaxed text-[#64635F]">
          <b className="text-[#353431]">No sign-up here.</b> Staff accounts
          are created by the Owner only — new staff get a one-time setup
          link and choose their own password.
        </p>
        <p className="mt-[22px] text-center text-xs text-[#64635F]">
          WebSurfaceHQ staff sign-in · This page is not indexed and is not
          linked from the customer site.
        </p>
      </div>
    </main>
  );
}
