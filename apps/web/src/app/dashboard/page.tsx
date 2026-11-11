"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { ApiError, createTarget, fieldErrors, listTargets, type Target } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Table } from "@/components/ui/Table";
import { SkeletonRows, EmptyState, ErrorState } from "@/components/ui/states";
import { Modal } from "@/components/ui/Modal";
import { useToast } from "@/components/ui/Toast";

type TargetsState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; targets: Target[] };

function verificationTone(status: string): "success" | "warning" | "default" {
  if (status === "verified") return "success";
  if (status === "pending") return "warning";
  return "default";
}

export default function DashboardPage() {
  const router = useRouter();
  const { user, loading, logout } = useAuth();
  const { push } = useToast();
  const [targetsState, setTargetsState] = useState<TargetsState>({ status: "loading" });
  const [addOpen, setAddOpen] = useState(false);
  const [domain, setDomain] = useState("");
  const [domainError, setDomainError] = useState("");
  const [adding, setAdding] = useState(false);
  /** The just-created target — its verification token is shown ONCE, here. */
  const [newTarget, setNewTarget] = useState<Target | null>(null);
  const [copied, setCopied] = useState(false);

  const loadTargets = useCallback(async () => {
    setTargetsState({ status: "loading" });
    try {
      const page = await listTargets();
      setTargetsState({ status: "ready", targets: page.data });
    } catch (err) {
      setTargetsState({
        status: "error",
        message:
          err instanceof ApiError
            ? err.message
            : "Could not load your targets. Please try again.",
      });
    }
  }, []);

  // Auth guard: no session -> /login (after the restore finishes).
  useEffect(() => {
    if (!loading && !user) router.push("/login");
  }, [loading, user, router]);

  // Initial targets load once the user is known. The state starts as
  // "loading" and is only updated in the async callbacks below (never
  // synchronously inside the effect).
  useEffect(() => {
    if (!user) return;
    let cancelled = false;
    (async () => {
      try {
        const page = await listTargets();
        if (!cancelled) {
          setTargetsState({ status: "ready", targets: page.data });
        }
      } catch (err) {
        if (!cancelled) {
          setTargetsState({
            status: "error",
            message:
              err instanceof ApiError
                ? err.message
                : "Could not load your targets. Please try again.",
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [user]);

  async function onAddTarget(e: FormEvent) {
    e.preventDefault();
    setDomainError("");
    const cleaned = domain.trim().toLowerCase();
    if (!cleaned || cleaned.includes("://") || cleaned.includes("/") || cleaned.includes(":")) {
      setDomainError("Enter a domain only, e.g. example.com — no scheme, path, or port.");
      return;
    }
    setAdding(true);
    try {
      const created = await createTarget(cleaned);
      setNewTarget(created);
      setDomain("");
      setAddOpen(false);
      push("success", `Target ${created.domain} added.`);
      void loadTargets();
    } catch (err) {
      if (err instanceof ApiError) {
        const fields = fieldErrors(err.details);
        if (fields.domain) {
          setDomainError(fields.domain);
        } else {
          setDomainError(err.message);
        }
      } else {
        setDomainError("Something went wrong. Please try again.");
      }
    } finally {
      setAdding(false);
    }
  }

  async function copyToken(token: string) {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 3000);
    } catch {
      push("error", "Could not copy automatically — select the token and copy it manually.");
    }
  }

  if (loading || !user) {
    return (
      <main className="min-h-screen bg-slate-950 px-4 py-8">
        <div className="mx-auto max-w-5xl">
          <SkeletonRows rows={4} />
        </div>
      </main>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800">
        <div className="mx-auto flex w-full max-w-5xl flex-wrap items-center justify-between gap-2 px-4 py-4 sm:px-6">
          <span className="text-lg font-bold tracking-tight">WebSurfaceHQ</span>
          <div className="flex items-center gap-3">
            <span className="max-w-[180px] truncate text-sm text-slate-300 sm:max-w-none">
              {user.email}
            </span>
            <Badge tone="info">Free — 3 scans/month</Badge>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                logout();
                router.push("/login");
              }}
            >
              Log out
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-5xl flex-col gap-6 px-4 py-8 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <Button onClick={() => setAddOpen(true)}>Add target</Button>
        </div>

        {/* Verification token — shown exactly ONCE, right after creation. */}
        {newTarget && newTarget.verification_token && (
          <Card>
            <CardTitle>Verify {newTarget.domain}</CardTitle>
            <p className="mt-2 text-sm text-slate-300">
              Prove you own this domain with <strong>one</strong> of these
              methods. This token is shown once — copy it now. It expires in
              7 days if unused.
            </p>
            <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center">
              <code className="flex-1 break-all rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-[var(--brand)]">
                {newTarget.verification_token}
              </code>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => copyToken(newTarget.verification_token ?? "")}
              >
                {copied ? "Copied" : "Copy token"}
              </Button>
            </div>
            <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-slate-300">
              <li>
                <strong>DNS TXT:</strong> add a TXT record for{" "}
                <code className="text-slate-100">{newTarget.domain}</code>{" "}
                with value{" "}
                <code className="text-slate-100">
                  websurfacehq-verify={newTarget.verification_token}
                </code>
              </li>
              <li>
                <strong>File:</strong> serve the token at{" "}
                <code className="break-all text-slate-100">
                  https://{newTarget.domain}/.well-known/scan-verify.txt
                </code>
              </li>
            </ul>
            <div className="mt-4">
              <Button variant="ghost" size="sm" onClick={() => setNewTarget(null)}>
                Done — I saved the token
              </Button>
            </div>
          </Card>
        )}

        <Card>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
            <CardTitle>Your targets</CardTitle>
            <span className="text-xs text-slate-400">
              Free plan: 1 domain
            </span>
          </div>

          {targetsState.status === "loading" && <SkeletonRows rows={3} />}

          {targetsState.status === "error" && (
            <ErrorState message={targetsState.message} onRetry={loadTargets} />
          )}

          {targetsState.status === "ready" && (
            <Table
              columns={["Domain", "Verification", "Added"]}
              isEmpty={targetsState.targets.length === 0}
              emptyState={
                <EmptyState
                  title="No targets yet"
                  description="Add a domain you own to start. You will prove ownership before any scan runs."
                  action={
                    <Button size="sm" onClick={() => setAddOpen(true)}>
                      Add your first target
                    </Button>
                  }
                />
              }
            >
              {targetsState.targets.map((t) => (
                <tr
                  key={t.id}
                  className="border-b border-slate-800 last:border-0"
                >
                  <td className="break-all px-4 py-3 font-medium">{t.domain}</td>
                  <td className="px-4 py-3">
                    <Badge tone={verificationTone(t.verification_status)}>
                      {t.verification_status}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-slate-400">
                    {new Date(t.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Card>

        {/* Honest stub — scans land in Week 2. No fake data. */}
        <Card>
          <CardTitle>Scans</CardTitle>
          <p className="mt-2 text-sm text-slate-400">
            Week 2 — scans land here. Add and verify a target first; the scan
            wizard, live progress, and findings arrive with the recon engine.
          </p>
        </Card>
      </main>

      <Modal open={addOpen} onClose={() => setAddOpen(false)} title="Add target">
        <form onSubmit={onAddTarget} noValidate className="flex flex-col gap-4">
          <Input
            id="domain"
            label="Domain"
            type="text"
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            error={domainError}
            hint="A domain you own, e.g. example.com. No http://, no path."
            placeholder="example.com"
          />
          <p className="text-xs text-slate-400">
            You will need to prove ownership (DNS TXT or a verification file)
            before any scan runs on this domain.
          </p>
          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              onClick={() => setAddOpen(false)}
              disabled={adding}
            >
              Cancel
            </Button>
            <Button type="submit" loading={adding}>
              Add target
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
