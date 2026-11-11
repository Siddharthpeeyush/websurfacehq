/**
 * WebSurfaceHQ — landing skeleton (Phase 0 scaffold).
 *
 * Honest placeholder only: no features, no scan data, no mock dashboard.
 * Real pages (signup/login, dashboard, scan wizard, findings, reports)
 * are built in Week 1+ per ENGINEERING-PLAN.md.
 */
export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-slate-950 px-6 text-center text-slate-100">
      <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
        WebSurfaceHQ
      </h1>
      <p className="mt-4 max-w-xl text-lg text-slate-300">
        Your attack surface, under control.
      </p>
      <p className="mt-8 rounded-md border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-400">
        Coming soon — scaffold. No scanning yet.
      </p>
    </main>
  );
}
