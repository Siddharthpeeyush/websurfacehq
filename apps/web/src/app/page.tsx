import Link from "next/link";

/**
 * WebSurfaceHQ — landing page (Week 1).
 * Keeps the Phase 0 skeleton copy and dark slate look, adds a nav with
 * Sign up / Log in links and a footer note. No scan data, no mock dashboard.
 */
export default function Home() {
  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800">
        <nav
          aria-label="Main"
          className="mx-auto flex w-full max-w-5xl items-center justify-between px-6 py-4"
        >
          <Link href="/" className="text-lg font-bold tracking-tight">
            WebSurfaceHQ
          </Link>
          <div className="flex items-center gap-2 sm:gap-3">
            <Link
              href="/login"
              className="rounded-md px-3 py-2 text-sm font-medium text-slate-200 hover:bg-slate-800"
            >
              Log in
            </Link>
            <Link
              href="/signup"
              className="rounded-md bg-[var(--brand)] px-3 py-2 text-sm font-medium text-[var(--brand-contrast)] hover:bg-[var(--brand-hover)] hover:text-white"
            >
              Sign up
            </Link>
          </div>
        </nav>
      </header>

      <main className="flex flex-1 flex-col items-center justify-center px-6 text-center">
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
          WebSurfaceHQ
        </h1>
        <p className="mt-4 max-w-xl text-lg text-slate-300">
          Your attack surface, under control.
        </p>
        <p className="mt-4 max-w-xl text-sm text-slate-400">
          Paste a domain you own, prove ownership, get a prioritised security
          report a developer can act on in 10 minutes.
        </p>
        <div className="mt-8 flex flex-col gap-3 sm:flex-row">
          <Link
            href="/signup"
            className="rounded-md bg-[var(--brand)] px-5 py-2.5 text-sm font-medium text-[var(--brand-contrast)] hover:bg-[var(--brand-hover)] hover:text-white"
          >
            Scan my website free
          </Link>
          <Link
            href="/login"
            className="rounded-md border border-slate-700 bg-slate-900 px-5 py-2.5 text-sm font-medium text-slate-200 hover:bg-slate-800"
          >
            Log in
          </Link>
        </div>
        <p className="mt-8 rounded-md border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-400">
          Free plan: 1 domain, 3 scans a month. Authorised scanning only.
        </p>
      </main>

      <footer className="border-t border-slate-800 px-6 py-4 text-center text-xs text-slate-500">
        WebSurfaceHQ — authorised scanning only. Never scan a domain you do
        not own or have written permission to scan.
      </footer>
    </div>
  );
}
