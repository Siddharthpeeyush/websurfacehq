# ADR-0005: Next.js 14 → 16 upgrade (React 19, ESLint 9 flat config)

**Status:** Accepted (11 Nov 2026, owner decision — "Upgrade to Next 16")
**Deciders:** Owner + migration coordinator. Supersedes the Next.js 14 version
choice in ADR-0002 (the stack split itself is unchanged).

## Context

Phase 0's CI gate is `npm audit --audit-level=high`. CI run #1 failed on a
HIGH in `glob` (GHSA-5j98, via `@next/eslint-plugin-next`), fixed with a
targeted npm override (glob 10.3.10 → 10.5.0, commit 5d4a10e). CI run #2
then failed again — the glob HIGH was gone, but the audit now reported:

- `next@14.2.35` itself is **CRITICAL** (multiple advisories, including
  unauthenticated remote code execution in the Image Optimization API), and
- `postcss` is **HIGH** (GHSA-qx2v-qp2m-jg93).

There is no patched stable Next 14 (the latest 14.x releases are canaries;
`npm audit fix --force` suggests `next@16.4.6`). Our app does not use
`next/image`, so the RCE is not reachable in our code — but the vulnerable
framework still ships inside the product, and the audit gate still fails.
Weakening the gate to hide a known critical was rejected outright: a security
company does not ship a known-critical framework dependency behind a lowered
bar. The two MEDIUM advisories on the 14 tree (glob path traversal
GHSA-3g3m-2fjr-6pw4, minimatch DoS GHSA-g3hv-75wg-m249) also had no fix on
Next 14.

## Decision

- **Frontend:** Next.js **16.4.6** (App Router) + TypeScript + Tailwind, hosted
  on Vercel Hobby. React / React DOM **19.3.1**, `@types/react*` **19.3.0**,
  `eslint-config-next` **16.4.6**, `eslint` **9.39.5**.
- **Lint:** ESLint 9 flat config (`apps/web/eslint.config.mjs`,
  `next/core-web-vitals` + TypeScript sets). The legacy `.eslintrc.json` is
  deleted. The `lint` script is now `eslint .` — the `next lint` command is
  removed in Next 16, and `next build` no longer lints. No lint rule was
  weakened or disabled; one new warning (`import/no-anonymous-default-export`
  on `postcss.config.mjs`) was fixed in the code (named export), not silenced.
- **Overrides:** the `glob@10.5.0` override is removed — Next 16's tree has
  no `glob` at all (`npm ls glob` is empty). No `overrides` key remains in
  `apps/web/package.json`.
- **Engines:** `apps/web/package.json` now requires Node `>=20.9.0` (Next 16
  minimum). The CI workflow still pins Node 20 in the web/audit jobs, which
  resolves to a 20.x above 20.9.0 and keeps working — but the runners already
  warn that Node 20 is deprecated, so the CI Node pin should be bumped to 22
  (parent action, via the GitHub web UI — the app cannot write workflow files).
- **TypeScript:** `tsconfig.json` `jsx` is now `react-jsx` (mandatory in 16)
  with `target` ES2017, and `next-env.d.ts` gained the Next 16 typed-routes
  imports — all applied by `next build` itself. `strict` and
  `noUncheckedIndexedAccess` are unchanged.
- **Security headers:** `next.config.mjs` is untouched and the headers were
  re-verified byte-for-byte on a live dev server after the upgrade
  (HSTS / CSP incl. the documented `unsafe-inline` concession / nosniff /
  Referrer-Policy / DENY / Permissions-Policy). `poweredByHeader: false`
  still holds (no `X-Powered-By` in responses).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep Next 14 + documented gate exception (accepted risk, `next/image` unused) | Ships a known-critical framework dependency in a security product and weakens the audit gate — the exact precedent this project must not set. Owner chose the upgrade. |
| Upgrade to Next 15 instead of 16 | The audit's own fix suggestion was 16.4.6, not a 15.x release, and Next 15 leaves its support window on 21 Oct 2026 — it would only buy months before another forced migration. |
| Override `next` to a patched 14.x | None exists (see Context). |
| `npm audit fix --force` | Installs `next@16.4.6` as a breaking change with no review — the same destination, done blindly. The migration was done deliberately instead (official codemod + manual review of every changed file). |

## Consequences

- **Positive:** the audit gate can go green on high/critical; the ESLint 8
  pin from Phase 0 is closed (flat config); React 19; no `glob` in the tree;
  the two MEDIUM advisories on the 14 tree are gone with it.
- **Negative:** a major-version migration during Phase 0 — the cost was
  small here (the app is 3 files, no async request APIs, no middleware, no
  `next/image`), but the same decision on a larger app would be a bigger
  job. `next build` no longer lints, so CI depends on the separate
  `npm run lint` step (already the case in `.github/workflows/ci.yml`).
- **Follow-ups:** bump the CI Node pin 20 → 22 (parent, web UI);
  `pip-audit` step has still never run (skipped in runs #1–#2 because
  `npm audit` failed first) — CI run #3 is the first full audit result;
  `npm audit` cannot run on this VM (egress proxy blocks the audit POST),
  so GitHub runners remain the authoritative audit check.
