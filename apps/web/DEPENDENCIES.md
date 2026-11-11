# WebSurfaceHQ — Web App Dependencies

Every dependency in `apps/web/package.json` is pinned to an exact version.
One line per dependency, with the reason it exists. No dependency was added
without a reason (per ENGINEERING-PLAN.md §1 / playbook rule).

## Runtime dependencies

- `next@16.4.6` — Framework: Next.js 16 App Router, the frontend stack locked in ENGINEERING-PLAN.md §0 and blueprint §1.2. Upgraded 11 Nov 2026 from 14.2.35 — see ADR-0005 (14.2.35 carried an unpatched critical and no patched 14.x existed).
- `react@19.3.1` — UI library required by Next.js 16.
- `react-dom@19.3.1` — React DOM renderer, required alongside `react` by Next.js.

## Dev dependencies

- `typescript@5.9.3` — Strict TypeScript compiler for `tsc --noEmit` typechecking.
- `tailwindcss@3.4.19` — Utility-first CSS framework, the styling stack locked in ENGINEERING-PLAN.md §0.
- `postcss@8.5.32` — CSS processor required by Tailwind CSS.
- `autoprefixer@10.6.2` — Adds vendor prefixes to Tailwind output via PostCSS.
- `eslint@9.39.5` — Linter, flat config (`eslint.config.mjs`). ESLint 9+ is required by `eslint-config-next` 16; the legacy `.eslintrc.json` was deleted in the Next 16 migration (11 Nov 2026, ADR-0005).
- `eslint-config-next@16.4.6` — Next.js lint rules (`next/core-web-vitals` + TypeScript set), version-matched to `next`.
- `prettier@3.10.0` — Code formatter.
- `@types/react@19.3.0` — TypeScript types for React 19.
- `@types/react-dom@19.3.0` — TypeScript types for React DOM 19.
- `@types/node@22.20.5` — TypeScript types for Node.js APIs used by Next.js config/tooling.

## Removed in the Next 16 migration (11 Nov 2026, ADR-0005)

- The `glob@10.5.0` npm override (added 11 Nov 2026 for GHSA-5j98, the run #1
  audit failure) is gone: Next 16's tree has no `glob` at all (`npm ls glob`
  is empty), so the override is unnecessary. Do not re-add it.

## Not installed (deliberately)

- No test framework — Phase 0 has no web tests yet, so there is deliberately NO
  `npm test` script (a previous always-exit-0 placeholder was removed in the
  Phase 0 review: a gate that cannot fail is worse than no gate). The first real
  web test lands in Week 1, and the CI web job re-adds a test step then.
- No Supabase / auth / Sentry / analytics SDKs — those land in Week 1 with the foundation layer, not the scaffold.
- No UI component library — the design system is built in Week 1 per the plan.
