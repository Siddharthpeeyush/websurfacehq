# WebSurfaceHQ — Web App Dependencies

Every dependency in `apps/web/package.json` is pinned to an exact version.
One line per dependency, with the reason it exists. No dependency was added
without a reason (per ENGINEERING-PLAN.md §1 / playbook rule).

## Runtime dependencies

- `next@14.2.35` — Framework: Next.js 14 App Router, the frontend stack locked in ENGINEERING-PLAN.md §0 and blueprint §1.2.
- `react@18.3.1` — UI library required by Next.js 14 (React 19 is not the locked stack; Next 14 pairs with React 18).
- `react-dom@18.3.1` — React DOM renderer, required alongside `react` by Next.js.

## Dev dependencies

- `typescript@5.9.3` — Strict TypeScript compiler for `tsc --noEmit` typechecking.
- `tailwindcss@3.4.19` — Utility-first CSS framework, the styling stack locked in ENGINEERING-PLAN.md §0.
- `postcss@8.5.32` — CSS processor required by Tailwind CSS.
- `autoprefixer@10.6.2` — Adds vendor prefixes to Tailwind output via PostCSS.
- `eslint@8.57.1` — Linter. Pinned to 8.x deliberately: Next.js 14 + `.eslintrc.json` (legacy eslintrc format) requires ESLint 8; ESLint 9+ defaults to flat config and drops `.eslintrc` support.
- `eslint-config-next@14.2.35` — Next.js lint rules (`next/core-web-vitals`), version-matched to `next`.
- `prettier@3.10.0` — Code formatter.
- `@types/react@18.3.31` — TypeScript types for React 18.
- `@types/react-dom@18.3.7` — TypeScript types for React DOM 18.
- `@types/node@22.20.5` — TypeScript types for Node.js APIs used by Next.js config/tooling.

## Not installed (deliberately)

- No test framework — Phase 0 has no web tests yet, so there is deliberately NO
  `npm test` script (a previous always-exit-0 placeholder was removed in the
  Phase 0 review: a gate that cannot fail is worse than no gate). The first real
  web test lands in Week 1, and the CI web job re-adds a test step then.
- No Supabase / auth / Sentry / analytics SDKs — those land in Week 1 with the foundation layer, not the scaffold.
- No UI component library — the design system is built in Week 1 per the plan.
