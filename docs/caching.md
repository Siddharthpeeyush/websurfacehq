# WebSurfaceHQ — Caching Strategy

**Status:** Phase 0 (scaffold / docs only). No cache exists yet. This strategy binds
Weeks 1–4: a cache entry that violates the tenancy rule below is a security bug, not
a performance tradeoff.

## 0. The rule that overrides everything else

**NEVER cache authenticated tenant data at a shared layer. Never share a cache key
across tenants.** A cached scan, finding, report, target, or user profile served to the
wrong tenant is a data breach, not a stale read. When in doubt, do not cache it.

Concretely: no tenant-scoped response is stored in Redis, in a CDN, or in any shared
cache. Authenticated API responses carry `Cache-Control: private, no-store` (or
`no-cache` where revalidation is safe). Only the public, tenant-independent data in §1
is cached, under tenant-independent keys.

## 1. Cache candidates

| Candidate | Location | TTL | Key | Invalidation |
|---|---|---|---|---|
| CISA KEV feed (JSON) | Upstash Redis | 24 h | `enrich:kev:v1` | Nightly job overwrites; version suffix in key so a bad feed can be rolled back by bumping the version |
| FIRST EPSS scores (CSV) | Upstash Redis (or Postgres table, preferred — see note) | 24 h | `enrich:epss:v1` | Nightly job overwrites; same version-suffix rule |
| NVD CVE details (per CVE) | Upstash Redis | 7 days | `enrich:cve:{cve_id}` | TTL only; CVE records are effectively immutable once published (a correction is a new revision — acceptable staleness for a 7-day TTL) |
| AI triage verdicts | Postgres (`findings.ai_verdict` etc.) + Redis lookup by hash | Until the finding changes | `triage:{finding_hash}` | Re-scan of the same finding reuses the verdict; a finding whose evidence changed gets a new hash → new verdict. No manual invalidation needed |
| Nuclei template list (curated 200) | Worker local disk (template dir) | Until nightly update | n/a (filesystem) | Nightly template-update job replaces the directory |
| Static frontend assets (JS/CSS/images) | Vercel CDN | Long (immutable, content-hashed filenames) | Content hash in filename | New deploy = new filenames; no invalidation needed |
| Public marketing pages | Vercel CDN / ISR | 1 h | URL | Revalidate on deploy |
| crt.sh subdomain results (per domain) | Redis | 1 h | `recon:crtsh:{domain}` | TTL only; a re-scan after TTL re-fetches. **Note:** the domain in the key is a *target* domain, not tenant data — but the *result* is scan data. This entry caches only the public CT-log response for a domain, and it is keyed per scan run in practice; do not serve it across tenants without re-checking ownership. When in doubt, skip this cache — crt.sh is free and fast |

**Note on EPSS/KEV storage:** the nightly enrichment job writes KEV + EPSS into Postgres
tables (bulk upsert) as the primary store; Redis holds a hot copy for the triage path
only. If Redis is flushed, enrichment still works from Postgres — the cache is a
performance layer, never the source of truth.

## 2. What is NEVER cached

- Any authenticated API response (scans, findings, targets, reports, billing).
- Any per-tenant data under a shared key (no `scan:{id}` in Redis unless the key also
  carries the tenant and the read path re-checks `can()` — and even then, prefer not
  to: the database is the source of truth and the data volume does not justify it).
- Signed URLs (they are short-lived by design; caching one extends its life past its
  expiry — a security bug).
- Verification tokens, API keys (hashed in DB only), JWTs, session data.
- LLM prompts containing finding evidence (evidence may contain redacted secrets;
  prompts are never cached beyond the verdict-by-hash entry above, which stores only
  the verdict, not the prompt or the evidence).

## 3. Headers

- Authenticated responses: `Cache-Control: private, no-store`.
- Public pages: `Cache-Control: public, max-age=3600`.
- Static assets: `Cache-Control: public, max-age=31536000, immutable` (content-hashed).
- Report downloads (signed URLs): `Cache-Control: private, no-store` — the browser
  may keep its own copy; no shared cache may.

## 4. Invalidation discipline

- Every cache entry has a TTL (no eternal entries) and a versioned key where the data
  shape can change (`:v1` suffix).
- The nightly enrichment job is the only writer for KEV/EPSS; the triage service is a
  reader. No other service writes enrichment keys.
- If a cache entry is ever suspected of serving stale or wrong-tenant data, the fix is
  to delete the key and let it rebuild — never to "fix" it in place.
