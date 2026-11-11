# WebSurfaceHQ — System Design

**Status:** Phase 0 (scaffold / docs only). The scaffold exists: `apps/web` (Next.js,
builds and serves locally) and `apps/api` (FastAPI, real `GET /health` → 200, 11
passing tests). No database, no deployed service, no scanning exists yet.
This document records the product design agreed before any feature is built. It is the
source of truth for scope; anything not in here is not in the MVP unless the owner orders it.
Spec: blueprint v4 (`~/workspace/vuln-scanner-platform/PDF-SOURCE.md`).
Tagline: "Your attack surface, under control."

## 1. Problem statement

Small-business website owners, indie developers, and small agencies have a website but no
security team. A manual penetration test in India costs Rs 50,000–2,00,000 and takes weeks.
Open-source scanners (Nuclei, OWASP ZAP) find raw vulnerabilities but their output is
40–60% noise, CLI-only, and unreadable to a non-expert founder. There is no cheap tool that
(1) proves the user owns the domain before scanning, (2) triages false positives with AI +
heuristics, (3) gives safe, reproducible proof-of-concept evidence, (4) shows what changed
since the last scan, and (5) ranks fixes by real-world exploitability (CISA KEV + EPSS),
not just CVSS.

WebSurfaceHQ fills that gap: paste a domain, prove you own it, get a report a developer
can act on in 10 minutes — no security expertise required.

**Core promise:** a scan a founder can act on in 10 minutes, for a site they own, with
zero unauthorized scanning and zero leaked secrets.

## 2. Users and roles

| Role | Who | What they do |
|---|---|---|
| **Owner (account holder)** | Startup founder, shop owner, freelancer, indie dev | Signs up, adds + verifies a domain, runs scans, reads reports, marks findings false positive / fixed, pays (later), deletes their data |
| **Viewer (post-MVP)** | Teammate / client of an agency | Read-only access to shared reports. NOT in MVP — see §7 |
| **Admin (internal)** | WebSurfaceHQ operator (the owner, Siddharth Peeyush) | Abuse handling, support, incident response. No separate admin UI in MVP; abuse handled via Supabase dashboard + audit logs |
| **Anonymous visitor** | Anyone on the landing page | Reads marketing + sample report only. Cannot scan, cannot see any tenant data |

MVP has exactly one user role: the account owner. Every account is a single-user tenant.
Team roles (owner/admin/viewer), invites, and ownership transfer are post-MVP (Month 2–3
backlog in the blueprint) and are deliberately not designed into Week 1 tables beyond a
nullable `team_id` on targets.

## 3. Core user flows

### 3.1 Sign up → verify domain → first scan (the happy path)
1. Visitor signs up (email + password via Supabase Auth, or Google OAuth). Email verification required.
2. User adds a target: `POST /targets` with a domain. System issues a verification token.
3. User proves ownership — DNS TXT `scan-verify=<token>` **or** file at
   `https://<domain>/.well-known/scan-verify.txt` containing the token. Token expires in
   7 days if unused. Re-verification required on ownership change.
4. System checks `targets.verification_status = 'verified'` before any intrusive stage.
   Passive recon (certificate-transparency lookup) may run pre-verification; port scan and
   Nuclei may not.
5. User creates a scan (depth: quick / standard / deep). Scan queues; dashboard polls
   `GET /scans/{id}` every 5 s for live progress (MVP; Supabase Realtime later).
6. Pipeline runs: verify → DNS/subdomain enum → port scan → HTTP probe → tech
   fingerprint → crawl → JS secret scan → Nuclei → AI triage → KEV/EPSS enrichment →
   report → notify.
7. User reads triaged findings (verdict: confirmed / likely_fp / needs_manual, confidence,
   KEV/EPSS, P0–P3 risk rank), copies a safe PoC, downloads the PDF report.

### 3.2 Re-scan and attack-surface diff (the retention loop)
1. User re-scans a verified target. Assets are hashed per scan (subdomain, port, tech, URL).
2. Diff computed vs previous scan: new/closed subdomains and ports, tech changes, findings
   fixed / still open / new.
3. Verified closure: the *exact* check that produced a finding is re-run; only a passing
   re-check earns a "Fix verified" badge (`findings.fix_verified_at`).
4. Dashboard timeline + email alert on a new critical finding since last scan.

### 3.3 False-positive feedback
1. User marks a finding `false_positive` (one click, with optional reason).
2. Next scan auto-suppresses the same finding (same template + URL + param) and the
   heuristic filter learns from it. The raw evidence is never hidden — AI is a filter,
   not a judge.

### 3.4 Account deletion / data export
1. User requests deletion → account, targets, scans, findings, stored evidence deleted
   immediately; audit entry anonymised. Scan evidence otherwise auto-deletes after 90 days.
2. Export: user can download their reports + findings (Week 4; format: PDF + JSON).

## 4. Functional requirements (MVP, Week 1–4)

| ID | Requirement |
|---|---|
| F1 | Email + Google signup/login/logout, email verification, password reset with expiry, session expiry (Supabase Auth only — no hand-rolled auth) |
| F2 | Target CRUD; unique `(user_id, domain)`; verification via DNS TXT or well-known file; 7-day token expiry |
| F3 | Scan create/list/get/cancel; statuses queued → recon → crawling → scanning → triaging → done / failed / cancelled; progress 0–100 |
| F4 | Recon: subfinder + crt.sh subdomains, httpx live-host probe, naabu top ports + nmap -sV on open ports only, tech fingerprint, TLS check, screenshots |
| F5 | JS secret scraper: Katana-collected JS (max 100 files, 5 MB each), regex + Shannon entropy > 4.5 + context scoring; findings redacted (first 4 + last 4 chars only); secrets never used to authenticate |
| F6 | Vuln: curated ~200 Nuclei templates (`-tags cve,misconfig,exposure,token`), dalfox (reflected XSS proof only), nikto (low concurrency); dedupe by template + URL + param |
| F7 | AI triage: heuristic filter first (~60% noise drop), then Gemini/Groq LLM for Medium+ only, max 50 LLM calls/scan, cached by finding hash; verdict + confidence + one-sentence reason stored |
| F8 | Reachability triage: one httpx probe per finding before LLM; unreachable findings auto-close as "not reachable" with probe evidence, never reach the LLM |
| F9 | Enrichment: nightly KEV JSON + EPSS CSV download; per-finding CVE, CVSS, KEV flag, EPSS score; sort KEV → EPSS → CVSS |
| F10 | Business risk score: severity × exposure × exploitability → P0/P1/P2/P3 badges; Top 5 Fixes list |
| F11 | Attack-path chaining: findings sharing an asset link into entry → pivot → crown-jewel paths; the severing fix leads the Top 5 |
| F12 | Safe PoC generator: copy-paste `curl` / Python `requests` snippets + Playwright screenshot for XSS; read-only proof only — no `--os-shell`, no dump, no stored payload, no data extraction |
| F13 | Reports: HTML + PDF (8 sections per blueprint §8.4), compliance appendix (OWASP Top 10 + PCI DSS / SOC 2 / ISO 27001 mapping per finding), copy-paste fix snippets per rule |
| F14 | Attack-surface diff + timeline; lite attack-surface map (domain → subdomains → ports → tech) on dashboard |
| F15 | Rate limits + quotas: Free 1 active scan, 3 scans/month, 1,000 requests/scan, 1 domain; auth endpoints 5 attempts / 15 min per IP + per email; per-target politeness 5 req/s, 2 concurrent, respect robots.txt + Retry-After |
| F16 | Audit log: who scanned what, when, with what scope (`audit_logs`) |
| F17 | Private storage (Supabase Storage, tenant-scoped paths `user_id/scan_id/...`); downloads via short-lived signed URLs after an auth check |
| F18 | Health endpoint `/health` (DB + Redis + Celery, component status, timeouts) and lightweight `/live` |

## 5. Non-functional requirements

| Area | Requirement |
|---|---|
| Security | Supabase Auth only; RLS on every table; central `can(user, action, resource)` on every endpoint; server is the source of truth, frontend only hides actions; SSRF blocklist enforced in the worker (see §6); safe payloads only; secrets redacted in logs/reports; no secrets in code, logs, or frontend bundle; CI secret scanner blocks merges |
| Tenancy | Every tenant-owned table carries `user_id`; every query tenant-scoped; cross-tenant access returns 404 (never 403 — no existence oracle); proven by test: user A changing an id in the URL gets 404 for user B's data |
| Reliability | Idempotent tasks (`task_id = scan_id:stage:target_hash`); exponential-backoff retries (60s / 300s / 900s, max 3), then dead-letter queue `dlq:scan:{id}` and scan marked `failed` with a human-readable error; scans resume from last completed stage (Render free tier sleeps) |
| Performance | Quick scan < 5 min, Standard < 20 min (median); API p95 < 2 s; dashboard polls every 5 s (no WebSockets in MVP) |
| Scalability | Modular monolith; split only when a single queue becomes the bottleneck; first bottleneck is Redis command volume, then Render worker memory during Nuclei (see §9) |
| Data | Money as integer paise/cents, never floats; migrations only via version-controlled files, never hand-edited in the dashboard; backups with a tested restore before launch; scan evidence auto-deleted after 90 days |
| Accessibility | WCAG 2.1 AA basics; app works at 375 px mobile and desktop; every data view has four states: loading skeleton / empty + primary action / error + retry / success |
| Observability | Structured JSON logs with `request_id` on every line, auto-redaction of password/token/secret fields; Sentry (frontend + backend); UptimeRobot; alerts on error rate > 5%, queue depth > 50, p95 > 2 s — each with a runbook |
| Cost | $0/month at MVP on free tiers (Vercel Hobby, Render Free, Supabase Free, Upstash Free, Gemini/Groq free, Sentry free); first paid at ~100 scans/day: Redis ~$10/mo, then Render ~$7/mo |

## 6. Tenancy model

- **Single-user tenant per account.** The tenant boundary is `auth.users.id` → `user_id` on
  every tenant-owned table (`targets`, `scans`, `assets`, `findings`, `scan_jobs`,
  `subscriptions`, `api_keys`, `notifications`, `support_tickets`).
- **Enforcement in depth:** (1) Supabase RLS policies on every table, (2) application-level
  tenant-scoped queries (`WHERE user_id = :user_id` on every query), (3) central `can()`
  check on every endpoint. Any one layer failing must still not leak data.
- **Teams (post-MVP):** `teams` + `team_members` (roles owner/admin/viewer); targets gain
  nullable `team_id`. Team features use the same central `can()` check. Rules when built:
  last owner cannot leave, invite links expire after 7 days, removed member loses access
  immediately with sessions revoked.
- **Storage tenancy:** paths scoped `user_id/scan_id/...`; private buckets; signed URLs only.
- **Cache tenancy:** never cache authenticated tenant data at a shared layer; only public
  enrichment data (KEV JSON, EPSS CSV) is cached, under tenant-independent keys.
- **No cross-tenant anything:** no shared scan results, no shared findings, no shared
  reports, no shared cache keys, no tenant id in a URL that another tenant can guess
  their way into (hence 404, not 403).

## 7. Out of scope (MVP — do not build unless the owner orders it)

- Auto-exploitation of any kind (no `--os-shell`, no data dump, no account takeover).
- Authenticated scanning (login forms / session-based crawling).
- Scheduled scans (Pro feature, Month 2).
- Team roles, invites, ownership transfer.
- Custom Nuclei template editor; user-supplied templates or shell commands.
- Autonomous remediation (changing a customer's site) — breaks the read-only rule.
  Copy-paste fix snippets are the safe equivalent.
- Identity blast radius (needs cloud/IdP access; enterprise scope).
- API access / API keys for CI/CD (Pro feature, Month 2–3).
- Slack integration, Jira/GitHub issue export (Month 2–3).
- Scanning government / military / critical infrastructure without an explicit written contract.
- Display ads anywhere on the product (ads kill trust on a security tool).
- Selling user data or scan results; selling a "clean" report or paid suppression of a finding.

## 8. Open questions (for the owner)

1. **Domain registration:** is `websurfacehq.com` actually registered yet? RDAP "no record"
   is not proof — only checkout confirms availability. (Owner action item.)
2. **First live-scan domain:** Week 2's first live scan runs on the owner's own domain only —
   confirm which domain (websurfacehq.com once registered, or another owned domain).
3. **Pricing timing:** Free tier is 3 scans/month — LOCKED 11 Nov 2026 by the owner. The blueprint's §0.4/§1.6 saying 3 scans/day is superseded. (Was a blueprint inconsistency; resolved.)
4. **LLM provider:** Gemini 2.5 Flash vs Groq Llama-3.1 for triage — pick one primary at
   Week 3; the other is the fallback. Both are free tier.
5. **Payment provider order:** Razorpay (India) + Lemon Squeezy (global) per blueprint —
   confirm Razorpay first, and whether billing lands in Week 4 or Month 2.
6. **Beta users:** 5 beta users are the owner's own sites + friends' sites with *written*
   permission only — confirm the list before Week 4.
7. **Support channel:** support tickets table exists in the schema — confirm whether support
   is email-only at launch or in-app tickets from day one.

## 9. Year-one load estimate (shown math)

Assumptions (from blueprint §7.3 targets, first 90 days: 500 free users, 30 paying users;
year-one steady state assumed below — these are planning numbers, not promises):

- **Users:** 500 free + 30 paying by day 90; assume 2,000 free + 100 paying by month 12.
  Active users (scan at least monthly): ~20% of free (400) + ~80% of paying (80) = ~480.
- **Scans:** free users average 2 scans/month, paying average 10 scans/month →
  400 × 2 + 80 × 10 = 800 + 800 = **1,600 scans/month ≈ 53 scans/day** average.
  Peak day (launch / newsletter): 3× average ≈ **160 scans/day**; peak hour ≈ 20 scans.
- **Background jobs:** ~13 pipeline stages per scan (verify → … → notify) →
  53 × 13 ≈ **690 tasks/day** average, ~2,100 on a peak day. Plus nightly enrichment
  (1 KEV + 1 EPSS download) and template updates. Well within Celery on one worker at
  this volume; the constraint is per-scan wall time, not task count.
- **Outbound scan traffic:** Free cap 1,000 requests/scan → 53 × 1,000 = **53,000
  requests/day** worst case; realistic standard scan ≈ 300–500 requests → ~20,000/day.
  Politeness cap (5 req/s per target) means a single scan cannot hammer a target.
- **Database size:** per scan ≈ 200 assets (~0.5 KB each = 100 KB) + ~30 findings
  (~2 KB each = 60 KB) + scan/scan_jobs rows (~10 KB) ≈ **~170 KB/scan**.
  1,600 scans/month × 170 KB ≈ **272 MB/month** before 90-day auto-delete caps it:
  steady state ≈ 90 days × 53 scans/day × 170 KB ≈ **~810 MB** — exceeds the Supabase
  free 500 MB tier, so the first paid upgrade is likely Supabase ($25/mo), not Redis,
  unless evidence is pruned harder. Raw JSONL/screenshots live in Storage (1 GB free),
  not Postgres — keep them there and keep Postgres rows lean.
- **File storage:** screenshots + raw JSONL + PDF ≈ ~2 MB/scan → 53 × 2 MB ≈
  **106 MB/day, ~3.2 GB/month**, capped by 90-day deletion at ~9.5 GB steady state —
  exceeds the 1 GB free Storage tier within the first month. Mitigation (decide Week 4):
  store screenshots only for confirmed findings, cap raw JSONL retention to 30 days.
- **API requests:** dashboard polling every 5 s during an active scan (20 min scan ≈
  240 polls) is the dominant API load: 53 scans/day × 240 ≈ **12,700 polls/day**,
  plus normal browsing ≈ ~20,000 API requests/day total. Trivial for Render free.
- **LLM calls:** Medium+ findings only, max 50/scan, cached by finding hash →
  53 × ~15 average ≈ **~800 calls/day**, within Gemini/Groq free tiers; re-scans
  re-use cached verdicts.
- **Upstash Redis:** ~10k commands/day free tier. Each scan issues roughly
  13 tasks × ~10 commands (enqueue, lock, rate-limit, progress) ≈ 130 commands +
  rate-limit checks ≈ **~200 commands/scan** → 53 scans/day ≈ **10,600/day** — the
  free tier is already marginal at the year-one average, and breaks first on a peak day.
- **First bottleneck: Upstash Redis command volume** (~10k/day free tier), then Render
  worker memory during Nuclei (512 MB free; curated 200 templates fit, full 8,000 do not),
  then Supabase Storage (1 GB) and Postgres (500 MB) as computed above. Fix order:
  Redis paid ($10/mo) → Render paid worker ($7/mo) → Supabase Pro ($25/mo) with
  storage pruning.

## 10. Phase 0 honesty note

This document is design only. In Phase 0 there is no Supabase project, no API, no worker,
no frontend, and no scan has ever run. Every requirement above is a commitment for
Weeks 1–4, not a description of something that exists. The Phase 0 exit gate is: dev
servers run, `/health` returns 200, CI is green on an empty skeleton.
