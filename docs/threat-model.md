# WebSurfaceHQ — Threat Model

**Status:** Phase 0. This model is written **before** the code for each entry point, per
Engineering Plan rule 1. It must be re-reviewed in Week 1 (security review #1) and
before every release. Nothing marked "present" below is implemented yet in Phase 0 —
"present" means *designed into the plan / committed for Week 1*, "missing" means *not
yet designed or not yet built*. The distinction is kept honest throughout.

## 1. Assets

| Asset | Value if compromised | Where it lives |
|---|---|---|
| User accounts + sessions | Account takeover → attacker scans as the victim, reads their reports | Supabase Auth (JWT) |
| Target domains + verification tokens | Lets an attacker "verify" a domain they do not own → unauthorized scanning | Postgres `targets` |
| Scan reports + findings | Business-sensitive: lists a company's live vulnerabilities, including secrets | Postgres `findings` + Storage (PDF/JSONL/screenshots) |
| Secrets found in JS bundles | Real AWS/Stripe/GitHub keys — usable for fraud if leaked | Postgres `findings` (redacted), Storage evidence (redacted) |
| Audit logs | Repudiation cover if tampered with; abuse evidence if leaked | Postgres `audit_logs` |
| API keys (post-MVP, Pro) | CI/CD scanning as the customer | Postgres `api_keys` (hash only, never raw) |
| Billing / subscription state | Fraudulent upgrades, free Pro access | Postgres `subscriptions` + gateway webhooks |
| Scanner infrastructure | SSRF pivot into cloud metadata / internal network; scanner used as an attack platform | Render workers, Go scanner-agent |
| LLM triage prompts + cached verdicts | Prompt injection via a malicious target page → triage manipulation | Celery triage service, Redis cache |

## 2. Entry points

Login, signup, password reset, target creation, target verification, scan creation,
scan progress/detail, findings list/detail + feedback, report download, report share
link, public API (post-MVP), billing webhooks (Razorpay / Lemon Squeezy), Celery task
inputs (scan config), and the scanner's outbound HTTP requests (the scanner *is* an
entry point into other people's infrastructure — that is the product's core risk).

## 3. STRIDE + OWASP Top 10 per entry point

Likelihood / Impact: L = Low, M = Medium, H = High. OWASP references are OWASP Top 10
2021 (A01 Broken Access Control … A10 SSRF).

### 3.1 Login / signup / password reset
| Threat (STRIDE) | OWASP | L / I | Mitigation present (planned) | Missing |
|---|---|---|---|---|
| Credential stuffing / brute force (Spoofing) | A07 Auth Failures | H / H | 5 attempts / 15 min per IP + per email, 429 + Retry-After, shared Redis store | Bot protection (CAPTCHA) on signup — decide Week 1; account lockout vs rate-limit tradeoff unresolved |
| User enumeration via different error messages (Info Disclosure) | A07 | M / M | Identical generic error for bad email vs bad password; identical "if an account exists" reset message | — |
| Weak / breached passwords (Spoofing) | A07 | M / H | Supabase Auth password rules; no hand-rolled hashing | Breached-password (HaveIBeenPwned) check — not planned for MVP |
| Session fixation / theft (Spoofing) | A07 | L / H | Supabase-managed sessions, HttpOnly + Secure + SameSite=Lax cookies | Session revocation on password change — verify Supabase behaviour in Week 1 |
| Signup spam / fake accounts (DoS, Abuse) | A07 | M / L | Rate limits; email verification required | CAPTCHA / email-domain blocklist — open question |

### 3.2 Target creation
| Threat | OWASP | L / I | Present (planned) | Missing |
|---|---|---|---|---|
| Creating a target for a domain the user does not own, then social-engineering verification (Spoofing) | A01 | M / H | Verification gate (DNS TXT / well-known file) before any intrusive stage; token expires in 7 days | Verification-token entropy + length — specify in Week 1 (min 32 random bytes, URL-safe) |
| Stored XSS via domain field (Tampering) | A03 Injection | L / M | Pydantic validation at boundary (hostname regex, max length); all output escaped in frontend; CSP | — |
| Enumeration of other users' targets (Info Disclosure) | A01 | M / M | Tenant-scoped queries + RLS + `can()`; cross-tenant → 404 | — |
| Mass target creation / quota abuse (DoS) | A04 Insecure Design | M / L | Free tier: 1 domain; per-user rate limit | — |

### 3.3 Target verification
| Threat | OWASP | L / I | Present (planned) | Missing |
|---|---|---|---|---|
| Attacker verifies a domain they briefly control (DNS hijack / expired domain) (Spoofing) | A01 | L / H | Re-verify on ownership change; verification is per-user, not global | Periodic re-verification cadence (e.g. every 90 days) — undecided |
| SSRF via verification fetch (worker fetches `https://<domain>/.well-known/...`) (Tampering) | A10 SSRF | H / H | Worker-side SSRF blocklist + DNS-rebinding check on the verification fetch too, not just scans | — |
| Token leakage via logs / error messages (Info Disclosure) | A09 Logging Failures | L / H | Tokens redacted from logs; token shown once at creation | — |

### 3.4 Scan creation
| Threat | OWASP | L / I | Present (planned) | Missing |
|---|---|---|---|---|
| Unauthorized scan of a third party's site (the product's core abuse) (Repudiation / Tampering) | A01, A04 | H / H | Verification gate enforced in worker, not just API; audit log on every scan; abuse workflow (ack 24h / investigate 72h / suspend same day if credible); ToS warranty | Automated abuse heuristics (e.g. many failed verifications → flag) — not planned for MVP |
| SSRF: scan target resolves to a private IP / cloud metadata (Tampering) | A10 SSRF | H / H | Blocklist `10/8, 172.16/12, 192.168/16, 127/8, 169.254.169.254`, `localhost`, `*.local`, `*.internal`, `metadata.google.internal`; DNS-rebinding check (resolve twice, compare); enforced in worker | IPv6 private ranges (e.g. `fc00::/7`, `fe80::/10`) — add to blocklist in Week 1; the blueprint lists IPv4 only |
| Command injection via scan config / template id (Tampering) | A03 Injection | M / H | Nuclei template IDs allow-listed (curated 200); no user-supplied shell; no custom templates in MVP; all DB queries parameterized | — |
| Resource exhaustion: huge scan config, deep crawl (DoS) | A04 | M / M | Per-scan budgets (1,000 requests/scan Free; max 500 URLs; max depth 3; max 100 JS files × 5 MB); per-target 5 req/s, 2 concurrent; global semaphore 20 concurrent outbound | Per-user concurrent-scan cap enforcement in Celery routing — implement in Week 1 |
| Cross-tenant scan access / IDOR (Info Disclosure) | A01 | M / H | `can()` + RLS + 404 for other tenants; 401/403/404 matrix test per endpoint | — |

### 3.5 Report download
| Threat | OWASP | L / I | Present (planned) | Missing |
|---|---|---|---|---|
| IDOR: guessing another tenant's report URL (Info Disclosure) | A01 | M / H | Private buckets; short-lived signed URLs issued only after `can()` passes; tenant-scoped paths | Signed-URL expiry value — set in Week 1 (propose 15 min) |
| Secrets in the report / PDF (Info Disclosure) | A09 | H / H | Redaction everywhere (first 4 + last 4 chars); manual review of first 10 reports; secret scanner in CI | Automated redaction test on every report fixture — add in Week 4 |
| XSS via finding evidence rendered in HTML report (Tampering) | A03 | M / M | All evidence escaped in frontend + HTML report; CSP headers | — |
| Open redirect via share link (Tampering) | A01 | L / L | Share links are token-scoped to one report; no `?next=` / redirect params | — |

### 3.6 Public API (post-MVP, Pro) — designed now, built later
| Threat | OWASP | L / I | Present (planned) | Missing |
|---|---|---|---|---|
| API key theft / leakage (Spoofing) | A07 | M / H | Keys hashed (never raw stored), shown once at creation, prefix for identification, scopes, `last_used_at`, revocation | Key rotation policy + expiry — decide when API ships |
| Key used to scan unverified domains (Tampering) | A01 | M / H | Same verification gate as the dashboard; same `can()` check | — |
| Webhook flooding / replay (DoS, Tampering) | A04 | M / M | Signature verification; stored processed event IDs; idempotent handlers (replay twice = no change) | Webhook endpoint rate limit — add when billing ships |

### 3.7 Billing webhooks (Razorpay / Lemon Squeezy)
| Threat | OWASP | L / I | Present (planned) | Missing |
|---|---|---|---|---|
| Forged webhook upgrades an account (Tampering) | A08 Integrity Failures | M / H | Signature verification; webhooks are the only source of truth (checkout page never upgrades); idempotent handlers | Daily reconciliation job (gateway vs DB) — planned, not built |
| Replay of a payment event (Tampering) | A08 | L / M | Stored processed event IDs | — |

### 3.8 Scanner outbound requests (the scanner as an attacker)
| Threat | OWASP | L / I | Present (planned) | Missing |
|---|---|---|---|---|
| Scanner used to DDoS / hammer a target (DoS) | A04 | M / H | 5 req/s + 2 concurrent per target; respect robots.txt + Retry-After; back off 60 s and halve concurrency on 429; never rotate IPs to evade a block | — |
| Stored XSS payload persists on the target (Tampering) | A03 | L / H | Reflected proof only; no stored payload; no `--os-shell`, no dump, no destructive payloads; SQLi boolean/time-delay only at risk 1 | — |
| Prompt injection via a malicious target page into LLM triage (Tampering) | A03 | M / M | LLM input truncated (max 2,000 chars), secrets redacted before the prompt; LLM output is a verdict, never executed; raw evidence always shown | Explicit prompt-injection test fixtures — add in Week 3 |
| DNS rebinding: domain resolves public, then private mid-scan (Tampering) | A10 | M / H | Resolve twice and compare; re-resolve before each intrusive stage | — |

## 4. Top risks (ranked)

1. **Unauthorized scanning** (abuse of the product itself) — H/H. Mitigated by the
   verification gate + audit log + abuse workflow, but it is the one risk that can end
   the company. Never weakened for convenience.
2. **SSRF via the scanner/worker** — H/H. Mitigated by the worker-side blocklist +
   DNS-rebinding check; the IPv6 gap in §3.4 must be closed in Week 1.
3. **Cross-tenant data leak** (reports contain live vulnerabilities + redacted secrets)
   — M/H. Mitigated in depth (RLS + `can()` + 404); proven by test, not by review alone.
4. **Secret leak in a report or log** — H/H if it happens, low likelihood with redaction.
   Mitigated by redaction + CI secret scan + manual review of the first 10 reports.
5. **AI triage false positives destroying trust** — M/H. Mitigated by heuristic-first
   triage + reachability probe + user feedback loop (see architecture §6).

## 5. What this model does NOT cover yet

- Infrastructure threats (Render/Supabase/Upstash account compromise, supply-chain
  attack on a ProjectDiscovery tool) — to be added when the first deploy exists.
- The Go scanner-agent's own attack surface (it execs external binaries) — to be
  modelled when the agent is built (Go 1.27.4 installed in Phase 0; see ADR-0002).
- Physical / insider threats — out of scope for a solo-founder MVP.
