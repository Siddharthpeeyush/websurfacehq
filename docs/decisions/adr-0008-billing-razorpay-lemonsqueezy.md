# ADR-0008: Billing — Razorpay (India) + Lemon Squeezy (international), Stripe later (16 Nov 2026)

**Status:** Accepted (owner decision, 16 Nov 2026 — "build this in week 4 as
proposed"). Build slot: Week 4 (Mon 30 Nov – Sun 6 Dec 2026), per
ENGINEERING-PLAN.md §3.

## Context

The blueprint (§6) specifies the billing design but assigned it no build
phase: Razorpay for India, Lemon Squeezy as global merchant of record,
Stripe later for usage-based API billing; webhooks as the only source of
truth for subscription state; money as integer minor units. The level-map
review (14 Nov 2026) flagged payments as homeless, and a Week 4 build slot
was proposed, pending owner confirmation. The owner-approved pricing ladder
(14 Nov 2026) is: Free (1 domain, 3 scans/month); ₹199 single scan; India
Starter ₹799 / Pro ₹1,999 / Business ₹6,999 per month; International
Starter $19 / Pro $49 / Business $149 per month. Raised tiers switch on only
as each tier's features go live; launch starts with Free + the ₹199 scan.
Free-tier limits (1 domain, 3 scans/month, 429 on breach) were proven live
in Week 1 — paid tiers unlock higher limits through the same server-side
check.

## Decision

1. **Gateways: Razorpay for India, Lemon Squeezy for international.**
   Razorpay because UPI is how India pays, plus GST invoices built in.
   Lemon Squeezy because it is the merchant of record: it handles all
   global tax/VAT, so the owner needs no tax registrations anywhere; it
   takes a bigger cut (~5%) in exchange for zero tax overhead for a solo
   founder. Stripe comes later, only when usage-based API billing arrives
   (the owner holds $25 Stripe credit from the GitHub Student Pack).
2. **Hosted checkout only — no card data ever touches our servers.**
   The customer pays on the gateway's own page. Card/UPI details are
   never seen, stored, or logged by us, keeping the product out of PCI
   scope. No billing code is written from scratch: checkout, the
   customer portal, and invoicing are the gateways' hosted surfaces.
3. **Checkout sessions and prices are created server-side.** The price
   comes from our server-side plan table, never from the browser, so a
   tampered request cannot buy a plan at a false price.
4. **Webhooks are the ONLY source of truth for subscription state.**
   The "payment successful" page never upgrades an account. Every
   webhook handler verifies the gateway signature, stores the processed
   event ID, and is idempotent (replaying an event twice changes
   nothing). Endpoints: `POST /webhooks/razorpay`,
   `POST /webhooks/lemonsqueezy`; billing API: `POST /billing/checkout`,
   `POST /billing/portal`, `GET /billing/subscription`.
5. **Money as integer paise/cents, never floats.** One `subscriptions`
   row per customer: `owner_id, plan, status, gateway,
   gateway_customer_id, gateway_subscription_id, current_period_end,
   amount_paise`. Plan limits are read from the row, so plan changes are
   data changes, not deploys.
6. **Self-serve lifecycle via the gateway customer portal.**
   Upgrades, downgrades, cancels, and invoices run through the portal;
   no billing screens are built. A customer can only act on their own
   subscription: portal access is tied to their gateway customer record,
   and our side trusts only signed gateway events.
7. **Cancel = access until period end, then Free, nothing deleted.**
   Cancellation never cuts access immediately: the customer keeps the
   paid plan until `current_period_end`, and the dashboard shows the end
   date. On that date the plan drops to Free automatically. Account, scan
   history, and reports are never deleted; domains beyond the Free limit
   are paused (no new scans, history kept, shown as paused), and
   re-subscribing re-enables them immediately.
8. **No prorated refund on a normal cancel** — the customer keeps the
   full paid period, so nothing is owed. Genuine exceptions (e.g. double
   charge) are refunded manually by the owner from the gateway dashboard;
   the webhook updates the account.
9. **Failed payments: past-due, then Free at period end.** The gateway
   retries and emails the customer; the webhook handler marks the account
   past-due, and it drops to Free at period end if payment never lands.

## Alternatives considered

- **Stripe for international from day one.** Rejected for launch: Stripe
  leaves global tax/VAT handling to the owner (or a paid Stripe Tax
  add-on), while Lemon Squeezy absorbs it as merchant of record. Stripe
  stays the plan for usage-based API billing, where its metering fits.
- **A single gateway for both markets.** Rejected: no single gateway is
  best at both UPI-first Indian checkout with GST invoices and
  zero-overhead global tax handling.
- **Writing billing from scratch (own checkout, own dunning, own
  invoices).** Rejected (blueprint rule): a solo founder must not own
  PCI scope, tax logic, or retry/dunning machinery.
- **Trusting the checkout success redirect to upgrade accounts.**
  Rejected: a redirect is forgeable. Only signed, idempotent webhooks
  change subscription state.
- **Immediate access cut on cancel, or prorated refunds by default.**
  Rejected: end-of-period access is the fair, standard, low-dispute
  policy, and it makes the no-refund rule coherent.

## Consequences

- Week 4 must build: checkout-session creation (server-side prices),
  both webhook handlers (signature verification, event-ID store,
  idempotency), the `subscriptions` table + plan-limit reads, the
  customer-portal link flow, the cancel/downgrade/pause behaviour, and
  the past-due path — each with tests, including webhook-replay and
  price-tamper cases, and a live end-to-end proof in test mode before
  launch.
- Launch needs Free + the ₹199 single-scan purchase working; monthly
  tiers switch on as their features go live.
- Owner-owned steps (cannot be delegated): create the Razorpay and
  Lemon Squeezy accounts (KYC/PAN/bank; no upfront cost — gateways take
  only a cut per sale) and supply test keys via the secure flow for
  Week 4 development; live keys at launch. Keys are never pasted in
  chat, docs, or code.
- The email provider for scan/diff emails is a separate open decision,
  also needed before Week 4 starts; billing emails (receipts, dunning,
  cancellation confirmations) are the gateways' own and do not depend
  on it.
