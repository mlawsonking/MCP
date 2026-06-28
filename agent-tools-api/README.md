# Agent Tools API (Engine #2 — tool suite)

Deterministic web utilities every AI agent/app needs, as one reliable HTTP call each. No LLM,
no paid services. cheerio/DNS only → fast cold starts, $0 marginal cost.

## Endpoints
- **`GET /api/validate-email?email=`** — syntax + live MX/A DNS + disposable/role/free detection.
  Returns `{ valid_syntax, has_mx, accepts_mail, disposable, role_account, free_provider, deliverable, score }`.
  (MX-level — no SMTP probe, which is slow/abusive.)
- **`GET /api/extract?url=&selectors={...}`** — CSS-selector scraping → structured JSON.
  Selector syntax: `"css"` (text), `"css@attr"` (attribute), `"css[]"` (all matches). href/src → absolute.
- **`GET /api/feed?url=&limit=25`** — RSS/Atom feed → clean JSON items.

All hardened: http/https only · SSRF guard (DNS-resolved) · 7s timeout · size cap · CORS open.

## Dev
```
npm install
node test/local.cjs
```
Deploy: `vercel deploy --prod --yes` (free tier). Monetize via RapidAPI / Apify / MCP / x402.
