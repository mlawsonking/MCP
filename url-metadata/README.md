# URL → Metadata (Engine #2, Tool #2)

Unfurl any link into structured metadata — the data every app needs for link previews and every
agent needs to summarize a URL. Deterministic, no LLM, no paid services.

## API
```
GET /api/meta?url=https://example.com
```
JSON: `{ ok, url, title, description?, image?, siteName?, type?, author?, themeColor?, canonical?, favicon?, lang?, ms }`.

Hardening: http/https only · SSRF guard · 7s timeout · 3 MB cap · content-type checked · CORS open.
Built on `cheerio` (light, no headless browser → fast cold start).

## Dev
```
npm install
node test/local.cjs
```
Deploy: `vercel deploy --prod --yes` from this folder (free tier). Monetize via RapidAPI / Apify / MCP / x402.
