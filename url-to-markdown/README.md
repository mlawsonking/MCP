# URL → Markdown (Engine #2, Tool #1)

A tiny, deterministic API that turns any web page into clean Markdown — the format AI agents
need for RAG. No LLM, no tracking, no external paid services. Deploys to a free serverless tier.

## API
```
GET /api/read?url=https://example.com               -> JSON
GET /api/read?url=https://example.com&format=markdown -> raw markdown
```
JSON shape: `{ ok, url, title, byline?, excerpt?, words, chars, ms, markdown }`.

Hardening: http/https only · SSRF guard (refuses private/loopback) · 7s fetch timeout · 5 MB cap ·
content-type checked · CORS open for browser/agent use.

## Why this exists
The beachhead of a portfolio of pay-per-call tools for the AI-agent economy (see `../../EXPANSION.md`).
Every agent doing retrieval needs clean page text; nobody wants to build/maintain the extraction.

## Monetization layers (added after it's live + getting calls)
1. **RapidAPI** listing (free + paid tiers; marketplace billing + 4M devs).
2. **Apify Actor** wrapper (pay-per-result; 80% payout).
3. **MCP server** wrapper so agents can call it as a native tool.
4. **x402 paywall** (HTTP 402 → agent pays USDC per call, no signup) for the agent-native upside.

## Dev
```
npm install
node test/local.cjs      # real-fetch end-to-end test
```
Deploy: from this folder, via the Vercel deploy tool (zero-config: static `index.html` + `api/` function).
