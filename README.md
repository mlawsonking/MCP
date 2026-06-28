# Agent Tools — free web utilities for AI agents (MCP + APIs)

A small toolbox of **deterministic web utilities** that AI agents and developers call constantly —
exposed both as plain HTTP APIs and as a single **MCP server**. No LLM in the loop, no API keys for
the free tier, no tracking. Just reliable, boring, useful tools.

> 10 tools · one MCP server · all live on a free serverless tier.

## 🔌 The MCP server
[`agent-tools-mcp/`](agent-tools-mcp/) exposes all 10 tools to any MCP client (Claude Desktop, Cursor,
Claude Code, …).

```jsonc
// add to your client's mcpServers config
{
  "mcpServers": {
    "agent-tools": { "command": "npx", "args": ["-y", "web-tools-mcp"] }
  }
}
```
Or run from source: `cd agent-tools-mcp && npm install && node index.mjs`
(self-test: `node test/client.mjs` — lists and calls all 10 tools).

## 🧰 The tools (live endpoints)
| Tool | Endpoint | Returns |
|------|----------|---------|
| `read_url` | `url-to-markdown-three.vercel.app/api/read` | page → clean Markdown (RAG) |
| `unfurl_url` | `url-metadata-three.vercel.app/api/meta` | title/description/image/favicon |
| `validate_email` | `agent-tools-api.vercel.app/api/validate-email` | syntax + MX/A DNS + disposable/role |
| `extract_web` | `agent-tools-api.vercel.app/api/extract` | CSS-selector scrape → JSON |
| `get_feed` | `agent-tools-api.vercel.app/api/feed` | RSS/Atom → JSON items |
| `dns_lookup` | `agent-tools-api.vercel.app/api/dns` | DNS records + SPF/DMARC |
| `domain_info` | `agent-tools-api.vercel.app/api/domain` | RDAP: age, registrar, expiry |
| `ssl_check` | `agent-tools-api.vercel.app/api/ssl` | TLS cert, days-to-expiry, trust |
| `http_inspect` | `agent-tools-api.vercel.app/api/http` | redirect chain + security headers |
| `structured_data` | `agent-tools-api.vercel.app/api/structured` | JSON-LD / schema.org / OpenGraph |

Every endpoint: `GET ?url=` (or `?domain=`/`?email=`), JSON out, CORS open. Try one in a browser.

## 🛡️ Built right
http/https only · DNS-resolved **SSRF guard** · request timeouts · response size caps ·
content-type checks. Deterministic — same input, same output. No LLM, no paid data sources.

## Repo layout
- `agent-tools-mcp/` — the MCP server (wraps all 10 tools)
- `agent-tools-api/` — the multi-endpoint API (email, extract, feed, dns, domain, ssl, http, structured)
- `url-to-markdown/`, `url-metadata/` — the two reader APIs

## License
MIT — see [LICENSE](LICENSE). Contributions and tool suggestions welcome.
