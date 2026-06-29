# Agent Tools — deterministic tools for AI agents (MCP + APIs)

A family of **deterministic** tools that AI agents and developers call constantly — each exposed both as
plain HTTP APIs **and** as an **MCP server**. No LLM in the loop, no API keys for the free tier, no
tracking. Same input → same output. Just reliable, boring, useful tools.

## The products

| Product | What it does | Install (MCP) | Live demo | Marketplace |
|---|---|---|---|---|
| **Agent Web Tools** | 10 web utilities: URL→Markdown, metadata, email validate, CSS scrape, RSS, DNS/RDAP/SSL/HTTP/structured-data | `npx -y web-tools-mcp` | [agent-tools-api.vercel.app](https://agent-tools-api.vercel.app) | [RapidAPI](https://rapidapi.com/mlawsonking/api/agent-web-tools) |
| **Package Guard** | Supply-chain guard for coding agents: verify a package exists (catch slopsquat/hallucinations), vulns/malware (OSV), typosquats, audit deps | `npx -y package-guard-mcp` | [package-guard.vercel.app](https://package-guard.vercel.app) | [RapidAPI](https://rapidapi.com/mlawsonking/api/package-guard) |
| **Agent Firewall** | Input/output safety: detect prompt-injection/jailbreak, vet URLs & IPs, pwned-password (HIBP), secret/PII redaction | `npx -y agent-firewall-mcp` | [agent-firewall-seven.vercel.app](https://agent-firewall-seven.vercel.app) | [RapidAPI](https://rapidapi.com/mlawsonking/api/agent-firewall) |
| **Payment Guard** | Pre-send risk check for agents that move money: screen a crypto address (or ENS name) / payment URL for OFAC sanctions, scams, and on-chain risk before a transfer | `npx -y payment-guard-mcp` | [payment-guard.vercel.app](https://payment-guard.vercel.app) | _RapidAPI: pending_ |

All four: deterministic, no LLM, free serverless tier; paid plans via RapidAPI for higher volume.
The last three form the **AI-agent safety suite**: Package Guard (supply chain) · Agent Firewall
(input/output) · Payment Guard (money).

## Quick start (MCP)
Add any or all to your client's `mcpServers` config (Claude Desktop, Cursor, Claude Code, …):

```jsonc
{
  "mcpServers": {
    "agent-tools":     { "command": "npx", "args": ["-y", "web-tools-mcp"] },
    "package-guard":   { "command": "npx", "args": ["-y", "package-guard-mcp"] },
    "agent-firewall":  { "command": "npx", "args": ["-y", "agent-firewall-mcp"] },
    "payment-guard":   { "command": "npx", "args": ["-y", "payment-guard-mcp"] }
  }
}
```

---

### 1) Agent Web Tools — 10 web utilities  ·  `web-tools-mcp`
| Tool | Endpoint | Returns |
|------|----------|---------|
| `read_url` | `/api/read` | page → clean Markdown (RAG) |
| `unfurl_url` | `/api/meta` | title/description/image/favicon |
| `validate_email` | `/api/validate-email` | syntax + MX/A DNS + disposable/role |
| `extract_web` | `/api/extract` | CSS-selector scrape → JSON |
| `get_feed` | `/api/feed` | RSS/Atom → JSON items |
| `dns_lookup` | `/api/dns` | DNS records + SPF/DMARC |
| `domain_info` | `/api/domain` | RDAP: age, registrar, expiry |
| `ssl_check` | `/api/ssl` | TLS cert, days-to-expiry, trust |
| `http_inspect` | `/api/http` | redirect chain + security headers |
| `structured_data` | `/api/structured` | JSON-LD / schema.org / OpenGraph |

Base: `https://agent-tools-api.vercel.app`. Code: [`agent-tools-mcp/`](agent-tools-mcp/) + [`agent-tools-api/`](agent-tools-api/).

### 2) Package Guard — supply-chain guard for coding agents  ·  `package-guard-mcp`
`verify_package` (the pre-install guard), `check_vulns` (OSV), `package_info`, `audit_deps`, `typosquat_scan`.
Data: OSV.dev + npm/PyPI. Base: `https://package-guard.vercel.app`. Code: [`package-guard-mcp/`](package-guard-mcp/) + [`package-guard/`](package-guard/).

### 3) Agent Firewall — input/output safety  ·  `agent-firewall-mcp`
`scan_content` (prompt-injection/jailbreak/obfuscation), `scan_secrets` (+ PII redaction), `check_url`,
`check_ip`, `check_password` (HIBP k-anonymity). Data: HIBP, RDAP, Tor, Team Cymru.
Base: `https://agent-firewall-seven.vercel.app`. Code: [`agent-firewall-mcp/`](agent-firewall-mcp/) + [`agent-firewall/`](agent-firewall/).

### 4) Payment Guard — pre-send risk check for agents that move money  ·  `payment-guard-mcp`
`screen_address` (address/ENS → OFAC-sanctioned? scam? on-chain risk → verdict), `screen_payment` (x402/
payment URL risk), `check_sanctioned` (fast OFAC), `resolve_name` (ENS → address, screened). Data: OFAC
SDN + ethereum-lists + ScamSniffer + public RPC + ENS. Chains: ETH/Base/Polygon/Arbitrum/Optimism.
Base: `https://payment-guard.vercel.app`. Code: [`payment-guard-mcp/`](payment-guard-mcp/) + [`payment-guard/`](payment-guard/).

---

## 🛡️ Built right
http/https only · DNS-resolved **SSRF guard** · request timeouts · response size caps · content-type
checks. Deterministic — same input, same output. No LLM, no paid data sources. Each API is a serverless
function on a free tier; the MCP servers are thin stdio wrappers that call the same endpoints.

## License
MIT — see [LICENSE](LICENSE). Contributions and tool suggestions welcome.
