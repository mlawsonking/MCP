# Deterministic guards and tools for AI agents

Six small tools that AI agents and developers call constantly, each available both as a plain HTTP API and as an MCP server. No LLM in the loop, and no accounts or API keys for the free tier. Same input, same output. Boring and reliable on purpose.

Five of them are guards: one check per risky action an agent takes, such as installing a package, reading untrusted text or email, following a link, sending money, or writing code. The sixth is a utility set for reading and parsing the web. All are free to run, with paid tiers on RapidAPI for higher volume.

## The tools

| Tool | What it checks | Install (MCP) | API | RapidAPI |
|---|---|---|---|---|
| Package Guard | A package before install: does it exist (slopsquat), vulns, malware, typosquats | `npx -y package-guard-mcp` | [live](https://package-guard.vercel.app) | [listing](https://rapidapi.com/mlawsonking/api/package-guard) |
| Agent Firewall | Untrusted input: prompt injection, leaked secrets/PII, URL and IP reputation | `npx -y agent-firewall-mcp` | [live](https://agent-firewall-seven.vercel.app) | [listing](https://rapidapi.com/mlawsonking/api/agent-firewall) |
| Payment Guard | A payee before sending: OFAC sanctions, scam lists, honeypot tokens, ENS spoofs | `npx -y payment-guard-mcp` | [live](https://payment-guard.vercel.app) | [listing](https://rapidapi.com/mlawsonking/api/payment-guard) |
| Email Guard | Inbound mail for injection/phishing, outbound for secret leaks and deliverability | `npx -y email-guard-mcp` | [live](https://email-guard-api.vercel.app) | [listing](https://rapidapi.com/mlawsonking/api/email-guard) |
| Code Guard | AI-generated code: injection, SSRF, secrets, weak crypto, unsafe deserialization | `npx -y @mlawsonking/code-guard-mcp` | [live](https://code-guard-api.vercel.app) | [listing](https://rapidapi.com/mlawsonking/api/code-guard) |
| Agent Web Tools | Web utilities: page to Markdown, metadata, CSS scrape, RSS, DNS, RDAP, SSL, HTTP | `npx -y web-tools-mcp` | [live](https://agent-tools-api.vercel.app) | [listing](https://rapidapi.com/mlawsonking/api/agent-web-tools) |

## Quick start (MCP)

Add any or all to your client config (Claude Desktop, Cursor, Claude Code, and so on):

```json
{
  "mcpServers": {
    "package-guard":  { "command": "npx", "args": ["-y", "package-guard-mcp"] },
    "agent-firewall": { "command": "npx", "args": ["-y", "agent-firewall-mcp"] },
    "payment-guard":  { "command": "npx", "args": ["-y", "payment-guard-mcp"] },
    "email-guard":    { "command": "npx", "args": ["-y", "email-guard-mcp"] },
    "code-guard":     { "command": "npx", "args": ["-y", "@mlawsonking/code-guard-mcp"] },
    "web-tools":      { "command": "npx", "args": ["-y", "web-tools-mcp"] }
  }
}
```

## Each one

### Package Guard  (`package-guard-mcp`)
`verify_package` (does it exist, else likely a hallucination or slopsquat, with suggestions), `check_vulns` (OSV), `package_info`, `audit_deps`, `typosquat_scan`. Ecosystems: npm, PyPI, Go, crates.io, RubyGems, Maven, NuGet. Data: OSV.dev, npm, PyPI. API: https://package-guard.vercel.app. Code: [`package-guard-mcp/`](package-guard-mcp/) and [`package-guard/`](package-guard/).

### Agent Firewall  (`agent-firewall-mcp`)
`scan_content` (prompt injection, jailbreak, hidden-text obfuscation), `scan_secrets` (secrets and PII, with a redacted copy), `check_url`, `check_ip`, `check_password` (HIBP, k-anonymity). Data: HIBP, RDAP, Tor, Team Cymru, DNS. API: https://agent-firewall-seven.vercel.app. Code: [`agent-firewall-mcp/`](agent-firewall-mcp/) and [`agent-firewall/`](agent-firewall/).

### Payment Guard  (`payment-guard-mcp`)
`screen_address` (address or ENS to a safe/caution/block verdict), `screen_payment` (x402 or merchant URL), `check_sanctioned` (fast OFAC), `resolve_name` (ENS, screened), `screen_token` (honeypot, rug, and tax risk via on-chain simulation). Data: OFAC SDN, ethereum-lists, ScamSniffer, honeypot.is, public RPC, ENS. Chains: Ethereum, Base, Polygon, Arbitrum, Optimism. API: https://payment-guard.vercel.app. Code: [`payment-guard-mcp/`](payment-guard-mcp/) and [`payment-guard/`](payment-guard/).

### Email Guard  (`email-guard-mcp`)
`scan_inbound` (injection and phishing hidden in a message, before the agent acts), `scan_outbound` (secret and PII leaks, deliverability), `check_domain_auth` (SPF, DMARC, MX, domain age, disposable). Data: DNS, RDAP, disposable-domain lists. API: https://email-guard-api.vercel.app. Code: [`email-guard-mcp/`](email-guard-mcp/) and [`email-guard/`](email-guard/).

### Code Guard  (`@mlawsonking/code-guard-mcp`)
`scan_code` and `scan_diff` (command, code, and SQL injection, SSRF, hardcoded secrets, weak crypto, unsafe deserialization, disabled TLS, XSS), `list_rules` (the rule catalog). API: https://code-guard-api.vercel.app. Code: [`code-guard-mcp/`](code-guard-mcp/) and [`code-guard/`](code-guard/).

### Agent Web Tools  (`web-tools-mcp`)
`read_url` (page to clean Markdown), `unfurl_url`, `validate_email`, `extract_web` (CSS scrape), `get_feed` (RSS/Atom), `dns_lookup`, `domain_info` (RDAP), `ssl_check`, `http_inspect`, `structured_data`. API: https://agent-tools-api.vercel.app. Code: [`agent-tools-mcp/`](agent-tools-mcp/) and [`agent-tools-api/`](agent-tools-api/).

## How they're built

http and https only, a DNS-resolved SSRF guard, request timeouts, response size caps, and content-type checks. Deterministic, no LLM, no paid data sources. Each API is a serverless function on a free tier, and the MCP servers are thin stdio wrappers that call the same endpoints.

## License

MIT, see [LICENSE](LICENSE). Contributions and tool suggestions welcome.
