# agent-firewall-mcp

**Input/output safety gate for AI agents, as an MCP server.** The 2026 doctrine (OWASP LLM01): *treat
every external input the agent touches as hostile.* Google measured a **+32% surge** in prompt-injection
payloads embedded in web content over three months of 2026.

```jsonc
{ "mcpServers": { "agent-firewall": { "command": "npx", "args": ["-y", "agent-firewall-mcp"] } } }
```

## Tools
- **`scan_content`** — detect prompt injection / jailbreak / obfuscation (zero-width, bidi, hidden HTML) in text or a fetched URL → `allow`/`review`/`block`.
- **`scan_secrets`** — detect leaked API keys/tokens/private-keys + PII (Luhn-checked cards, SSNs, emails) → findings + a **redacted** copy.
- **`check_url`** — URL/domain safety: heuristics + domain age (RDAP) + redirect chain → `safe`/`suspicious`/`malicious`.
- **`check_ip`** — IP reputation: Tor exit, ASN/org (Team Cymru), reverse DNS, datacenter, blocklist → verdict.
- **`check_password`** — is a password in a known breach? HIBP Pwned Passwords (k-anonymity; plaintext never leaves the server).

Deterministic, free, no LLM. Data: HIBP, RDAP, Tor Project, Team Cymru, DNS + curated rulesets.
Backed by the live API `https://agent-firewall-seven.vercel.app` (override with `AGENT_FIREWALL_API`).
Part of the [Agent Tools](https://github.com/mlawsonking/MCP) family. MIT.
