# agent-firewall-mcp

An MCP server that treats every external input as untrusted. It scans text for prompt injection, checks URLs and IPs, screens for leaked secrets and PII, and checks passwords against known breaches. Deterministic, no LLM, free.

The basic rule for agent security (OWASP's LLM01) is to treat anything the agent reads from the outside as potentially hostile: web pages, tool output, files, user input. These are the checks for doing that at the point where the content comes in, before it reaches the model.

## Install

```json
{ "mcpServers": { "agent-firewall": { "command": "npx", "args": ["-y", "agent-firewall-mcp"] } } }
```

## Tools

- `scan_content`: detect prompt injection, jailbreak attempts, and hidden-text obfuscation (zero-width characters, bidi tricks, hidden HTML) in text or a fetched URL. Returns allow, review, or block.
- `scan_secrets`: find leaked API keys, tokens, and private keys, plus PII (Luhn-checked card numbers, SSNs, emails). Returns the findings and a redacted copy of the text.
- `check_url`: URL and domain safety, using structural heuristics, domain age from RDAP, and the redirect chain. Returns safe, suspicious, or malicious.
- `check_ip`: IP reputation, covering Tor exit nodes, ASN and org (via Team Cymru), reverse DNS, whether it's a datacenter address, and blocklist status.
- `check_password`: check a password against HIBP's Pwned Passwords using k-anonymity, so the plaintext never leaves the server.

Data comes from HIBP, RDAP, the Tor Project, Team Cymru, DNS, and curated rulesets. It calls https://agent-firewall-seven.vercel.app (set `AGENT_FIREWALL_API` to override). One of six agent guards in this repo. MIT.
