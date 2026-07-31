# agent-firewall-mcp

An MCP server that treats every external input as untrusted. It matches text against known prompt-injection patterns, checks URLs and IPs, screens for leaked secrets and PII, and checks passwords against known breaches. Deterministic, no LLM, free.

The basic rule for agent security (OWASP's LLM01) is to treat anything the agent reads from the outside as potentially hostile: web pages, tool output, files, user input. These are the checks for doing that at the point where the content comes in, before it reaches the model.

## Install

```json
{ "mcpServers": { "agent-firewall": { "command": "npx", "args": ["-y", "agent-firewall-mcp"] } } }
```

## Tools

- `scan_content`: match text or a fetched URL against 11 known prompt-injection and jailbreak patterns, plus 5 obfuscation checks (zero-width characters, bidi tricks, the Unicode tag block, CSS-hidden text, HTML-comment instructions). Returns allow, review, or block, and the rule IDs that fired. It is a pattern matcher, not a classifier: a novel phrasing or a paraphrase will not be caught, and `allow` means nothing matched rather than that the content is safe.
- `scan_secrets`: match text against 22 secret patterns — AWS access key ids, GitHub tokens, OpenAI, Anthropic, Google API keys, Slack, Stripe live secret keys, Twilio, npm tokens, JWTs, PEM private-key blocks, Azure storage keys, SAS tokens and AD client secrets, GCP service-account key ids and OAuth refresh tokens, database and ODBC connection-string passwords, SendGrid, GitLab, Hugging Face, and a generic `key = "value"` assignment — and 3 PII patterns: email, US SSN, Luhn-checked card numbers. A credential from a vendor not on that list is not found unless it happens to be written as one of those assignments, and that rule is narrow: `api-key = "abc12345"` matches, `{"api_key": "abc12345"}` does not, and an unquoted value does not. A clean result is not proof the text is clean. Returns the findings (masked) and a redacted copy: the secret value is replaced and the label stays, `api_key = "[REDACTED:Generic Secret Assignment]"`. The line is not dropped and the document is not scrubbed. A PEM block is removed in full.
- `check_url`: URL and domain safety, using structural heuristics (punycode host, 14 known shorteners, 23 abuse-prone TLDs, raw-IP host, credentials in the URL, brand lookalikes), domain age from RDAP, and the final URL after redirects. "Brand lookalike" is a substring test — one of 14 brand names in the hostname that is not the registrable domain, like `paypal.com.secure-login.tk`. It is not edit distance and not homoglyphs, so `paypa1.com` gets past it. Only the final URL is re-checked, not every hop, and its flags only count when the redirect lands on a different host. Domain age is looked up for the host you passed in, not the host you land on. Returns safe, suspicious, or malicious.
- `check_ip`: IP reputation, covering Tor exit nodes (Tor Project bulk exit list), ASN and org (via Team Cymru), reverse DNS, whether the org name looks like a datacenter, and one DNSBL lookup: Spamhaus ZEN, IPv4 only. Spamhaus refuses queries from many cloud resolvers, so the lookup can be inconclusive; that comes back as `listed: null` with a note and adds nothing to the score. Only `listed: true` moves the verdict, so an inconclusive lookup ends up with the same verdict as a clean one — read `blocklist.listed` rather than the verdict alone.
- `check_password`: check a password against HIBP's Pwned Passwords using k-anonymity, so the plaintext never leaves the server.

Data comes from HIBP, RDAP, the Tor Project, Team Cymru, DNS, and curated rulesets. It calls https://agent-firewall-seven.vercel.app (set `AGENT_FIREWALL_API` to override). One of six agent guards in this repo. MIT.
