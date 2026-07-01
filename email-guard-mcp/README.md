# email-guard-mcp

An MCP server for email safety. It checks inbound mail before your agent acts on it, and outbound mail before your agent sends it. Deterministic, no LLM, free.

Once an agent can read and send email, the inbox turns into an attack surface. An incoming message can try to hijack the agent with instructions buried in the body, which people have started calling AI agent phishing. On the way out, an agent can leak a secret or send something that gets its sending domain flagged as spam.

## Install

```json
{ "mcpServers": { "email-guard": { "command": "npx", "args": ["-y", "email-guard-mcp"] } } }
```

## Tools

- `scan_inbound`: run this before acting on a message. It looks for injection and hijack instructions (including zero-width, bidi, and hidden-HTML tricks), spoofed or impersonating senders (SPF, DKIM, or DMARC failures, reply-to mismatches, disposable or brand-new domains), and risky links. It returns a verdict plus clean structured metadata, so the agent works from the facts instead of the raw, possibly poisoned, text.
- `scan_outbound`: run this before sending. It flags leaked secrets and PII (and returns a redacted copy), deliverability problems that hurt your sender reputation, and dead recipients (disposable domains, or no MX records, which guarantees a bounce).
- `check_domain_auth`: SPF, DMARC, MX, domain age, and disposable status for a domain or address. Returns weak or enforced.

Data comes from DNS (SPF, DKIM, DMARC, MX), RDAP for domain age, disposable-domain lists, and injection and secret rulesets. Same input always gives the same output. It calls https://email-guard-api.vercel.app (set `EMAIL_GUARD_API` to override). One of six agent guards in this repo. MIT.
