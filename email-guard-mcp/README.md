# email-guard-mcp

Email safety for AI agents — as an MCP server. Deterministic, free, **no LLM**.

**Why:** agents now read and send email, which makes the inbox the newest attack surface. Inbound, a malicious
email can hijack the agent via **prompt injection hidden in the body** ("AI agent phishing"). Outbound, an agent
can leak secrets or **burn its sender domain**. Email Guard is the deterministic check for both.

## Tools
- **`scan_inbound`** — before the agent acts on an email: prompt-injection / hijack instructions (including hidden
  zero-width, bidi, and HTML payloads), spoofed / impersonating senders (SPF/DKIM/DMARC fail, brand impersonation,
  reply-to mismatch, disposable or brand-new domains), and risky links → **verdict** (allow/review/block) + **safe
  structured metadata** so you act on facts, not the raw injection-laden text.
- **`scan_outbound`** — before the agent sends: leaked secrets/API-keys + PII (returns a redacted copy),
  deliverability/spam problems that burn the sender domain, and recipient risk (disposable / no-MX bounce) → verdict.
- **`check_domain_auth`** — SPF/DMARC/MX/domain-age/disposable posture for a domain or email → `weak` / `enforced`.

## Install
```json
{ "mcpServers": { "email-guard": { "command": "npx", "args": ["-y", "email-guard-mcp"] } } }
```

Free public data: DNS (SPF/DMARC/MX), RDAP (domain age), disposable-domain lists, injection + secret rulesets.
No LLM, deterministic (same input → same output). API: https://email-guard-api.vercel.app · part of the
agent-guardrail suite (Package Guard · Agent Firewall · Payment Guard · Email Guard).
