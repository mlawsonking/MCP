# Deterministic checks for AI agents, with the misses written down

![tests](https://github.com/mlawsonking/MCP/actions/workflows/test.yml/badge.svg)

Deterministic detection of known attack patterns against the things an agent does: installing a package, reading untrusted text or email, following a link, sending money, writing code. No LLM anywhere in the detection path. Same input, same verdict, every time, with a rule id and a ruleset version attached to each one. Free, MIT, and the complete product runs locally.

**This is a tripwire, not a blocker.** It detects patterns it has rules for. It does not stop an attacker who reads those rules, and the rules are public. What determinism buys is not protection, it is evidence: a verdict you can reproduce, diff between commits, and put in a check that fails when your agent's exposure changes.

## How well it works, measured

[CORPUS.md](CORPUS.md) is the answer, produced by running `node scripts/corpus-report.js`. Nothing in it is an estimate and CI fails if a case stops behaving the way it is recorded.

<!-- corpus:start -->
| category | caught | rate | false positives |
| --- | --- | --- | --- |
| injection | 3/7 | 43% | 0/0 |
| obfuscation | 5/5 | 100% | 0/0 |
| email-transport | 5/5 | 100% | 0/1 |
| shell-rewrite | 11/13 | 85% | 0/5 |
| secrets | 4/4 | 100% | 0/2 |
| package-name | 4/6 | 67% | 0/3 |
| **all** | **32/40** | **80%** | **0/11** |
<!-- corpus:end -->

The injection row is the honest one: 3 of 7. Reword an attack and the rules score it zero, and four such rewordings live in the corpus as recorded misses. The false-positive column is zero across 11 ordinary cases, which matters just as much, because a checker that fires on `git commit -m "fix $(whoami) thing"` gets switched off and then detects nothing at all.

Every claim on this page maps to a case in [the corpus](agent-guards/corpus/index.js). If a sentence here cannot be reproduced by running it, it should not be here.

## What it is, and what it is not

Every check is a regex against a known pattern, a Unicode or structural test, or a lookup against a public list: OSV, OFAC, HIBP, Spamhaus, DNS, RDAP, an Ethereum RPC node. Nothing here is a classifier and nothing here understands what it reads. Where a check could not run, the response says so and never reports a pass in its place. For an actual boundary you want permissions or a sandbox, and you should run both.

Guide: [Why your AI agent needs deterministic guardrails](https://dev.to/mlawsonking/why-your-ai-agent-needs-deterministic-guardrails-and-how-to-add-one-in-a-few-lines-2l6j).

## The tools

The hosted URLs are a free shared mirror of the same engines, rate-limited and with no SLA. There is no paid tier: if you need volume or privacy, run it locally, where there is no limit and nothing leaves the machine.

| Tool | What it checks | Install (MCP) | Hosted mirror |
|---|---|---|---|
| Package Guard | A package before install: does it exist (slopsquat), OSV vulns and malware advisories, typosquats | `npx -y package-guard-mcp` | [live](https://package-guard.vercel.app) |
| Agent Firewall | Untrusted input: 11 injection/jailbreak patterns, 5 hidden-text signals, 22 secret and 3 PII patterns, URL and IP reputation | `npx -y agent-firewall-mcp` | [live](https://agent-firewall-seven.vercel.app) |
| Payment Guard | A payee before sending: OFAC EVM address lists, scam lists, honeypot simulation, ENS resolved then screened | `npx -y payment-guard-mcp` | [live](https://payment-guard.vercel.app) |
| Email Guard | Inbound mail for the same injection patterns plus phishing signals, outbound for secret leaks and deliverability | `npx -y email-guard-mcp` | [live](https://email-guard-api.vercel.app) |
| Code Guard | AI-generated code: 31 regex rules across 12 categories (injection, SSRF, weak crypto, unsafe deserialization, XSS), plus the shared secret patterns | `npx -y @mlawsonking/code-guard-mcp` | [live](https://code-guard-api.vercel.app) |
| Agent Web Tools | Web utilities: page to Markdown, metadata, JSON-LD, email MX, CSS scrape, RSS, DNS, RDAP, SSL, HTTP | `npx -y web-tools-mcp` | [live](https://agent-tools-api.vercel.app) |

## In Claude Code: the plugin

The checks above are most useful when nobody has to remember to call them. This repository is also a
Claude Code plugin marketplace, and the plugin puts three of these engines in the path of what the
agent already does:

```
/plugin marketplace add mlawsonking/MCP
/plugin install agent-guards@agent-guards
```

Before a Bash command runs, the package names in it are checked and a typosquat is stopped. After an
Edit or a Write, the lines that just changed are scanned for credentials and dangerous code patterns.
After a WebFetch, the content is scanned for injection phrasings and the Unicode tricks used to hide
them. It also brings a `guard` command for scanning a file, a diff or a dependency on demand, and for
pre-commit hooks and CI.

No hook makes a network call, the whole thing needs Node 18 and nothing else, and it is quiet unless
it has something to say. The measured cost is 64 to 96 ms per tool call, and the measured
false-positive rate is in the [plugin README](agent-guards-plugin/), along with what each check does
not do.

## Quick start (MCP)

The simplest install is one local server with all 31 tools:

```json
{
  "mcpServers": {
    "agent-guards": { "command": "npx", "args": ["-y", "agent-guards"] }
  }
}
```

Copy-paste instructions for [Cursor](recipes/cursor.md), [Cline](recipes/cline.md),
[Windsurf](recipes/windsurf.md), [LangChain/LangGraph](recipes/langchain-langgraph.md), and a
[plain MCP host](recipes/mcp.md) are in `recipes/`.

If you only want one product, add any or all of the thin facades instead:

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
`scan_content` runs 11 regex rules for known injection and jailbreak phrasings, plus 5 obfuscation signals: zero-width characters, bidi overrides, Unicode tag-block smuggling, hidden CSS, and instructions buried in HTML comments. It adds the weights of whatever matched into a 0-100 score. The verdict is that score against two thresholds, 15 for review and 35 for block, and nothing more. An attack that matches none of the 11 rules and none of the 5 signals scores zero, and the verdict comes back allow. `scan_secrets` runs 22 secret patterns and 3 PII patterns and hands back a redacted copy of the text. `check_url`, `check_ip`, `check_password` (HIBP, k-anonymity). Data: HIBP, RDAP, Tor, Team Cymru, DNS. API: https://agent-firewall-seven.vercel.app. Code: [`agent-firewall-mcp/`](agent-firewall-mcp/) and [`agent-firewall/`](agent-firewall/).

### Payment Guard  (`payment-guard-mcp`)
`screen_address` (address or ENS to a safe/caution/block verdict), `screen_payment` (x402 or merchant URL), `check_sanctioned` (fast OFAC), `resolve_name`, `screen_token` (honeypot, rug and tax risk via a simulated buy and sell on honeypot.is).

The sanctions check unions every EVM-format OFAC SDN list (ETH, ARB, BSC, ETC, USDC, USDT), because OFAC lists addresses by currency rather than by chain, so one `0x` address is checked against all six. Bitcoin, Tron, Solana, Monero and the rest are on the SDN list and this API cannot accept those address formats, so "not sanctioned" means "absent from the six EVM lists" and nothing else. `resolve_name` resolves an ENS name and screens the address it points at; there is no lookalike or homoglyph check on the name itself. Honeypot simulation is Ethereum and Base only, because honeypot.is returns "Invalid chain" for the other three. Data: OFAC SDN, ethereum-lists, ScamSniffer, honeypot.is, public RPC, ENS. Chains: Ethereum, Base, Polygon, Arbitrum, Optimism. API: https://payment-guard.vercel.app. Code: [`payment-guard-mcp/`](payment-guard-mcp/) and [`payment-guard/`](payment-guard/).

### Email Guard  (`email-guard-mcp`)
`scan_inbound` (the same 11 injection rules and 5 obfuscation signals, run over the subject, body and HTML part before the agent acts, plus sender and link checks), `scan_outbound` (secret and PII leaks, deliverability), `check_domain_auth` (SPF, DMARC, MX, domain age, disposable).

SPF and DMARC are read from DNS. DKIM is not checked: the record lives at `<selector>._domainkey.<domain>` and a domain name alone does not reveal the selector. When a message carries an `Authentication-Results` header I report what it says and mark the result `verified_here: false`. I don't verify the signature and I don't look up any DKIM record. In a raw .eml from someone you don't trust, that header is just text the attacker typed. Data: DNS, RDAP, disposable-domain lists. API: https://email-guard-api.vercel.app. Code: [`email-guard-mcp/`](email-guard-mcp/) and [`email-guard/`](email-guard/).

### Code Guard  (`@mlawsonking/code-guard-mcp`)
`scan_code` and `scan_diff` run 31 regex rules across 12 categories: command, code and SQL injection, SSRF, weak crypto, unsafe deserialization, disabled TLS, XSS, SSTI, auth, misconfiguration and logic. Hardcoded credentials are not one of those 31. They come from the shared scanner, the same 22 secret and 3 PII patterns Agent Firewall uses, reported under `hardcoded-*` ids. Coverage is JavaScript/TypeScript, Python, and patterns that apply to any language. `list_rules` returns the catalog. Every rule is a regex tested against one line at a time, so there is no data-flow analysis: anything split across two lines is invisible, and safe code that happens to look like a rule gets flagged. API: https://code-guard-api.vercel.app. Code: [`code-guard-mcp/`](code-guard-mcp/) and [`code-guard/`](code-guard/).

### Agent Web Tools  (`web-tools-mcp`)
`read_url` (page to clean Markdown), `unfurl_url`, `validate_email`, `extract_web` (CSS scrape), `get_feed` (RSS/Atom), `dns_lookup`, `domain_info` (RDAP), `ssl_check`, `http_inspect`, `structured_data`. API: https://agent-tools-api.vercel.app. Code: [`agent-tools-mcp/`](agent-tools-mcp/) and [`agent-tools-api/`](agent-tools-api/).

## How they're built

http and https only. The SSRF guard resolves the hostname and rejects private and loopback addresses, and it re-runs on every redirect hop rather than only the first URL, up to 5 hops. Outbound requests time out between 6 and 9 seconds: 7 for a page fetch, an OSV query or an on-chain RPC call, 6 for the Tor, RDAP and disposable-domain lists, 8 for the OFAC and scam lists, 9 for honeypot.is. Fetched responses are capped at 3 MB and the content type is checked. Deterministic, no LLM, no paid data sources. Each API is a serverless function on a free tier, and the MCP servers are thin stdio wrappers that call the same endpoints. The tests behind these claims run on every push; see the badge at the top.

## What I collect

One endpoint per product sends an event to PostHog: `scan-content`, `scan-inbound`, `scan-code`, `verify-package`, `screen-address` and `read`. The other 33 endpoints send nothing. The event carries a caller id hashed with SHA-256 (from the RapidAPI user, the `Authorization` header, or the IP), the user-agent, the referer, the origin, which endpoint was hit, and two flags worked out from the user-agent and referer: browser or API caller, and whether the call came from the demo page. It is pseudonymous, not anonymous: the same caller hashes to the same id. No request body, scanned text, address, or email content is ever sent. The code is `shared/lib/common.js`, and it does nothing without a `POSTHOG_KEY` set.

## Who wrote this

I built this solo, with heavy use of AI agents. The rules are covered by the test suite that runs in CI, and every claim in this README is mine.

## License

MIT, see [LICENSE](LICENSE). Contributions and tool suggestions welcome.
