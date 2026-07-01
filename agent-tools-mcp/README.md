# web-tools-mcp

An MCP server with a set of web utilities for AI agents: read a page as Markdown, pull link metadata, scrape with CSS selectors, parse feeds, and run DNS, RDAP, SSL, and HTTP checks. Deterministic, no LLM, and no API keys needed for the free tier.

## Install

```json
{ "mcpServers": { "web-tools": { "command": "npx", "args": ["-y", "web-tools-mcp"] } } }
```

## Tools

- `read_url`: fetch a page and return the main content as clean Markdown, with the nav and ads stripped out. Good for RAG.
- `unfurl_url`: get a URL's title, description, preview image, site name, and favicon.
- `validate_email`: syntax check plus a live MX lookup, with disposable, role, and free-provider detection.
- `extract_web`: scrape a page with CSS selectors and get back the fields you asked for.
- `get_feed`: fetch an RSS or Atom feed and return the items as JSON.
- `dns_lookup`: DNS records (A, AAAA, MX, NS, TXT, and the rest) plus SPF and DMARC detection.
- `domain_info`: registration details via RDAP, including domain age, registrar, and expiry.
- `ssl_check`: inspect a host's TLS certificate: issuer, validity window, days until expiry, and SANs.
- `http_inspect`: final status, the full redirect chain, response headers, and a security-header report.
- `structured_data`: extract JSON-LD, OpenGraph, and Twitter card data from a page.

It calls the API at https://agent-tools-api.vercel.app (set `TOOLS_API_URL` if you self-host). One of six agent tools and guards in this repo: package-guard, agent-firewall, payment-guard, email-guard, code-guard, and web-tools. MIT.
