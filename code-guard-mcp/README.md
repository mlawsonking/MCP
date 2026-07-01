# code-guard-mcp

An MCP server that scans code for security bugs. A coding agent calls it on the code or diff it just produced, before committing or running it. Rule-based, no LLM, free.

More than half of new code is AI-assisted now, and a fair amount of it ships with the usual problems: injection, hardcoded secrets, disabled TLS checks, unsafe deserialization. This catches the common cases in one call. Treat it as a fast first pass, not a substitute for a real security review.

## Install

Add it to your MCP client config (Claude Desktop, Cursor, Claude Code, and so on):

```json
{ "mcpServers": { "code-guard": { "command": "npx", "args": ["-y", "@mlawsonking/code-guard-mcp"] } } }
```

## Tools

- `scan_code`: scan a snippet. Returns a verdict (pass, review, or block) and a list of findings, each with the rule, category, severity, line number, and a suggested fix. Covers command, code, and SQL injection, SSRF, hardcoded secrets and API keys, weak crypto, unsafe deserialization (pickle, yaml), disabled TLS verification, and XSS or template injection.
- `scan_diff`: the same scan, but only on the added lines of a unified diff, with correct new-file line numbers. Useful inside a commit loop.
- `list_rules`: the full rule catalog, so you can see what it checks and what it doesn't.

Same input always gives the same output. It calls the API at https://code-guard-api.vercel.app (set `CODE_GUARD_API` to point at your own copy). One of six agent guards in this repo: package-guard, agent-firewall, payment-guard, email-guard, code-guard, and web-tools. MIT.
