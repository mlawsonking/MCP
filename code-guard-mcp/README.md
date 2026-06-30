# code-guard-mcp

Security scanner for **AI-generated code**, as an MCP server — the check a coding agent runs on its *own* code or
diff **before it commits**. Deterministic, free, **no LLM**.

**Why:** 53% of code is now AI-written and ~25% ships vulnerable, yet nothing scans it *in the agent's loop* for
free. Code Guard is that fast first-line scanner (not a full audit replacement).

## Tools
- **`scan_code`** — scan a snippet → findings `{rule, category, severity, line, message, remediation}` + verdict
  `pass`/`review`/`block`. Detects command/code/SQL injection, SSRF, hardcoded secrets, weak crypto, unsafe
  deserialization (pickle/yaml), disabled TLS verification, XSS / template injection.
- **`scan_diff`** — scan only the **added lines** of a unified diff (correct new-file line numbers).
- **`list_rules`** — the rule catalog (coverage transparency).

## Install
```json
{ "mcpServers": { "code-guard": { "command": "npx", "args": ["-y", "code-guard-mcp"] } } }
```

Deterministic (same input → same output). API: https://code-guard-api.vercel.app · part of the agent-guardrail
suite (Package Guard · Agent Firewall · Payment Guard · Email Guard · Code Guard).
