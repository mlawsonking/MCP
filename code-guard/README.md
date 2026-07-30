# Code Guard

Security scanner for **AI-generated code** — the check a coding agent runs on its *own* code or diff **before it
commits**. Deterministic, free, **no LLM**. Live: **https://code-guard-api.vercel.app**

53% of code is now AI-written and ~25% of it ships vulnerable, yet nothing scans it *in the agent's loop* for free.
Code Guard is that first-line scanner — a deterministic rule engine for the high-frequency classes (it is **not** a
full audit replacement).

| Endpoint | What it does |
|---|---|
| `POST /api/scan-code` | Scan a code snippet → findings `{rule, category, severity, line, code, message, remediation}` + verdict `pass`/`review`/`block` |
| `POST /api/scan-diff` | Scan only the **added lines** of a unified diff (with correct new-file line numbers) |
| `GET /api/rules` | The rule catalog (coverage transparency), grouped by category |

**Detects:** command / code / SQL injection · SSRF (heuristic) · hardcoded secrets & API keys · weak crypto
(MD5/SHA1, ECB, DES, insecure RNG) · unsafe deserialization (pickle/yaml/marshal/node-serialize) · disabled TLS
verification · XSS / server-side template injection · misconfig (Flask debug, JWT alg=none). Languages: JS/TS, Python,
+ language-agnostic rules. 31 code rules across 12 categories, each with a stable ID, plus hardcoded-secret
detection covering 12 credential patterns. `GET /api/rules` returns 32 entries because it lists the secret
rules as one grouped `hardcoded-*` entry. Every scan response carries the `rules_version` that produced it.

These are regex rules, not a compiler. They read text, not program structure, so they find the patterns
they know and miss anything spelled differently. Treat a clean result as "none of my 31 rules matched",
not as "this code is safe".

```bash
curl -s -X POST https://code-guard-api.vercel.app/api/scan-code -H 'Content-Type: application/json' \
  -d '{"language":"python","code":"os.system(\"echo \"+x)\nobj=pickle.loads(d)"}'
# { "verdict":"block", "counts":{"critical":2,...}, "findings":[{ "id":"py-os-system","line":1,... }] }
```

Deterministic (same input → same output). Reuses the Agent Firewall secret-scanner. MCP server:
[`code-guard-mcp`](https://www.npmjs.com/package/code-guard-mcp). Part of the agent-guardrail suite:
Package Guard · Agent Firewall · Payment Guard · Email Guard · **Code Guard**.
