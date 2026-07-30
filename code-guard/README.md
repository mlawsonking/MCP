# Code Guard

Security scanner for **AI-generated code** — the check a coding agent runs on its *own* code or diff **before it
commits**. Deterministic, free, **no LLM**. Live: **https://code-guard-api.vercel.app**

A coding agent writes a patch and commits it in the same breath. Nothing cheap sits in that loop and reads
the diff first. Code Guard is that first-line scanner: a deterministic rule engine for the high-frequency
classes. It is **not** a replacement for a real audit.

| Endpoint | What it does |
|---|---|
| `POST /api/scan-code` | Scan a code snippet → findings `{rule, category, severity, line, code, message, remediation}` + verdict `pass`/`review`/`block` |
| `POST /api/scan-diff` | Scan only the **added lines** of a unified diff (with correct new-file line numbers) |
| `GET /api/rules` | The rule catalog (coverage transparency): id, category, severity and language per entry |

**Detects:** command / code / SQL injection · SSRF (heuristic) · hardcoded secrets & API keys · weak crypto
(MD5/SHA1, ECB, DES, insecure RNG) · unsafe deserialization (pickle/yaml/marshal/node-serialize) · disabled TLS
verification · XSS / server-side template injection · misconfig (Flask debug, JWT alg=none).
31 code rules across 12 categories, each with a stable ID, plus hardcoded-secret detection covering 12
credential patterns and 3 personal-data patterns (email, US SSN, card number), all under `hardcoded-*` ids.
`GET /api/rules` returns 32 entries because it lists the secret and PII rules as one grouped `hardcoded-*`
entry. Every scan response carries the `rules_version` that produced it.

**Languages:** JS/TS and Python. That is the whole list. 11 rules are JS/TS, 14 are Python, 6 are
language-agnostic. There is no Go, Ruby, PHP, Java or Rust ruleset. A `language` I don't recognise is
ignored. I sniff the source instead and land on one of three answers, `js`, `py` or `unknown`. Which one
you get depends on what the file happens to contain. `import java.util.List;` reads as Python. A Go
file with a `const` line reads as JavaScript. A Go file with nothing but `func` and `import "fmt"` lands
on `unknown`, and then all 31 rules run against every line, which catches more and flags more things that
are not bugs. Outside JS/TS and Python, count on the 6 language-agnostic rules and the secret scan.
Anything else you get is luck.

The 31 code rules are regexes matched one line at a time. No parser, no data flow, no taint tracking, so
it isn't static analysis in the sense a SAST vendor means it. That cuts both ways.
`db.query("SELECT ... " + id)` is caught on one line and missed the moment you split it across two. The
word `DES` on a line trips weak-cipher, comment or variable name included (`DES_KEY` does not, the rule is
whole-word). The `hardcoded-*` patterns are the exception: those run over the whole source, so a PEM
private-key block spanning several lines is still caught. Treat a clean result as "none of my 31 rules
matched", not as "this code is safe".

```bash
curl -s -X POST https://code-guard-api.vercel.app/api/scan-code -H 'Content-Type: application/json' \
  -d '{"language":"python","code":"os.system(\"echo \"+x)\nobj=pickle.loads(d)"}'
# { "verdict":"block", "counts":{"critical":2,...}, "findings":[{ "id":"py-os-system","line":1,... }] }
```

Deterministic (same input → same output). Reuses the Agent Firewall secret-scanner. MCP server:
[`code-guard-mcp`](https://www.npmjs.com/package/code-guard-mcp). Part of the agent-guardrail suite:
Package Guard · Agent Firewall · Payment Guard · Email Guard · **Code Guard**.
