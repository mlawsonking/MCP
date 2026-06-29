# Package Guard

**The pre-install supply-chain guard for AI coding agents.** Before your agent runs `npm install` or
`pip install`, it should ask one question: *is this package real, safe, and the one I actually meant?*

In 2026, ~20% of package names LLMs recommend **don't exist** — and attackers register those
hallucinated names ("slopsquatting") to poison agents. Package Guard catches that in one call.

Free. Deterministic (no LLM). Backed by [OSV.dev](https://osv.dev) + the npm/PyPI registries.

## Tools (HTTP + MCP)

| Endpoint | What it does |
|---|---|
| `GET /api/verify-package` | **The guard.** Exists? (else hallucination/slopsquat + suggestions) · vulns/malware · slopsquat-risk · deprecated · license → a `verdict` (`safe`/`caution`/`danger`) |
| `GET /api/check-vulns` | Known vulnerabilities + malware advisories for `name@version` (OSV) |
| `GET /api/package-info` | latest · deprecated · license · repo · weekly downloads · age |
| `GET /api/audit-deps` | Batch-audit a whole dependency list (`?packages=` or POST package.json/requirements) |
| `GET /api/typosquat-scan` | Generate lookalike names + flag which are registered/suspicious |

Ecosystems: `npm`, `pypi`, `go`, `crates`, `rubygems`, `maven`, `nuget` (vulns via OSV across all;
existence/metadata for npm + pypi).

## Examples

```bash
# Is this package safe to install?
curl "https://package-guard.vercel.app/api/verify-package?name=express"
# A hallucinated / unregistered name → danger + "did you mean"
curl "https://package-guard.vercel.app/api/verify-package?name=expresss-router-helper"
# Audit a list at once
curl "https://package-guard.vercel.app/api/audit-deps?packages=react,lodash,left-pad"
```

MIT. Part of the [Agent Tools](https://github.com/mlawsonking/MCP) family.
