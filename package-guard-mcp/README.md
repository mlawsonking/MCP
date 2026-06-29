# package-guard-mcp

**The pre-install supply-chain guard for AI coding agents, as an MCP server.**

Before your agent runs `npm install` / `pip install`, have it call `verify_package`. In 2026 ~20% of
package names LLMs recommend **don't exist**, and attackers register those hallucinated names
("slopsquatting") to poison agents. This catches it in one call.

```jsonc
{ "mcpServers": { "package-guard": { "command": "npx", "args": ["-y", "package-guard-mcp"] } } }
```

## Tools
- **`verify_package`** — the guard. Exists? (else hallucination/slopsquat + suggestions) · vulns/malware · slopsquat-risk · deprecated · license → a `verdict` (`safe`/`caution`/`danger`).
- **`check_vulns`** — known vulnerabilities + malware advisories (OSV) for `name@version`.
- **`package_info`** — latest · deprecated · license · repo · weekly downloads · age.
- **`audit_deps`** — batch-audit a list of names, a `package.json`, or a `requirements.txt`.
- **`typosquat_scan`** — generate lookalikes + flag registered/suspicious ones.

Ecosystems: `npm`, `pypi`, `go`, `crates`, `rubygems`, `maven`, `nuget` (vulns via OSV across all).
Deterministic, free, no LLM. Data: [OSV.dev](https://osv.dev) + npm/PyPI. MIT.

Backed by the live API at `https://package-guard.vercel.app` (override with `PACKAGE_GUARD_API`).
