# package-guard-mcp

An MCP server that vets a package before your agent installs it. It checks that the package actually exists, isn't known to be malicious, and is the one the agent meant. Deterministic, no LLM, free.

LLMs regularly suggest package names that don't exist, and attackers register those hallucinated names to slip malware into agent-run installs. People call it slopsquatting. One call to `verify_package` catches that, along with known vulnerabilities and typosquats.

## Install

```json
{ "mcpServers": { "package-guard": { "command": "npx", "args": ["-y", "package-guard-mcp"] } } }
```

## Tools

- `verify_package`: the main guard. Returns safe, caution, or danger, based on whether the package exists (if not, it's likely a hallucination or slopsquat, and you get suggested real names), known vulnerabilities and malware, typosquat risk, deprecation, and license.
- `check_vulns`: known vulnerabilities and malware advisories for a name and version, from OSV.
- `package_info`: registry metadata, including latest version, deprecation, license, repository, weekly downloads, and age.
- `audit_deps`: check a whole list at once, or a package.json, or a requirements.txt.
- `typosquat_scan`: generate likely lookalike names and flag the ones that are registered or look suspicious.

Ecosystems: npm, PyPI, Go, crates.io, RubyGems, Maven, NuGet. Vulnerability data comes from OSV.dev across all of them, with registry metadata from npm and PyPI. It calls https://package-guard.vercel.app (set `PACKAGE_GUARD_API` to override). One of six agent guards in this repo. MIT.
