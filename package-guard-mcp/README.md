# package-guard-mcp

An MCP server that vets a package before your agent installs it. It checks that the name is registered, that OSV has no advisory against it, and how new and how downloaded it is. Deterministic, no LLM, free.

LLMs regularly suggest package names that don't exist, and attackers register those hallucinated names to slip malware into agent-run installs. People call it slopsquatting. The check for it is a registry lookup: if npm or PyPI has no package by that name, `verify_package` returns `likely_hallucination: true`. That means "not in this registry" and nothing more — it can't separate an invented name from a typo or a rename, and a package that only exists in your private registry will read as missing.

It never fetches or reads package contents. No install scripts, no code, no tarballs. A malicious package with no OSV advisory and healthy download numbers comes back `safe`.

## Install

```json
{ "mcpServers": { "package-guard": { "command": "npx", "args": ["-y", "package-guard-mcp"] } } }
```

## Tools

- `verify_package`: the main guard. Returns safe, caution, or danger, based on whether the registry has the name (if not you get `likely_hallucination`, plus a "did you mean" list on npm), known vulnerabilities and malware from OSV, age and weekly downloads, whether the name is within 2 edits of an npm search hit, deprecation, and license.
- `check_vulns`: known vulnerabilities and malware advisories for a name and version, from OSV.
- `package_info`: registry metadata, including latest version, deprecation, license, repository, weekly downloads, and age.
- `audit_deps`: check a list of names, or the `dependencies` and `devDependencies` in a package.json, or a requirements.txt.
- `typosquat_scan`: generate ASCII lookalike names and report which are registered.

## Scope and limits

`check_vulns` is a straight OSV.dev query and covers all seven ecosystems: npm, PyPI, Go, crates.io, RubyGems, Maven, NuGet. Everything else needs a package registry, and there are two clients: npm and PyPI. So `verify_package`, `package_info`, `audit_deps` and `typosquat_scan` take `npm` or `pypi` only. Suggestions and the confusable-name signal use npm's search API, so they are npm only.

`audit_deps` reads manifests, not lockfiles, and does not resolve the dependency tree. It checks the entries you send and nothing they depend on, up to 40 names. A version range is reduced to the digits inside it, so `^4.17.20` is checked as `4.17.20`.

`vulnerabilities.checked: false` with `count: null` means the OSV request failed and the package was not checked; `verify_package` downgrades the verdict to `caution` instead of calling it safe. `count: 0` means OSV answered and had nothing. `audit_deps` has no such guard yet: if its batch OSV call fails, every package reports 0 vulns.

It calls https://package-guard.vercel.app (set `PACKAGE_GUARD_API` to override). One of six agent guards in this repo. MIT.
