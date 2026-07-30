# Package Guard

**The pre-install supply-chain guard for AI coding agents.** Before your agent runs `npm install` or
`pip install`, it should ask one question: *is this name registered, and does OSV know anything bad
about it?*

LLMs recommend package names that don't exist, and attackers register those hallucinated names
("slopsquatting") so the next agent that suggests one installs theirs.

The check for that is a registry lookup, nothing cleverer. I ask npm or PyPI whether the name is
registered. If it isn't, the response carries `likely_hallucination: true`. Read that flag as "no
package by this name in this registry". It can't tell an AI-invented name from a typo or from a
package that was renamed, and anything that lives only in your company's private registry will read
as non-existent here.

Free. Deterministic (no LLM). Backed by [OSV.dev](https://osv.dev) + the npm/PyPI registries.

## Tools (HTTP + MCP)

| Endpoint | What it does |
|---|---|
| `GET /api/verify-package` | **The guard.** Is the name registered (else `likely_hallucination` + npm "did you mean") · OSV vulns/malware · age + download signals · deprecated · license → a `verdict` (`safe`/`caution`/`danger`) |
| `GET /api/check-vulns` | Known vulnerabilities + malware advisories for `name@version` (OSV) |
| `GET /api/package-info` | latest · deprecated · license · repo · weekly downloads · age |
| `GET /api/audit-deps` | Check a list of names, or the `dependencies` + `devDependencies` in a package.json, or a requirements.txt. Direct entries only, first 40 |
| `GET /api/typosquat-scan` | Generate ASCII lookalike names and report which are registered |

## Ecosystems

`check-vulns` queries OSV.dev, which covers all seven: npm, PyPI, Go, crates.io, RubyGems, Maven,
NuGet. The vulnerability half of `verify-package` uses the same OSV query.

Everything else reads a package registry, and there are two registry clients in `lib/pkg.js`
(`meta()`): npm, and PyPI when you pass `ecosystem=pypi`. That covers existence, weekly downloads,
age, deprecation, license and the lookalike-variant check. The "did you mean" suggestions and the
`confusable_with` signal go through npm's search API, so they are npm only — PyPI names get no
suggestions and can't reach `slopsquat.risk: "high"`, which requires a confusable hit.

So `verify-package`, `package-info`, `typosquat-scan` and `audit-deps` are npm and PyPI tools today.
If you pass one of the other five ecosystems they still resolve the name against npm, and the answer
is wrong: `ecosystem=nuget&name=Newtonsoft.Json` comes back `exists: false`, and
`ecosystem=go&name=github.com/gin-gonic/gin` comes back as a registry error. Use `check-vulns` for
those five until I've fixed it.

## What it doesn't do

- It doesn't read package contents. No install scripts, no code, no tarballs are fetched or
  analysed. A malicious package with no OSV advisory and healthy download numbers comes back `safe`.
- `likely_hallucination` is registry non-existence. A private or internal package, and a name that
  was unpublished, look exactly like an invented one.
- Vulnerability data is only as current as OSV. A zero-day with no advisory is invisible here.
- `vulnerabilities.checked: false` (with `count: null`) means the OSV request failed, so nothing was
  checked. `count: 0` means OSV answered and had nothing for that name and version. A failed lookup
  pushes the verdict to `caution`, never `safe`. `audit-deps` does not have that guard yet: if its
  batch OSV call fails, every package in the report shows `vulns: 0`.
- `audit-deps` reads manifests, not lockfiles, and does not resolve the tree. It checks the direct
  entries you send and nothing they depend on. A version range is reduced to the digits inside it
  (`^4.17.20` is checked as `4.17.20`), so it can miss a vuln in the version you'd actually install.
- `typosquat-scan` generates ASCII edits only: deletions, adjacent transpositions, doubled letters,
  the swaps `l`/`1`, `o`/`0`, `rn`/`m`, `-`/`_`, `.`→`-`, `i`→`l`, `s`→`z`, and the name with every
  hyphen or underscore dropped. No Unicode homoglyphs, and it stops at 20 variants. A variant is
  marked `suspicious` when it is registered and either under a year old or has no creation date.

## Examples

```bash
# Verdict on a package before installing it
curl "https://package-guard.vercel.app/api/verify-package?name=express"
# An unregistered name → danger + "did you mean"
curl "https://package-guard.vercel.app/api/verify-package?name=expresss-router-helper"
# Audit a list at once
curl "https://package-guard.vercel.app/api/audit-deps?packages=react,lodash,left-pad"
```

MIT. Part of the [Agent Tools](https://github.com/mlawsonking/MCP) family.
