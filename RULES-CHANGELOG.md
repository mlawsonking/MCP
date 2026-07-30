# Rules changelog

Every detection ruleset carries a version string, and every scan response returns the `rules_version`
that produced it. Pin to a version if you need a verdict to stay stable; read this file before you
upgrade.

Two rulesets are versioned separately because they ship in different places:

- **shared** (`shared/lib/safety.js`) — prompt-injection patterns, obfuscation signals, secret and PII
  rules, URL structure analysis. Used by Agent Firewall, Email Guard, Code Guard and Payment Guard.
- **code** (`code-guard/lib/codescan.js`) — the static code rules. Used by Code Guard.

Two data sources are not versioned by us because they are fetched live and change upstream. Responses
report what was actually loaded instead:

- OFAC sanctioned addresses, and the ethereum-lists and ScamSniffer blocklists (Payment Guard). The
  response carries `coverage.lists_loaded` and `list_size`.
- The disposable-domain list (Email Guard, Agent Web Tools).

## shared 2026.07.30

First versioned release. No rule behaviour changed; this records what was already there.

- 11 prompt-injection and jailbreak patterns, each with a stable ID.
- 5 obfuscation signals: `zero-width-chars`, `bidi-override`, `unicode-tag-smuggling`, `hidden-html`,
  `html-comment-instruction`.
- 12 secret patterns and 3 PII patterns, each with a stable ID.
- `scanInjection`, `scanSecrets` and `analyzeUrl` now return `rules_version`.

## code 2026.07.30

First versioned release. No rule behaviour changed.

- 31 code rules across 12 categories, each with a stable ID, covering JS/TS, Python and
  language-agnostic patterns.
- `GET /api/rules` returns 32 entries: the 31 code rules plus one grouped `hardcoded-*` entry standing
  in for the shared secret ruleset.
- `scanCode` and `scanDiff` now return `rules_version`.

## How to bump

1. Change the rule in `shared/lib/safety.js` or `code-guard/lib/codescan.js`.
2. Bump `RULES_VERSION` / `CODE_RULES_VERSION` in that same file.
3. Add an entry here saying what changed and what a caller might now see differently.
4. `node scripts/sync-shared.js` if you touched a shared file, then run the suites.
