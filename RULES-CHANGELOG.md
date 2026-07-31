# Rules changelog

Every detection ruleset carries a version string, and every scan response returns the `rules_version`
that produced it. Pin to a version if you need a verdict to stay stable; read this file before you
upgrade.

Three rulesets are versioned separately because they ship in different places:

- **shared** (`agent-guards/engines/{injection,secrets,url}.js`) — prompt-injection patterns,
  obfuscation signals, secret and PII rules, URL structure analysis. Used by Agent Firewall, Email
  Guard, Code Guard and Payment Guard, and by the hosted APIs.
- **code** (`agent-guards/engines/code.js`) — the static code rules. Used by Code Guard.
- **name** (`agent-guards/engines/{pkgname,shellcmd}.js`) — package-name and command-shape rules.
  These run only in the Claude Code plugin's hooks, the `guard` CLI and the GitHub Action, all of
  which ship from this repository, so this ruleset can move without redeploying anything.

Two data sources are not versioned by us because they are fetched live and change upstream. Responses
report what was actually loaded instead:

- OFAC sanctioned addresses, and the ethereum-lists and ScamSniffer blocklists (Payment Guard). The
  response carries `coverage.lists_loaded` and `list_size`.
- The disposable-domain list (Email Guard, Agent Web Tools).

## name 2026.07.31

First release. Seven rule IDs across two engines, answering "does this look like a name chosen to be
mistaken for a real one" and "is this command about to run something it just downloaded". Neither
engine touches the network, because they run inside a PreToolUse hook that sits in front of every
shell command an agent issues.

| Rule | Fires on | Severity |
| --- | --- | --- |
| `pkg-name-nonascii` | any character outside ASCII in a package name | critical |
| `pkg-name-separator` | the name matches a popular one once `-`, `_` and `.` are removed | critical |
| `pkg-name-confusable` | one substitution away from a popular name, and the pair is a visual lookalike | critical |
| `pkg-name-near` | one or two edits from a popular name, any edit | medium |
| `pkg-name-affix` | a popular name with `js`, `.js`, `node-` or `python-` attached | medium |
| `pkg-cached-verdict` | an earlier online check of this exact name returned danger or caution | inherits |
| `cmd-remote-to-shell` | a download piped straight into a shell | medium |

The comparison list is `agent-guards/data/popular-*.json`: the 3,000 most downloaded packages on npm
and on PyPI, dated inside the file. It is a snapshot, so a package that became popular after that
date is not on it.

Known false-positive rate, measured against 1,500 real npm packages sampled from ranks 3,001 to
12,500: 28 flagged, 2 of which would block (`date-format`, which collides with `dateformat`, and
`isurl`, which collides with `is-url`). Both are real packages differing from another real package
only by punctuation, which is the same shape as the `crossenv` attack. No rule that reads only the
name can separate them.

Two things this ruleset deliberately does not do: npm scopes are exempt from the similarity rules
when the scope is one that popular packages publish under, because only the scope's owner can
publish into it; and PyPI names are compared in PEP 503 form, because pip treats `discord.py`,
`discord-py` and `discord_py` as the same project.

## shared 2026.07.30.1

Ten new secret patterns. No existing rule changed, so anything that matched before still matches.
A second release on the same date gets a `.1` rather than tomorrow's date.

New rules, by family:

- **Azure** — `azure-storage-key` (the `AccountKey=` value in a storage connection string),
  `azure-sas-token` (the `sig=` parameter), `azure-ad-secret` (Entra client secrets, which carry a
  distinctive `8Q~`/`7Q~` shape).
- **Google Cloud** — `gcp-sa-key-id` (the `private_key_id` in a service-account JSON) and
  `gcp-oauth-refresh` (`1//` refresh tokens). The PEM body inside a service-account file was already
  covered by `private-key`.
- **Connection strings** — `db-connection-uri` redacts just the password out of
  `postgres://user:pass@host` and the same shape for mysql, mongodb, redis, amqp, mssql and ftp, so
  the host and user stay readable. `connection-string-password` covers the ADO.NET/ODBC
  `Password=...;` form.
- **Other formats** — `sendgrid`, `gitlab-pat`, `huggingface`.

Secret rules go from 12 to 22. `RULESET_INFO.secrets.rules` and `/api/rules` counts move with them.

The rules now live in `agent-guards/engines/secrets.js` rather than `shared/lib/safety.js`. Behaviour
is identical; `shared/lib/safety.js` re-exports the core under the same names.

## shared 2026.07.30

First versioned release.

- 11 prompt-injection and jailbreak patterns, each with a stable ID.
- 5 obfuscation signals: `zero-width-chars`, `bidi-override`, `unicode-tag-smuggling`, `hidden-html`,
  `html-comment-instruction`.
- 12 secret patterns and 3 PII patterns, each with a stable ID.
- `scanInjection`, `scanSecrets` and `analyzeUrl` now return `rules_version`.

**Redaction fix (behaviour change).** `scanSecrets` was redacting the wrong half of a match. It took
`m[1] || m[0]`, so `api_key = "hunter2"` removed the words `api_key` and left the value in the
`redacted` output, and a PEM block removed the literal `RSA ` while every line of the key body
survived. It also did a document-wide `split/join` on the matched text, so redacting `RSA ` corrupted
unrelated text elsewhere in the document.

Each rule now declares which capture group holds the secret, the private-key rule matches the whole
armoured block, and redaction splices exact character spans back-to-front with overlapping spans
merged. The `redacted` string and `preview` values change. Findings, verdicts and response shape do
not.

Anyone who relied on `redacted` being safe to log or forward should re-run anything they kept.

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
