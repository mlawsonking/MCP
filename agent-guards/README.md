# agent-guards core

The detection engines behind Package Guard, Agent Firewall, Payment Guard, Email Guard, Code Guard
and Agent Web Tools, in one package, running on your machine.

Everything here is deterministic: regex rules, published lists, and parsers. No model is called in
any detection path, so the same input gives the same verdict and every verdict names the rules
version that produced it.

## Run it

```bash
npx agent-guards
```

That starts an MCP stdio server with every tool from all six products. No configuration, no API key,
no account.

```bash
npx agent-guards --offline          # local engines only
npx agent-guards --only code-guard  # one product
npx agent-guards --list             # what you get, and which tools need the network
npx agent-guards --disable check_ip,check_password
```

The same package installs the `guard` CLI:

```bash
npx --yes --package agent-guards guard scan src/
npx --yes --package agent-guards guard diff
npx --yes --package agent-guards guard stats --json
```

## pre-commit

This repository publishes a staged-diff hook for the [pre-commit](https://pre-commit.com) framework.
It needs Node 18 or newer. Add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/mlawsonking/MCP
    rev: main  # pin this to a commit SHA in a shared repository
    hooks:
      - id: agent-guards-diff
```

Then run `pre-commit install`. The hook scans added lines only and uses the rules in that pinned
checkout. It does not call a model or send file contents anywhere. A second manual hook,
`agent-guards-scan`, scans the whole working tree when you run
`pre-commit run agent-guards-scan --hook-stage manual`.

## Local and cloud, and why the difference matters

Local tools run entirely on your machine. The text you scan never leaves it.

| Local, works offline | Needs the network |
|---|---|
| prompt-injection and Unicode-obfuscation scanning | package existence, age and vulnerabilities (npm, PyPI, OSV) |
| secret and PII detection, with redaction | sanctions and scam-list screening (OFAC lists, blocklists) |
| code and diff scanning | breached-password lookup (Have I Been Pwned) |
| URL structure analysis | domain age, ASN, blocklist reputation |
| email parsing, spoof heuristics, header reading | SPF/DMARC/MX records, disposable-domain list |

Cloud tools say which service they call in their own tool description. With `--offline`, they report
that they could not check. They do not return a verdict.

That distinction is the whole design. A check that did not run is not a pass. This codebase shipped
the opposite once: four endpoints answered "not sanctioned", "no known vulnerabilities", "not a
honeypot" and "safe" when the lookup behind each had failed or was never attempted. A security tool
that says "clear" when it means "I don't know" is worse than no tool.

## What it catches, and what it does not

The injection scanner matches known instruction-override, jailbreak, prompt-leak, exfiltration and
tool-poisoning phrasings, and the Unicode tricks used to hide them: zero-width characters, bidi
overrides, the Unicode tag block, hidden CSS, instructions in HTML comments. It is a deterministic
pattern scanner, not a classifier. Novel phrasing gets through. Anyone who reads the rules can write
around them. It is one layer, not a wall.

The secret scanner matches 22 credential formats plus generic assignments and 3 PII patterns. A
secret in a format it does not know, or split across lines, is not detected. What it does guarantee
is that the value it found is gone from the `redacted` output, not just the label next to it.

The code scanner is 31 regex rules across JS/TS and Python. No parser, no data flow, no taint
tracking, so `exec(cmd)` with a bare variable does not fire while `exec("ls " + dir)` does. That is a
deliberate limit and there is a test pinning it.

Sanctions screening covers the EVM-format OFAC address lists. Honeypot checks only cover the chains
honeypot.is actually simulates.

## Using it as a library

```js
const guards = require('agent-guards');

guards.injection.scan(untrustedText);      // { risk, score, verdict, findings, rules_version }
guards.secrets.scan(text);                 // { found, verdict, findings, redacted, rules_version }
guards.code.scanDiff(unifiedDiff, 'py');   // findings against new-file line numbers
await guards.safeFetch(url);               // SSRF-guarded: pins the resolved IP, rechecks every hop
```

`safeFetch` is the one to reach for whenever you fetch a URL you did not choose. It resolves the
hostname once, refuses the request if anything it resolves to is private or loopback, and connects
to that exact address, so there is no second lookup for DNS rebinding to poison. It re-checks every
redirect hop and never pools sockets, because a pooled connection skips the pin.

## Rule updates

The rules go stale. Addresses get sanctioned, packages get pulled from npm for shipping malware, and
none of that reaches you if the rules only change when you reinstall. So about once a day the server
and the CLI ask the rules feed whether there is a newer ruleset, and apply it if there is.

A pull sends two things: which surface asked (`cli`, `plugin`, `mcp` or `facade`) and the rules
version you already have.

```
GET /api/rules/latest?surface=mcp&have=2026.07.31
```

No machine id, no user id, no file names, nothing you scanned. Bundles are signed with Ed25519 and
verified against a public key compiled into this package, so it does not matter which mirror served
one. A bundle that fails its signature, its schema, or its ReDoS check is discarded and you keep the
rules you had. Rules never roll back to an older version on their own.

```bash
guard update --status     # what is in use, and when it last checked
guard update              # pull now
```

Every verdict carries `rules_provenance`, which is either `bundled` or `feed@<version>`, so you can
always tell which ruleset produced a result.

To turn updates off: `--offline`, `AGENT_GUARDS_NO_FEED=1`, or `{"feed": false}` in
`~/.agent-guards/config.json`. `AGENT_GUARDS_FEED_URL` points it somewhere else. With updates off
everything still works on the rules compiled into the package.

The bundle format, the verification steps, and how the malicious-package list is curated are in
[rules/README.md](../rules/README.md).

## Tests

```bash
npm test
```

Offline suites only. Anything that asserts against a third-party endpoint is run by hand, because a
suite that goes red at random teaches everyone to ignore red.

## Licence

MIT.
