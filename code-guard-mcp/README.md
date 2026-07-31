# code-guard-mcp

An MCP server that scans code for security bugs. A coding agent calls it on the code or diff it just produced, before committing or running it. Rule-based, no LLM, free.

More than half of new code is AI-assisted now, and a fair amount of it ships with the usual problems: injection, hardcoded secrets, disabled TLS checks, unsafe deserialization. This catches the common cases in one call. Treat it as a fast first pass, not a substitute for a real security review.

## Install

Add it to your MCP client config (Claude Desktop, Cursor, Claude Code, and so on):

```json
{ "mcpServers": { "code-guard": { "command": "npx", "args": ["-y", "@mlawsonking/code-guard-mcp"] } } }
```

## Tools

- `scan_code`: scan a snippet. Returns a verdict (pass, review, or block) and a list of findings, each with the rule, category, severity, line number, and a suggested fix. Covers command, code, and SQL injection, SSRF, hardcoded secrets and API keys, weak crypto, unsafe deserialization (pickle, yaml), disabled TLS verification, XSS or template injection, and personal data left in source (email, US SSN, card number).
- `scan_diff`: the same scan, but only on the added lines of a unified diff, with correct new-file line numbers. Useful inside a commit loop. It only reads added lines, so a pattern spanning an added line and an untouched one is not seen.
- `list_rules`: the full rule catalog, so you can see what it checks and what it doesn't. 32 entries: the 31 code rules, plus one grouped `hardcoded-*` entry covering 22 credential patterns and 3 personal-data patterns.

## Languages

JS/TS and Python. That is the whole list. 11 rules are JS/TS, 14 are Python, 6 are language-agnostic. There is no Go, Ruby, PHP, Java or Rust ruleset. A `language` value it doesn't recognise is ignored and the language is sniffed from the source instead, which returns one of three answers: `js`, `py` or `unknown`. Which one depends on what the file happens to contain. `import java.util.List;` reads as Python, a Go file with a `const` line reads as JavaScript, a Go file with only `func` and `import "fmt"` lands on unknown. Unknown runs all 31 rules against every line, which catches more and flags more things that are not bugs.

## What it doesn't do

The 31 code rules are regexes matched one line at a time. No parser, no data flow, no taint tracking, so it isn't static analysis in the sense a SAST tool means it. It reads text. `db.query("SELECT ... " + id)` is caught on one line and missed the moment you split it across two. The word `DES` on a line trips weak-cipher, comment or variable name included. The `hardcoded-*` patterns are the exception: those run over the whole source, so a multi-line private-key block is still caught. A pass means none of the rules matched, not that the code is safe.

Same input always gives the same output. It calls the API at https://code-guard-api.vercel.app (set `CODE_GUARD_API` to point at your own copy). One of six agent guards in this repo: package-guard, agent-firewall, payment-guard, email-guard, code-guard, and web-tools. MIT.
