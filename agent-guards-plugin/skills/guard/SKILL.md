---
name: guard
description: Run an agent-guards security check on demand. Use when the user asks to scan a file, directory or diff for secrets, vulnerable code patterns or prompt injection; to check a package before installing it; to look at an .eml file; or to see what the guards have caught (stats). Also use when the user says "/guard".
argument-hint: "[path | diff | package <name> | email <file.eml> | stats]"
allowed-tools: Bash Read
---

Run the bundled `guard` command and report what it found.

The command is:

```
node "${CLAUDE_PLUGIN_ROOT}/bin/guard" <args>
```

Pick the arguments from what the user asked for. `$ARGUMENTS` holds what they typed after `/guard`.

| What they asked for | Arguments to use |
| --- | --- |
| nothing at all | `diff` — scan what is staged in git |
| a file or directory path | `scan <path>` |
| "diff", "my changes", "staged" | `diff` (add `--unstaged` for the working tree) |
| a package, or "should I install X" | `package <name>` (add `--ecosystem pypi` for Python) |
| an `.eml` file, or an email | `email <path>` |
| "stats", "what has it caught", "this week" | `stats` (add `--days N` for a different window) |

Then:

1. Run it with the Bash tool. Do not add `--json` unless the user asks for machine-readable output; the plain output is written to be read.
2. Report the findings as they are. Each one carries a rule ID, a line number where there is one, and what to do about it. Keep the rule IDs in your summary: they are how someone looks a finding up or suppresses it.
3. Read the "not checked" list at the bottom of the output and pass it on. It is not filler. A clean result from `scan` means the rules that exist did not match, not that the file is safe, and the user needs that distinction to decide what to do next.
4. If the exit code is 1, findings reached the failure threshold. If it is 2, the command could not run — say what went wrong rather than reporting a clean result.

Two things to be careful about:

- Do not paraphrase a verdict upward. If the output says `caution`, do not report it as a problem solved or as a pass.
- If the user is about to install something and `guard package` returned `danger`, say so plainly and do not run the install for them.
