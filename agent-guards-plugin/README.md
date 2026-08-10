# Agent Guards for Claude Code

Three checks that run on their own while you work, and one command you can run yourself.

Claude Code installs a package: the package names get checked before the install runs, and an
install that looks like a typosquat is stopped. Claude Code writes a file: the lines it just wrote
get scanned for credentials and for a short list of dangerous code patterns. Claude Code fetches a
page: the page gets scanned for prompt-injection phrasings and for the invisible characters used to
hide them.

Nothing is sent anywhere. No hook makes a network call. No model runs inside any check, so the same
input always gives the same answer and every answer names the rule that produced it.

## Install

```
/plugin marketplace add mlawsonking/MCP
/plugin install agent-guards@agent-guards
```

You need Node 18 or newer on your PATH. That is the only requirement. There is nothing to
configure, no account, and no API key.

## What each hook does

**Before a Bash command runs.** The command is parsed. If it installs packages (npm, pnpm, yarn,
bun, npx, pip, pipx, uv, poetry) each name is checked against a bundled list of the 3,000 most
downloaded packages on npm and on PyPI:

| Rule | Example | What happens |
| --- | --- | --- |
| `pkg-name-nonascii` | `еxpress` with a Cyrillic е | blocked |
| `pkg-name-separator` | `crossenv` against `cross-env` | blocked |
| `pkg-name-confusable` | `1odash` against `lodash` | blocked |
| `pkg-name-near` | `expres` against `express` | warned |
| `pkg-name-affix` | `momentjs` against `moment` | warned |
| `pkg-cached-verdict` | a package an earlier online check called dangerous | blocked or warned |
| `cmd-remote-to-shell` | `curl … \| bash` | warned |

**After an Edit or a Write.** Only the lines that changed are scanned, using 22 credential patterns,
3 personal-data patterns and 31 code rules. Credentials and personal data are always reported. Code
findings are reported at high and critical only, so `Math.random()` does not interrupt you.
Findings come back with the file, the line as it is numbered in the file, the rule ID and what to
do about it. This hook never blocks: the write already happened, and there is nothing to prevent.

**After a WebFetch.** The fetched content is scanned for 11 injection phrasings and 5 obfuscation
signals: zero-width characters, bidirectional overrides, the Unicode tag block, text hidden with
CSS, and instructions parked in HTML comments. The content is never altered and never withheld. The
findings arrive next to it.

## What these checks do not do

This is the part I would want to read first.

The install check reads the **name only**. It does not ask npm whether the package exists, it does
not query OSV for advisories, it does not look at download counts, and it never downloads or
inspects package contents. It cannot, because a hook that waits on a network round trip taxes every
command you run. A quiet install check means nothing in the name looked wrong. It does not mean the
package is safe. Every message the hook prints says so.

`/guard package <name>` does the full online check, and its result is cached locally, so the next
time that package comes up the hook has the real verdict to work from.

The edit and fetch scans are regular expressions against known patterns. They are not static
analysis and not a classifier. A credential in a format the rules do not know is not detected. An
injection written in a phrasing nobody has catalogued is not detected. Anyone who reads
[the rules](../agent-guards/engines) can write something that walks past them.

The package list is a snapshot, dated inside
[popular-npm.json](../agent-guards/data/popular-npm.json). A package that got popular after that
date is not on it.

The command check reads text, and a shell rewrites text before it runs it. GuardFall (Adversa AI,
June 2026) found ten of eleven agent shell guards checking the string the model produced rather than
the one bash would execute, so this one normalizes the rewrites that are deterministic: `$IFS` as a
word separator, quotes and backslashes inside a command name, a variable whose value is assigned
literally in the same command, an assignment prefix in front of the real command. What a shell can
produce at run time is not decidable by reading text, so `curl … | $(something)` and a variable that
is never assigned here are reported as unresolved rather than waved through. That is the honest
answer, and it is the reason the finding says the check cannot clear it either way.

It is still a filter, not a boundary. It runs before the command does, on the command as written. It
cannot see what a script fetches once it is running, and anyone deliberately working around it will.
For a boundary you want permissions or a sandbox, and you should run both.

## How often it is wrong

I measured this rather than guessing. Against 1,500 real npm packages sampled from ranks 3,001 to
12,500, which is the hardest case because they are genuinely popular and just off the list:

| Rank band | Flagged | Would block |
| --- | --- | --- |
| 3,001 to 3,500 | 12 of 500 | 1 (`date-format`, which collides with `dateformat`) |
| 6,001 to 6,500 | 9 of 500 | 1 (`isurl`, which collides with `is-url`) |
| 12,001 to 12,500 | 7 of 500 | 0 |

Two false blocks in 1,500. Both are real packages whose names differ from another real package only
by punctuation, which is the same shape as the `crossenv` attack, and no rule that reads only the
name can tell them apart. If one hits you, the block message names the package it resembles so you
can see the collision in about two seconds, and you can run the install yourself.

Packages on the list itself are never flagged, and most installs are of those.

The command checks were measured the same way. 429 distinct shell commands harvested from this
repository's npm scripts, GitHub workflow steps and README code blocks, plus the shell-init idioms
everyone has in a dotfile (`eval "$(pyenv init -)"`, `eval "$(ssh-agent -s)"`, `docker run -v
$(pwd):/w`), produce zero download-and-run, decode-and-run or dynamic-execution findings. That
number is the reason those rules are narrow: a check that fires on `git commit -m "fix $(whoami)
thing"` gets the whole plugin uninstalled by lunchtime.

## Speed

Measured on Windows 11 and Node 22, two runs of 20 calls each, timed around the whole child process:

| Hook | Time per tool call |
| --- | --- |
| Bash, no package manager in the command | 64 ms |
| Bash, install checked | 82 ms |
| Bash, install denied | 84 ms |
| Edit or Write | 96 ms |
| WebFetch | 91 ms |
| a bare `node -e "process.exit(0)"` for comparison | 48 ms |

So the checks themselves cost 16 to 48 ms and the rest is Node starting up. A command with no package
manager and no pipe in it exits before any rule file is loaded. Your machine will differ; the number
worth comparing is the gap between each row and the last one.

Once the rules feed has applied a bundle, add about 9 ms to the rows that load rules: the hook reads
the cached bundle and revalidates it before use. Measured the same way, an Edit hook goes from 96 ms
on the rules compiled into the plugin to 105 ms on a bundle pulled from the feed. The bundle is
revalidated rather than trusted because it is a file in your home directory that anything on the
machine could have edited.

## When the guard itself breaks

Fail-open, and it says so. If a hook throws, times out, or cannot read its input, the tool call goes
ahead and you get a line saying the check did not run. This applies to the blocking hook too. A
security tool that bricks your shell because of its own bug is a worse outcome than a check that
did not happen, but a check that quietly did not happen is the worst outcome of the three, so it is
never silent about it.

Every hook sets a 10 second timeout. The Claude Code default is 10 minutes, which would be
indistinguishable from a hang.

## The `/guard` command

```
/guard                       scan what is staged in git
/guard src/                  scan a file or a directory
/guard package left-pad      the full online check: registry, OSV, downloads, deprecation
/guard email message.eml     parse and scan an inbound message
/guard stats                 what the guards have caught on this machine
```

`guard` is also on the PATH inside Claude Code's Bash tool while the plugin is enabled, so you can
run `guard diff` or `guard scan src/` directly, and use it in a pre-commit hook or a CI step. It
exits 0 when nothing reaches the failure threshold, 1 when something does, and 2 when it could not
run at all. `--fail-on caution` lowers the bar, `--json` gives you machine-readable output.

## The ledger

Every check appends one line to `~/.agent-guards/ledger.jsonl`. `guard stats` reads it back:

```
agent-guards, last 7 days

      8 checks run
      1 stopped before it ran
      4 reported after the fact
      1 check that could not finish
```

A line holds a timestamp, the event, the engine, the verdict, what the guard actually did, the rule
IDs that fired, and a short label: a package name, a file's basename, a hostname. It holds no file
contents, no secret values, no page text and no absolute paths. There is no code anywhere in this
repository that uploads it. If you do not believe me, the file is JSON lines and you can read it.

The "stopped" and "reported" counts are separate on purpose. Most of these checks are advisory, and
counting an advisory finding as something that was stopped would be this tool claiming credit for
work it did not do.

## Rule updates

The rules go stale. Sanctioned addresses get added, scam addresses get reported, and packages get
pulled from npm for shipping malware, and none of that reaches you if the rules only change when you
reinstall. So `guard` checks for a newer ruleset about once a day and applies it if there is one.

The hooks never do this. They are the intercept path, they run on every tool call, and they are not
allowed to touch the network at all. That is not a promise in a comment: `agent-guards/test/no-network.cjs`
replaces `fetch`, `net.connect`, `http.request`, `https.request`, `tls.connect` and the DNS functions
with throws, every hook test runs behind it, and adding one network call to a hook turns exactly one
assertion red. The update happens when you run `/guard` or a `guard` command, never in a hook.

A pull sends two things: which surface asked, which here is `plugin`, and the rules version you
already have.

```
GET /api/rules/latest?surface=plugin&have=2026.07.31
```

No machine id, no user id, no file names, nothing you scanned. Bundles are signed with Ed25519 and
verified against a public key compiled into the package, so it does not matter which mirror served
one. A bundle that fails its signature, its schema, or its ReDoS check is discarded and you keep the
rules you had.

`guard update --status` shows what is in use and when it last checked. The format and the steps to
verify a bundle yourself are in [rules/README.md](../rules/README.md).

## Turning it off

`AGENT_GUARDS_DISABLE=1` in the environment makes every hook exit without doing anything. The block
message names that variable, so nobody ends up stuck.

`AGENT_GUARDS_NO_FEED=1` turns off rule updates and leaves everything else working. So does
`{"feed": false}` in `~/.agent-guards/config.json`. The rules compiled into the plugin are the floor
and they keep working with no network at all.

## Where the code is

The detection engines are in [agent-guards/](../agent-guards) in this repository and the plugin
bundles a copy so it works with no install. The same engines run the six MCP servers listed in the
[repository README](../README.md) and the hosted APIs behind them.

Built solo with heavy use of AI agents. Every rule is tested and every claim on this page is mine.

MIT licensed.
