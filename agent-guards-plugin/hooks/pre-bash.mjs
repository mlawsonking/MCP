#!/usr/bin/env node
// PreToolUse on Bash — look at what a command is about to install, before it installs it.
//
// This runs in front of every shell command the agent issues, so the first thing it does is decide
// whether it has any business being here. A command with no package manager and no pipe in it exits
// before a single engine is loaded; that path is the whole cost of the hook for most commands.
//
// The checks that do run are local. No network call happens here, ever: a hook that waits on
// registry.npmjs.org adds that latency to every install, and the first slow day it gets uninstalled.
// So the question this answers is "does this name look like a name chosen to be mistaken for a real
// one", plus anything a previous online run already learned and cached. Whether the package exists,
// whether OSV holds an advisory for it, and what is inside it are NOT checked here, and the message
// says so every time it speaks. `/guard package <name>` does the full online check.

import { createRequire } from 'module';
import { readInput, silent, emit, run, note, disabled } from './lib/hookio.mjs';

const require = createRequire(import.meta.url);
const started = Date.now();

await run('install', async () => {
  if (disabled()) silent();

  const input = await readInput();
  if (!input || input.tool_name !== 'Bash') silent();

  const command = input.tool_input && input.tool_input.command;
  if (!command || typeof command !== 'string') silent();

  // Cheap prefilter. Everything below this line is skipped for the ordinary `ls`, `git status`,
  // `cd` and `npm run build` that make up most of what an agent runs.
  if (!/(^|[\s;&|(])(npm|pnpm|yarn|bun|bunx|npx|pip|pip3|pipx|uv|poetry|python3?)([\s;&|)]|$)/.test(command)
      && !command.includes('|') && !/\biex\b|\binvoke-expression\b/i.test(command)) silent();

  const { parse } = require('../core/engines/shellcmd.js');
  const parsed = parse(command);
  if (!parsed.installs.length && !parsed.risky.length) silent();

  const { inspect } = require('../core/engines/pkgname.js');

  const blocking = [];
  const warnings = [];
  const checkedNames = [];
  const unread = [];

  for (const install of parsed.installs) {
    for (const skip of install.skipped) unread.push(`${skip.arg} (${skip.reason})`);
    for (const pkg of install.packages) {
      checkedNames.push(pkg.name);
      const result = inspect(pkg.name, install.ecosystem);
      if (!result || !result.ok) continue;
      for (const finding of result.findings || []) {
        const line = `${pkg.name}: ${finding.message} [${finding.id}]`;
        if (finding.severity === 'critical') blocking.push({ line, id: finding.id, name: pkg.name });
        else warnings.push({ line, id: finding.id, name: pkg.name });
      }
    }
  }
  // Every line the user sees carries its rule id, package findings and command findings alike. It is
  // how someone looks a finding up, and how they tell us which rule is wrong.
  for (const r of parsed.risky) warnings.push({ line: `${r.message} [${r.id}]`, id: r.id, name: 'command' });

  // Only claim a scope for work that was actually done. A command with no package names in it — a
  // curl piped into a shell, say — gets the command-shape sentence and not the package one.
  const scope = checkedNames.length
    ? 'Checked locally: the package names only, against a bundled list of the most-downloaded packages, plus any cached result from an earlier online check. NOT checked here: whether the package exists, OSV advisories, download counts, or package contents.'
    : 'Checked locally: the shape of the command. No package name in it was checked, because none was found.';
  const ms = Date.now() - started;

  if (blocking.length) {
    note(require, {
      event: 'install_check', engine: 'pkgname', verdict: 'danger', action: 'blocked', source: 'hook', ms,
      subject: blocking.map((b) => b.name).join(' '), rules: blocking.map((b) => b.id), findings: blocking.length,
    });
    emit({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason:
          `agent-guards stopped this install.\n\n${blocking.map((b) => '  ' + b.line).join('\n')}\n\n` +
          `${scope}\n\n` +
          `If this is the package you meant, the user can run the command themselves, or set AGENT_GUARDS_DISABLE=1 to turn this plugin off for the session. Run /guard package <name> for the full online check before overriding.`,
      },
      systemMessage: `agent-guards blocked an install: ${blocking.map((b) => b.name).join(', ')}. ${blocking[0].line}`,
    });
  }

  if (warnings.length) {
    note(require, {
      event: 'install_check', engine: 'pkgname', verdict: 'caution', action: 'warned', source: 'hook', ms,
      subject: warnings.map((w) => w.name).join(' '), rules: warnings.map((w) => w.id), findings: warnings.length,
    });
    emit({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        additionalContext:
          `agent-guards has something to flag about this command, and is not blocking it:\n${warnings.map((w) => '  ' + w.line).join('\n')}\n${scope}`,
      },
      systemMessage: `agent-guards: ${warnings[0].line}`,
    });
  }

  // Clean. Record it so `guard stats` can show how much ran, and say nothing.
  //
  // `unread` holds arguments this parser decided were not registry names — a local path, a git URL,
  // a GitHub shorthand. Those are real installs that were not checked. Saying so out loud on every
  // `npm install .` would be noise, so it goes in the ledger, where `guard stats` reports it as
  // work that did not happen rather than work that came back clean.
  //
  // Only real skips go in `skipped`. This engine never consults a registry or OSV, by design, and
  // recording that on every clean check made `guard stats` report every install as one that "could
  // not finish" — which is a different and much worse thing than "finished, within a scope that is
  // written on the box". What this engine does not do belongs in its description; what did not
  // happen on THIS run belongs here.
  note(require, {
    event: 'install_check', engine: 'pkgname', verdict: 'safe', action: 'none', source: 'hook', ms,
    subject: checkedNames.join(' ').slice(0, 100),
    skipped: unread.map((u) => `unchecked-argument: ${u}`),
  });
  silent();
});
