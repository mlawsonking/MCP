#!/usr/bin/env node
// PostToolUse on Edit and Write — read the lines that just changed, not the whole file.
//
// Scanning only the change is the point. A repository with a decade of history has findings in it
// that nobody is going to act on right now; the thing worth saying is "the edit you just made put a
// credential in this file, at this line". So Write is scanned over its content and Edit over its
// new_string, and the line numbers are resolved against the file on disk so they match what the
// editor shows.
//
// This one never blocks. The tool has already run by the time a PostToolUse hook is called, so there
// is nothing to prevent; the finding goes back as context next to the tool result, where the agent
// can act on it, and as a visible line for the user. That is the deliberate posture for the advisory
// hooks and the README says so.
//
// Quiet by default: every secret and every piece of personal data is reported, but code findings are
// only reported at high and critical. The code ruleset includes things like Math.random() that are
// worth knowing in a review and are not worth a message on every edit.

import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { basename } from 'path';
import { readInput, silent, emit, run, note, disabled } from './lib/hookio.mjs';

const require = createRequire(import.meta.url);
const started = Date.now();
const MAX_FILE = 4 * 1024 * 1024;

await run('edit', async () => {
  if (disabled()) silent();

  const input = await readInput();
  if (!input) silent();
  const tool = input.tool_name;
  if (tool !== 'Edit' && tool !== 'Write') silent();

  const args = input.tool_input || {};
  const filePath = args.file_path || args.filePath;
  // Write carries the whole new file; Edit carries only the replacement text.
  const added = tool === 'Write' ? args.content : args.new_string;
  if (typeof added !== 'string' || !added.trim()) silent();

  const { scan: scanSecrets } = require('../core/engines/secrets.js');
  const { scanCode } = require('../core/engines/code.js');

  const secrets = scanSecrets(added);
  const code = scanCode(added, filePath ? filePath.split('.').pop() : undefined);

  // Line numbers. For Write the snippet is the file, so its own numbering is right. For Edit the
  // snippet sits somewhere inside the file and the offset has to be found; if it cannot be found
  // (the file changed again, or it is too large to read) the numbers are reported as relative to the
  // edited block and labelled as such rather than presented as file lines.
  let lineOffset = 0;
  let relative = false;
  if (tool === 'Edit' && filePath) {
    try {
      const file = readFileSync(filePath, 'utf8');
      if (file.length <= MAX_FILE) {
        const at = file.indexOf(added);
        if (at >= 0) lineOffset = file.slice(0, at).split('\n').length - 1;
        else relative = true;
      } else relative = true;
    } catch { relative = true; }
  }

  const label = filePath ? basename(filePath) : 'the edited text';
  const where = (line) => relative
    ? `${label} (line ${line} of the edited block; the block could not be located in the file)`
    : `${label}:${line + lineOffset}`;

  const lines = [];
  const ruleIds = [];

  // Secrets first: they are the reason this hook exists.
  for (const f of secrets.findings) {
    const upTo = String(added).slice(0, f.index);
    const line = upTo.split('\n').length;
    lines.push(`${where(line)} — ${f.type} (${f.preview}) [${f.id}]. ${f.kind === 'pii'
      ? 'This is personal data. Take it out of the source; rotation does not apply.'
      : 'Move it to an environment variable or a secrets manager, and rotate it: assume it is already in git history.'}`);
    ruleIds.push(f.id);
  }

  for (const f of code.findings) {
    if (f.severity !== 'critical' && f.severity !== 'high') continue;
    if (f.id.startsWith('hardcoded-')) continue; // already reported above, from the same scanner
    lines.push(`${where(f.line)} — ${f.message} [${f.id}, ${f.severity}]. ${f.remediation}`);
    ruleIds.push(f.id);
  }

  const ms = Date.now() - started;

  if (!lines.length) {
    note(require, {
      event: 'edit_scan', engine: 'secrets+code', verdict: 'safe', action: 'none', source: 'hook', ms,
      subject: label, findings: 0,
    });
    silent();
  }

  const verdict = secrets.findings.some((f) => f.severity === 'critical') || code.counts.critical ? 'danger' : 'caution';
  note(require, {
    event: 'edit_scan', engine: 'secrets+code', verdict, action: 'warned', source: 'hook', ms,
    subject: label, rules: ruleIds, findings: lines.length,
  });

  const scope = `Scanned the ${tool === 'Write' ? 'written file' : 'changed lines'} only, with ${secrets.rules_version} secret rules and ${code.rules_version} code rules. Pattern matching: a credential in a format these rules do not know is not detected, and the rest of the file was not read.`;

  emit({
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext: `agent-guards found ${lines.length} ${lines.length === 1 ? 'thing' : 'things'} in what was just written:\n${lines.map((l) => '  ' + l).join('\n')}\n${scope}`,
    },
    systemMessage: `agent-guards: ${lines.length} ${lines.length === 1 ? 'finding' : 'findings'} in ${label} — ${lines[0]}`,
  });
});
