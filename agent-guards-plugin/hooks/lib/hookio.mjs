// The plumbing every hook in this plugin shares: read the event off stdin, write a decision to
// stdout, and never be the reason a command fails.
//
// Failure posture, decided once and applied everywhere (the README says the same thing in prose):
// if this plugin throws, times out, or cannot read its own input, the tool call proceeds. A security
// guard that bricks a shell because of its own bug is a worse outcome than the check not running.
// But it is never silent about it — a guard that fails quietly is the fail-open bug this project
// exists to avoid, so an internal error produces a visible line saying the check did not run.
//
// stdout is parsed as JSON by Claude Code, so nothing else may ever be written there.

import { writeSync } from 'fs';

const MAX_INPUT = 8 * 1024 * 1024;

export function readInput(timeoutMs = 5000) {
  return new Promise((resolve) => {
    let data = '';
    let settled = false;
    const finish = (value) => { if (!settled) { settled = true; clearTimeout(timer); resolve(value); } };
    const timer = setTimeout(() => finish(null), timeoutMs);

    try {
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (chunk) => {
        data += chunk;
        if (data.length > MAX_INPUT) finish(parse(data));
      });
      process.stdin.on('end', () => finish(parse(data)));
      process.stdin.on('error', () => finish(null));
    } catch {
      finish(null);
    }
  });
}

function parse(text) {
  try { return JSON.parse(text); } catch { return null; }
}

// Nothing to say. This is the common case and it has to cost nothing.
export function silent() {
  process.exit(0);
}

// fs.writeSync rather than process.stdout.write: writes to a pipe are asynchronous, and calling
// process.exit() straight after one can cut the JSON in half. A truncated decision is read as no
// decision, which would turn a block into a silent allow.
export function emit(payload) {
  try { writeSync(1, JSON.stringify(payload)); } catch { /* a closed pipe is not our problem */ }
  process.exit(0);
}

// The guard itself broke. Say so where the user will see it, allow the action, and get out of the
// way. `detail` is the error text; it goes in the visible message because a hook error the user
// cannot diagnose is a hook they will disable rather than fix.
export function errored(hookName, detail) {
  emit({
    systemMessage: `agent-guards: the ${hookName} check did not run (${String(detail).slice(0, 200)}). The command was allowed through unchecked.`,
    suppressOutput: true,
  });
}

// Wrap a hook body so no throw can escape it.
export async function run(hookName, body) {
  try {
    await body();
    process.exit(0);
  } catch (e) {
    errored(hookName, (e && e.message) || e);
  }
}

// Every hook records what it did, and a ledger that cannot be written never stops a check.
export function note(require, entry) {
  try { require('../core/lib/ledger.js').record(entry); } catch { /* ignore */ }
}

// The single switch that turns the whole plugin off without uninstalling it. Documented in the
// README; named in the message whenever a hook blocks something, so nobody is ever stuck.
export function disabled() {
  const v = process.env.AGENT_GUARDS_DISABLE;
  return !!(v && String(v).trim() && String(v).trim() !== '0' && String(v).trim().toLowerCase() !== 'false');
}
