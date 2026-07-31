// Turning results into text a person reads in a terminal.
//
// Two rules. No colour codes unless stdout is a TTY, because half of these runs are in CI logs and a
// pre-commit hook, and escape sequences in a log are worse than plain text. And every clean result
// says what it did not check: "nothing found" and "nothing looked for" print differently.

const isTTY = !!process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (isTTY ? `[${code}m${s}[0m` : s);

const RED = (s) => c('31', s);
const YELLOW = (s) => c('33', s);
const GREEN = (s) => c('32', s);
const DIM = (s) => c('2', s);
const BOLD = (s) => c('1', s);

// The badge names the SEVERITY, not what was done about it. `guard stats` prints findings that
// stopped nothing next to findings that stopped an install, and a badge reading BLOCK on a line that
// blocked nothing is the summary claiming credit it has not earned.
const MARK = { danger: 'DANGER', caution: 'WARN', safe: 'ok', unknown: 'UNKNOWN' };

function plural(n, one, many) { return `${n} ${n === 1 ? one : many}`; }

function badge(verdict) {
  if (verdict === 'danger' || verdict === 'block') return RED(MARK.danger);
  if (verdict === 'caution' || verdict === 'review' || verdict === 'warn') return YELLOW(MARK.caution);
  if (verdict === 'unknown') return YELLOW(MARK.unknown);
  return GREEN(MARK.safe);
}

// The list of checks that did not run, printed under every result that has one. This is the part
// people skip writing and it is the part that keeps the output honest.
function skipped(entries) {
  if (!entries || !entries.length) return '';
  const lines = entries.map((e) => `    - ${typeof e === 'string' ? e : `${e.id}: ${e.reason}`}`);
  return DIM(`  not checked:\n${lines.join('\n')}`) + '\n';
}

function findingLine(f) {
  const where = f.line !== undefined ? `:${f.line}` : '';
  const sev = f.severity ? ` [${f.severity}]` : '';
  return `  ${f.id}${where}${sev} ${f.message || f.type || ''}`.replace(/\s+$/, '');
}

function duration(ms) {
  return DIM(`${Math.round(ms)}ms`);
}

module.exports = { badge, skipped, findingLine, duration, plural, RED, YELLOW, GREEN, DIM, BOLD, isTTY };
