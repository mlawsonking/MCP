// The `guard` command line.
//
// Same engines as the hooks and the MCP server; a different way in. The shape that matters most is
// `guard npm install <pkg>`: it checks first, then hands the real command straight through, so it can
// be aliased over `npm` and forgotten about. The rest exist because a check nobody can run on demand
// is a check nobody trusts — `guard scan`, `guard diff` for what is staged, `guard package` for the
// full online verdict, and `guard stats` for what the week actually caught.
//
// Exit codes, because this belongs in pre-commit hooks and CI:
//   0  nothing at or above the failure threshold
//   1  something at or above it
//   2  the command could not run at all (bad usage, unreadable input)
// The threshold is `danger` by default and moves with --fail-on.

const fs = require('fs');
const path = require('path');

const { badge, skipped, findingLine, plural, DIM, BOLD, RED, YELLOW, GREEN } = require('./render');
const { passthrough, git } = require('./exec');
const ledger = require('../lib/ledger');
const cache = require('../lib/cache');

// Verdicts and --fail-on levels share one ladder. `any` is a threshold rather than a verdict: it
// sits at the lowest rung anything can reach, so --fail-on any trips on a low finding.
const LEVEL = { safe: 0, ok: 0, pass: 0, allow: 0, clear: 0, any: 1, note: 1, low: 1, caution: 2, review: 2, warn: 2, unknown: 2, danger: 3, block: 3 };
const SEVERITY_TO_VERDICT = { critical: 'danger', high: 'danger', medium: 'caution', low: 'note' };

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', '.next', 'coverage', 'vendor', '__pycache__', '.venv', 'venv', '.cache']);
const SCANNABLE = /\.(js|mjs|cjs|jsx|ts|tsx|py|rb|go|java|php|sh|bash|zsh|ps1|yml|yaml|json|env|toml|ini|cfg|conf|tf|sql|md|txt)$/i;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_FILES = 2000;

function parseArgs(argv) {
  const flags = {};
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { rest.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=');
      if (v !== undefined) flags[k] = v;
      else if (argv[i + 1] && !argv[i + 1].startsWith('-') && ['fail-on', 'ecosystem', 'days', 'lang'].includes(k)) { flags[k] = argv[++i]; }
      else flags[k] = true;
    } else if (/^-[a-zA-Z]$/.test(a)) {
      flags[a.slice(1)] = true;
    } else rest.push(a);
  }
  return { flags, rest };
}

function out(s = '') { process.stdout.write(s + '\n'); }
function err(s = '') { process.stderr.write(s + '\n'); }

function threshold(flags) {
  const t = String(flags['fail-on'] || 'danger').toLowerCase();
  return LEVEL[t] === undefined ? LEVEL.danger : LEVEL[t];
}

function exitFor(verdict, flags) {
  return (LEVEL[verdict] || 0) >= threshold(flags) ? 1 : 0;
}

function record(entry, flags) {
  if (flags['no-ledger']) return;
  ledger.record({ source: 'cli', ...entry });
}

// ---------------------------------------------------------------- install passthrough

const MANAGERS = new Set(['npm', 'pnpm', 'yarn', 'bun', 'npx', 'bunx', 'pip', 'pip3', 'pipx', 'uv', 'poetry', 'python', 'python3']);

async function cmdInstall(argv, flags) {
  const { parse } = require('../engines/shellcmd');
  const { inspect } = require('../engines/pkgname');

  const commandLine = argv.join(' ');
  const parsed = parse(commandLine);

  if (!parsed.installs.length) {
    // Not an install we can read. Running it unchecked without saying so would be the fail-open bug
    // this whole project is about, so say it and run it.
    err(`guard: "${commandLine}" is not an install command this parser recognises, so nothing was checked. Running it unchanged.`);
    const r = passthrough(argv[0], argv.slice(1));
    return r.code === null ? 2 : r.code;
  }

  const results = [];
  const online = !flags.offline;
  for (const install of parsed.installs) {
    for (const pkg of install.packages) {
      const local = inspect(pkg.name, install.ecosystem);
      let full = null;
      if (online) {
        full = await fullPackageCheck(pkg.name, install.ecosystem, pkg.version);
      }
      results.push({ pkg, install, local, full });
    }
  }

  let worst = 'safe';
  for (const r of results) {
    const v = r.full && r.full.verdict ? r.full.verdict : r.local.verdict;
    if ((LEVEL[v] || 0) > (LEVEL[worst] || 0)) worst = v;
  }

  for (const r of results) {
    printPackage(r, flags);
  }
  for (const risk of parsed.risky) {
    out(`${badge('caution')} ${risk.id}: ${risk.message}`);
    if ((LEVEL.caution) > (LEVEL[worst] || 0)) worst = 'caution';
  }

  const willBlock = worst === 'danger' && !flags.force;
  record({
    event: 'install_check', engine: online ? 'packages' : 'pkgname', verdict: worst,
    action: willBlock ? 'blocked' : (worst === 'safe' ? 'none' : 'reported'),
    subject: results.map((r) => r.pkg.name).join(' ').slice(0, 100),
    rules: results.flatMap((r) => (r.local.findings || []).map((f) => f.id)),
    findings: results.reduce((a, r) => a + (r.local.findings || []).length, 0),
  }, flags);

  if (willBlock) {
    err('');
    err(RED('guard: not running this install.') + ' Re-run with --force to do it anyway, after reading the reasons above.');
    return 1;
  }
  if (worst === 'danger' && flags.force) {
    err(YELLOW('guard: --force given, running the install anyway.'));
  }

  const r = passthrough(argv[0], argv.slice(1));
  if (r.code === null) { err(`guard: could not run ${argv[0]}: ${r.error}`); return 2; }
  return r.code;
}

// The online check, run through the same tool the MCP server exposes so the CLI and the tool cannot
// disagree. The result is written to the local cache, which is what lets the offline hook say
// something useful about this package next time.
async function fullPackageCheck(name, ecosystem, version) {
  try {
    const registry = require('../tools/index.js');
    const tool = registry.byName('verify_package');
    if (!tool) return null;
    const res = await registry.runTool(tool, { name, ecosystem: ecosystem === 'pypi' ? 'pypi' : 'npm', version }, { offline: false, disabled: new Set() });
    if (res && res.ok && res.verdict) {
      cache.put(ecosystem, name, res.verdict, res.reasons, {
        malicious: res.vulnerabilities && res.vulnerabilities.malicious,
        vulnerabilities: res.vulnerabilities && res.vulnerabilities.count,
        source: 'verify_package',
      });
    }
    return res;
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}

function printPackage({ pkg, install, local, full }, flags) {
  if (flags.json) return;
  const verdict = full && full.verdict ? full.verdict : local.verdict;
  const label = `${pkg.name}${pkg.version ? '@' + pkg.version : ''} (${install.ecosystem})`;
  out(`${badge(verdict)} ${BOLD(label)}`);

  for (const f of local.findings || []) out(findingLine({ id: f.id, severity: f.severity, message: f.message }));

  if (full) {
    if (full.ok === false) {
      out(DIM(`  the online check did not run: ${full.error || full.reason || 'unknown error'}`));
    } else {
      for (const reason of full.reasons || []) out(`  ${reason}`);
      if (full.checks_skipped) out(skipped(full.checks_skipped).trimEnd());
    }
  } else {
    out(skipped([
      { id: 'registry-existence', reason: 'offline: not checked' },
      { id: 'osv-advisories', reason: 'offline: not checked' },
    ]).trimEnd());
  }
}

// ---------------------------------------------------------------- scan

function walk(dir, acc) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    if (acc.files.length >= MAX_FILES) { acc.truncated = true; return acc; }
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name) || e.name.startsWith('.') && e.name !== '.github') continue;
      walk(full, acc);
    } else if (e.isFile()) {
      if (!SCANNABLE.test(e.name) && !/^\.env/.test(e.name)) { acc.skippedByType++; continue; }
      acc.files.push(full);
    }
  }
  return acc;
}

function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch { return null; }
}

function scanText(text, label, langHint) {
  const { scanCode } = require('../engines/code');
  const { scan: scanInjection } = require('../engines/injection');
  const code = scanCode(text, langHint);
  const injection = scanInjection(text);
  const findings = [];
  for (const f of code.findings) findings.push({ id: f.id, line: f.line, severity: f.severity, message: f.message, remediation: f.remediation });
  for (const f of injection.findings) findings.push({ id: f.id, severity: injection.score >= 35 ? 'high' : 'medium', message: `${f.category}: ${String(f.match).replace(/\s+/g, ' ').slice(0, 120)}` });
  let verdict = 'safe';
  for (const f of findings) {
    const v = SEVERITY_TO_VERDICT[f.severity] || 'note';
    if ((LEVEL[v] || 0) > (LEVEL[verdict] || 0)) verdict = v;
  }
  return { label, verdict, findings, code_rules_version: code.rules_version, injection_rules_version: injection.rules_version };
}

async function cmdScan(argv, flags) {
  const target = argv[0];
  if (!target) { err('guard scan <path|->   (- reads stdin)'); return 2; }

  const results = [];
  let truncated = false;
  let skippedByType = 0;

  if (target === '-') {
    const text = readStdin();
    if (text === null) { err('guard: could not read stdin'); return 2; }
    results.push(scanText(text, 'stdin', flags.lang));
  } else {
    let stat;
    try { stat = fs.statSync(target); } catch { err(`guard: cannot read ${target}`); return 2; }
    let files = [];
    if (stat.isDirectory()) {
      const acc = walk(target, { files: [], truncated: false, skippedByType: 0 });
      files = acc.files; truncated = acc.truncated; skippedByType = acc.skippedByType;
    } else files = [target];

    for (const f of files) {
      let text;
      try {
        if (fs.statSync(f).size > MAX_FILE_BYTES) { skippedByType++; continue; }
        text = fs.readFileSync(f, 'utf8');
      } catch { continue; }
      const r = scanText(text, path.relative(process.cwd(), f) || f, path.extname(f).slice(1));
      if (r.findings.length) results.push(r);
      else results.push({ ...r, quiet: true });
    }
  }

  const withFindings = results.filter((r) => r.findings.length);
  let worst = 'safe';
  for (const r of results) if ((LEVEL[r.verdict] || 0) > (LEVEL[worst] || 0)) worst = r.verdict;

  if (flags.json) {
    out(JSON.stringify({ target, verdict: worst, files_scanned: results.length, files_with_findings: withFindings.length, truncated, results: withFindings }, null, 2));
  } else {
    for (const r of withFindings) {
      out(`${badge(r.verdict)} ${BOLD(r.label)}`);
      for (const f of r.findings) out(findingLine(f));
    }
    out('');
    out(`${results.length} file(s) scanned, ${withFindings.length} with findings. ${badge(worst)}`);
    if (truncated) out(DIM(`  stopped at ${MAX_FILES} files; the rest of the tree was not scanned`));
    if (skippedByType) out(DIM(`  ${skippedByType} file(s) skipped: not a recognised source type, or over ${MAX_FILE_BYTES / 1024 / 1024}MB`));
    out(skipped([
      'package dependencies: use `guard package <name>`',
      'anything the code and injection rulesets do not have a pattern for. These are regex rulesets, not static analysis.',
    ]).trimEnd());
  }

  record({
    event: 'cli_scan', engine: 'code+injection', verdict: worst, action: 'reported', subject: target === '-' ? 'stdin' : path.basename(String(target)),
    findings: withFindings.reduce((a, r) => a + r.findings.length, 0),
    rules: withFindings.flatMap((r) => r.findings.map((f) => f.id)),
  }, flags);

  return exitFor(worst, flags);
}

// ---------------------------------------------------------------- diff

async function cmdDiff(argv, flags) {
  const args = flags.unstaged ? ['diff', '--unified=3'] : ['diff', '--cached', '--unified=3'];
  const r = git(args);
  if (!r.ok) { err(`guard: ${r.error}`); return 2; }
  const diff = r.out;
  if (!diff.trim()) {
    out(`Nothing ${flags.unstaged ? 'unstaged' : 'staged'} to scan.`);
    return 0;
  }

  const { scanDiff } = require('../engines/code');
  const { scan: scanInjection } = require('../engines/injection');

  // One scan per file in the diff, so line numbers and the language guess are per file.
  const perFile = diff.split(/^diff --git /m).filter(Boolean).map((chunk) => 'diff --git ' + chunk);
  const results = [];
  for (const chunk of perFile) {
    const m = chunk.match(/^\+\+\+ b\/(.+)$/m);
    const file = m ? m[1] : '(unknown file)';
    const res = scanDiff(chunk, path.extname(file).slice(1));
    const added = chunk.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).map((l) => l.slice(1)).join('\n');
    const inj = scanInjection(added);
    const findings = res.findings.map((f) => ({ id: f.id, line: f.line, severity: f.severity, message: f.message, remediation: f.remediation }));
    for (const f of inj.findings) findings.push({ id: f.id, severity: inj.score >= 35 ? 'high' : 'medium', message: `${f.category}: ${String(f.match).replace(/\s+/g, ' ').slice(0, 120)}` });
    let verdict = 'safe';
    for (const f of findings) { const v = SEVERITY_TO_VERDICT[f.severity] || 'note'; if ((LEVEL[v] || 0) > (LEVEL[verdict] || 0)) verdict = v; }
    results.push({ label: file, verdict, findings, addedLines: res.addedLines });
  }

  const withFindings = results.filter((r) => r.findings.length);
  let worst = 'safe';
  for (const r of results) if ((LEVEL[r.verdict] || 0) > (LEVEL[worst] || 0)) worst = r.verdict;

  if (flags.json) {
    out(JSON.stringify({ mode: flags.unstaged ? 'unstaged' : 'staged', verdict: worst, files: results.length, results: withFindings }, null, 2));
  } else {
    for (const r of withFindings) {
      out(`${badge(r.verdict)} ${BOLD(r.label)}`);
      for (const f of r.findings) out(findingLine(f));
    }
    const addedTotal = results.reduce((a, r) => a + (r.addedLines || 0), 0);
    out('');
    out(`${results.length} file(s), ${addedTotal} added line(s) scanned. ${badge(worst)}`);
    out(skipped(['removed lines and unchanged context: only added lines are scanned']).trimEnd());
  }

  record({
    event: 'cli_diff', engine: 'code+injection', verdict: worst, action: 'reported',
    subject: `${results.length} file(s)`, findings: withFindings.reduce((a, r) => a + r.findings.length, 0),
    rules: withFindings.flatMap((r) => r.findings.map((f) => f.id)),
  }, flags);

  return exitFor(worst, flags);
}

// ---------------------------------------------------------------- package

async function cmdPackage(argv, flags) {
  const name = argv[0];
  if (!name) { err('guard package <name> [--ecosystem npm|pypi]'); return 2; }
  const ecosystem = String(flags.ecosystem || (flags.pypi ? 'pypi' : 'npm')).toLowerCase();

  const { inspect } = require('../engines/pkgname');
  const local = inspect(name, ecosystem);
  const full = flags.offline ? null : await fullPackageCheck(name, ecosystem, flags.version);

  const verdict = full && full.verdict ? full.verdict : local.verdict;
  if (flags.json) {
    out(JSON.stringify({ name, ecosystem, verdict, local, online: full }, null, 2));
  } else {
    printPackage({ pkg: { name, version: flags.version }, install: { ecosystem }, local, full }, flags);
  }

  record({ event: 'cli_package', engine: full ? 'packages' : 'pkgname', verdict, action: 'reported', subject: name, rules: (local.findings || []).map((f) => f.id) }, flags);
  return exitFor(verdict, flags);
}

// ---------------------------------------------------------------- email

async function cmdEmail(argv, flags) {
  const file = argv[0];
  if (!file) { err('guard email <file.eml>   (- reads stdin)'); return 2; }
  let raw;
  try { raw = file === '-' ? readStdin() : fs.readFileSync(file, 'utf8'); } catch { err(`guard: cannot read ${file}`); return 2; }
  if (raw === null) { err('guard: could not read stdin'); return 2; }

  const registry = require('../tools/index.js');
  const tool = registry.byName('scan_inbound');
  if (!tool) { err('guard: the email tool is not available in this build'); return 2; }
  const res = await registry.runTool(tool, { raw }, { offline: !!flags.offline, disabled: new Set() });

  const verdict = res.verdict || (res.ok === false ? 'unknown' : 'safe');
  if (flags.json) out(JSON.stringify(res, null, 2));
  else {
    out(`${badge(verdict)} ${BOLD(file === '-' ? 'stdin' : path.basename(file))}`);
    if (res.subject) out(`  subject: ${String(res.subject).slice(0, 120)}`);
    if (res.from) out(`  from: ${String(res.from).slice(0, 120)}`);
    for (const f of res.findings || []) out(findingLine({ id: f.id || f.type, severity: f.severity, message: f.match || f.message || f.note }));
    for (const n of res.notes || []) out(`  ${n}`);
    if (res.checks_skipped) out(skipped(res.checks_skipped).trimEnd());
  }

  record({ event: 'cli_email', engine: 'email', verdict, action: 'reported', subject: file === '-' ? 'stdin' : path.basename(file), findings: (res.findings || []).length }, flags);
  return exitFor(verdict, flags);
}

// ---------------------------------------------------------------- stats

function cmdStats(argv, flags) {
  const days = Number(flags.days || 7);
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const { entries, unreadable, exists, path: file } = ledger.read({ since });
  const s = ledger.summarize(entries);

  if (flags.json) { out(JSON.stringify({ since, ...s, ledger: file, unreadable_lines: unreadable }, null, 2)); return 0; }

  if (!exists) {
    out(`No ledger yet at ${file}.`);
    out('It gets written the first time a hook or a guard command runs a check.');
    return 0;
  }

  out(BOLD(`agent-guards, last ${days === 1 ? 'day' : days + ' days'}`));
  out('');
  out(`  ${String(s.checks).padStart(5)} ${plural(s.checks, 'check run', 'checks run').replace(/^\d+ /, '')}`);
  out(`  ${String(s.blocked).padStart(5)} stopped before ${s.blocked === 1 ? 'it' : 'they'} ran`);
  out(`  ${String(s.reported).padStart(5)} reported after the fact`);
  out(`  ${String(s.incomplete).padStart(5)} ${s.incomplete === 1 ? 'check' : 'checks'} that could not finish`);
  out('');

  if (s.caught.length) {
    out(BOLD('  what it found'));
    for (const e of s.caught.slice(0, 15)) {
      const when = String(e.ts).slice(0, 16).replace('T', ' ');
      const did = e.action === 'blocked' ? 'stopped' : 'reported';
      out(`  ${badge(e.verdict)} ${DIM(when)} ${DIM(did.padEnd(8))} ${e.subject || ''} ${DIM(`(${(e.rules || []).join(', ') || e.engine})`)}`);
    }
    if (s.caught.length > 15) out(DIM(`  … and ${s.caught.length - 15} more`));
    out('');
  } else {
    out(DIM('  Nothing was flagged in this window.'));
    out('');
  }

  if (s.rules.length) {
    out(BOLD('  rules that fired'));
    for (const [rule, n] of s.rules.slice(0, 10)) out(`  ${String(n).padStart(5)}  ${rule}`);
    out('');
  }

  const events = Object.entries(s.events).sort((a, b) => b[1] - a[1]);
  if (events.length) {
    out(BOLD('  by kind'));
    for (const [ev, n] of events) out(`  ${String(n).padStart(5)}  ${ev}`);
    out('');
  }

  out(DIM(`  ledger: ${file}`));
  out(DIM(`  ${cache.stats().entries} package verdict(s) cached at ${cache.cachePath()}`));
  if (unreadable) out(DIM(`  ${unreadable} line(s) in the ledger could not be parsed and were skipped`));
  out(DIM('  Local file. Nothing in it is uploaded, and it holds no file contents, secret values or message bodies.'));
  return 0;
}

// ---------------------------------------------------------------- help

const HELP = `guard — deterministic security checks, in the path you already use.

  guard npm install <pkg…>        check the packages, then run the real command
  guard pnpm add <pkg…>           same for pnpm, yarn, bun, npx, pip, uv, poetry
  guard pip install <pkg…>

  guard scan <path|->             secrets, code rules and injection patterns on a file, a tree or stdin
  guard diff                      the same, on what is staged in git (--unstaged for the working tree)
  guard package <name>            the full online check for one package: registry, OSV, downloads
  guard email <file.eml>          parse and scan an inbound message
  guard stats                     what the guards have caught on this machine (--days N)

Options
  --json                          machine-readable output
  --force                         run an install the check called danger
  --offline                       local engines only; says what it could not check
  --fail-on <danger|caution|any>  exit 1 at this level or worse (default: danger)
  --no-ledger                     do not record this run
  --ecosystem <npm|pypi>          for guard package

Exit codes: 0 nothing at or above the threshold, 1 something at or above it, 2 could not run.

Every check here is a pattern, a list, or a lookup. There is no model in any detection path, so the
same input always gives the same verdict, and every verdict names the rule behind it. What that also
means: novel attacks that no rule describes are not detected. Each command prints what it did not
check underneath what it did.`;

async function main(argv) {
  const { flags, rest } = parseArgs(argv);

  if (flags.help || flags.h || (!rest.length && !flags.version)) { out(HELP); return rest.length ? 0 : (flags.help || flags.h ? 0 : 2); }
  if (flags.version || flags.v) {
    let v = 'unknown';
    try { v = require('../package.json').version || 'unknown'; } catch { /* vendored copies may not ship one */ }
    out(v);
    return 0;
  }

  const cmd = rest[0];
  const args = rest.slice(1);

  try {
    if (MANAGERS.has(cmd)) return await cmdInstall(rest, flags);
    if (cmd === 'scan') return await cmdScan(args, flags);
    if (cmd === 'diff') return await cmdDiff(args, flags);
    if (cmd === 'package' || cmd === 'pkg') return await cmdPackage(args, flags);
    if (cmd === 'email') return await cmdEmail(args, flags);
    if (cmd === 'stats') return cmdStats(args, flags);
    err(`guard: unknown command "${cmd}"`);
    err('');
    err(HELP);
    return 2;
  } catch (e) {
    err(`guard: ${(e && e.stack) || e}`);
    return 2;
  }
}

module.exports = { main, parseArgs, scanText, HELP, LEVEL };
