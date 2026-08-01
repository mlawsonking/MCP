// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/engines/shellcmd.js
// Regenerate: node scripts/sync-shared.js
// Reading a shell command well enough to know what it is about to install.
//
// This exists because the useful moment to check a package is the moment before it is installed, and
// on an agent that moment is a shell command someone is about to run. So the command has to be taken
// apart: which of its pipeline stages is an install, which arguments are package names rather than
// flags or file paths or git URLs, and which of them carry a version.
//
// It is a parser for a purpose, not a shell. It does not expand variables, do glob expansion, follow
// `xargs`, or understand a package name arriving through a subshell. Anything it cannot read it
// reports as unread rather than dropping, because a silently skipped argument is the same failure as
// a check that did not run: the caller would see "nothing found" and believe it.

const { NAME_RULES_VERSION } = require('../lib/version');

const NPM_INSTALL_ACTIONS = new Set(['install', 'i', 'add', 'in', 'ins', 'inst', 'isnt', 'isntall', 'update', 'up', 'upgrade']);
const PIP_INSTALL_ACTIONS = new Set(['install']);

// Flags that swallow the argument after them. Without this list, `pip install -r requirements.txt`
// reads "requirements.txt" as a package and `npm i --registry https://…` reads the URL as one.
const VALUE_FLAGS = new Set([
  '-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index-url',
  '--extra-index-url', '-f', '--find-links', '-t', '--target', '--prefix', '--root',
  '--python', '-p', '--registry', '-w', '--workspace', '--tag', '--cache', '--userconfig',
  '--globalconfig', '--prefer-offline-timeout', '--filter', '--dir', '-C', '--cwd', '--index',
]);

const SHELLS = new Set(['sh', 'bash', 'zsh', 'ksh', 'dash', 'fish', 'csh', 'tcsh', 'iex', 'invoke-expression', 'python', 'python3', 'perl', 'ruby', 'node']);

// A heredoc is data for the command on the line above it, not another shell command. Claude Code
// passes the whole Bash input to this parser, including heredoc bodies. Treating those bodies as
// commands made prose in a commit message look like install arguments. Keep the command lines and
// remove each body (including its delimiter) before splitting on newlines.
function heredocsOnLine(line) {
  const found = [];
  let quote = null;
  let escaped = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (escaped) { escaped = false; continue; }
    if (ch === '\\' && quote !== "'") { escaped = true; continue; }
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) break;
    if (ch !== '<' || line[i + 1] !== '<' || line[i + 2] === '<') continue;

    i += 2;
    let stripTabs = false;
    if (line[i] === '-') { stripTabs = true; i++; }
    while (/\s/.test(line[i] || '')) i++;
    if (i >= line.length) continue;

    let delimiter = '';
    const delimiterQuote = line[i] === '"' || line[i] === "'" ? line[i++] : null;
    if (!delimiterQuote && line[i] === '\\') i++;
    while (i < line.length) {
      const c = line[i];
      if (delimiterQuote ? c === delimiterQuote : /[\s;|&()<>]/.test(c)) break;
      delimiter += c;
      i++;
    }
    if (delimiter) found.push({ delimiter, stripTabs });
  }
  return found;
}

function stripHeredocBodies(command) {
  const lines = String(command || '').split('\n');
  const kept = [];
  const pending = [];

  for (const raw of lines) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (pending.length) {
      const current = pending[0];
      const candidate = current.stripTabs ? line.replace(/^\t+/, '') : line;
      if (candidate === current.delimiter) pending.shift();
      kept.push('');
      continue;
    }
    kept.push(raw);
    pending.push(...heredocsOnLine(line));
  }
  return kept.join('\n');
}

// Tokenize on whitespace while keeping quoted runs together. Quotes are removed; escapes inside
// double quotes are left alone because nothing downstream cares about the difference.
function tokenize(s) {
  const out = [];
  let cur = '';
  let quote = null;
  let has = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) { quote = null; continue; }
      cur += ch; has = true; continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; has = true; continue; }
    if (/\s/.test(ch)) { if (has) { out.push(cur); cur = ''; has = false; } continue; }
    cur += ch; has = true;
  }
  if (has) out.push(cur);
  return out;
}

// Split a command line into pipelines, then each pipeline into its stages. Operators inside quotes
// are left alone; the scan tracks quoting as it goes.
function split(command) {
  const text = stripHeredocBodies(command);
  const pipelines = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) { cur += ch; if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    const two = text.slice(i, i + 2);
    if (two === '&&' || two === '||') { pipelines.push(cur); cur = ''; i++; continue; }
    if (ch === ';' || ch === '\n') { pipelines.push(cur); cur = ''; continue; }
    cur += ch;
  }
  pipelines.push(cur);

  return pipelines.map((p) => p.trim()).filter(Boolean).map((p) => {
    const stages = [];
    let s = '';
    let q = null;
    for (let i = 0; i < p.length; i++) {
      const ch = p[i];
      if (q) { s += ch; if (ch === q) q = null; continue; }
      if (ch === '"' || ch === "'") { q = ch; s += ch; continue; }
      if (ch === '|') { stages.push(s); s = ''; continue; }
      s += ch;
    }
    stages.push(s);
    return { raw: p, stages: stages.map((x) => x.trim()).filter(Boolean) };
  });
}

// "express@4.17.1" -> { name: express, version: 4.17.1 }. Scopes keep their leading @.
function parseNpmSpec(token) {
  const t = String(token);
  const scoped = t.startsWith('@');
  const at = t.indexOf('@', scoped ? 1 : 0);
  if (at > 0) return { name: t.slice(0, at), version: t.slice(at + 1) || undefined, raw: t };
  return { name: t, version: undefined, raw: t };
}

// "requests[socks]==2.31.0" -> { name: requests, version: 2.31.0 }
function parsePipSpec(token) {
  const t = String(token);
  const m = t.match(/^([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*(?:(===|==|>=|<=|~=|!=|>|<)\s*([^\s,;]+))?/);
  if (!m) return { name: t, raw: t };
  return { name: m[1], version: m[4] || undefined, raw: t };
}

// Reasons an argument is not a package name. Each one is returned so the caller can say what it
// chose not to check instead of quietly ignoring it.
function notPackage(token) {
  const t = String(token);
  if (t.startsWith('-')) return null; // a flag, not something skipped
  if (t === '.' || t === '..') return 'a local path';
  if (/^[.~/\\]/.test(t)) return 'a local path';
  if (/^[A-Za-z]:[\\/]/.test(t)) return 'a local path';
  if (/^(git\+|https?:|ssh:|file:|github:|gitlab:|bitbucket:|npm:|link:|workspace:|portal:)/i.test(t)) return 'an install from a URL or the filesystem rather than a registry name';
  if (/^[^@/\s]+\/[^@/\s]+$/.test(t) && !t.startsWith('@')) return 'a GitHub owner/repo shorthand rather than a registry name';
  if (/[$`*?]/.test(t)) return 'a shell expansion this parser does not expand';
  return null;
}

// One pipeline stage -> an install description, or null.
function readStage(stage) {
  const tokens = tokenize(stage);
  if (!tokens.length) return null;

  let idx = 0;
  // Leading environment assignments and `sudo`.
  while (idx < tokens.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[idx]) || tokens[idx] === 'sudo' || tokens[idx] === 'command')) idx++;
  if (idx >= tokens.length) return null;

  const bin = tokens[idx].replace(/^.*[\\/]/, '').replace(/\.(exe|cmd|bat|ps1)$/i, '').toLowerCase();
  let rest = tokens.slice(idx + 1);

  let manager = null, ecosystem = null, action = null, specParser = parseNpmSpec;

  if (bin === 'npm' || bin === 'pnpm' || bin === 'yarn' || bin === 'bun') {
    // `pnpm dlx` / `yarn dlx` / `bun x` run a package without installing it, which is the same risk.
    if (rest[0] === 'dlx' || (bin === 'bun' && rest[0] === 'x')) {
      manager = `${bin} ${rest[0]}`; ecosystem = 'npm'; action = 'exec'; rest = rest.slice(1);
    } else if (rest[0] && NPM_INSTALL_ACTIONS.has(rest[0].toLowerCase())) {
      manager = bin; ecosystem = 'npm'; action = rest[0].toLowerCase(); rest = rest.slice(1);
    } else if (bin === 'yarn' && rest.length && !rest[0].startsWith('-') && !NPM_INSTALL_ACTIONS.has(rest[0].toLowerCase())) {
      return null; // `yarn build` and friends
    } else if (bin === 'yarn' && rest.length === 0) {
      return null; // bare `yarn` installs the lockfile, no names to check
    } else return null;
  } else if (bin === 'npx' || bin === 'bunx') {
    manager = bin; ecosystem = 'npm'; action = 'exec';
  } else if (bin === 'pip' || bin === 'pip3' || bin === 'pipx') {
    if (!rest[0] || !PIP_INSTALL_ACTIONS.has(rest[0].toLowerCase())) return null;
    manager = bin; ecosystem = 'pypi'; action = 'install'; rest = rest.slice(1); specParser = parsePipSpec;
  } else if (bin === 'uv') {
    if (rest[0] === 'pip' && rest[1] === 'install') { manager = 'uv pip'; ecosystem = 'pypi'; action = 'install'; rest = rest.slice(2); specParser = parsePipSpec; }
    else if (rest[0] === 'add') { manager = 'uv'; ecosystem = 'pypi'; action = 'add'; rest = rest.slice(1); specParser = parsePipSpec; }
    else if (rest[0] === 'tool' && (rest[1] === 'install' || rest[1] === 'run')) { manager = 'uv tool'; ecosystem = 'pypi'; action = rest[1]; rest = rest.slice(2); specParser = parsePipSpec; }
    else return null;
  } else if (bin === 'poetry') {
    if (rest[0] !== 'add') return null;
    manager = 'poetry'; ecosystem = 'pypi'; action = 'add'; rest = rest.slice(1); specParser = parsePipSpec;
  } else if (bin === 'python' || bin === 'python3') {
    // python -m pip install X
    const m = rest.indexOf('-m');
    if (m === -1 || rest[m + 1] !== 'pip' || rest[m + 2] !== 'install') return null;
    manager = 'python -m pip'; ecosystem = 'pypi'; action = 'install'; rest = rest.slice(m + 3); specParser = parsePipSpec;
  } else return null;

  const packages = [];
  const skipped = [];
  const flags = [];
  for (let i = 0; i < rest.length; i++) {
    const tok = rest[i];
    if (tok.startsWith('-')) {
      flags.push(tok);
      const bare = tok.split('=')[0];
      if (VALUE_FLAGS.has(bare) && !tok.includes('=') && rest[i + 1] !== undefined) i++;
      continue;
    }
    const why = notPackage(tok);
    if (why) { skipped.push({ arg: tok, reason: why }); continue; }
    const spec = specParser(tok);
    if (spec.name) packages.push(spec);
    // `npx pkg arg arg` — everything after the package is that command's own arguments.
    if (action === 'exec') break;
  }

  return { manager, ecosystem, action, packages, skipped, flags, raw: stage.trim() };
}

// Command shapes that are worth a word regardless of any package name. Both of these hand control of
// the machine to whatever a server returns, which is not something to notice after the fact.
function riskyPatterns(pipeline) {
  const out = [];
  const stages = pipeline.stages;
  const fetchers = /^(curl|wget|iwr|invoke-webrequest|fetch)\b/i;
  for (let i = 0; i < stages.length - 1; i++) {
    if (!fetchers.test(stages[i].trim().replace(/^\S*[\\/]/, ''))) continue;
    const nextBin = tokenize(stages[i + 1])[0];
    if (!nextBin) continue;
    const bare = String(nextBin).replace(/^.*[\\/]/, '').replace(/\.(exe|cmd|bat|ps1)$/i, '').toLowerCase();
    if (SHELLS.has(bare)) {
      out.push({
        id: 'cmd-remote-to-shell',
        severity: 'medium',
        message: `This downloads something and runs it immediately (\`${stages[i].trim().slice(0, 60)} | ${bare}\`). Whatever that URL returns at the moment it is fetched gets executed, and nothing here has read it.`,
        raw: pipeline.raw,
      });
      break;
    }
  }
  // The PowerShell spelling has no pipe: iwr … | iex is covered above, but `iex (iwr …)` is not.
  if (/\b(iex|invoke-expression)\b[^|]*\b(iwr|invoke-webrequest|curl|wget|downloadstring)\b/i.test(pipeline.raw)) {
    out.push({
      id: 'cmd-remote-to-shell',
      severity: 'medium',
      message: 'This fetches a script and evaluates it in the same expression. Whatever that URL returns gets executed, and nothing here has read it.',
      raw: pipeline.raw,
    });
  }
  return out;
}

function parse(command) {
  const pipelines = split(command);
  const installs = [];
  const risky = [];
  for (const p of pipelines) {
    for (const stage of p.stages) {
      const read = readStage(stage);
      if (read) installs.push(read);
    }
    risky.push(...riskyPatterns(p));
  }
  // The same shape appearing twice in one command line is one thing to say, not two.
  const seen = new Set();
  const uniqueRisky = risky.filter((r) => { const k = r.id + r.raw; if (seen.has(k)) return false; seen.add(k); return true; });
  return { installs, risky: uniqueRisky, pipelines: pipelines.length, rules_version: NAME_RULES_VERSION };
}

module.exports = { parse, split, tokenize, parseNpmSpec, parsePipSpec, readStage, notPackage, stripHeredocBodies };
