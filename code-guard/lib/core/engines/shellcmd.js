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

// GuardFall (Adversa AI, 2026-06-30) named the structural mistake behind ten of eleven agent shell
// guards: the string the guard inspects is not the string the shell runs. bash expands, unquotes and
// rewrites first. Everything below closes that gap for the rewrites a shell performs
// deterministically, and reports what it cannot resolve instead of passing it. Nothing here
// evaluates, expands by running anything, or executes any part of a command: it is all text.
//
// $IFS is the field separator, so `curl${IFS}-sL${IFS}url` is three words by the time bash sees it.
// Single quotes suppress the expansion, so a literal ${IFS} inside them stays literal.
function expandIfs(text) {
  let out = '';
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote === "'") { out += ch; if (ch === "'") quote = null; continue; }
    if (quote === '"') { out += ch; if (ch === '"') quote = null; continue; }
    if (ch === "'" || ch === '"') { quote = ch; out += ch; continue; }
    if (ch === '$') {
      const m = /^\$\{IFS\}|^\$IFS(?![A-Za-z0-9_])/.exec(text.slice(i));
      if (m) { out += ' '; i += m[0].length - 1; continue; }
    }
    out += ch;
  }
  return out;
}

// A command name can be spelled `bash`, `b"a"sh`, `b\ash` or `/usr/bin/bash`. Quotes are already
// gone by the time a token arrives here. Path-stripping and backslash-unescaping disagree about
// `b\ash` (one reads the backslash as a directory separator, the other as an escape), so both
// readings are returned and a match on either counts. Guessing wrong in the other direction would
// mean missing a real one.
function binaryNames(token) {
  const raw = String(token);
  const clean = (s) => s.replace(/\.(exe|cmd|bat|ps1)$/i, '').toLowerCase();
  const asPath = clean(raw.replace(/^.*[\\/]/, ''));
  const asEscaped = clean(raw.replace(/\\(.)/g, '$1').replace(/^.*[\\/]/, ''));
  return [...new Set([asPath, asEscaped])].filter(Boolean);
}

// `FOO=1 curl …` runs curl. The assignment prefix has to come off before anything reads the command
// name, or a leading assignment hides the command from every check below.
function effectiveCommand(stage) {
  let text = String(stage).trim();
  for (;;) {
    const m = /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)\s+/.exec(text);
    if (!m) return text;
    text = text.slice(m[0].length);
  }
}

// What sits in an execution position: a name, something built by another command, or a variable
// whose value is not knowable from the text. The last two are the honest part. A command
// substitution can produce anything, so no static reading of it is possible, and saying so is the
// only correct answer.
function classifyBinary(stage, env) {
  const text = effectiveCommand(stage);
  if (!text) return null;
  if (/^\$\(|^`/.test(text)) return { dynamic: true };
  const toks = tokenize(text);
  const first = toks[0];
  if (!first) return null;
  if (/\$\(|`/.test(first)) return { dynamic: true };
  // An expansion does not have to be the whole word: `${X}sh`, `b${Z}ash` and `${UNSET:-bash}` all
  // produce a command name. Only the plain $VAR and ${VAR} spellings can be read from an assignment
  // in the same command line. Every other form (`${VAR:-default}`, `${VAR#trim}`, `${!indirect}`,
  // `$((…))`) is computed while the shell runs, so it is reported rather than guessed at.
  if (first.includes('$')) {
    let firstUnknown = null;
    const resolved = first.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, braced, bare) => {
      const name = braced || bare;
      const value = Object.prototype.hasOwnProperty.call(env, name) ? env[name] : undefined;
      if (typeof value === 'string' && value) return value;
      if (!firstUnknown) firstUnknown = name;
      return ' ';
    });
    if (resolved.includes(' ') || resolved.includes('$')) {
      return { unresolved: firstUnknown || first, spelling: first };
    }
    return { names: binaryNames(resolved), from: first };
  }
  return { names: binaryNames(first) };
}

// `X=bash` then `… | $X` is two pipelines, so assignments are collected across the whole command
// line rather than per stage. A value that is itself computed is recorded as unknown, which sends it
// down the unresolved path instead of inventing an answer.
function collectAssignments(stage, env) {
  const toks = tokenize(stage);
  let i = toks[0] === 'export' ? 1 : 0;
  for (; i < toks.length; i++) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/.exec(toks[i]);
    if (!m) break;
    env[m[1]] = /[$`]/.test(m[2]) ? null : m[2];
  }
}

// Decoding a blob and running the result is the same shape as downloading and running it, and the
// blob does not have to arrive over the network.
// A flag of null means the command only ever decompresses, so its presence is enough. Compression is
// decoding: `zcat payload.gz | bash` hides what runs exactly as well as base64 does, and it does not
// need the network to get the blob onto the machine.
const DECODERS = [
  { bin: 'base64', flag: /^--?[A-Za-z]*[dD][A-Za-z]*$|^--decode$/ },
  { bin: 'base32', flag: /^--?[A-Za-z]*[dD][A-Za-z]*$|^--decode$/ },
  { bin: 'xxd', flag: /^-r$/ },
  { bin: 'openssl', flag: /^-d$/ },
  { bin: 'uudecode', flag: null },
  { bin: 'gzip', flag: /^-[a-z]*d[a-z]*$|^--decompress$|^--uncompress$/ },
  { bin: 'gunzip', flag: null },
  { bin: 'zcat', flag: null },
  { bin: 'xz', flag: /^-[a-z]*d[a-z]*$|^--decompress$/ },
  { bin: 'unxz', flag: null },
  { bin: 'xzcat', flag: null },
  { bin: 'lzcat', flag: null },
  { bin: 'bzip2', flag: /^-[a-z]*d[a-z]*$|^--decompress$/ },
  { bin: 'bunzip2', flag: null },
  { bin: 'bzcat', flag: null },
  { bin: 'zstd', flag: /^-[a-z]*d[a-z]*$|^--decompress$/ },
  { bin: 'unzstd', flag: null },
  { bin: 'zstdcat', flag: null },
  { bin: 'lz4', flag: /^-[a-z]*d[a-z]*$|^--decompress$/ },
  { bin: 'brotli', flag: /^-[a-z]*d[a-z]*$|^--decompress$/ },
  // Extraction only counts when the archive is written to stdout, which is what feeds a pipe.
  { bin: 'tar', flag: /^-[A-Za-z]*O[A-Za-z]*$|^--to-stdout$/ },
  { bin: 'unzip', flag: /^-[a-z]*p[a-z]*$/ },
  { bin: '7z', flag: /^-so$/ },
  { bin: '7za', flag: /^-so$/ },
];

function isDecoder(stage) {
  const toks = tokenize(effectiveCommand(stage));
  if (!toks.length) return false;
  const names = binaryNames(toks[0]);
  const d = DECODERS.find((x) => names.includes(x.bin));
  if (!d) return false;
  if (!d.flag) return true;
  return toks.slice(1).some((t) => d.flag.test(t));
}

// Split a command line into pipelines, then each pipeline into its stages. Operators inside quotes
// are left alone; the scan tracks quoting as it goes.
function split(command) {
  const text = expandIfs(stripHeredocBodies(command));
  const pipelines = [];
  let cur = '';
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) { cur += ch; if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    const two = text.slice(i, i + 2);
    if (two === '&&' || two === '||') { pipelines.push(cur); cur = ''; i++; continue; }
    // A newline does not always end a command. A trailing backslash escapes it, and a line ending in
    // `|` leaves the pipeline open. Both are ordinary README formatting, and treating them as
    // terminators put the fetch and the shell in separate pipelines where nothing compared them.
    if (ch === '\n') {
      const trimmed = cur.replace(/[ \t\r]+$/, '');
      if (trimmed.endsWith('\\')) { cur = `${trimmed.slice(0, -1)} `; continue; }
      if (trimmed.endsWith('|')) { cur = `${trimmed} `; continue; }
    }
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

// Interpreters that can take their program as an argument instead of reading it from stdin. Keyed by
// the flag that carries the program.
const INLINE_PROGRAM_FLAGS = {
  python: ['-c'], python3: ['-c'], perl: ['-e'], ruby: ['-e'],
  node: ['-e', '-p', '--eval', '--print'],
  sh: ['-c'], bash: ['-c'], zsh: ['-c'], ksh: ['-c'], dash: ['-c'], fish: ['-c'], csh: ['-c'], tcsh: ['-c'],
};

// Returns the program text when the interpreter was handed one on the command line, otherwise null.
// `python -` and a bare `python` both read the program from stdin, and `bash -s` does too, so those
// return null and stay on the risky path. -m is deliberately absent: `python -m code` runs whatever
// arrives on stdin, so a module name is not a promise that stdin is data.
function inlineProgram(tokens, bare) {
  const flags = INLINE_PROGRAM_FLAGS[bare];
  if (!flags) return null;
  for (let i = 1; i < tokens.length; i++) {
    const tok = String(tokens[i]);
    if (tok === '-') return null;
    if (flags.includes(tok)) return tokens[i + 1] === undefined ? '' : String(tokens[i + 1]);
  }
  return null;
}

// An inline script can still read stdin and execute it, which is the original shape wearing a hat.
// Only the combination counts: reading stdin is ordinary, executing what it read is not.
function inlineProgramRunsStdin(src) {
  if (!src) return false;
  const readsStdin = /stdin|\/dev\/stdin|readFileSync\s*\(\s*0|\bARGF\b|\bfileinput\b/i.test(src);
  if (!readsStdin) return false;
  return /\b(exec|eval|execfile|compile|Function|system|instance_eval)\b/i.test(src);
}

// Command shapes that are worth a word regardless of any package name. Both of these hand control of
// the machine to whatever a server returns, which is not something to notice after the fact.
function riskyPatterns(pipeline, env = Object.create(null)) {
  const out = [];
  const stages = pipeline.stages;
  const fetchers = /^(curl|wget|iwr|invoke-webrequest|fetch)\b/i;
  const add = (id, message) => { out.push({ id, severity: 'medium', message, raw: pipeline.raw }); };

  // A source stage is one that brings in bytes nobody here has read: fetched from a URL, or decoded
  // from a blob. Any interpreter downstream of one is running those bytes, whether the pipe is
  // direct or has something in between.
  for (let i = 0; i < stages.length - 1 && !out.length; i++) {
    const source = effectiveCommand(stages[i]);
    const fetched = fetchers.test(source.replace(/^\S*[\\/]/, ''));
    const decoded = isDecoder(source);
    if (!fetched && !decoded) continue;

    for (let j = i + 1; j < stages.length; j++) {
      const target = classifyBinary(stages[j], env);
      if (!target) continue;

      if (target.dynamic) {
        add('cmd-dynamic-exec', `The command on the receiving end of this pipe is built by another command (\`${stages[j].trim().slice(0, 40)}\`), so what actually runs cannot be read before it runs. This check cannot clear it either way.`);
        break;
      }
      if (target.unresolved) {
        add('cmd-unresolved-exec', `The receiving end of this pipe is \`${target.spelling || '$' + target.unresolved}\`, and what it expands to is not knowable from this command, so what runs here is unknown. This check cannot clear it either way.`);
        break;
      }
      // A hook runs this on every Bash call, so an unexpected shape reports nothing rather than
      // throwing and taking the tool call down with it.
      const shell = (target.names || []).find((n) => SHELLS.has(n));
      if (!shell) continue;

      // `… | python -c '<script>'` runs the script written right there and reads the pipe as data.
      // That is a pipe into a parser, not a download being executed.
      const inline = inlineProgram(tokenize(stages[j]), shell);
      if (inline !== null && !inlineProgramRunsStdin(inline)) continue;

      const spelling = target.from ? `${shell} (via ${target.from})` : shell;
      if (fetched) {
        add('cmd-remote-to-shell', `This downloads something and runs it immediately (\`${source.slice(0, 60)} | ${spelling}\`). Whatever that URL returns at the moment it is fetched gets executed, and nothing here has read it.`);
      } else {
        add('cmd-decode-to-shell', `This decodes something and runs the result (\`${source.slice(0, 40)} | ${spelling}\`). Decoding first hides what runs from anything that reads the command, including this check.`);
      }
      break;
    }
  }

  // `eval` and `source` run whatever their argument turns out to be. The common shells-init idiom
  // (`eval "$(pyenv init -)"`) is the same shape as the dangerous one, so the generators that
  // everyone actually uses are named here rather than warned about forever.
  const EVALS = new Set(['eval', 'source', '.', 'iex', 'invoke-expression']);
  const KNOWN_INIT = /\b(ssh-agent|pyenv|rbenv|nodenv|jenv|goenv|direnv|starship|zoxide|fnm|mise|asdf|brew|conda|micromamba|thefuck|atuin|navi|oh-my-posh|keychain|gpg-agent)\b/;
  for (const stage of stages) {
    if (out.length) break;
    const toks = tokenize(stage);
    if (!toks.length) continue;
    if (!binaryNames(toks[0]).some((n) => EVALS.has(n))) continue;
    const argText = stage.trim().slice(toks[0].length);
    if (!/\$\(|`|\$\{?[A-Za-z_]/.test(argText)) continue;
    if (KNOWN_INIT.test(argText)) continue;
    add('cmd-dynamic-exec', `\`${binaryNames(toks[0])[0]}\` here runs text that is produced when the command runs, so what executes cannot be read beforehand. This check cannot clear it either way.`);
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
  // Assignments carry forward across pipelines, so the map is built as the command line is walked
  // rather than per pipeline.
  const env = Object.create(null);
  for (const p of pipelines) {
    for (const stage of p.stages) collectAssignments(stage, env);
    for (const stage of p.stages) {
      const read = readStage(stage);
      if (read) installs.push(read);
    }
    risky.push(...riskyPatterns(p, env));
  }
  // The same shape appearing twice in one command line is one thing to say, not two.
  const seen = new Set();
  const uniqueRisky = risky.filter((r) => { const k = r.id + r.raw; if (seen.has(k)) return false; seen.add(k); return true; });
  return { installs, risky: uniqueRisky, pipelines: pipelines.length, rules_version: NAME_RULES_VERSION };
}

module.exports = { parse, split, tokenize, parseNpmSpec, parsePipSpec, readStage, notPackage, stripHeredocBodies };
