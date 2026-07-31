// Membership lookup against the known-malicious package list, without parsing it.
//
// The list is the largest thing the rules feed carries by an order of magnitude: about 228,000
// advisories covering roughly 228,000 distinct npm and PyPI names. As JSON that is 6 MB, and a
// PreToolUse hook that parsed 6 MB before every `npm install` would cost more than the check is
// worth — the whole hook budget today is 65 to 89 milliseconds.
//
// So the list does not live in the JSON bundle. It is a sorted TSV, one package per line, and this
// file binary-searches it on disk. A lookup is four or five 4 KB reads and no parse at all. The
// file is not loaded, not cached in memory, and not walked.
//
// Line format, tab separated:
//
//     <ecosystem>\t<name>\t<versions>\t<advisory>
//
// `versions` is `*` when the advisory names no versions, which in OSV means the whole package is
// malicious, and a comma-separated list when it names some. That distinction is the difference
// between "never install this" and "this package was compromised at 4.4.2" — and it is the reason
// this is not a list of names. Measured against the 3,000 most-installed npm packages, 42 of them
// appear here, every one of them a legitimate package that was briefly compromised: debug 4.4.2,
// chalk 5.6.1, ansi-styles 6.2.2 and the rest of the September 2025 npm worm. A names-only list
// would have reported `npm install debug` as malicious.
//
// Sort order is byte order on `<ecosystem>\t<name>`, which is what the builder writes and what the
// search below assumes. If that ever stops being true the search silently misses, so the builder
// asserts it and there is a test that reads a real file.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { home } = require('./paths');

const CHUNK = 4096;

function listPath() { return path.join(home(), 'rules', 'packages.tsv'); }

// Read the line containing byte offset `pos`, plus where it started. Returns null past the end.
function lineAt(fd, size, pos) {
  if (pos >= size) return null;
  // Walk backwards to the start of the line.
  let start = pos;
  const back = Buffer.alloc(CHUNK);
  while (start > 0) {
    const from = Math.max(0, start - CHUNK);
    const n = fs.readSync(fd, back, 0, start - from, from);
    let found = -1;
    for (let i = n - 1; i >= 0; i--) if (back[i] === 0x0a) { found = from + i + 1; break; }
    if (found !== -1) { start = found; break; }
    start = from;
  }
  // Then forwards to the end of it.
  const parts = [];
  let at = start;
  for (;;) {
    if (at >= size) break;
    const buf = Buffer.alloc(Math.min(CHUNK, size - at));
    const n = fs.readSync(fd, buf, 0, buf.length, at);
    if (!n) break;
    const nl = buf.indexOf(0x0a);
    if (nl === -1) { parts.push(buf.slice(0, n)); at += n; continue; }
    parts.push(buf.slice(0, nl));
    at += nl;
    break;
  }
  return { start, text: Buffer.concat(parts).toString('utf8').replace(/\r$/, '') };
}

function parseLine(text) {
  const f = text.split('\t');
  if (f.length < 3) return null;
  return {
    ecosystem: f[0],
    name: f[1],
    versions: f[2] === '*' ? null : f[2].split(',').filter(Boolean),
    advisory: f[3] || null,
  };
}

// Binary search for `<ecosystem>\t<name>`. Returns the parsed line or null.
function find(ecosystem, name, file) {
  const target = `${String(ecosystem || '').toLowerCase()}\t${name}`;
  const p = file || listPath();
  let fd;
  try { fd = fs.openSync(p, 'r'); } catch { return null; }
  try {
    const size = fs.fstatSync(fd).size;
    let lo = 0;
    let hi = size;
    let guard = 0;
    while (lo < hi && guard++ < 64) {
      const mid = Math.floor((lo + hi) / 2);
      const line = lineAt(fd, size, mid);
      if (!line) { hi = mid; continue; }
      const key = line.text.slice(0, line.text.indexOf('\t', line.text.indexOf('\t') + 1));
      if (key === target) return parseLine(line.text);
      if (key < target) {
        // Move past this line, or a mid landing inside it would loop forever.
        lo = line.start + Buffer.byteLength(line.text, 'utf8') + 1;
      } else {
        hi = line.start;
      }
    }
    return null;
  } catch { return null; }
  finally { try { fs.closeSync(fd); } catch { /* already gone */ } }
}

// The question a caller actually has: I am about to install this, what do you know?
//
// Returns null when the list is not installed at all, so a caller can say "not checked" instead of
// "clean". A missing list is not a clean bill of health, which is the bug class this project keeps
// finding in its own code.
function check(ecosystem, name, version, file) {
  const p = file || listPath();
  if (!fs.existsSync(p)) return null;
  const hit = find(ecosystem, name, p);
  if (!hit) return { known: false, verdict: 'clear' };
  if (!hit.versions) {
    return { known: true, verdict: 'malicious', scope: 'package', advisory: hit.advisory, note: 'every version of this package is on the malicious list' };
  }
  if (version && hit.versions.includes(String(version))) {
    return { known: true, verdict: 'malicious', scope: 'version', versions: hit.versions, advisory: hit.advisory, note: `version ${version} is on the malicious list` };
  }
  // The name is on the list but this version is not. Saying "clear" here would be wrong and saying
  // "malicious" would be worse: this is how a legitimate package that was compromised once looks.
  return {
    known: true,
    verdict: 'caution',
    scope: 'version',
    versions: hit.versions,
    advisory: hit.advisory,
    note: version
      ? `version ${version} is not on the malicious list, but ${hit.versions.length} version(s) of this package are: ${hit.versions.join(', ')}`
      : `no version was given. ${hit.versions.length} version(s) of this package are on the malicious list: ${hit.versions.join(', ')}`,
  };
}

function stats(file) {
  const p = file || listPath();
  try {
    const st = fs.statSync(p);
    return { available: true, path: p, bytes: st.size };
  } catch { return { available: false, path: p, bytes: 0 }; }
}

function sha256File(file) {
  try { return crypto.createHash('sha256').update(fs.readFileSync(file || listPath())).digest('hex'); }
  catch { return null; }
}

module.exports = { check, find, stats, listPath, sha256File, parseLine };
