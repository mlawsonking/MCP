// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/engines/pkgname.js
// Regenerate: node scripts/sync-shared.js
// Package checks that need no network at all.
//
// Every other package check in this codebase asks a registry or OSV, which means none of them can
// run inside a hook: a PreToolUse hook sits in front of every shell command an agent runs, and a
// guard that adds a network round trip to `npm install` gets uninstalled by Friday. So this engine
// answers the one question that can be answered from the machine alone — does this name look like a
// name someone registered to be mistaken for a real one — and is explicit that this is all it did.
//
// What it checks:
//   pkg-name-nonascii    a character outside ASCII in the name. `еxpress` with a Cyrillic е is a
//                        different package from `express` and looks identical in a terminal.
//   pkg-name-separator   the name matches a popular package once hyphens, underscores and dots are
//                        removed. `crossenv` against `cross-env` is the textbook npm attack.
//   pkg-name-confusable  one character apart from a popular name, and the swap is a visual one
//                        (l/1, o/0, rn/m). Nobody types those by accident.
//   pkg-name-near        one or two edits from a popular name, any edit. Heuristic, so it warns.
//   pkg-name-affix       a popular name with js, .js, node- or python- stuck on it.
//   pkg-cached-verdict   a verdict from an earlier run that DID reach OSV and the registry, with its
//                        age attached.
//
// What it does not check, ever, and says so in every response: whether the package exists, whether
// OSV holds an advisory for it, how often it is downloaded, and what is inside it. A `safe` from this
// engine means "nothing about this name looked wrong", not "this package is safe to install".
//
// The comparison list is agent-guards/data/popular-*.json — a few thousand names, each one measured
// against the registry's own download numbers on the date recorded in the file. It is a snapshot, so
// a package that became popular after that date is not in it and a squat aimed at that package will
// not be caught here.

const { Checks, stamp } = require('../lib/verdict');
const { NAME_RULES_VERSION } = require('../lib/version');
const cache = require('../lib/cache');

const DATA = {
  npm: () => require('../data/popular-npm.json'),
  pypi: () => require('../data/popular-pypi.json'),
};

// PyPI compares project names after collapsing every run of - _ . into a single - and lowercasing
// (PEP 503), so `Discord.py`, `discord-py` and `discord_py` are all the same project and typing any
// of them installs it. npm does no such thing: there, `cross-env` and `crossenv` are two packages,
// which is the entire reason the separator rule below exists. Missing this distinction had the
// engine reporting `discord.py` as a squat of `discord-py`, which is the same package.
function canonical(name, ecosystem) {
  const n = String(name || '');
  return ecosystem === 'pypi' ? n.replace(/[-_.]+/g, '-').toLowerCase() : n;
}

const loaded = new Map();
function popular(ecosystem) {
  const eco = ecosystem === 'pypi' ? 'pypi' : 'npm';
  if (loaded.has(eco)) return loaded.get(eco);

  let file;
  try { file = DATA[eco](); }
  catch { file = null; }

  if (!file || !Array.isArray(file.names)) {
    const empty = { available: false, generated: null, size: 0, set: new Set(), byLength: new Map(), collapsed: new Map() };
    loaded.set(eco, empty);
    return empty;
  }

  const set = new Set(file.names);
  const byLength = new Map();
  const collapsed = new Map();
  const scopes = new Set();
  for (const n of file.names) {
    const len = n.length;
    if (!byLength.has(len)) byLength.set(len, []);
    byLength.get(len).push(n);
    const c = collapse(n);
    if (!collapsed.has(c)) collapsed.set(c, n);
    const s = scopeOf(n);
    if (s) scopes.add(s);
  }
  const out = { available: true, generated: file.generated || null, size: file.names.length, set, byLength, collapsed, scopes };
  loaded.set(eco, out);
  return out;
}

// Strip the punctuation that carries no meaning to a reader glancing at a name — but NOT the scope
// boundary. An earlier version dropped the leading @ and the slash too, which made `babel-core`
// collapse onto `@babel/core` and get reported as a squat of it. Those are two different real
// packages: `babel-core` is Babel 6 and `@babel/core` is Babel 7, and the same shape repeats for
// every library that moved into a scope. A scope is owned by whoever registered it, so crossing that
// boundary is not a punctuation difference at all.
function collapse(name) {
  const lower = String(name).toLowerCase();
  const m = lower.match(/^(@[^/]+)\/(.+)$/);
  if (m) return `${m[1].replace(/[-_.]/g, '')}/${m[2].replace(/[-_.]/g, '')}`;
  return lower.replace(/[-_.]/g, '');
}

function scopeOf(name) {
  const m = String(name).match(/^(@[^/]+)\//);
  return m ? m[1].toLowerCase() : null;
}

// Pairs that look alike in a terminal font. A name that differs from a popular one by exactly one of
// these is not a typo; the shapes were chosen so the difference does not register.
const CONFUSABLE_PAIRS = [
  ['l', '1'], ['l', 'i'], ['i', '1'], ['o', '0'], ['s', '5'], ['g', 'q'],
  ['b', '6'], ['z', '2'], ['a', '4'], ['e', '3'], ['t', '7'],
];
function isConfusablePair(a, b) {
  const x = String(a).toLowerCase(), y = String(b).toLowerCase();
  return CONFUSABLE_PAIRS.some(([p, q]) => (x === p && y === q) || (x === q && y === p));
}

// Levenshtein distance with the operations kept, capped: anything further than `max` returns null so
// the common case exits early instead of filling a table.
function editOps(a, b, max) {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > max) return null;
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (d[i][j] < rowMin) rowMin = d[i][j];
    }
    if (rowMin > max) return null;
  }
  if (d[m][n] > max) return null;

  // Walk back for the edits themselves. Only substitutions are described, because only a
  // substitution can be a lookalike swap.
  const subs = [];
  let i = m, j = n;
  while (i > 0 && j > 0) {
    const cost = a[i - 1] === b[j - 1] ? 0 : 1;
    if (d[i][j] === d[i - 1][j - 1] + cost) {
      if (cost) subs.push({ from: a[i - 1], to: b[j - 1] });
      i--; j--;
    } else if (d[i][j] === d[i - 1][j] + 1) i--;
    else j--;
  }
  return { distance: d[m][n], subs };
}

// Candidate popular names worth comparing against. The length filter removes almost everything
// before any table gets built. The scope filter matters more than it looks:
//
//   an unscoped name is compared only against unscoped names, so `express` is never measured against
//   `@types/express`, which is a different publisher and not a near miss of anything;
//
//   a scoped name whose scope is NOT one of the known ones is compared against every scoped name,
//   whatever the scope. That is the case that matters: `@babe1/core` has to reach `@babel/core` to
//   be caught, and filtering to an exact scope match would have made a forged scope invisible.
//   A scoped name whose scope IS known never gets here; it was exempted earlier.
function candidates(list, name, max) {
  const scoped = !!scopeOf(name);
  const out = [];
  for (let len = name.length - max; len <= name.length + max; len++) {
    const bucket = list.byLength.get(len);
    if (!bucket) continue;
    for (const n of bucket) if (!!scopeOf(n) === scoped) out.push(n);
  }
  return out;
}

const SQUAT_AFFIXES = {
  suffix: ['js', '-js', '.js', '_js', 'py', '-py', '_py', 'python', '-python', '-node', 'node', '-lib', '.io'],
  prefix: ['node-', 'nodejs-', 'python-', 'py-', 'js-'],
};

// Very short names are excluded from every distance rule. `ms`, `qs` and `fs` sit one edit from
// hundreds of legitimate names and flagging them teaches people to ignore the guard.
const MIN_LENGTH = 5;

function inspect(name, ecosystem = 'npm', opts = {}) {
  const eco = ecosystem === 'pypi' || ecosystem === 'pip' || ecosystem === 'python' ? 'pypi' : 'npm';
  const raw = String(name || '').trim();
  const checks = new Checks();
  const findings = [];

  if (!raw) return stamp({ ok: false, error: 'Provide a package name' });

  const canon = canonical(raw, eco);
  const list = popular(eco);

  // 1. Characters outside ASCII. This one does not need the list, so it runs either way.
  const nonAscii = [...raw].filter((ch) => ch.codePointAt(0) > 127);
  if (nonAscii.length) {
    const points = [...new Set(nonAscii)].map((ch) => `${ch} (U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')})`);
    findings.push({
      id: 'pkg-name-nonascii',
      severity: 'critical',
      message: `The name contains ${nonAscii.length} character(s) outside ASCII: ${points.join(', ')}. A name that renders like a familiar package but is built from lookalike letters is a different package.`,
    });
  }
  checks.ran('name-charset');

  if (!list.available) {
    checks.skipped('popular-list', 'the bundled list of popular package names could not be loaded, so no name-similarity check ran');
  } else if (raw.length < MIN_LENGTH) {
    checks.ran('popular-list');
    checks.skipped('name-similarity', `the name is ${raw.length} characters and the similarity rules need at least ${MIN_LENGTH}; short names sit one edit from too much to be meaningful`);
  } else if (list.set.has(canon)) {
    // The name IS one of the popular ones. That is worth saying, and it is not a safety claim.
    checks.ran('popular-list', `"${canon}" is itself on the popular list generated ${list.generated}`);
    checks.ran('name-similarity');
  } else if (eco === 'npm' && scopeOf(canon) && list.scopes.has(scopeOf(canon))) {
    // The name is under a scope that popular packages are published from. An npm scope belongs to
    // whoever registered it and nobody else can publish into it, so `@aws-sdk/client-sqs` sitting one
    // edit from `@aws-sdk/client-sts` is two packages from the same publisher, not a squat. Running
    // the similarity rules here produced four of the eighteen false positives in the sample this was
    // measured against. The name-shape check above still applies, so a lookalike scope such as
    // `@babeI/core` does not match here and is not exempted.
    checks.ran('popular-list');
    checks.skipped('name-similarity', `"${scopeOf(canon)}" is a scope that popular packages are published under, and only its owner can publish into it, so name-similarity rules were not applied`);
  } else {
    checks.ran('popular-list');
    checks.ran('name-similarity');

    // 2. Separator-insensitive collision. cross-env vs crossenv.
    const c = collapse(canon);
    const twin = list.collapsed.get(c);
    if (twin && twin !== canon) {
      findings.push({
        id: 'pkg-name-separator',
        severity: 'critical',
        resembles: twin,
        message: `"${raw}" is "${twin}" with the punctuation changed. That is the shape of a deliberate substitute, not a typo.`,
      });
    }

    // 3. A popular base with a squat affix bolted on. Run before the distance rules so a name that
    // both rules would describe is reported once, by the rule that explains it better.
    let affixTarget = null;
    for (const suf of SQUAT_AFFIXES.suffix) {
      if (canon.length > suf.length && canon.endsWith(suf)) {
        const base = canon.slice(0, -suf.length).replace(/[-_.]$/, '');
        if (base.length >= MIN_LENGTH && list.set.has(base)) {
          affixTarget = base;
          findings.push({ id: 'pkg-name-affix', severity: 'medium', resembles: base, message: `"${raw}" is the popular package "${base}" with "${suf}" appended. Check that this is the package you meant.` });
          break;
        }
      }
    }
    if (!affixTarget) {
      for (const pre of SQUAT_AFFIXES.prefix) {
        if (canon.length > pre.length && canon.startsWith(pre)) {
          const base = canon.slice(pre.length);
          if (base.length >= MIN_LENGTH && list.set.has(base)) {
            affixTarget = base;
            findings.push({ id: 'pkg-name-affix', severity: 'medium', resembles: base, message: `"${raw}" is the popular package "${base}" with "${pre}" in front of it. Check that this is the package you meant.` });
            break;
          }
        }
      }
    }

    // 4 and 5. Edit distance against the popular names.
    let best = null;
    for (const target of candidates(list, canon, 2)) {
      if (target === canon || target.length < MIN_LENGTH) continue;
      const r = editOps(canon, target, 2);
      if (!r || r.distance === 0) continue;
      if (!best || r.distance < best.distance) best = { target, ...r };
      if (best.distance === 1 && best.subs.some((s) => isConfusablePair(s.from, s.to))) break;
    }

    if (best && best.target !== affixTarget && !(twin && best.target === twin)) {
      const lookalike = best.distance === 1 && best.subs.length === 1 && isConfusablePair(best.subs[0].from, best.subs[0].to);
      if (lookalike) {
        findings.push({
          id: 'pkg-name-confusable',
          severity: 'critical',
          resembles: best.target,
          message: `"${raw}" differs from "${best.target}" by swapping "${best.subs[0].to}" for "${best.subs[0].from}", which are hard to tell apart in a terminal.`,
        });
      } else if (best.distance <= (canon.length >= 8 ? 2 : 1)) {
        findings.push({
          id: 'pkg-name-near',
          severity: 'medium',
          resembles: best.target,
          message: `"${raw}" is ${best.distance} edit${best.distance === 1 ? '' : 's'} away from "${best.target}", which is one of the most downloaded ${eco} packages. It may be a different package with a similar name, or it may be meant to be mistaken for it.`,
        });
      }
    }

  }

  // 6. Anything an earlier online run already learned about this exact name.
  let cached = null;
  if (opts.useCache !== false) {
    try { cached = cache.get(eco, canon); } catch { cached = null; }
  }
  if (cached) {
    checks.ran('cached-verdict', `from a run on ${cached.at}`);
    if (cached.verdict === 'danger' || cached.verdict === 'caution') {
      const age = cached.age_days === 0 ? 'today' : `${cached.age_days} day(s) ago`;
      findings.push({
        id: 'pkg-cached-verdict',
        severity: cached.verdict === 'danger' ? 'critical' : 'medium',
        message: `A full check of "${raw}" ${age} returned ${cached.verdict}: ${(cached.reasons || []).join(' ') || 'no reason recorded'}`,
        cached_at: cached.at,
      });
    }
  } else {
    checks.skipped('cached-verdict', 'no earlier online check of this package is cached on this machine');
  }

  // These never run here. Naming them is the point: the caller has to know that a clean answer from
  // this engine is a statement about the name and nothing else.
  checks.skipped('registry-existence', 'no network in this engine: whether the package is registered was not checked');
  checks.skipped('osv-advisories', 'no network in this engine: known vulnerabilities and malware advisories were not checked');
  checks.skipped('download-volume', 'no network in this engine: how widely the package is used was not checked');
  checks.skipped('package-contents', 'nothing here downloads or inspects package contents, in any mode');

  const worstSeverity = findings.reduce((a, f) => Math.max(a, f.severity === 'critical' ? 2 : 1), 0);
  let verdict = worstSeverity === 2 ? 'danger' : worstSeverity === 1 ? 'caution' : 'safe';

  // The four network checks above are skipped by design in this engine, so their absence must not
  // move the verdict: that is what `local_only` and the skipped list are for. The comparison list is
  // different. It is the ONLY thing this engine checks a name against, it ships inside the package,
  // and when it fails to load there is no name check at all. Reporting "safe" then is a check that
  // did not run being read as a pass, which is the worst bug this codebase can ship.
  //
  // This is not hypothetical. Published 0.3.0 omitted `data/` from its npm `files` list, so every
  // install answered `safe` for `crossenv`, a real npm typosquat attack. The `files` entry is fixed
  // and a tarball test now guards it; this is the second lock, so that a list which cannot load can
  // never again read as a clean name.
  const listMissing = !list.available;
  if (listMissing && verdict === 'safe') verdict = 'unknown';

  const out = stamp({
    ok: true,
    name: raw,
    ecosystem: eco,
    verdict,
    findings,
    local_only: true,
    summary: listMissing
      ? `The bundled list of popular package names could not be loaded, so the name "${raw}" was not compared against anything. This is not a result: nothing was checked.`
      : verdict === 'safe'
        ? `Nothing in the name "${raw}" resembles a known popular package closely enough to flag. The registry, OSV and the package contents were not consulted, so this is not a statement that the package is safe.`
        : findings.map((f) => f.message).join(' '),
    list_generated: list.available ? list.generated : null,
    list_size: list.available ? list.size : 0,
  }, { checks, rulesVersion: NAME_RULES_VERSION });
  out.verdict = verdict;
  return out;
}

module.exports = { inspect, collapse, editOps, isConfusablePair, popular, MIN_LENGTH };
