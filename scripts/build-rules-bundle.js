#!/usr/bin/env node
// Build the signed rules bundle the local surfaces pull.
//
// Two kinds of thing go in. The pattern rulesets come out of agent-guards/engines, which stays the
// single source of truth for detection: the feed ships the same rules the package ships, so the two
// can never disagree about what a rule id means. The intel lists come off the network: OFAC's
// sanctioned EVM addresses, two scam-address blocklists, and the malicious-package advisories from
// OSV.
//
// Three rules this script exists to enforce:
//
//   Nothing broken gets published. Every pattern goes through the ReDoS gate in
//   agent-guards/lib/redos.js before anything is written. A red gate means no new bundle and
//   clients stay on the last good version, which is the correct outcome.
//
//   Staleness is disclosed, never hidden. If a source will not answer, its previous contents are
//   carried forward and the bundle says so, with the age in days, in `sources`. A sanctions list
//   silently served as fresh is the OFAC landmine reborn, and it is the one failure mode here that
//   would actually hurt someone.
//
//   The output is deterministic. Same inputs, same bytes, so a day on which nothing changed
//   produces no commit and no version bump. Object keys are written in a fixed order and every
//   list is sorted.
//
// Usage:
//   node scripts/build-rules-bundle.js                 fetch everything, write rules/
//   node scripts/build-rules-bundle.js --offline       rebuild from the last bundle without fetching
//   node scripts/build-rules-bundle.js --osv-dir DIR   use already-downloaded OSV zips from DIR

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const OUT_DIR = path.join(ROOT, 'rules');
const BUNDLE = path.join(OUT_DIR, 'bundle.json');
const SIDECAR = path.join(OUT_DIR, 'packages.tsv');
const CHANGELOG = path.join(OUT_DIR, 'CHANGELOG.md');

const { INJECTION_RULES } = require(path.join(ROOT, 'agent-guards/engines/injection'));
const { SECRET_RULES, PII_RULES } = require(path.join(ROOT, 'agent-guards/engines/secrets'));
const { RULES: CODE_RULES } = require(path.join(ROOT, 'agent-guards/engines/code'));
const { OFAC_EVM_LISTS } = require(path.join(ROOT, 'agent-guards/engines/payments'));
const redos = require(path.join(ROOT, 'agent-guards/lib/redos'));
const schema = require(path.join(ROOT, 'agent-guards/lib/rules-schema'));
const zipread = require('./lib/zipread');

const args = process.argv.slice(2);
const OFFLINE = args.includes('--offline');
const OSV_DIR = (() => { const i = args.indexOf('--osv-dir'); return i === -1 ? null : args[i + 1]; })();

const log = (...a) => console.log(...a);
const die = (msg) => { console.error(`\nbuild failed: ${msg}`); process.exit(1); };

// ---------------------------------------------------------------------------------------------
// sources
// ---------------------------------------------------------------------------------------------

const OFAC_BASE = 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_';
const SCAM_SOURCES = [
  { id: 'ethereum-lists-darklist', url: 'https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json' },
  { id: 'scamsniffer-blacklist', url: 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json' },
];
const OSV_ZIPS = [
  { ecosystem: 'npm', url: 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip', file: 'npm-all.zip' },
  { ecosystem: 'pypi', url: 'https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip', file: 'pypi-all.zip' },
];

async function get(url, { timeoutMs = 120000 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'agent-guards rules pipeline (+https://github.com/mlawsonking/MCP)' } });
    if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
    return { ok: true, text: await r.text() };
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
  finally { clearTimeout(t); }
}

async function download(url, dest, { timeoutMs = 600000 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'agent-guards rules pipeline' } });
    if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
    fs.writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
    return { ok: true, bytes: fs.statSync(dest).size };
  } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
  finally { clearTimeout(t); }
}

// ---------------------------------------------------------------------------------------------
// rulesets, out of the engines
// ---------------------------------------------------------------------------------------------

function rulesets() {
  return {
    injection: INJECTION_RULES.map((r) => ({ id: r.id, category: r.cat, weight: r.w, pattern: r.re.source, flags: r.re.flags })),
    secrets: SECRET_RULES.map((r) => ({ id: r.id, type: r.type, pattern: r.re.source, flags: r.re.flags, severity: r.severity, value_group: r.vg || 0 })),
    pii: PII_RULES.map((r) => ({ id: r.id, type: r.type, pattern: r.re.source, flags: r.re.flags, severity: r.severity, value_group: r.vg || 0, ...(r.luhn ? { luhn: true } : {}) })),
    code: CODE_RULES.map((r) => ({ id: r.id, category: r.cat, severity: r.sev, language: r.lang, pattern: r.re.source, flags: r.re.flags, message: r.msg, fix: r.fix || '' })),
  };
}

// ---------------------------------------------------------------------------------------------
// intel
// ---------------------------------------------------------------------------------------------

const EVM_RE = /^0x[0-9a-f]{40}$/;

async function buildOfac(previous, report) {
  const found = new Map();
  const loaded = [];
  const missing = [];
  for (const name of OFAC_EVM_LISTS) {
    const r = OFFLINE ? { ok: false, error: 'offline' } : await get(`${OFAC_BASE}${name}.txt`);
    if (!r.ok) { missing.push(`${name} (${r.error})`); continue; }
    let n = 0;
    for (const line of r.text.split(/\r?\n/)) {
      const a = line.trim().toLowerCase();
      // Some of these files carry non-EVM addresses (the USDT list holds Tron ones). They could
      // never match a lookup, so they are dropped rather than counted.
      if (EVM_RE.test(a)) { found.set(a, `OFAC SDN (${name})`); n++; }
    }
    loaded.push(name);
    log(`  ofac ${name}: ${n}`);
  }

  // A partial load narrows sanctions coverage. Carrying the previous list forward is the safe
  // choice, and saying which lists are missing is the honest one.
  const prev = previous && previous.lists && previous.lists.ofac_evm;
  if (missing.length && prev) {
    for (const [a, why] of Object.entries(prev.entries || {})) if (!found.has(a)) found.set(a, why);
  }
  const ok = missing.length === 0;
  report.push({
    id: 'ofac-evm',
    ok,
    url: `${OFAC_BASE}*.txt`,
    fetched: ok ? today() : (prev ? prev.fetched : null),
    age_days: ok ? 0 : ageDays(prev && prev.fetched),
    note: ok ? '' : `could not load ${missing.join(', ')}; carried the previous list forward`,
  });
  if (!ok) log(`  ! ofac incomplete: ${missing.join(', ')}`);

  return {
    source: 'OFAC SDN sanctioned digital-currency addresses via github.com/0xB10C/ofac-sanctioned-digital-currency-addresses',
    fetched: ok ? today() : (prev ? prev.fetched : today()),
    entries: sortedObject(found),
  };
}

async function buildScam(previous, report) {
  const found = new Map();
  let anyOk = false;
  for (const s of SCAM_SOURCES) {
    const r = OFFLINE ? { ok: false, error: 'offline' } : await get(s.url);
    if (!r.ok) { report.push({ id: s.id, ok: false, url: s.url, fetched: null, age_days: null, note: `could not load: ${r.error}` }); continue; }
    let parsed;
    try { parsed = JSON.parse(r.text); } catch { report.push({ id: s.id, ok: false, url: s.url, fetched: null, age_days: null, note: 'response was not JSON' }); continue; }
    let n = 0;
    if (Array.isArray(parsed)) {
      for (const e of parsed) {
        const addr = String((e && e.address) || e || '').toLowerCase();
        if (!EVM_RE.test(addr) || found.has(addr)) continue;
        found.set(addr, String((e && e.comment) || s.id).slice(0, 200));
        n++;
      }
    }
    anyOk = true;
    report.push({ id: s.id, ok: true, url: s.url, fetched: today(), age_days: 0, note: '' });
    log(`  scam ${s.id}: ${n}`);
  }

  const prev = previous && previous.lists && previous.lists.scam_addresses;
  if (!anyOk && prev) for (const [a, why] of Object.entries(prev.entries || {})) found.set(a, why);
  return {
    source: SCAM_SOURCES.map((s) => s.id).join(' + '),
    fetched: anyOk ? today() : (prev ? prev.fetched : today()),
    entries: sortedObject(found),
  };
}

// The curated slice, and the rule that defines it.
//
// OSV's npm export is 213 MB and its PyPI export is 31 MB, holding about 228,000 `MAL-` advisories
// between them. What is dropped is every advisory BODY: the summary, the prose, the references, the
// credits, the indicators of compromise. What is kept is every non-withdrawn advisory's package
// name, ecosystem, affected versions and advisory id. No package is dropped and there is no date
// cutoff, so "not on the list" means what it says.
//
// The versions are the point. 42 of the 3,000 most-installed npm packages appear here — debug,
// chalk, axios, ansi-styles and the rest of the September 2025 worm — because they were compromised
// at specific versions. A names-only slice would report `npm install debug` as malware.
async function buildMalicious(report) {
  const dir = OSV_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'agent-guards-osv-'));
  const rows = [];
  const counts = { npm: 0, pypi: 0, versioned: 0, withdrawn: 0, advisories: 0 };
  let allOk = true;

  for (const src of OSV_ZIPS) {
    const zipPath = path.join(dir, src.file);
    if (!fs.existsSync(zipPath)) {
      if (OFFLINE) { allOk = false; report.push({ id: `osv-${src.ecosystem}`, ok: false, url: src.url, fetched: null, age_days: null, note: 'offline and no local copy' }); continue; }
      log(`  downloading ${src.url} ...`);
      const d = await download(src.url, zipPath);
      if (!d.ok) {
        allOk = false;
        report.push({ id: `osv-${src.ecosystem}`, ok: false, url: src.url, fetched: null, age_days: null, note: `could not download: ${d.error}` });
        continue;
      }
      log(`  ${src.file}: ${(d.bytes / 1048576).toFixed(1)} MB`);
    }

    const buf = fs.readFileSync(zipPath);
    const entries = zipread.listEntries(buf, (n) => n.startsWith('MAL-'));
    const byName = new Map();
    for (const e of entries) {
      let adv;
      try { adv = JSON.parse(zipread.readEntry(buf, e).toString('utf8')); } catch { continue; }
      counts.advisories++;
      // A withdrawn advisory is one the maintainers decided was not malicious. Publishing it would
      // be accusing a package of something its own advisory retracted.
      if (adv.withdrawn) { counts.withdrawn++; continue; }
      for (const a of adv.affected || []) {
        const name = a.package && a.package.name;
        if (!name || typeof name !== 'string') continue;
        const cur = byName.get(name) || { versions: new Set(), advisory: adv.id };
        for (const v of Array.isArray(a.versions) ? a.versions : []) if (typeof v === 'string') cur.versions.add(v);
        byName.set(name, cur);
      }
    }
    for (const [name, info] of byName) {
      // No versions in the advisory means the whole package is malicious, which is how OSV says it.
      const versions = [...info.versions].sort();
      if (versions.length) counts.versioned++;
      rows.push(`${src.ecosystem}\t${name}\t${versions.length ? versions.join(',') : '*'}\t${info.advisory}`);
    }
    counts[src.ecosystem] = byName.size;
    report.push({ id: `osv-${src.ecosystem}`, ok: true, url: src.url, fetched: today(), age_days: 0, note: '' });
    log(`  osv ${src.ecosystem}: ${entries.length} advisories, ${byName.size} packages, ${counts.withdrawn} withdrawn so far`);
  }

  if (!rows.length) return { ok: false, counts };

  // Byte order on the whole line, which sorts on `<ecosystem>\t<name>` because the ecosystem never
  // contains a tab. lib/malicious-packages.js binary-searches on exactly this ordering.
  rows.sort();
  for (let i = 1; i < rows.length; i++) {
    if (rows[i] < rows[i - 1]) return die('package list came out unsorted, which would silently break the binary search');
  }
  return { ok: allOk, text: rows.join('\n') + '\n', counts };
}

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

const today = () => new Date().toISOString().slice(0, 10);
function ageDays(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? Math.max(0, Math.floor((Date.now() - t) / 86400000)) : null;
}
function sortedObject(map) {
  const out = {};
  for (const k of [...map.keys()].sort()) out[k] = map.get(k);
  return out;
}
function readPrevious() {
  try { return JSON.parse(fs.readFileSync(BUNDLE, 'utf8')); } catch { return null; }
}
// Today's date, or today with a counter if a bundle already went out today with different contents.
function nextVersion(previous) {
  const base = today().replace(/-/g, '.');
  if (!previous || typeof previous.version !== 'string') return base;
  if (!previous.version.startsWith(base)) return base;
  const parts = previous.version.split('.');
  return parts.length === 4 ? `${base}.${Number(parts[3]) + 1}` : `${base}.1`;
}

// ---------------------------------------------------------------------------------------------

(async () => {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const previous = readPrevious();
  const report = [];

  log('rulesets from agent-guards/engines');
  const sets = rulesets();
  log(`  injection ${sets.injection.length} · secrets ${sets.secrets.length} · pii ${sets.pii.length} · code ${sets.code.length}`);

  // The gate, before anything is written. A pattern that can hang a client must not reach one.
  log('ReDoS gate');
  const patterns = [];
  for (const [name, list] of Object.entries(sets)) for (const r of list) patterns.push({ id: `${name}:${r.id}`, source: r.pattern, flags: r.flags });
  const gate = await redos.checkPatterns(patterns);
  if (!gate.ok) {
    for (const f of gate.failures) console.error(`  FAIL ${f.id} [${f.gate}]: ${f.reason}`);
    die(`${gate.failures.length} pattern(s) failed the ReDoS gate; no bundle written`);
  }
  log(`  ${patterns.length} patterns passed`);

  log('intel');
  const ofac = await buildOfac(previous, report);
  const scam = await buildScam(previous, report);
  const malicious = await buildMalicious(report);
  if (!malicious.text) die('no malicious-package data and no local copy to fall back on');

  const sidecarBytes = Buffer.from(malicious.text, 'utf8');
  const sidecarSha = crypto.createHash('sha256').update(sidecarBytes).digest('hex');

  // Everything except the version and the timestamp. If this has not changed, nothing has, and
  // republishing an identical bundle under a new version would be noise in every client's log.
  const payload = {
    schema: schema.SCHEMA_VERSION,
    rulesets: sets,
    lists: {
      ofac_evm: ofac,
      scam_addresses: scam,
      malicious_packages: {
        source: 'OSV malicious-package advisories (MAL-) for npm and PyPI, from osv-vulnerabilities.storage.googleapis.com',
        fetched: today(),
        file: 'packages.tsv',
        sha256: sidecarSha,
        bytes: sidecarBytes.length,
        npm_count: malicious.counts.npm,
        pypi_count: malicious.counts.pypi,
        versioned_count: malicious.counts.versioned,
      },
    },
    sources: report.sort((a, b) => (a.id < b.id ? -1 : 1)),
  };
  // The fetch dates move every day even when the contents do not, so they are not part of the
  // comparison. What matters is whether any rule, address or package changed.
  const fingerprint = (b) => crypto.createHash('sha256').update(JSON.stringify({
    rulesets: b.rulesets,
    ofac: b.lists.ofac_evm.entries,
    scam: b.lists.scam_addresses.entries,
    packages: b.lists.malicious_packages.sha256,
    sources_ok: (b.sources || []).map((s) => `${s.id}:${s.ok}`),
  })).digest('hex');

  const changed = !previous || fingerprint(previous) !== fingerprint(payload);
  const version = changed ? nextVersion(previous) : previous.version;
  const generated = changed ? new Date().toISOString() : previous.generated;

  const stale = report.filter((s) => !s.ok);
  const doc = {
    schema: payload.schema,
    version,
    generated,
    notes: stale.length ? `${stale.length} source(s) could not be refreshed: ${stale.map((s) => s.id).join(', ')}` : 'all sources refreshed',
    rulesets: payload.rulesets,
    lists: payload.lists,
    sources: payload.sources,
  };
  const text = JSON.stringify(doc, null, 1) + '\n';

  // The client's own validator, run here. If the thing we are about to publish would be refused by
  // a client, that is a build failure, not a discovery for someone else to make.
  const v = schema.validate(text);
  if (!v.ok) {
    for (const e of v.errors.slice(0, 10)) console.error(`  ${e}`);
    die('the bundle we just built fails the client validator');
  }

  if (!changed) {
    log(`\nnothing changed since ${version}; leaving rules/ alone`);
    // A stale source with unchanged contents still deserves saying out loud.
    for (const s of stale) log(`  stale: ${s.id} — ${s.note}`);
    process.exit(0);
  }

  fs.writeFileSync(SIDECAR, sidecarBytes);
  fs.writeFileSync(BUNDLE, text);

  const entry = [
    `## ${version}`,
    '',
    `Generated ${generated}.`,
    '',
    `- rules: injection ${sets.injection.length}, secrets ${sets.secrets.length}, pii ${sets.pii.length}, code ${sets.code.length}`,
    `- OFAC EVM addresses: ${Object.keys(ofac.entries).length}`,
    `- scam addresses: ${Object.keys(scam.entries).length}`,
    `- malicious packages: ${malicious.counts.npm} npm, ${malicious.counts.pypi} PyPI (${malicious.counts.versioned} pinned to specific versions, ${malicious.counts.withdrawn} withdrawn advisories excluded)`,
    ...(stale.length ? ['', ...stale.map((s) => `- STALE: ${s.id} — ${s.note}`)] : []),
    '',
    '',
  ].join('\n');
  const old = fs.existsSync(CHANGELOG) ? fs.readFileSync(CHANGELOG, 'utf8') : '# Rules bundle changelog\n\nNewest first. Written by scripts/build-rules-bundle.js.\n\n';
  const header = old.slice(0, old.indexOf('\n\n', old.indexOf('\n\n') + 1) + 2) || old;
  fs.writeFileSync(CHANGELOG, header + entry + old.slice(header.length));

  log(`\nwrote ${path.relative(ROOT, BUNDLE)} (${(text.length / 1024).toFixed(0)} KB) version ${version}`);
  log(`wrote ${path.relative(ROOT, SIDECAR)} (${(sidecarBytes.length / 1048576).toFixed(2)} MB, ${malicious.counts.npm + malicious.counts.pypi} packages)`);
  for (const s of stale) log(`  stale: ${s.id} — ${s.note}`);
})().catch((e) => die(String((e && e.stack) || e)));
