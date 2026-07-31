// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/lib/cache.js
// Regenerate: node scripts/sync-shared.js
// A local cache of package verdicts that cost a network call to get.
//
// The point is the hook. A PreToolUse hook may not touch the network, so on its own it can only see
// what a name looks like. But `guard` and the MCP tools do reach OSV and the registries, and when
// they do, the answer is written here. The next install of that same package gets the full verdict
// from a file read. The guard therefore gets better the more the rest of the toolkit is used, and it
// never pretends a cache miss is a clean bill of health.
//
// Entries carry the time they were taken so a reader can say "OSV said this three days ago" instead
// of implying it was checked just now. Nothing here is uploaded.

const fs = require('fs');
const path = require('path');
const { cachePath, ensureDir } = require('./paths');

const MAX_ENTRIES = 2000;

function load() {
  try {
    const raw = fs.readFileSync(cachePath(), 'utf8');
    const j = JSON.parse(raw);
    return j && typeof j === 'object' && j.entries ? j : { version: 1, entries: {} };
  } catch {
    return { version: 1, entries: {} };
  }
}

function key(ecosystem, name) { return `${String(ecosystem || 'npm').toLowerCase()}:${name}`; }

// Returns the entry plus how old it is, or null. Age is the caller's business: a five-minute-old
// verdict and a five-month-old one are both cache hits and only one of them is worth acting on.
function get(ecosystem, name) {
  const e = load().entries[key(ecosystem, name)];
  if (!e || !e.at) return null;
  const ageMs = Date.now() - Date.parse(e.at);
  if (!Number.isFinite(ageMs) || ageMs < 0) return null;
  return { ...e, age_days: Math.floor(ageMs / 86400000), age_ms: ageMs };
}

// Store only the fields a later reader needs. The full tool response is not kept: it is large, it
// contains registry prose that changes, and none of it is needed to decide whether to stop an
// install.
function put(ecosystem, name, verdict, reasons, extra = {}) {
  const dir = path.dirname(cachePath());
  if (!ensureDir(dir)) return false;

  const store = load();
  store.entries[key(ecosystem, name)] = {
    verdict: String(verdict || 'unknown'),
    reasons: (Array.isArray(reasons) ? reasons : [reasons]).filter(Boolean).map((r) => String(r).slice(0, 300)).slice(0, 5),
    at: new Date().toISOString(),
    ...(extra.malicious !== undefined ? { malicious: !!extra.malicious } : {}),
    ...(extra.vulnerabilities !== undefined ? { vulnerabilities: extra.vulnerabilities } : {}),
    ...(extra.source ? { source: String(extra.source).slice(0, 40) } : {}),
  };

  // Bound the file. Oldest entries go first; this is a cache, not a record.
  const keys = Object.keys(store.entries);
  if (keys.length > MAX_ENTRIES) {
    const sorted = keys.sort((a, b) => Date.parse(store.entries[a].at) - Date.parse(store.entries[b].at));
    for (const k of sorted.slice(0, keys.length - MAX_ENTRIES)) delete store.entries[k];
  }

  // Write beside the target and rename, so a reader never sees a half-written file and two writers
  // racing lose an entry rather than corrupting the cache.
  try {
    const tmp = cachePath() + `.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(store));
    fs.renameSync(tmp, cachePath());
    return true;
  } catch {
    return false;
  }
}

function stats() {
  const store = load();
  const keys = Object.keys(store.entries);
  return { entries: keys.length, path: cachePath() };
}

module.exports = { get, put, stats, cachePath, MAX_ENTRIES };
