// Which rules the engines actually run, and where they came from.
//
// Every engine ships its rules compiled into it. Those are the floor: with no network, no feed and
// no cache, everything still works, and that is the shape most installs will be in most of the
// time. When the feed client has applied a bundle, the rules in it replace the built-in ones and
// every verdict says so.
//
// Provenance is not decoration. A verdict that says `rules_version: 2026.08.14` without saying
// where those rules came from cannot be reproduced by anyone else, and a user who wants to know why
// their result changed overnight has nowhere to look. So `rules_provenance` is either the literal
// string "bundled" or "feed@<version>", and it appears next to every `rules_version` the engines
// emit.
//
// This module deliberately does not import any engine. The engines import it, so a dependency the
// other way would be a cycle. It reads the cached bundle at most once per process, because it is on
// the hook path: the whole per-tool-call budget is under a tenth of a second and validating the
// cached bundle costs four to seven milliseconds of it.

let loaded = false;
let active = null;

// The cached bundle, validated. Returns null when there is none, which is the normal case for a
// fresh install and the only case on the hosted APIs, where nothing writes to a home directory.
function load() {
  if (loaded) return active;
  loaded = true;
  try {
    // Required lazily. Pulling the feed client in at module scope would drag the network layer into
    // every process that touches an engine, including the hooks, which are not allowed to have it.
    active = require('./feed').loadCached();
  } catch { active = null; }
  return active;
}

// Call after applying an update so a long-running server picks the new rules up without a restart.
function reload() { loaded = false; active = null; return load(); }

// The active rules for a set, or null to mean "use the ones compiled in".
function rules(name) {
  const b = load();
  return b && b.rulesets && Array.isArray(b.rulesets[name]) && b.rulesets[name].length ? b.rulesets[name] : null;
}

// An intel list from the active bundle, or null.
function list(name) {
  const b = load();
  return b && b.lists ? b.lists[name] || null : null;
}

// The version to report. `fallback` is the engine's own compiled-in version string.
function version(fallback) {
  const b = load();
  return b ? b.version : fallback;
}

// "bundled" or "feed@<version>".
function provenance() {
  const b = load();
  return b ? `feed@${b.version}` : 'bundled';
}

// Everything a surface needs to tell a user where its rules came from, in one object.
function status() {
  const b = load();
  if (!b) return { source: 'bundled', provenance: 'bundled', version: null, generated: null, stale_sources: [] };
  return {
    source: 'feed',
    provenance: `feed@${b.version}`,
    version: b.version,
    generated: b.generated,
    notes: b.notes,
    stale_sources: (b.sources || []).filter((s) => !s.ok).map((s) => ({ id: s.id, note: s.note, age_days: s.age_days })),
    counts: {
      injection: b.rulesets.injection.length,
      secrets: b.rulesets.secrets.length,
      pii: b.rulesets.pii.length,
      code: b.rulesets.code.length,
      ofac_addresses: b.lists.ofac_evm ? b.lists.ofac_evm.count : 0,
      scam_addresses: b.lists.scam_addresses ? b.lists.scam_addresses.count : 0,
      malicious_packages: b.lists.malicious_packages
        ? b.lists.malicious_packages.counts.npm + b.lists.malicious_packages.counts.pypi
        : 0,
    },
  };
}

module.exports = { rules, list, version, provenance, status, reload, load };
