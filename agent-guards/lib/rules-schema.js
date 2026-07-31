// The rules bundle: what a feed is allowed to say, and how a client checks it before believing any
// of it.
//
// Two rules govern this file and neither is negotiable.
//
//   Rules are data, never code. A bundle carries pattern SOURCE STRINGS. Nothing that arrives over
//   the feed is ever eval'd, required, or turned into a function. The only thing done with a
//   pattern is `new RegExp(source, flags)`, and only after it has cleared the ReDoS gate in
//   lib/redos.js.
//
//   A hostile or broken feed must not be able to break a client. Everything here therefore treats
//   the bundle as remote input from someone who wants to hurt you: sizes are bounded, shapes are
//   checked field by field, unknown keys are dropped rather than carried, and prototype-poisoning
//   key names are refused outright. Validation failures are returned, never thrown, because the
//   caller's job on failure is to keep running on its built-in rules — not to crash.
//
// The public format is documented in rules/README.md at the repo root so a stranger can audit a
// bundle without reading this file. If you change a bound here, change it there too.

const { lint, MAX_SOURCE_LENGTH } = require('./redos');

const SCHEMA_VERSION = 1;

// Bounds. Every one of these exists so that a bundle cannot cost a client unbounded memory or time.
const LIMITS = {
  bundle_bytes: 12 * 1024 * 1024,
  rules_per_set: 500,
  pattern_length: MAX_SOURCE_LENGTH,
  id_length: 80,
  text_length: 400,
  list_entries: 300000,
  package_versions: 2000,
  sources: 50,
};

const VALID_FLAGS = /^[gimsuy]*$/;
const VERSION_RE = /^\d{4}\.\d{2}\.\d{2}(\.\d+)?$/;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const LANGUAGES = ['any', 'js', 'py'];
// A JSON object key that would let a merge downstream reach Object.prototype. JSON.parse puts these
// on the object as ordinary own properties rather than invoking the setter, so they are harmless
// here — but they stop being harmless the moment anything spreads or Object.assigns the result, and
// a rules feed has no legitimate reason to ship one.
const POISON_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// ---------------------------------------------------------------------------------------------
// small field checkers
// ---------------------------------------------------------------------------------------------

const fail = (errors, msg) => { errors.push(msg); return undefined; };

function str(v, errors, what, max) {
  if (typeof v !== 'string') return fail(errors, `${what}: expected a string`);
  if (!v.length) return fail(errors, `${what}: empty`);
  if (v.length > max) return fail(errors, `${what}: ${v.length} characters, over the ${max} limit`);
  return v;
}

function id(v, errors, what) {
  const s = str(v, errors, what, LIMITS.id_length);
  if (s === undefined) return undefined;
  if (!ID_RE.test(s)) return fail(errors, `${what}: "${s.slice(0, 30)}" is not a valid rule id`);
  return s;
}

function oneOf(v, allowed, errors, what) {
  if (!allowed.includes(v)) return fail(errors, `${what}: "${String(v).slice(0, 30)}" is not one of ${allowed.join(', ')}`);
  return v;
}

function int(v, errors, what, min, max) {
  if (!Number.isInteger(v)) return fail(errors, `${what}: expected an integer`);
  if (v < min || v > max) return fail(errors, `${what}: ${v} is outside ${min}..${max}`);
  return v;
}

// A pattern is checked for shape here and for cost in lib/redos.js. Both have to pass; this one is
// synchronous and cheap so it runs first and keeps obviously-broken patterns out of the worker.
function pattern(rule, errors, what) {
  const source = str(rule.pattern, errors, `${what}.pattern`, LIMITS.pattern_length);
  if (source === undefined) return undefined;
  const flags = rule.flags === undefined ? '' : rule.flags;
  if (typeof flags !== 'string' || !VALID_FLAGS.test(flags)) {
    return fail(errors, `${what}.flags: "${String(flags).slice(0, 10)}" is not a valid flag string`);
  }
  try { new RegExp(source, flags); }
  catch (e) { return fail(errors, `${what}.pattern: does not compile (${String((e && e.message) || e).slice(0, 120)})`); }
  const l = lint(source);
  if (!l.ok) return fail(errors, `${what}.pattern: ${l.reason}`);
  return { source, flags };
}

function plainObject(v, errors, what) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return fail(errors, `${what}: expected an object`);
  for (const k of Object.keys(v)) {
    if (POISON_KEYS.has(k)) return fail(errors, `${what}: refusing a key named "${k}"`);
  }
  return v;
}

function arrayOf(v, errors, what, max) {
  if (!Array.isArray(v)) return fail(errors, `${what}: expected an array`);
  if (v.length > max) return fail(errors, `${what}: ${v.length} entries, over the ${max} limit`);
  return v;
}

// ---------------------------------------------------------------------------------------------
// rulesets
// ---------------------------------------------------------------------------------------------

function injectionRules(raw, errors) {
  const list = arrayOf(raw, errors, 'rulesets.injection', LIMITS.rules_per_set);
  if (!list) return undefined;
  const out = [];
  const seen = new Set();
  list.forEach((r, i) => {
    const what = `rulesets.injection[${i}]`;
    if (!plainObject(r, errors, what)) return;
    const rid = id(r.id, errors, `${what}.id`);
    const cat = str(r.category, errors, `${what}.category`, LIMITS.id_length);
    const w = int(r.weight, errors, `${what}.weight`, 0, 100);
    const p = pattern(r, errors, what);
    if (rid === undefined || cat === undefined || w === undefined || p === undefined) return;
    if (seen.has(rid)) return fail(errors, `${what}.id: "${rid}" is a duplicate`);
    seen.add(rid);
    out.push({ id: rid, cat, w, re: new RegExp(p.source, p.flags), source: p.source, flags: p.flags });
  });
  return out;
}

function secretRules(raw, errors, what0, withLuhn) {
  const list = arrayOf(raw, errors, what0, LIMITS.rules_per_set);
  if (!list) return undefined;
  const out = [];
  const seen = new Set();
  list.forEach((r, i) => {
    const what = `${what0}[${i}]`;
    if (!plainObject(r, errors, what)) return;
    const rid = id(r.id, errors, `${what}.id`);
    const type = str(r.type, errors, `${what}.type`, LIMITS.text_length);
    const sev = oneOf(r.severity, SEVERITIES, errors, `${what}.severity`);
    const p = pattern(r, errors, what);
    // The value group is the capture group holding the secret itself. Getting it wrong is how the
    // redactor once handed back secrets while redacting their labels, so it is required and
    // checked against the pattern's actual group count rather than trusted.
    const vg = int(r.value_group, errors, `${what}.value_group`, 0, 20);
    if (rid === undefined || type === undefined || sev === undefined || p === undefined || vg === undefined) return;
    const groups = new RegExp(p.source + '|').exec('').length - 1;
    if (vg > groups) return fail(errors, `${what}.value_group: ${vg} but the pattern has ${groups} capture group(s)`);
    if (seen.has(rid)) return fail(errors, `${what}.id: "${rid}" is a duplicate`);
    seen.add(rid);
    const rule = { id: rid, type, severity: sev, re: new RegExp(p.source, p.flags), vg, source: p.source, flags: p.flags };
    if (withLuhn && r.luhn === true) rule.luhn = true;
    out.push(rule);
  });
  return out;
}

function codeRules(raw, errors) {
  const list = arrayOf(raw, errors, 'rulesets.code', LIMITS.rules_per_set);
  if (!list) return undefined;
  const out = [];
  const seen = new Set();
  list.forEach((r, i) => {
    const what = `rulesets.code[${i}]`;
    if (!plainObject(r, errors, what)) return;
    const rid = id(r.id, errors, `${what}.id`);
    const cat = str(r.category, errors, `${what}.category`, LIMITS.id_length);
    const sev = oneOf(r.severity, SEVERITIES, errors, `${what}.severity`);
    const lang = oneOf(r.language, LANGUAGES, errors, `${what}.language`);
    const msg = str(r.message, errors, `${what}.message`, LIMITS.text_length);
    const fix = r.fix === undefined ? '' : str(r.fix, errors, `${what}.fix`, LIMITS.text_length);
    const p = pattern(r, errors, what);
    if ([rid, cat, sev, lang, msg, fix, p].some((v) => v === undefined)) return;
    if (seen.has(rid)) return fail(errors, `${what}.id: "${rid}" is a duplicate`);
    seen.add(rid);
    out.push({ id: rid, cat, sev, lang, msg, fix, re: new RegExp(p.source, p.flags), source: p.source, flags: p.flags });
  });
  return out;
}

// ---------------------------------------------------------------------------------------------
// intel lists
// ---------------------------------------------------------------------------------------------

const EVM_RE = /^0x[0-9a-f]{40}$/;

function addressList(raw, errors, what0) {
  const o = plainObject(raw, errors, what0);
  if (!o) return undefined;
  const source = str(o.source, errors, `${what0}.source`, LIMITS.text_length);
  const fetched = str(o.fetched, errors, `${what0}.fetched`, 40);
  const entries = plainObject(o.entries, errors, `${what0}.entries`);
  if (source === undefined || fetched === undefined || entries === undefined) return undefined;
  const keys = Object.keys(entries);
  if (keys.length > LIMITS.list_entries) return fail(errors, `${what0}.entries: ${keys.length} entries, over the ${LIMITS.list_entries} limit`);
  const map = new Map();
  for (const k of keys) {
    const addr = String(k).toLowerCase();
    // Anything that is not an EVM address could never match a lookup anyway; dropping it quietly
    // keeps one malformed row from rejecting a whole sanctions list.
    if (!EVM_RE.test(addr)) continue;
    const reason = entries[k];
    if (typeof reason !== 'string' || reason.length > LIMITS.text_length) continue;
    map.set(addr, reason);
  }
  return { source, fetched, entries: map, count: map.size, dropped: keys.length - map.size };
}

const SHA256_RE = /^[0-9a-f]{64}$/;
const SIDECAR_NAME_RE = /^[a-z0-9][a-z0-9.-]{0,60}$/;

// The malicious-package list is not carried inline. It is about 228,000 packages, 6 MB as JSON,
// and a hook that parsed 6 MB before every install would cost more than the check is worth. The
// bundle therefore names a sidecar file and pins its SHA-256, and lib/malicious-packages.js
// binary-searches that file on disk.
//
// The pin is what keeps this honest. The bundle is signed, so the hash inside it is signed too,
// and a sidecar that does not match the hash is refused. One signature still covers everything.
function packageList(raw, errors, what0) {
  const o = plainObject(raw, errors, what0);
  if (!o) return undefined;
  const source = str(o.source, errors, `${what0}.source`, LIMITS.text_length);
  const fetched = str(o.fetched, errors, `${what0}.fetched`, 40);
  const file = str(o.file, errors, `${what0}.file`, 64);
  const sha256 = str(o.sha256, errors, `${what0}.sha256`, 64);
  const bytes = int(o.bytes, errors, `${what0}.bytes`, 0, 64 * 1024 * 1024);
  if ([source, fetched, file, sha256, bytes].some((v) => v === undefined)) return undefined;
  // A bare filename, never a path. The client joins it to its own rules directory and to the
  // bundle's own URL, so anything with a slash or a dot-dot in it would escape both.
  if (!SIDECAR_NAME_RE.test(file)) return fail(errors, `${what0}.file: "${file.slice(0, 40)}" is not a plain file name`);
  if (!SHA256_RE.test(sha256)) return fail(errors, `${what0}.sha256: not a SHA-256 digest`);

  const counts = {};
  for (const k of ['npm', 'pypi', 'versioned']) {
    const v = int(o[`${k}_count`], errors, `${what0}.${k}_count`, 0, LIMITS.list_entries);
    if (v === undefined) return undefined;
    counts[k] = v;
  }
  return { source, fetched, file, sha256, bytes, counts };
}

function sources(raw, errors) {
  const list = arrayOf(raw === undefined ? [] : raw, errors, 'sources', LIMITS.sources);
  if (!list) return undefined;
  const out = [];
  list.forEach((s, i) => {
    const what = `sources[${i}]`;
    if (!plainObject(s, errors, what)) return;
    const sid = str(s.id, errors, `${what}.id`, LIMITS.id_length);
    const ok = typeof s.ok === 'boolean' ? s.ok : fail(errors, `${what}.ok: expected a boolean`);
    if (sid === undefined || ok === undefined) return;
    out.push({
      id: sid,
      ok,
      url: typeof s.url === 'string' ? s.url.slice(0, LIMITS.text_length) : '',
      fetched: typeof s.fetched === 'string' ? s.fetched.slice(0, 40) : null,
      age_days: Number.isFinite(s.age_days) ? s.age_days : null,
      note: typeof s.note === 'string' ? s.note.slice(0, LIMITS.text_length) : '',
    });
  });
  return out;
}

// ---------------------------------------------------------------------------------------------
// the whole bundle
// ---------------------------------------------------------------------------------------------

// Compare two `YYYY.MM.DD[.N]` versions. Returns <0, 0 or >0. Both must already match VERSION_RE.
function compareVersions(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

// Validate raw bundle text. Returns { ok, bundle?, errors }.
//
// `text` rather than a parsed object on purpose: the byte length is one of the bounds, and the
// signature is over bytes, so the bytes are what a caller has and what this should check.
function validate(text, opts = {}) {
  const errors = [];
  const raw = typeof text === 'string' ? text : '';
  const bytes = Buffer.byteLength(raw, 'utf8');
  const maxBytes = opts.maxBytes || LIMITS.bundle_bytes;
  if (!bytes) return { ok: false, errors: ['bundle is empty'] };
  if (bytes > maxBytes) return { ok: false, errors: [`bundle is ${bytes} bytes, over the ${maxBytes} limit`] };

  let doc;
  try { doc = JSON.parse(raw); }
  catch (e) { return { ok: false, errors: [`bundle is not valid JSON: ${String((e && e.message) || e).slice(0, 120)}`] }; }
  if (!plainObject(doc, errors, 'bundle')) return { ok: false, errors };

  if (doc.schema !== SCHEMA_VERSION) {
    // A newer schema is not an error to shout about, but it is a refusal: applying a format we do
    // not understand is exactly how a client breaks itself on a feed it should have ignored.
    return { ok: false, errors: [`bundle schema is ${JSON.stringify(doc.schema)}, this client understands ${SCHEMA_VERSION}`] };
  }

  const version = str(doc.version, errors, 'bundle.version', 40);
  if (version !== undefined && !VERSION_RE.test(version)) fail(errors, `bundle.version: "${version}" is not YYYY.MM.DD[.N]`);
  const generated = str(doc.generated, errors, 'bundle.generated', 40);

  const rulesets = plainObject(doc.rulesets, errors, 'bundle.rulesets');
  const lists = plainObject(doc.lists, errors, 'bundle.lists');
  if (!rulesets || !lists || version === undefined || generated === undefined) return { ok: false, errors };

  const injection = injectionRules(rulesets.injection, errors);
  const secrets = secretRules(rulesets.secrets, errors, 'rulesets.secrets', false);
  const pii = secretRules(rulesets.pii, errors, 'rulesets.pii', true);
  const code = codeRules(rulesets.code, errors);
  const ofac = addressList(lists.ofac_evm, errors, 'lists.ofac_evm');
  const scam = addressList(lists.scam_addresses, errors, 'lists.scam_addresses');
  const malicious = packageList(lists.malicious_packages, errors, 'lists.malicious_packages');
  const srcs = sources(doc.sources, errors);

  if (errors.length) return { ok: false, errors };

  // A ruleset that arrives empty would silently switch a detector off. That is the fail-open bug
  // class wearing a new hat, so it is refused here rather than discovered later by a user who
  // wondered why nothing was being caught.
  for (const [name, set] of [['injection', injection], ['secrets', secrets], ['pii', pii], ['code', code]]) {
    if (!set.length) errors.push(`rulesets.${name}: empty — a bundle may not switch a detector off`);
  }
  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    errors: [],
    bundle: {
      schema: SCHEMA_VERSION,
      version,
      generated,
      notes: typeof doc.notes === 'string' ? doc.notes.slice(0, LIMITS.text_length) : '',
      bytes,
      rulesets: { injection, secrets, pii, code },
      lists: { ofac_evm: ofac, scam_addresses: scam, malicious_packages: malicious },
      sources: srcs,
    },
  };
}

// Every pattern in a validated bundle, in the shape lib/redos.js wants. The caller runs this
// through the bounded-execution gate before the bundle is allowed anywhere near a scan.
function patternsOf(bundle) {
  const out = [];
  const push = (set, prefix) => { for (const r of set) out.push({ id: `${prefix}:${r.id}`, source: r.source, flags: r.flags }); };
  push(bundle.rulesets.injection, 'injection');
  push(bundle.rulesets.secrets, 'secrets');
  push(bundle.rulesets.pii, 'pii');
  push(bundle.rulesets.code, 'code');
  return out;
}

module.exports = { validate, patternsOf, compareVersions, SCHEMA_VERSION, LIMITS, VERSION_RE };
