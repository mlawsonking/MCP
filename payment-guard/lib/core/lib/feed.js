// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/lib/feed.js
// Regenerate: node scripts/sync-shared.js
// The rules feed client: the one place in the local surfaces that is allowed to touch the network.
//
// What it does, in the order it does it, because the order is the security argument:
//
//   1. Fetch a small manifest. It names a bundle URL, the bundle's size and SHA-256, and a
//      detached Ed25519 signature over the bundle's bytes.
//   2. Fetch the bundle, from an allowlisted host only, with a hard byte cap.
//   3. Check the SHA-256, then verify the signature against the public key compiled into this
//      package. A bundle that fails either is discarded.
//   4. Validate the bundle against the schema in lib/rules-schema.js.
//   5. Put every pattern in it through the ReDoS gate in lib/redos.js. The publisher already ran
//      that gate; running it again here is the point, because the feed is remote input.
//   6. Refuse a version older than or equal to the one already cached.
//   7. Only then write it to disk and let the engines use it.
//
// Two separate switches, because they are two separate decisions and running them together was a
// real bug caught by this file's own tests: `force` means "do not wait for the TTL, pull now", and
// it is what `guard update` passes. `allowRollback` means "install this even though it is older
// than what I have", and nothing passes it unless a human asked for it by name. Folding the second
// into the first would have made a routine `guard update` capable of silently downgrading rules.
//
// The version that gets recorded is the one INSIDE the signed bundle, never the one the manifest
// claimed. A manifest is unsigned, so anything it says is a hint; the bundle is the evidence.
//
// Any failure at any step is not an error the caller has to handle. It leaves the client on the
// rules it already had — the last good bundle, or the ones compiled into the package — and says so
// in the provenance. A guard that stops guarding because an update failed would be the fail-open
// bug class with extra steps.
//
// What leaves the machine: an HTTP GET carrying the current rules version and a surface tag
// ("cli", "plugin", "mcp", "facade"). No machine id, no usage data, no scanned content, ever. This
// is documented in every surface's README and --help, and turning it off is one environment
// variable. It never runs inside a hook: hooks are the intercept path and must not block on a
// network call.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { home, ensureDir } = require('./paths');
const { safeFetch } = require('./net');
const schema = require('./rules-schema');
const redos = require('./redos');

// The public half of the key the publish pipeline signs with. The private half lives in a GitHub
// Actions secret and nowhere else. Verifying with a key that ships inside the package is what makes
// the transport untrusted: it does not matter which mirror served the bundle.
//
// Rotation: add the new key to the FRONT of this list, ship a release, and only then start signing
// with it. Removing the old key is a later release, so nobody is stranded mid-upgrade.
const TRUSTED_KEYS = [
  // agent-guards rules feed, key 1, generated 2026-07-31
  'MCowBQYDK2VwAyEA/9neavSj1zSMlyMVmrV8OOWPIP8B0JqMRAiGES2r0BU=',
];

const DEFAULT_MANIFEST_URL = 'https://agent-firewall-seven.vercel.app/api/rules/latest';

// A bundle may only be fetched from one of these. A manifest is unsigned, so without this a feed
// that had been tampered with could point the client at any URL it liked and use it as a probe.
const ALLOWED_BUNDLE_HOSTS = [
  'raw.githubusercontent.com',
  'agent-firewall-seven.vercel.app',
  'package-guard.vercel.app',
  'payment-guard.vercel.app',
  'email-guard-api.vercel.app',
  'code-guard-api.vercel.app',
  'agent-tools-api.vercel.app',
];

const TTL_MS = 24 * 3600 * 1000;
const JITTER_MS = 6 * 3600 * 1000;   // spreads pulls so a million clients do not all wake at midnight
const MANIFEST_MAX_BYTES = 64 * 1024;
const SURFACES = ['cli', 'plugin', 'mcp', 'facade', 'unknown'];

function rulesDir() { return path.join(home(), 'rules'); }
function bundlePath() { return path.join(rulesDir(), 'bundle.json'); }
function statePath() { return path.join(rulesDir(), 'state.json'); }

// ---------------------------------------------------------------------------------------------
// opting out
// ---------------------------------------------------------------------------------------------

// Three ways to turn it off, and the reason for three is that they belong to different people: a
// user sets the environment variable, a script passes --offline, and a packager can drop a config
// file. Any one of them wins.
function disabledReason(opts = {}) {
  if (opts.offline) return 'offline mode';
  const env = process.env.AGENT_GUARDS_NO_FEED;
  if (env && !/^(0|false|no)$/i.test(String(env).trim())) return 'AGENT_GUARDS_NO_FEED is set';
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(home(), 'config.json'), 'utf8'));
    if (cfg && cfg.feed === false) return `feed: false in ${path.join(home(), 'config.json')}`;
  } catch { /* no config, or unreadable: not a reason to disable */ }
  return null;
}

function manifestUrl(opts = {}) {
  const override = opts.url || process.env.AGENT_GUARDS_FEED_URL;
  return override && String(override).trim() ? String(override).trim() : DEFAULT_MANIFEST_URL;
}

// ---------------------------------------------------------------------------------------------
// local state
// ---------------------------------------------------------------------------------------------

function readState() {
  try {
    const s = JSON.parse(fs.readFileSync(statePath(), 'utf8'));
    return s && typeof s === 'object' ? s : {};
  } catch { return {}; }
}

function writeState(patch) {
  if (!ensureDir(rulesDir())) return false;
  const next = { ...readState(), ...patch };
  try {
    const tmp = statePath() + `.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(next, null, 2));
    fs.renameSync(tmp, statePath());
    return true;
  } catch { return false; }
}

// The bundle already on disk, validated again on the way in. It is validated rather than trusted
// because the file lives in the user's home directory: anything on the machine could have edited
// it, and re-running the schema costs a few milliseconds.
function loadCached() {
  let text;
  try { text = fs.readFileSync(bundlePath(), 'utf8'); } catch { return null; }
  const v = schema.validate(text);
  if (!v.ok) return null;
  return v.bundle;
}

function cachedVersion() {
  const st = readState();
  return typeof st.version === 'string' && schema.VERSION_RE.test(st.version) ? st.version : null;
}

// ---------------------------------------------------------------------------------------------
// verification
// ---------------------------------------------------------------------------------------------

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

// Verify a detached Ed25519 signature over the bundle bytes against every key we trust.
function verifySignature(bytes, signatureB64, keys = TRUSTED_KEYS) {
  let sig;
  try { sig = Buffer.from(String(signatureB64 || ''), 'base64'); } catch { return false; }
  // Ed25519 signatures are always 64 bytes. Checking up front means a truncated or padded
  // signature is refused rather than handed to the verifier to interpret.
  if (sig.length !== 64) return false;
  for (const k of keys) {
    try {
      const key = crypto.createPublicKey({ key: Buffer.from(k, 'base64'), format: 'der', type: 'spki' });
      if (crypto.verify(null, bytes, key, sig)) return true;
    } catch { /* a key that will not import cannot verify anything; try the next */ }
  }
  return false;
}

function hostAllowed(url, opts = {}) {
  // If the user pointed the client somewhere themselves, that host is theirs to choose — but only
  // that host, and only for this run.
  const extra = [];
  const override = opts.url || process.env.AGENT_GUARDS_FEED_URL;
  if (override) { try { extra.push(new URL(String(override)).hostname); } catch { /* ignore */ } }
  return ALLOWED_BUNDLE_HOSTS.includes(url.hostname) || extra.includes(url.hostname);
}

// ---------------------------------------------------------------------------------------------
// the update
// ---------------------------------------------------------------------------------------------

function dueForPull(state, now) {
  if (!state.last_attempt) return true;
  const last = Date.parse(state.last_attempt);
  if (!Number.isFinite(last)) return true;
  // Deterministic per-machine jitter, so a given machine keeps its slot instead of drifting.
  const seed = crypto.createHash('sha256').update(String(home())).digest()[0] / 255;
  return now - last >= TTL_MS + Math.floor(seed * JITTER_MS);
}

// Pull, verify and apply. Never throws. Returns a result object describing exactly what happened,
// which is what the surfaces print.
async function update(opts = {}) {
  const surface = SURFACES.includes(opts.surface) ? opts.surface : 'unknown';
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const have = cachedVersion();

  const off = disabledReason(opts);
  if (off) return { ok: false, action: 'skipped', reason: `updates are off (${off})`, version: have, surface };

  const state = readState();
  if (!opts.force && !dueForPull(state, now)) {
    return { ok: true, action: 'skipped', reason: 'checked recently', version: have, surface };
  }

  const url = manifestUrl(opts);
  const fetchImpl = opts.fetchImpl || safeFetch;
  writeState({ last_attempt: new Date(now).toISOString() });

  // 1. the manifest
  const sep = url.includes('?') ? '&' : '?';
  const manifestRes = await fetchImpl(`${url}${sep}surface=${encodeURIComponent(surface)}&have=${encodeURIComponent(have || 'none')}`, {
    maxBytes: MANIFEST_MAX_BYTES,
    accept: 'application/json',
    headers: state.etag ? { 'If-None-Match': state.etag } : undefined,
  });
  if (manifestRes && manifestRes.notModified) {
    writeState({ last_success: new Date(now).toISOString() });
    return { ok: true, action: 'up-to-date', reason: 'the feed reports no change', version: have, surface };
  }
  if (!manifestRes || !manifestRes.ok) {
    return { ok: false, action: 'failed', reason: `could not reach the feed: ${(manifestRes && manifestRes.error) || 'no response'}`, version: have, surface };
  }

  let manifest;
  try { manifest = JSON.parse(manifestRes.text); } catch { manifest = null; }
  if (!manifest || typeof manifest !== 'object') {
    return { ok: false, action: 'failed', reason: 'the feed returned something that is not a manifest', version: have, surface };
  }

  // A manifest claiming a version we already have saves us downloading megabytes to find out. It is
  // only ever a shortcut: the real decision is made below, on the signed bundle.
  if (!opts.allowRollback && have && typeof manifest.version === 'string' && schema.VERSION_RE.test(manifest.version)
      && schema.compareVersions(manifest.version, have) <= 0) {
    writeState({ last_success: new Date(now).toISOString(), etag: manifestRes.etag || state.etag });
    return { ok: true, action: 'up-to-date', reason: `the feed is at ${manifest.version}`, version: have, surface };
  }

  let bundleUrl;
  try { bundleUrl = new URL(String(manifest.url || '')); } catch { bundleUrl = null; }
  if (!bundleUrl || bundleUrl.protocol !== 'https:') {
    return { ok: false, action: 'refused', reason: 'the manifest did not name an https bundle URL', version: have, surface };
  }
  if (!hostAllowed(bundleUrl, opts)) {
    return { ok: false, action: 'refused', reason: `the manifest pointed at ${bundleUrl.hostname}, which is not a host this client will fetch rules from`, version: have, surface };
  }

  // 2. the bundle
  const claimedBytes = Number.isFinite(manifest.bytes) ? manifest.bytes : schema.LIMITS.bundle_bytes;
  if (claimedBytes > schema.LIMITS.bundle_bytes) {
    return { ok: false, action: 'refused', reason: `the manifest offers a ${claimedBytes}-byte bundle, over the ${schema.LIMITS.bundle_bytes} limit`, version: have, surface };
  }
  const bundleRes = await fetchImpl(bundleUrl.href, { maxBytes: schema.LIMITS.bundle_bytes, accept: 'application/json' });
  if (!bundleRes || !bundleRes.ok) {
    return { ok: false, action: 'failed', reason: `could not download the bundle: ${(bundleRes && bundleRes.error) || 'no response'}`, version: have, surface };
  }
  // safeFetch stops reading at the cap and says so. A truncated bundle would fail the hash anyway,
  // but saying which thing went wrong is worth the extra branch.
  if (bundleRes.truncated) {
    return { ok: false, action: 'refused', reason: `the bundle is larger than the ${schema.LIMITS.bundle_bytes}-byte limit`, version: have, surface };
  }

  const bytes = Buffer.from(bundleRes.text, 'utf8');

  // 3. integrity
  const digest = sha256(bytes);
  if (typeof manifest.sha256 !== 'string' || manifest.sha256.toLowerCase() !== digest) {
    return { ok: false, action: 'refused', reason: 'the bundle does not match the SHA-256 in the manifest', version: have, surface };
  }
  if (!verifySignature(bytes, manifest.signature, opts.keys)) {
    return { ok: false, action: 'refused', reason: 'the bundle signature did not verify', version: have, surface };
  }

  // 4. schema
  const v = schema.validate(bundleRes.text);
  if (!v.ok) {
    return { ok: false, action: 'refused', reason: `the bundle failed validation: ${v.errors[0]}`, version: have, surface, errors: v.errors };
  }

  // 5. version, taken from the signed bundle rather than the manifest's claim
  if (have && !opts.allowRollback && schema.compareVersions(v.bundle.version, have) <= 0) {
    return {
      ok: false,
      action: 'refused',
      reason: `the feed offered ${v.bundle.version} but ${have} is already installed; rules are never rolled back automatically`,
      version: have,
      surface,
    };
  }

  // 6. cost
  const gate = await redos.checkPatterns(schema.patternsOf(v.bundle), opts.redos);
  if (!gate.ok) {
    return {
      ok: false,
      action: 'refused',
      reason: `a pattern in the bundle failed the ReDoS check: ${gate.failures[0].id} (${gate.failures[0].reason})`,
      version: have,
      surface,
      errors: gate.failures.map((f) => `${f.id}: ${f.reason}`),
    };
  }

  // 7. the sidecar, if this bundle brings a new one
  //
  // The malicious-package list lives beside the bundle rather than inside it, and the bundle pins
  // its SHA-256. Because the bundle is signed, that hash is signed, so verifying the sidecar
  // against it extends the same chain of trust to a file that never gets its own signature.
  const sidecar = v.bundle.lists.malicious_packages;
  let sidecarResult = { action: 'unchanged' };
  if (sidecar) {
    sidecarResult = await fetchSidecar(sidecar, bundleUrl, fetchImpl, opts);
    if (!sidecarResult.ok && sidecarResult.fatal) {
      return { ok: false, action: 'refused', reason: sidecarResult.reason, version: have, surface };
    }
  }

  // 8. keep it
  if (!ensureDir(rulesDir())) {
    return { ok: false, action: 'failed', reason: `could not create ${rulesDir()}`, version: have, surface };
  }
  try {
    const tmp = bundlePath() + `.${process.pid}.tmp`;
    fs.writeFileSync(tmp, bundleRes.text);
    fs.renameSync(tmp, bundlePath());
  } catch (e) {
    return { ok: false, action: 'failed', reason: `could not write the bundle: ${String((e && e.message) || e)}`, version: have, surface };
  }
  writeState({
    version: v.bundle.version,
    generated: v.bundle.generated,
    applied_at: new Date(now).toISOString(),
    last_success: new Date(now).toISOString(),
    etag: manifestRes.etag || null,
    sha256: digest,
  });

  // Drop the engines' cached view so a long-running MCP server starts using the new rules without
  // being restarted. Required lazily: lib/rulesets.js requires this file back, and doing it at
  // module scope would be a cycle.
  try { require('./rulesets').reload(); } catch { /* the update still happened */ }

  return {
    ok: true,
    action: 'applied',
    reason: `rules updated to ${v.bundle.version}`,
    version: v.bundle.version,
    previous: have,
    surface,
    bundle: v.bundle,
    packages: sidecarResult,
    stale_sources: v.bundle.sources.filter((s) => !s.ok).map((s) => s.id),
  };
}

// Download the malicious-package sidecar and check it against the hash the signed bundle pins.
//
// A sidecar failure is deliberately NOT fatal to the update in most cases: the rules in the bundle
// are good and applying them is better than refusing everything because one large file would not
// download. The exception is a sidecar that arrives and does not match its hash, which is evidence
// of tampering rather than of a flaky network, and that stops the update.
async function fetchSidecar(spec, bundleUrl, fetchImpl, opts = {}) {
  const dest = path.join(rulesDir(), spec.file);
  // Already have exactly this file: nothing to do. This is the common case, because the package
  // list changes far less often per byte than the rest of the bundle.
  try {
    const current = crypto.createHash('sha256').update(fs.readFileSync(dest)).digest('hex');
    if (current === spec.sha256) return { ok: true, action: 'unchanged', file: dest, bytes: spec.bytes };
  } catch { /* not there yet, or unreadable: fetch it */ }

  let url;
  try { url = new URL(spec.file, bundleUrl); } catch { return { ok: false, fatal: true, reason: 'the bundle named a sidecar that does not form a URL' }; }
  if (url.protocol !== 'https:' || !hostAllowed(url, opts)) {
    return { ok: false, fatal: true, reason: `the package list would come from ${url.hostname}, which is not a host this client will fetch rules from` };
  }

  const res = await fetchImpl(url.href, { maxBytes: Math.max(1, spec.bytes) + 1024, accept: 'text/plain' });
  if (!res || !res.ok || res.truncated) {
    return { ok: false, fatal: false, action: 'skipped', reason: `could not download the package list: ${(res && res.error) || 'no response'}` };
  }
  const bytes = Buffer.from(res.text, 'utf8');
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  if (digest !== spec.sha256) {
    return { ok: false, fatal: true, reason: 'the package list does not match the SHA-256 the signed bundle pins' };
  }
  if (!ensureDir(rulesDir())) return { ok: false, fatal: false, action: 'skipped', reason: 'could not create the rules directory' };
  try {
    const tmp = dest + `.${process.pid}.tmp`;
    fs.writeFileSync(tmp, bytes);
    fs.renameSync(tmp, dest);
  } catch (e) {
    return { ok: false, fatal: false, action: 'skipped', reason: `could not write the package list: ${String((e && e.message) || e)}` };
  }
  return { ok: true, action: 'updated', file: dest, bytes: bytes.length };
}

module.exports = {
  update,
  loadCached,
  cachedVersion,
  readState,
  writeState,
  disabledReason,
  manifestUrl,
  verifySignature,
  hostAllowed,
  dueForPull,
  sha256,
  rulesDir,
  bundlePath,
  statePath,
  TRUSTED_KEYS,
  ALLOWED_BUNDLE_HOSTS,
  DEFAULT_MANIFEST_URL,
  TTL_MS,
  SURFACES,
};
