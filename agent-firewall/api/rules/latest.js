// GET /api/rules/latest — the rules feed.
//
// This returns a manifest, not the rules. The manifest names where the signed bundle is, how big it
// is, its SHA-256, and the detached Ed25519 signature over its bytes. A client fetches the bundle
// separately and decides whether to trust it by verifying that signature against a public key
// compiled into the package. That is why this endpoint can be this simple: it is not a trusted
// component. Tampering with what it returns can waste a client's bandwidth and nothing else.
//
// Freshness without a deploy. The bundle and this manifest are written by a scheduled GitHub
// Actions workflow and committed to the repository, where GitHub's raw CDN serves them the moment
// they land. This handler revalidates against that copy every few minutes and serves whatever it
// got. If GitHub cannot be reached it serves the copy vendored into this deployment and says so in
// `served_from`, with the age, because a stale sanctions list served as fresh is the single worst
// thing this project could do.
//
// It is also the heartbeat. A pull carries the surface that made it and the rules version that
// surface already has, and nothing else — no machine id, no usage data, no scanned content. Those
// two fields are what "weekly returning users" is counted from.

const crypto = require('crypto');
const { sendJson, handleOptions, track } = require('../../lib/common.js');

const ORIGIN = 'https://raw.githubusercontent.com/mlawsonking/MCP/main/rules/manifest.json';
const REVALIDATE_MS = 5 * 60 * 1000;
const ORIGIN_TIMEOUT_MS = 2500;
const MAX_BYTES = 256 * 1024;

// The copy that shipped with this deployment. It is the floor, not the source: it only gets served
// when the origin is unreachable.
let vendored = null;
try { vendored = require('../../rules/manifest.json'); } catch { vendored = null; }

// Per-isolate, so a warm function answers without touching GitHub at all.
let cached = { at: 0, doc: null };

// A plain fetch rather than the SSRF-guarded one: this URL is a constant in this file, not
// something a caller supplied, so there is no untrusted host to guard against and no reason to pay
// for the per-request DNS pinning that guard does.
async function fromOrigin() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ORIGIN_TIMEOUT_MS);
  try {
    const r = await fetch(ORIGIN, { signal: ctrl.signal, headers: { 'User-Agent': 'agent-guards rules feed' } });
    if (!r.ok) return null;
    // Refuse on the declared length before reading the body, so an oversized response is not
    // buffered into this function's memory first. Checking after `await r.text()` would bound what
    // gets parsed rather than what gets downloaded, which is not the same promise.
    const declared = Number(r.headers && typeof r.headers.get === 'function' ? r.headers.get('content-length') : NaN);
    if (Number.isFinite(declared) && declared > MAX_BYTES) return null;
    const text = await r.text();
    // And again on the real size. `text.length` counts UTF-16 code units, not bytes, so a body of
    // multi-byte characters can pass a length check and still be over the cap on the wire.
    if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) return null;
    const doc = JSON.parse(text);
    return doc && typeof doc === 'object' && typeof doc.version === 'string' ? doc : null;
  } catch { return null; }
  finally { clearTimeout(timer); }
}

async function current() {
  const now = Date.now();
  if (cached.doc && now - cached.at < REVALIDATE_MS) return { doc: cached.doc, served_from: 'origin' };
  const fresh = await fromOrigin();
  if (fresh) { cached = { at: now, doc: fresh }; return { doc: fresh, served_from: 'origin' }; }
  if (cached.doc) return { doc: cached.doc, served_from: 'origin-cached' };
  return { doc: vendored, served_from: 'vendored' };
}

function ageDays(iso) {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? Math.floor((Date.now() - t) / 86400000) : null;
}

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;

  const url = new URL(req.url, 'http://x');
  const surface = String(url.searchParams.get('surface') || 'unknown').slice(0, 20).replace(/[^a-z-]/g, '');
  const have = String(url.searchParams.get('have') || 'none').slice(0, 20).replace(/[^0-9.a-z]/g, '');

  const { doc, served_from } = await current();
  if (!doc) {
    // No origin and no vendored copy. Say so plainly; a client that gets this keeps the rules it
    // already has, which is the correct outcome.
    return sendJson(res, 503, { ok: false, error: 'The rules feed has no manifest to serve right now. Keep using the rules you have.' });
  }

  // Awaited, unlike everywhere else. This handler is fast enough that the beacon would be lost to
  // the function freezing after the response, and this particular event is the heartbeat the whole
  // retention number is read from. A client pulls once a day, so the hundred milliseconds this costs
  // are worth paying to not be guessing. `track` never rejects.
  await track(req, 'guard_call', {
    client: 'rules-pull',
    // The feed is not one of the six products, but every dashboard groups by this field, so leaving
    // it unset files the heartbeat under "?".
    product: 'rules-feed',
    endpoint: 'rules/latest',
    surface,
    have,
    version: doc.version,
    served_from,
  });

  const body = {
    ok: true,
    ...doc,
    served_from,
    // Every source the bundle was built from, with the ones that could not be refreshed marked. A
    // caller never has to guess whether "not sanctioned" was measured against a current list.
    stale_sources: (doc.sources || []).filter((s) => !s.ok).map((s) => ({ id: s.id, note: s.note, age_days: s.age_days })),
    generated_days_ago: ageDays(doc.generated),
    docs: 'https://github.com/mlawsonking/MCP/blob/main/rules/README.md',
    privacy: 'This request carried the surface tag and the rules version you already have. Nothing else. Set AGENT_GUARDS_NO_FEED=1 to stop it.',
  };

  const etag = '"' + crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex').slice(0, 32) + '"';
  res.setHeader('ETag', etag);
  // Short and public: the manifest is the same for everyone, and a few minutes of CDN caching keeps
  // an unchanged pull off the function entirely.
  res.setHeader('Cache-Control', 'public, max-age=300, stale-while-revalidate=3600');

  // Vercel's edge rewrites the ETag as a weak validator, so what comes back on the next request is
  // `W/"abc"` and not the `"abc"` this handler issued. Comparing the raw strings would miss every
  // time and send the whole body again, which is the one thing the ETag exists to avoid. Measured on
  // the live deployment, not guessed.
  const unweak = (v) => String(v || '').replace(/^W\//, '');
  if (unweak(req.headers['if-none-match']) === unweak(etag)) {
    res.statusCode = 304;
    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.end();
  }
  return sendJson(res, 200, body);
};
