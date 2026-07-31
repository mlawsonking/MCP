// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: shared/lib/common.js
// Regenerate: node scripts/sync-shared.js
// Shared helpers for the API functions: HTTP plumbing, the usage beacon, and the upgrade hint.
//
// The SSRF-safe fetch used to live in this file. It now lives in the agent-guards core
// (`agent-guards/lib/net.js`) and is re-exported here under the same name, because the guard needs
// to behave identically whether it is reached through the hosted API, the MCP server or the local
// engines. What stays here is the part that only makes sense inside a serverless HTTP handler.
//
// The `./core/...` path resolves in the DESTINATION: `scripts/sync-shared.js` copies this file to
// `<product>/lib/common.js` and the core to `<product>/lib/core/`, so they end up siblings.

const { safeFetch, isPrivateIp } = require('./core/lib/net');

function sendJson(res, code, obj) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.statusCode = code;
  res.end(JSON.stringify(obj));
}

function handleOptions(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.statusCode = 204; res.end(); return true;
  }
  return false;
}

// --- WAU beacon → PostHog. Fail-safe, dependency-free, no-op without POSTHOG_KEY. Never blocks/affects the response.
function track(req, event, properties) {
  try {
    const key = process.env.POSTHOG_KEY;
    if (!key) return;
    const h = (req && req.headers) || {};
    const raw = h['x-rapidapi-user'] || h['authorization'] || h['x-forwarded-for'] || 'anon';
    const distinct_id = 'u_' + require('crypto').createHash('sha256').update(String(raw)).digest('hex').slice(0, 16);
    const ua = String(h['user-agent'] || '').slice(0, 180);
    const referer = String(h['referer'] || '').slice(0, 200);
    const props = Object.assign({}, properties || {}, {
      ua,
      origin: String(h['origin'] || '').slice(0, 120),
      referer,
      client: /mozilla/i.test(ua) ? 'browser' : 'api',
      demo: referer.indexOf('vercel.app') !== -1,
    });
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1500);
    if (timer.unref) timer.unref();
    fetch('https://us.i.posthog.com/capture/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key, event, distinct_id, properties: props }),
      signal: ctrl.signal,
    }).then(() => clearTimeout(timer)).catch(() => clearTimeout(timer));
  } catch { /* analytics must never affect the API */ }
}

// Upgrade hint for DIRECT (non-RapidAPI) traffic: a non-breaking extra field so
// heavy free users can discover the paid path. RapidAPI callers never see it —
// the marketplace already handles their plans.
function upgradeInfo(req, slug) {
  try {
    const h = (req && req.headers) || {};
    if (h['x-rapidapi-proxy-secret'] || h['x-rapidapi-user']) return undefined;
    return {
      note: 'Free public endpoint (rate-limited). Higher volume, hard SLAs: https://rapidapi.com/mlawsonking/api/' + slug,
      pricing: '/api/pricing',
    };
  } catch { return undefined; }
}

module.exports = { isPrivateIp, sendJson, handleOptions, safeFetch, track, upgradeInfo };
