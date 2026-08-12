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

// Keep the runtime alive until a background promise settles.
//
// This exists because the beacon was silently not firing. A serverless function is frozen the moment
// its response is sent, so a fire-and-forget POST started just before `res.end()` never gets to
// flush. On a slow handler the event loop is still turning and it goes out; on a fast one it does
// not. That is not a theory: agent-firewall produced ZERO events in 90 days while the other five
// products reported normally, and the difference is that its hero endpoint is pure local regex and
// answers in about a millisecond. Confirmed on the live deployment by calling one slow endpoint
// (check-url, which does RDAP lookups) and one fast one (scan-content) back to back: only the slow
// one arrived.
//
// So the measurement was not "low usage", it was "no measurement", which is the same bug class this
// project keeps finding in its own checks: an absent answer read as a real one.
//
// `waitUntil` is the platform's own answer to this. It is reached through a well-known global rather
// than a package so nothing new has to be installed, and if it is missing we fall back to the old
// behaviour, which is no worse than before.
function keepAlive(promise) {
  try {
    const ctx = globalThis[Symbol.for('@vercel/request-context')];
    const waitUntil = ctx && typeof ctx.get === 'function' && ctx.get() && ctx.get().waitUntil;
    if (typeof waitUntil === 'function') { waitUntil(promise); return true; }
  } catch { /* not on a runtime that offers it */ }
  return false;
}

// --- WAU beacon → PostHog. Fail-safe, dependency-free, no-op without POSTHOG_KEY. Never blocks the
// response: it either rides on waitUntil or it is fire-and-forget. Returns the in-flight promise so
// a caller that must not lose the event can await it.
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
    // One caller is allowed to name its own client, and only one: the rules feed, whose pulls are
    // tagged `rules-pull` so they can be counted as installs rather than lost in the API traffic.
    // Everything else keeps the browser/api split the WAU numbers are read through, so this is an
    // explicit override rather than a general-purpose one.
    if (properties && properties.client === 'rules-pull') props.client = 'rules-pull';
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1500);
    if (timer.unref) timer.unref();
    const sent = fetch('https://us.i.posthog.com/capture/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key, event, distinct_id, properties: props }),
      signal: ctrl.signal,
    }).then(() => clearTimeout(timer)).catch(() => clearTimeout(timer));
    keepAlive(sent);
    return sent;
  } catch { /* analytics must never affect the API */ }
  return undefined;
}

// A note for DIRECT (non-RapidAPI) traffic, as a non-breaking extra field.
//
// This used to sell a paid plan and promise "hard SLAs". Both were wrong: the plans bought less
// throughput than this free endpoint already allows, and nothing backs an SLA on free hosting. The
// real answer for anyone hitting the limit is to stop calling a shared endpoint and run the same
// engines locally, where there is no limit and no payload leaves the machine.
function upgradeInfo(req, slug) {
  try {
    const h = (req && req.headers) || {};
    if (h['x-rapidapi-proxy-secret'] || h['x-rapidapi-user']) return undefined;
    return {
      note: 'Free shared endpoint, rate-limited, no SLA. For volume or privacy run the same checks locally: npx -y agent-guards',
      local: 'npx -y agent-guards',
      pricing: '/api/pricing',
    };
  } catch { return undefined; }
}

module.exports = { isPrivateIp, sendJson, handleOptions, safeFetch, track, upgradeInfo };
