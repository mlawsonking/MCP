// Shared helpers for the agent-tools API functions.
const dns = require('dns').promises;
const net = require('net');

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const p = ip.split('.').map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
    return false;
  }
  const lc = ip.toLowerCase();
  return lc === '::1' || lc === '::' || lc.startsWith('fe80') || lc.startsWith('fc') || lc.startsWith('fd');
}

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

// SSRF-safe fetch. Returns { ok, code?, error?, text?, finalUrl?, contentType? }.
async function safeFetch(target, opts = {}) {
  const { timeoutMs = 7000, maxBytes = 3 * 1024 * 1024, accept = 'text/html,application/xhtml+xml,application/xml,application/rss+xml,text/plain', ua = 'agent-tools-bot/1.0 (+https://github.com/)' } = opts;
  let u;
  try { u = new URL(target); } catch { return { ok: false, code: 400, error: 'Invalid URL' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, code: 400, error: 'Only http and https URLs are supported' };
  try {
    const { address } = await dns.lookup(u.hostname);
    if (isPrivateIp(address)) return { ok: false, code: 400, error: 'Refusing to fetch a private/loopback address' };
  } catch { return { ok: false, code: 400, error: 'Could not resolve host' }; }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(u.href, { redirect: 'follow', signal: ctrl.signal, headers: { 'User-Agent': ua, Accept: accept } });
    const contentType = r.headers.get('content-type') || '';
    if (!r.ok) return { ok: false, code: 502, error: `Upstream returned HTTP ${r.status}`, finalUrl: r.url };
    const reader = r.body.getReader();
    const chunks = []; let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) { try { await reader.cancel(); } catch {} break; }
      chunks.push(value);
    }
    return { ok: true, text: Buffer.concat(chunks).toString('utf-8'), finalUrl: r.url, contentType };
  } catch (e) {
    return { ok: false, code: 504, error: 'Fetch failed or timed out', detail: String((e && e.message) || e) };
  } finally { clearTimeout(timer); }
}

// --- WAU beacon → PostHog. Fail-safe, dependency-free, no-op without POSTHOG_KEY. Never blocks/affects the response.
function track(req, event, properties) {
  try {
    const key = process.env.POSTHOG_KEY;
    if (!key) return;
    const h = (req && req.headers) || {};
    const raw = h['x-rapidapi-user'] || h['authorization'] || h['x-forwarded-for'] || 'anon';
    const distinct_id = 'u_' + require('crypto').createHash('sha256').update(String(raw)).digest('hex').slice(0, 16);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1500);
    if (timer.unref) timer.unref();
    fetch('https://us.i.posthog.com/capture/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key, event, distinct_id, properties: properties || {} }),
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
