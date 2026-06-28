// HTTP inspector: status, redirect chain, response headers, and security-header checks.
// GET /api/http?url=example.com[&method=GET|HEAD]
// Deterministic, $0. Useful for monitoring, debugging, and agent reconnaissance.

const dns = require('dns').promises;
const { sendJson, handleOptions, isPrivateIp } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  let target = String(q.url || '').trim();
  if (!target) return sendJson(res, 400, { ok: false, error: 'Missing required ?url= parameter' });
  if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
  const method = String(q.method || 'GET').toUpperCase() === 'HEAD' ? 'HEAD' : 'GET';

  const chain = [];
  let current = target, headers = {}, finalStatus = 0, finalUrl = target;
  try {
    for (let i = 0; i < 6; i++) {
      const u = new URL(current);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return sendJson(res, 400, { ok: false, error: 'Only http/https URLs are supported' });
      const { address } = await dns.lookup(u.hostname);
      if (isPrivateIp(address)) return sendJson(res, 400, { ok: false, error: 'Refusing to fetch a private/loopback address' });

      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 7000);
      let r;
      try { r = await fetch(u.href, { method, redirect: 'manual', signal: ctrl.signal, headers: { 'User-Agent': 'agent-tools-bot/1.0 (+https://github.com/)' } }); }
      finally { clearTimeout(t); }

      const loc = r.headers.get('location');
      if (r.status >= 300 && r.status < 400 && loc) {
        const next = new URL(loc, u.href).href;
        chain.push({ url: u.href, status: r.status, location: next });
        current = next;
        continue;
      }
      chain.push({ url: u.href, status: r.status });
      finalStatus = r.status; finalUrl = u.href;
      headers = {}; r.headers.forEach((v, k) => { headers[k] = v; });
      break;
    }
  } catch (e) {
    return sendJson(res, 504, { ok: false, error: 'Request failed or timed out', detail: String((e && e.message) || e), chain });
  }

  const security = {
    hsts: !!headers['strict-transport-security'],
    csp: !!headers['content-security-policy'],
    x_frame_options: headers['x-frame-options'] || undefined,
    x_content_type_options: headers['x-content-type-options'] || undefined,
    referrer_policy: headers['referrer-policy'] || undefined,
    permissions_policy: headers['permissions-policy'] || undefined,
  };

  return sendJson(res, 200, {
    ok: true, url: target, final_url: finalUrl, status: finalStatus, redirects: Math.max(0, chain.length - 1),
    chain, server: headers['server'] || undefined, content_type: headers['content-type'] || undefined,
    security, headers, ms: Date.now() - started,
  });
};
