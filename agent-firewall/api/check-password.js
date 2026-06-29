// check-password — is this password in a known breach? HIBP Pwned Passwords, k-anonymity.
// The plaintext is hashed locally; only the first 5 hash chars leave the server. Never logged/echoed.
// POST { "password": "..." }  |  GET ?password=...  (POST recommended)
const crypto = require('crypto');
const { sendJson, handleOptions } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const pw = (req.body && req.body.password) || (req.query && req.query.password) || '';
  if (!pw) return sendJson(res, 400, { ok: false, error: 'Missing password (POST {password} or ?password=).' });

  const sha1 = crypto.createHash('sha1').update(String(pw)).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5), suffix = sha1.slice(5);
  try {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 6000);
    const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { signal: ctrl.signal, headers: { 'Add-Padding': 'true', 'User-Agent': 'agent-firewall' } });
    clearTimeout(t);
    const txt = await r.text();
    let count = 0;
    for (const line of txt.split(/\r?\n/)) { const [suf, c] = line.split(':'); if (suf && suf.trim() === suffix) { count = parseInt(c, 10) || 0; break; } }
    const pwned = count > 0;
    const verdict = count === 0 ? 'safe' : count < 100 ? 'compromised' : 'severely-compromised';
    return sendJson(res, 200, {
      ok: true, pwned, count, verdict,
      advice: pwned ? 'This password has appeared in known breaches — do not use it.' : 'Not found in known breach corpora.',
      ms: Date.now() - started,
    });
  } catch (e) { return sendJson(res, 502, { ok: false, error: 'HIBP lookup failed', detail: String((e && e.message) || e) }); }
};
