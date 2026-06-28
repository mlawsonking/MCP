// Domain registration info via RDAP (the official, free JSON successor to WHOIS).
// GET /api/domain?name=example.com
// Returns creation/expiry dates, domain age, registrar, status, nameservers.
// Domain age is a strong trust/fraud signal — high value, deterministic, $0.

const { sendJson, handleOptions } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  let name = String(q.name || q.domain || '').trim().toLowerCase();
  if (!name) return sendJson(res, 400, { ok: false, error: 'Missing required ?name= parameter' });
  try { if (name.includes('://')) name = new URL(name).hostname; } catch {}
  name = name.replace(/\/.*$/, '').replace(/:.*$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(name)) return sendJson(res, 400, { ok: false, error: 'Invalid domain' });

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(name)}`, { signal: ctrl.signal, headers: { Accept: 'application/rdap+json' } });
    if (r.status === 404) return sendJson(res, 404, { ok: false, error: 'Domain not found or not registered', domain: name });
    if (!r.ok) return sendJson(res, 502, { ok: false, error: `RDAP returned HTTP ${r.status}`, domain: name });
    const d = await r.json();

    const ev = d.events || [];
    const evDate = (a) => { const e = ev.find((x) => x.eventAction === a); return e ? e.eventDate : undefined; };
    const registration = evDate('registration');
    const expiration = evDate('expiration');
    const lastChanged = evDate('last changed');
    const ageDays = registration ? Math.floor((Date.now() - new Date(registration)) / 86400000) : undefined;
    const expiresInDays = expiration ? Math.floor((new Date(expiration) - Date.now()) / 86400000) : undefined;

    let registrar;
    const reg = (d.entities || []).find((e) => (e.roles || []).includes('registrar'));
    if (reg && Array.isArray(reg.vcardArray) && reg.vcardArray[1]) {
      const fn = reg.vcardArray[1].find((x) => x[0] === 'fn');
      if (fn) registrar = fn[3];
    }

    return sendJson(res, 200, {
      ok: true, domain: (d.ldhName || name).toLowerCase(), status: d.status || undefined,
      registration: registration || undefined, expiration: expiration || undefined, last_changed: lastChanged || undefined,
      age_days: ageDays, expires_in_days: expiresInDays, registrar: registrar || undefined,
      nameservers: (d.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
      ms: Date.now() - started,
    });
  } catch (e) {
    return sendJson(res, 504, { ok: false, error: 'RDAP lookup failed or timed out', detail: String((e && e.message) || e) });
  } finally { clearTimeout(timer); }
};
