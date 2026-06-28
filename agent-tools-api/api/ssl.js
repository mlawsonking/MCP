// SSL/TLS certificate inspector.
// GET /api/ssl?host=example.com
// Returns issuer, subject, validity window, days remaining, SANs, protocol. Useful for cert
// monitoring and trust checks. Deterministic, $0 (direct TLS handshake).

const tls = require('tls');
const { sendJson, handleOptions } = require('../lib/common.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  let host = String(q.host || q.domain || q.url || '').trim();
  if (!host) return sendJson(res, 400, { ok: false, error: 'Missing required ?host= parameter' });
  try { if (host.includes('://')) host = new URL(host).hostname; } catch {}
  host = host.replace(/\/.*$/, '').replace(/:.*$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) return sendJson(res, 400, { ok: false, error: 'Invalid host' });

  const result = await new Promise((resolve) => {
    let settled = false;
    const finish = (v) => { if (!settled) { settled = true; resolve(v); } };
    const socket = tls.connect({ host, port: 443, servername: host, timeout: 8000, rejectUnauthorized: false }, () => {
      try {
        const cert = socket.getPeerCertificate(false);
        const authorized = socket.authorized;
        const proto = socket.getProtocol();
        finish({ cert, proto, authorized });
      } catch (e) { finish({ error: String((e && e.message) || e) }); }
      finally { try { socket.end(); } catch {} }
    });
    socket.on('error', (e) => finish({ error: String((e && e.message) || e) }));
    socket.on('timeout', () => { finish({ error: 'connection timed out' }); try { socket.destroy(); } catch {} });
  });

  if (result.error) return sendJson(res, 502, { ok: false, error: 'TLS connection failed', detail: result.error, host });
  const c = result.cert || {};
  const validTo = c.valid_to ? new Date(c.valid_to) : null;
  const daysRemaining = validTo ? Math.floor((validTo - Date.now()) / 86400000) : undefined;
  const sans = c.subjectaltname ? c.subjectaltname.split(',').map((s) => s.replace(/^\s*DNS:/, '').trim()) : undefined;

  return sendJson(res, 200, {
    ok: true, host, protocol: result.proto || undefined, trusted: !!result.authorized,
    issuer: c.issuer ? (c.issuer.O || c.issuer.CN) : undefined,
    subject: c.subject ? c.subject.CN : undefined,
    valid_from: c.valid_from || undefined, valid_to: c.valid_to || undefined,
    days_remaining: daysRemaining, expired: daysRemaining !== undefined ? daysRemaining < 0 : undefined,
    sans, serial: c.serialNumber || undefined, ms: Date.now() - started,
  });
};
