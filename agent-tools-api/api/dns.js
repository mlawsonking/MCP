// DNS records + email-auth (SPF/DMARC) lookup.
// GET /api/dns?domain=example.com[&type=all|A|AAAA|MX|NS|TXT|CNAME|SOA|CAA]
// Deterministic, free (DNS only). Useful for deliverability, security, and agent reconnaissance.

const dns = require('dns').promises;
const { sendJson, handleOptions } = require('../lib/common.js');

const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SRV'];

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  let domain = String(q.domain || q.host || '').trim().toLowerCase();
  const type = String(q.type || 'all').toUpperCase();
  if (!domain) return sendJson(res, 400, { ok: false, error: 'Missing required ?domain= parameter' });
  try { if (domain.includes('://')) domain = new URL(domain).hostname; } catch {}
  domain = domain.replace(/\/.*$/, '').replace(/:.*$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) return sendJson(res, 400, { ok: false, error: 'Invalid domain' });
  if (type !== 'ALL' && !TYPES.includes(type)) return sendJson(res, 400, { ok: false, error: `Unsupported type. Use: ${TYPES.join(', ')} or all` });

  const want = type === 'ALL' ? ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'] : [type];
  const records = {};
  await Promise.all(want.map(async (t) => {
    try {
      let r;
      if (t === 'A') r = await dns.resolve4(domain);
      else if (t === 'AAAA') r = await dns.resolve6(domain);
      else if (t === 'MX') r = (await dns.resolveMx(domain)).sort((a, b) => a.priority - b.priority);
      else if (t === 'TXT') r = (await dns.resolveTxt(domain)).map((a) => a.join(''));
      else r = await dns.resolve(domain, t);
      if (r && r.length) records[t] = r;
    } catch {}
  }));

  const txt = records.TXT || [];
  const spf = txt.find((t) => /^v=spf1/i.test(t)) || null;
  let dmarc = null;
  try { const d = await dns.resolveTxt('_dmarc.' + domain); dmarc = d.map((a) => a.join('')).find((t) => /^v=DMARC1/i.test(t)) || null; } catch {}

  return sendJson(res, 200, {
    ok: true, domain, records,
    email_auth: { has_mx: !!records.MX, spf: !!spf, spf_record: spf || undefined, dmarc: !!dmarc, dmarc_record: dmarc || undefined },
    ms: Date.now() - started,
  });
};
