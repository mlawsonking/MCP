// screen-payment — risk-check an x402/payment endpoint or merchant URL before an agent transacts.
// GET /api/screen-payment?url=https://pay.example.com/x402
const { sendJson, handleOptions, safeFetch } = require('../lib/common.js');
const { analyzeUrl, getDomainAgeDays } = require('../lib/safety.js');
const { requirePayment } = require('../lib/x402.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  if (await requirePayment(req, res, { resource: '/api/screen-payment' })) return;
  const started = Date.now();
  const url = String((req.query && (req.query.url || req.query.endpoint)) || '').trim();
  if (!url) return sendJson(res, 400, { ok: false, error: 'Missing ?url= (an x402/payment endpoint or merchant URL)' });

  const a = analyzeUrl(url);
  if (!a.valid) return sendJson(res, 200, { ok: true, url, valid: false, verdict: 'block', score: 100, flags: a.flags, reasons: ['URL is malformed — do not send a payment to it.'], ms: Date.now() - started });

  let score = a.score;
  const flags = [...a.flags];
  const age = await getDomainAgeDays(a.host);
  if (typeof age === 'number') {
    if (age < 30) { score += 25; flags.push({ id: 'very-new-domain', severity: 'high', note: `domain registered ${age}d ago` }); }
    else if (age < 180) { score += 12; flags.push({ id: 'new-domain', severity: 'medium', note: `domain registered ${age}d ago` }); }
  }
  let redirected = false, finalUrl;
  try {
    const f = await safeFetch(url, {});
    if (f.ok && f.finalUrl && f.finalUrl !== url) {
      finalUrl = f.finalUrl; redirected = true;
      const fa = analyzeUrl(f.finalUrl);
      if (fa.valid && fa.host !== a.host) { score += fa.score; for (const fl of fa.flags) flags.push({ ...fl, note: `${fl.note || fl.id} (after redirect)` }); }
    }
  } catch {}

  score = Math.min(100, score);
  const verdict = score >= 50 ? 'block' : score >= 25 ? 'caution' : 'safe';
  const reasons = flags.length ? flags.map((f) => f.note || f.id) : ['No structural red flags; domain looks ordinary. Still verify the recipient is who you expect.'];
  return sendJson(res, 200, { ok: true, url, valid: true, host: a.host, domain_age_days: age, redirected, final_url: finalUrl, score, verdict, flags, reasons, ms: Date.now() - started });
};
