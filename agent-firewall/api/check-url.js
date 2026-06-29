// check-url — URL/domain safety: structural heuristics + domain age (RDAP) + redirect chain → verdict.
// GET /api/check-url?url=https://...
const { sendJson, handleOptions, safeFetch } = require('../lib/common.js');
const { analyzeUrl, getDomainAgeDays } = require('../lib/safety.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const url = String((req.query && req.query.url) || '').trim();
  if (!url) return sendJson(res, 400, { ok: false, error: 'Missing ?url=' });

  const a = analyzeUrl(url);
  if (!a.valid) return sendJson(res, 200, { ok: true, url, valid: false, verdict: 'suspicious', score: a.score, flags: a.flags, ms: Date.now() - started });

  let score = a.score;
  const flags = [...a.flags];
  const age = await getDomainAgeDays(a.host);
  if (typeof age === 'number') {
    if (age < 30) { score += 25; flags.push({ id: 'very-new-domain', severity: 'high', note: `registered ${age}d ago` }); }
    else if (age < 180) { score += 12; flags.push({ id: 'new-domain', severity: 'medium', note: `registered ${age}d ago` }); }
  }

  let redirected = false, finalUrl;
  try {
    const f = await safeFetch(url, {});
    if (f.ok && f.finalUrl && f.finalUrl !== url) {
      finalUrl = f.finalUrl; redirected = true;
      const fa = analyzeUrl(f.finalUrl);
      if (fa.valid && fa.host !== a.host) {
        score += fa.score;
        for (const fl of fa.flags) flags.push({ ...fl, note: `${fl.note || ''} (after redirect)`.trim() });
      }
    }
  } catch {}

  score = Math.min(100, score);
  const verdict = score >= 50 ? 'malicious' : score >= 25 ? 'suspicious' : 'safe';
  return sendJson(res, 200, { ok: true, url, valid: true, host: a.host, domain_age_days: age, redirected, final_url: finalUrl, score, verdict, flags, ms: Date.now() - started });
};
