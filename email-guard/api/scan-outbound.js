// scan-outbound — before an agent SENDS an email, check it won't (a) leak secrets/PII, (b) get the sender
// domain blacklisted (deliverability), or (c) bounce off a dead/disposable recipient. Protects reputation + data.
// POST { from, to, subject, body, html }  OR  POST { email: "<raw RFC822>" }
const { sendJson, handleOptions } = require('../lib/common.js');
const { scanSecrets, analyzeUrl } = require('../lib/safety.js');
const { parseEmail, checkDomainAuth, isDisposable, deliverabilityScan } = require('../lib/email.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const body = req.body || {};
  const input = body.email || (Object.keys(body).length ? body : '');
  if (!input || (typeof input === 'string' && !input.trim())) {
    return sendJson(res, 400, { ok: false, error: 'Provide the outbound email: POST {from,to,subject,body,html} or {"email":"<raw>"}.' });
  }
  const p = parseEmail(input);
  const leak = scanSecrets([p.subject, p.body, p.html].filter(Boolean).join('\n'));
  const deliver = deliverabilityScan(p);
  const toDom = p.to.domain;

  const [recipDisposable, recipAuth] = await Promise.all([
    toDom ? isDisposable(toDom) : Promise.resolve(false),
    toDom ? checkDomainAuth(toDom) : Promise.resolve(null),
  ]);
  const recipFlags = [];
  if (toDom && recipAuth && recipAuth.mx.length === 0) recipFlags.push({ id: 'recipient-no-mx', severity: 'high', note: `${toDom} has no MX records — mail will bounce, which hurts your sender reputation` });
  if (recipDisposable) recipFlags.push({ id: 'recipient-disposable', severity: 'medium', note: `${toDom} is a disposable/throwaway domain` });

  const linkFindings = deliver.links.slice(0, 10)
    .map((u) => { const a = analyzeUrl(u); return { url: u.slice(0, 200), host: a.host, score: a.score, flags: a.flags.map((f) => f.id) }; })
    .filter((l) => l.score > 0).sort((a, b) => b.score - a.score);
  const maxLink = linkFindings.reduce((m, l) => Math.max(m, l.score), 0);

  let score = 0;
  if (leak.verdict === 'block') score += 60; else if (leak.verdict === 'review') score += 25;
  score += Math.min(40, deliver.score);
  score += recipFlags.reduce((s, f) => s + (f.severity === 'high' ? 25 : 12), 0);
  score += Math.min(20, Math.round(maxLink * 0.25));
  score = Math.min(100, score);

  const verdict = (leak.verdict === 'block' || score >= 50) ? 'block' : score >= 25 ? 'review' : 'allow';
  const risk = score >= 60 ? 'critical' : score >= 35 ? 'high' : score >= 15 ? 'medium' : score > 0 ? 'low' : 'none';

  const reasons = [];
  if (leak.secrets) reasons.push(`${leak.secrets} secret(s) in body`);
  if (leak.pii) reasons.push(`${leak.pii} PII item(s)`);
  if (deliver.flags.length) reasons.push('deliverability: ' + deliver.flags.map((f) => f.id).join(', '));
  recipFlags.forEach((f) => reasons.push(f.id));

  return sendJson(res, 200, {
    ok: true, verdict, risk, score,
    leak: { found: leak.found, secrets: leak.secrets, pii: leak.pii, findings: leak.findings, redacted: leak.redacted.length > 2000 ? leak.redacted.slice(0, 2000) + '…' : leak.redacted },
    deliverability: { score: deliver.score, flags: deliver.flags, linkCount: deliver.links.length },
    recipient: { to: p.to.email || undefined, domain: toDom || undefined, disposable: recipDisposable, hasMx: recipAuth ? recipAuth.mx.length > 0 : undefined, flags: recipFlags },
    links: linkFindings,
    reasons,
    advice: verdict === 'block'
      ? 'Do NOT send. ' + (leak.verdict === 'block' ? 'It contains secrets/PII — redact and re-check. ' : '') + 'Fix the flagged issues first.'
      : verdict === 'review' ? 'Review before sending — content/deliverability risk could hurt your sender reputation.' : 'Looks safe to send.',
    ms: Date.now() - started,
  });
};
