// check-domain-auth — SPF / DMARC / MX / domain-age / disposable posture for a sender or recipient domain.
// The deterministic "can this domain send trustworthy mail / is it real" check. GET ?domain=example.com (or an email).
const { sendJson, handleOptions } = require('../lib/common.js');
const { getDomainAgeDays } = require('../lib/safety.js');
const { checkDomainAuth, isDisposable } = require('../lib/email.js');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  let domain = (req.query && req.query.domain) || (req.body && req.body.domain) || '';
  domain = String(domain).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (domain.includes('@')) domain = domain.split('@')[1];
  if (!domain || !/\.[a-z]{2,}$/i.test(domain)) return sendJson(res, 400, { ok: false, error: 'Provide ?domain=example.com (or an email address).' });

  const [auth, disposable, ageDays] = await Promise.all([checkDomainAuth(domain), isDisposable(domain), getDomainAgeDays(domain)]);
  const notes = [];
  if (!auth.spf.present) notes.push('no SPF record');
  if (!auth.dmarc.present) notes.push('no DMARC record');
  else if (auth.dmarc.policy === 'none') notes.push('DMARC is p=none (monitoring only, not enforced)');
  if (auth.mx.length === 0) notes.push('no MX records (does not receive mail)');
  if (disposable) notes.push('disposable/throwaway domain');
  if (typeof ageDays === 'number' && ageDays < 30) notes.push(`domain only ${ageDays} days old`);

  const authPosture = (!auth.spf.present || !auth.dmarc.present || auth.dmarc.policy === 'none') ? 'weak' : 'enforced';
  return sendJson(res, 200, { ok: true, domain, spf: auth.spf, dmarc: auth.dmarc, mx: auth.mx, domainAgeDays: ageDays, disposable, authPosture, notes, ms: Date.now() - started });
};
