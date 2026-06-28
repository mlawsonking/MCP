// Email validation: syntax + live MX/A DNS lookup + disposable/role/free detection.
// GET /api/validate-email?email=foo@bar.com
// No SMTP probe (that is slow, gets IPs blocked, and is abusive) — this is MX-level validation,
// the standard fast/clean check. Deterministic, free (DNS only), no external paid services.

const dns = require('dns').promises;
const { sendJson, handleOptions } = require('../lib/common.js');

const disposable = new Set(require('../data/disposable-domains.json').map((d) => d.toLowerCase()));
const roleLocals = new Set(['admin', 'administrator', 'info', 'support', 'sales', 'contact', 'billing', 'help', 'helpdesk', 'postmaster', 'webmaster', 'hostmaster', 'abuse', 'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'marketing', 'team', 'office', 'hello', 'enquiries', 'inquiries', 'careers', 'jobs', 'hr', 'press', 'media', 'security', 'privacy', 'legal', 'accounts', 'accounting', 'finance', 'service', 'services', 'newsletter', 'notifications', 'notification', 'root']);
const freeProviders = new Set(['gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'gmx.net', 'zoho.com', 'yandex.com', 'mail.com', 'mail.ru', 'fastmail.com', 'hey.com', 'tutanota.com', 'tuta.io']);
const SYNTAX = /^[^\s@"]+(\.[^\s@"]+)*@[^\s@.]+(\.[^\s@.]+)+$/;

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const q = req.query || {};
  const email = String(q.email || (req.body && req.body.email) || '').trim();
  if (!email) return sendJson(res, 400, { ok: false, error: 'Missing required ?email= parameter' });

  const validSyntax = email.length <= 254 && SYNTAX.test(email);
  const at = email.lastIndexOf('@');
  const local = at >= 0 ? email.slice(0, at) : '';
  const domain = at >= 0 ? email.slice(at + 1).toLowerCase() : '';

  let hasMx = false, hasA = false, mx = [];
  if (validSyntax && domain) {
    try { const recs = await dns.resolveMx(domain); if (recs && recs.length) { hasMx = true; mx = recs.sort((a, b) => a.priority - b.priority).slice(0, 5).map((r) => r.exchange); } } catch {}
    if (!hasMx) { try { const a = await dns.resolve4(domain).catch(() => dns.resolve6(domain)); if (a && a.length) hasA = true; } catch {} }
  }
  const acceptsMail = hasMx || hasA;
  const isDisposable = domain ? disposable.has(domain) : false;
  const isRole = local ? roleLocals.has(local.toLowerCase()) : false;
  const isFree = domain ? freeProviders.has(domain) : false;
  const deliverable = validSyntax && acceptsMail && !isDisposable;
  const score = !validSyntax ? 0 : !acceptsMail ? 0.2 : isDisposable ? 0.25 : isRole ? 0.7 : isFree ? 0.85 : 0.95;

  return sendJson(res, 200, {
    ok: true, email, valid_syntax: validSyntax, local: local || undefined, domain: domain || undefined,
    has_mx: hasMx, accepts_mail: acceptsMail, mx_records: mx.length ? mx : undefined,
    disposable: isDisposable, role_account: isRole, free_provider: isFree,
    deliverable, score, ms: Date.now() - started,
  });
};
