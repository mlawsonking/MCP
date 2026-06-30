// Email Guard — email-specific helpers. Deterministic, no LLM. Built-in dns/net/fetch only.
// Reuses agent-firewall engine (scanInjection / scanSecrets / analyzeUrl / dnsblCheck / getDomainAgeDays).
const dns = require('dns').promises;

// ---------- parsing ----------
function parseHeaders(block) {
  const out = {};
  const unfolded = String(block).replace(/\r?\n[ \t]+/g, ' '); // RFC822 line unfolding
  for (const line of unfolded.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i > 0) { const k = line.slice(0, i).trim().toLowerCase(); const v = line.slice(i + 1).trim(); out[k] = out[k] ? out[k] + ' ' + v : v; }
  }
  return out;
}

function parseAddress(str) {
  if (!str) return { display: '', email: '', domain: '' };
  str = String(str).trim();
  const m = str.match(/<([^>]+)>/);
  const email = (m ? m[1] : str).trim().toLowerCase().replace(/^mailto:/, '');
  const display = (m ? str.slice(0, m.index).trim() : '').replace(/^"|"$/g, '').trim();
  const domain = (email.split('@')[1] || '').toLowerCase().replace(/[>,;\s].*$/, '');
  return { display, email: /@/.test(email) ? email : '', domain };
}

function parseEmail(input) {
  let headers = {}, body = '', html = '', raw = '';
  if (typeof input === 'string') {
    raw = input;
    const idx = input.search(/\r?\n\r?\n/);
    headers = parseHeaders(idx >= 0 ? input.slice(0, idx) : input);
    body = idx >= 0 ? input.slice(idx).trim() : '';
  } else if (input && typeof input === 'object') {
    const hsrc = input.headers || {};
    for (const k in hsrc) headers[k.toLowerCase()] = hsrc[k];
    if (input.from) headers.from = input.from;
    if (input.to) headers.to = input.to;
    if (input.subject) headers.subject = input.subject;
    if (input.replyTo || input['reply-to']) headers['reply-to'] = input.replyTo || input['reply-to'];
    if (input.returnPath || input['return-path']) headers['return-path'] = input.returnPath || input['return-path'];
    body = input.body || input.text || '';
    html = input.html || '';
  }
  const from = parseAddress(headers.from);
  const replyTo = parseAddress(headers['reply-to']);
  const returnPath = parseAddress(headers['return-path']);
  const to = parseAddress(headers.to);
  const subject = headers.subject || '';
  const combined = [subject, body, html].filter(Boolean).join('\n');
  return { headers, from, replyTo, returnPath, to, subject, body, html, combined, raw };
}

// Authentication-Results header (added by the receiving server) is the most reliable inbound signal.
function parseAuthResults(h) {
  if (!h) return null;
  const g = (k) => { const m = String(h).match(new RegExp('\\b' + k + '\\s*=\\s*(pass|fail|softfail|hardfail|neutral|none|temperror|permerror|bestguesspass)', 'i')); return m ? m[1].toLowerCase() : null; };
  const r = { spf: g('spf'), dkim: g('dkim'), dmarc: g('dmarc') };
  return (r.spf || r.dkim || r.dmarc) ? r : null;
}

// ---------- domain auth via DNS ----------
async function checkDomainAuth(domain) {
  domain = String(domain || '').toLowerCase();
  const out = { domain, spf: { present: false }, dmarc: { present: false, policy: null }, mx: [] };
  if (!domain) return out;
  try {
    const flat = (await dns.resolveTxt(domain)).map((r) => r.join(''));
    const spf = flat.find((r) => /^v=spf1/i.test(r.trim()));
    if (spf) out.spf = { present: true, qualifier: (spf.match(/([-~?+])all\b/) || [])[1] || null, record: spf.slice(0, 220) };
  } catch {}
  try {
    const flat = (await dns.resolveTxt(`_dmarc.${domain}`)).map((r) => r.join(''));
    const d = flat.find((r) => /v=DMARC1/i.test(r));
    if (d) out.dmarc = { present: true, policy: ((d.match(/\bp\s*=\s*(none|quarantine|reject)/i) || [])[1] || 'none').toLowerCase(), record: d.slice(0, 220) };
  } catch {}
  try { out.mx = (await dns.resolveMx(domain)).sort((a, b) => a.priority - b.priority).map((m) => m.exchange).slice(0, 5); } catch {}
  return out;
}

// ---------- disposable / throwaway domains ----------
const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org', 'throwawaymail.com', 'yopmail.com', 'getnada.com', 'trashmail.com', 'sharklasers.com', 'grr.la', 'guerrillamail.info', 'maildrop.cc', 'dispostable.com', 'fakeinbox.com', 'mintemail.com', 'mohmal.com', 'emailondeck.com', 'spamgourmet.com', 'tempinbox.com', '33mail.com', 'mailnesia.com', 'tempr.email', 'discard.email', 'mailcatch.com', 'tempmailo.com', '1secmail.com', 'moakt.com', 'burnermail.io', 'spambog.com', 'minuteinbox.com', 'email-temp.com', 'mail7.io', 'fakemail.net', 'tmpmail.org', 'getairmail.com', 'inboxkitten.com']);
let _disp = { set: null, at: 0 };
async function disposableSet() {
  if (_disp.set && Date.now() - _disp.at < 6 * 3600_000) return _disp.set;
  try {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 6000);
    const r = await fetch('https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf', { signal: ctrl.signal });
    clearTimeout(t);
    if (r.ok) { const set = new Set(DISPOSABLE); (await r.text()).split(/\r?\n/).forEach((d) => { d = d.trim().toLowerCase(); if (d && !d.startsWith('#')) set.add(d); }); _disp = { set, at: Date.now() }; return set; }
  } catch {}
  return DISPOSABLE;
}
async function isDisposable(domain) { return (await disposableSet()).has(String(domain || '').toLowerCase()); }

// ---------- sender risk (spoofing / impersonation) ----------
const BRANDS_EMAIL = ['paypal', 'apple', 'microsoft', 'office365', 'google', 'gmail', 'amazon', 'netflix', 'facebook', 'instagram', 'coinbase', 'binance', 'metamask', 'wellsfargo', 'chase', 'bankofamerica', 'docusign', 'dropbox', 'linkedin', 'usps', 'fedex', 'dhl', 'irs', 'stripe'];
function senderRisk(p) {
  const flags = []; let score = 0;
  const add = (id, sev, w, note) => { flags.push({ id, severity: sev, note }); score += w; };
  const fromDom = p.from.domain;
  if (p.replyTo.domain && fromDom && p.replyTo.domain !== fromDom) add('replyto-mismatch', 'medium', 18, `Reply-To ${p.replyTo.domain} ≠ From ${fromDom}`);
  if (p.returnPath.domain && fromDom && p.returnPath.domain !== fromDom) add('returnpath-mismatch', 'medium', 14, `Return-Path ${p.returnPath.domain} ≠ From ${fromDom}`);
  const dispEmail = (p.from.display.match(/[\w.+-]+@[\w.-]+\.\w{2,}/) || [])[0];
  if (dispEmail && dispEmail.toLowerCase() !== p.from.email) add('display-name-spoof', 'high', 26, `display name shows ${dispEmail} but sender is ${p.from.email || 'unknown'}`);
  const disp = p.from.display.toLowerCase();
  for (const b of BRANDS_EMAIL) { if (disp.includes(b) && fromDom && !fromDom.includes(b)) { add('brand-impersonation', 'high', 28, `claims "${b}" but domain is ${fromDom}`); break; } }
  return { flags, score: Math.min(100, score), fromDomain: fromDom };
}

// ---------- deliverability / spam heuristics (outbound) ----------
const SPAM_WORDS = /\b(act now|limited time|urgent|guarantee[d]?|risk[- ]?free|no obligation|congratulations|winner|click here|buy now|order now|earn \$|make money fast|work from home|double your|wire transfer|lottery|claim your prize|100% free|free access|cash bonus|investment opportunity|miracle|viagra|weight loss)\b/gi;
function extractLinks(text) {
  const t = String(text || ''); const out = new Set(); let m;
  const href = /href\s*=\s*["']([^"']+)["']/gi; while ((m = href.exec(t))) out.add(m[1]);
  const bare = /\bhttps?:\/\/[^\s"'<>)\]]+/gi; while ((m = bare.exec(t))) out.add(m[0]);
  return [...out].filter((u) => /^https?:\/\//i.test(u)).slice(0, 25);
}
function deliverabilityScan(p) {
  const flags = []; let score = 0;
  const add = (id, sev, w, note) => { flags.push({ id, severity: sev, note }); score += w; };
  const subj = p.subject || '';
  const text = [subj, p.body, p.html].filter(Boolean).join('\n');
  const hits = [...new Set((text.match(SPAM_WORDS) || []).map((s) => s.toLowerCase()))];
  if (hits.length) add('spam-trigger-words', 'medium', Math.min(30, hits.length * 6), `${hits.length} spammy phrase(s): ${hits.slice(0, 5).join(', ')}`);
  if (subj && subj === subj.toUpperCase() && /[A-Z]{4,}/.test(subj)) add('all-caps-subject', 'low', 10, 'subject is ALL CAPS');
  const excl = (subj.match(/!/g) || []).length; if (excl >= 2) add('excessive-exclamation', 'low', 8, `${excl} "!" in subject`);
  const links = extractLinks(text);
  if (links.length > 8) add('many-links', 'low', 10, `${links.length} links`);
  if (p.html && !p.body) add('no-plaintext', 'low', 8, 'HTML with no plain-text part');
  const imgs = (String(p.html).match(/<img/gi) || []).length;
  const words = String(p.body || p.html || '').replace(/<[^>]+>/g, ' ').split(/\s+/).filter(Boolean).length;
  if (imgs > 0 && words < 20) add('image-heavy', 'medium', 15, 'image-heavy with little text');
  const bulk = /\b(unsubscribe|newsletter|mailing list)\b/i.test(text) || links.length > 4;
  if (bulk && !p.headers['list-unsubscribe']) add('missing-unsubscribe', 'medium', 14, 'looks bulk but no List-Unsubscribe header (CAN-SPAM / deliverability)');
  return { flags, score: Math.min(100, score), links };
}

module.exports = { parseEmail, parseAddress, parseAuthResults, checkDomainAuth, isDisposable, senderRisk, deliverabilityScan, extractLinks };
