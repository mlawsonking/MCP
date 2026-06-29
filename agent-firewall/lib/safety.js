// Agent Firewall — detection rulesets + reputation helpers. Deterministic, no LLM.
const dns = require('dns').promises;
const net = require('net');

// ---------- Prompt-injection / jailbreak detection ----------
// Each rule: weight contributes to a 0..~100 risk score. Curated; defense-in-depth, not a guarantee.
const INJECTION_RULES = [
  { id: 'ignore-previous', cat: 'instruction-override', w: 35, re: /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(all\s+)?(previous|prior|above|earlier|preceding|the\s+system)\b[^.\n]{0,20}\b(instruction|prompt|message|rule|context|direction)/i },
  { id: 'new-instructions', cat: 'instruction-override', w: 25, re: /\b(here are|follow|obey)\b[^.\n]{0,30}\b(new|the\s+real|updated|true)\b[^.\n]{0,20}\binstruction/i },
  { id: 'role-override', cat: 'role-manipulation', w: 30, re: /\b(you\s+are\s+now|from\s+now\s+on|act\s+as|pretend\s+to\s+be|roleplay\s+as|behave\s+like)\b/i },
  { id: 'dan-jailbreak', cat: 'jailbreak', w: 40, re: /\b(DAN|do\s+anything\s+now|developer\s+mode|jailbreak|unfiltered|without\s+(any\s+)?restrictions|no\s+longer\s+bound)\b/i },
  { id: 'system-prompt-exfil', cat: 'prompt-leak', w: 35, re: /\b(reveal|show|print|repeat|output|tell\s+me|what\s+(is|are))\b[^.\n]{0,30}\b(your\s+)?(system\s+prompt|initial\s+instruction|the\s+above|your\s+(instruction|rule|directive|prompt))/i },
  { id: 'exfil-action', cat: 'data-exfiltration', w: 35, re: /\b(send|post|exfiltrate|upload|leak|transmit|forward)\b[^.\n]{0,40}(https?:\/\/|to\s+the\s+(following|url|server|endpoint)|api\s+key|credential|secret|token)/i },
  { id: 'tool-poison', cat: 'tool-poisoning', w: 30, re: /\b(call|invoke|use|run|execute)\b[^.\n]{0,30}\b(tool|function|command|shell|os\.system|subprocess|eval)\b/i },
  { id: 'secret-ask', cat: 'credential-phishing', w: 20, re: /\b(give|provide|share|reveal|what\s+is)\b[^.\n]{0,25}\b(api\s*key|password|secret|access\s*token|private\s*key|credential)/i },
  { id: 'imperative-override', cat: 'instruction-override', w: 12, re: /\b(do\s+not\s+(tell|inform|warn|mention)|without\s+(telling|informing|notifying)|do\s+not\s+(refuse|decline))\b/i },
  { id: 'fake-system-tag', cat: 'prompt-injection', w: 28, re: /(<\|?(system|im_start|im_end)\|?>|\[\/?(INST|SYS|SYSTEM)\]|###\s*(system|instruction)\s*:)/i },
  { id: 'urgency-coercion', cat: 'social-engineering', w: 8, re: /\b(this\s+is\s+(urgent|critical)|you\s+must\s+(immediately|now)|or\s+(you|the\s+user)\s+will\s+be)\b/i },
];

const ZERO_WIDTH = /[​-‍⁠﻿]/g;        // zero-width / joiners / BOM
const BIDI = /[‪-‮⁦-⁩]/g;            // bidi overrides (Trojan Source)
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;             // unicode "tag" block (invisible smuggling)
const HIDDEN_HTML = /(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*#?(fff(fff)?|white)\b|opacity\s*:\s*0)/i;
const HTML_COMMENT_INSTR = /<!--[^>]*\b(ignore|instruction|system|assistant|you\s+are)\b/i;

function scanInjection(text) {
  const t = String(text || '');
  const findings = [];
  let score = 0;
  for (const r of INJECTION_RULES) {
    const m = t.match(r.re);
    if (m) { score += r.w; findings.push({ id: r.id, category: r.cat, weight: r.w, match: m[0].slice(0, 120) }); }
  }
  // Obfuscation signals
  const zw = (t.match(ZERO_WIDTH) || []).length;
  if (zw) { const w = Math.min(30, 10 + zw); score += w; findings.push({ id: 'zero-width-chars', category: 'obfuscation', weight: w, match: `${zw} hidden char(s)` }); }
  const bidi = (t.match(BIDI) || []).length;
  if (bidi) { score += 30; findings.push({ id: 'bidi-override', category: 'obfuscation', weight: 30, match: `${bidi} bidi control char(s)` }); }
  const tags = (t.match(TAG_CHARS) || []).length;
  if (tags) { score += 35; findings.push({ id: 'unicode-tag-smuggling', category: 'obfuscation', weight: 35, match: `${tags} invisible tag char(s)` }); }
  if (HIDDEN_HTML.test(t)) { score += 20; findings.push({ id: 'hidden-html', category: 'obfuscation', weight: 20, match: 'hidden-CSS content' }); }
  if (HTML_COMMENT_INSTR.test(t)) { score += 20; findings.push({ id: 'html-comment-instruction', category: 'obfuscation', weight: 20, match: 'instruction in HTML comment' }); }

  score = Math.min(100, score);
  const risk = score >= 60 ? 'critical' : score >= 35 ? 'high' : score >= 15 ? 'medium' : findings.length ? 'low' : 'none';
  const verdict = score >= 35 ? 'block' : score >= 15 ? 'review' : 'allow';
  return { risk, score, verdict, findings, categories: [...new Set(findings.map((f) => f.category))] };
}

// ---------- Secret + PII detection ----------
const SECRET_RULES = [
  { id: 'aws-access-key', type: 'AWS Access Key ID', re: /\b((AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b/g, severity: 'critical' },
  { id: 'github-pat', type: 'GitHub Token', re: /\b((ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})\b/g, severity: 'critical' },
  { id: 'openai', type: 'OpenAI API Key', re: /\b(sk-(proj-)?[A-Za-z0-9_-]{20,})\b/g, severity: 'critical' },
  { id: 'anthropic', type: 'Anthropic API Key', re: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g, severity: 'critical' },
  { id: 'google-api', type: 'Google API Key', re: /\b(AIza[0-9A-Za-z_-]{35})\b/g, severity: 'high' },
  { id: 'slack', type: 'Slack Token', re: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g, severity: 'critical' },
  { id: 'stripe', type: 'Stripe Secret Key', re: /\b((sk|rk)_live_[0-9A-Za-z]{24,})\b/g, severity: 'critical' },
  { id: 'twilio', type: 'Twilio Key', re: /\b(SK[0-9a-fA-F]{32})\b/g, severity: 'high' },
  { id: 'npm', type: 'npm Token', re: /\b(npm_[0-9A-Za-z]{36})\b/g, severity: 'critical' },
  { id: 'jwt', type: 'JWT', re: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g, severity: 'medium' },
  { id: 'private-key', type: 'Private Key Block', re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, severity: 'critical' },
  { id: 'generic-secret', type: 'Generic Secret Assignment', re: /\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]/gi, severity: 'medium' },
];
const PII_RULES = [
  { id: 'email', type: 'Email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, severity: 'low' },
  { id: 'ssn', type: 'US SSN', re: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'high' },
  { id: 'credit-card', type: 'Credit Card', re: /\b(?:\d[ -]?){13,16}\b/g, severity: 'high', luhn: true },
];

function luhn(num) {
  const s = String(num).replace(/\D/g, '');
  if (s.length < 13 || s.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = s.length - 1; i >= 0; i--) { let d = +s[i]; if (alt) { d *= 2; if (d > 9) d -= 9; } sum += d; alt = !alt; }
  return sum % 10 === 0;
}
function maskSecret(s) { s = String(s); if (s.length <= 6) return s[0] + '****'; return s.slice(0, 3) + '*'.repeat(Math.min(12, s.length - 5)) + s.slice(-2); }

function scanSecrets(text) {
  const t = String(text || '');
  const findings = [];
  let redacted = t;
  const apply = (rules, kind) => {
    for (const r of rules) {
      r.re.lastIndex = 0; let m;
      while ((m = r.re.exec(t)) !== null) {
        const val = m[1] || m[0];
        if (r.luhn && !luhn(val)) continue;
        findings.push({ id: r.id, kind, type: r.type, severity: r.severity, preview: maskSecret(val), index: m.index });
        redacted = redacted.split(val).join(`[REDACTED:${r.type}]`);
        if (!r.re.global) break;
      }
    }
  };
  apply(SECRET_RULES, 'secret');
  apply(PII_RULES, 'pii');
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  const worst = findings.reduce((a, f) => Math.max(a, order[f.severity] || 0), 0);
  const verdict = worst >= 3 ? 'block' : worst >= 1 ? 'review' : 'allow';
  return { found: findings.length, secrets: findings.filter((f) => f.kind === 'secret').length, pii: findings.filter((f) => f.kind === 'pii').length, verdict, findings, redacted };
}

// ---------- URL safety ----------
const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'gq', 'tk', 'ml', 'cf', 'work', 'click', 'link', 'country', 'kim', 'review', 'loan', 'date', 'racing', 'stream', 'win', 'bid', 'rest', 'cam', 'quest']);
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 'bl.ink']);
const BRANDS = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'instagram', 'coinbase', 'binance', 'metamask', 'wellsfargo', 'chase', 'bankofamerica'];

function analyzeUrl(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { return { valid: false, flags: [{ id: 'invalid-url', severity: 'high' }], score: 40 }; }
  const flags = [];
  const host = u.hostname.toLowerCase();
  const labels = host.split('.');
  const tld = labels[labels.length - 1];
  let score = 0;
  const add = (id, sev, w, note) => { flags.push({ id, severity: sev, note }); score += w; };

  if (u.protocol !== 'https:') add('no-https', 'medium', 12, `scheme is ${u.protocol}`);
  if (net.isIP(host)) add('ip-as-host', 'high', 25, 'host is a raw IP address');
  if (host.includes('xn--')) add('punycode', 'high', 25, 'punycode/IDN host (possible homograph)');
  if (u.username || u.password) add('userinfo-in-url', 'high', 25, 'credentials embedded in URL');
  if (SUSPICIOUS_TLDS.has(tld)) add('suspicious-tld', 'medium', 18, `.${tld} is abuse-prone`);
  if (SHORTENERS.has(host)) add('url-shortener', 'low', 10, 'shortener hides the real destination');
  if (labels.length > 5) add('excessive-subdomains', 'medium', 15, `${labels.length} labels`);
  if (host.length > 50) add('long-host', 'low', 8, `${host.length} chars`);
  if (u.port && !['', '80', '443'].includes(u.port)) add('nonstandard-port', 'low', 8, `port ${u.port}`);
  // brand-in-subdomain lookalike: a known brand appears but is NOT the registrable domain
  const sld = labels.length >= 2 ? labels[labels.length - 2] : '';
  for (const b of BRANDS) {
    if (host.includes(b) && sld !== b) { add('brand-lookalike', 'high', 28, `mentions "${b}" but domain is "${sld}.${tld}"`); break; }
  }
  if (/[^\x00-\x7F]/.test(host)) add('non-ascii-host', 'medium', 15, 'non-ASCII characters in host');

  score = Math.min(100, score);
  return { valid: true, host, tld, flags, score };
}

// ---------- IP / domain reputation ----------
function revIp(ip) { return ip.split('.').reverse().join('.'); }

let _torCache = { set: null, at: 0 };
async function torExitSet() {
  if (_torCache.set && Date.now() - _torCache.at < 3600_000) return _torCache.set;
  try {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 6000);
    const r = await fetch('https://check.torproject.org/torbulkexitlist', { signal: ctrl.signal });
    clearTimeout(t);
    const txt = await r.text();
    const set = new Set(txt.split(/\s+/).filter((x) => net.isIPv4(x)));
    _torCache = { set, at: Date.now() };
    return set;
  } catch { return _torCache.set || null; }
}

async function asnLookup(ip) {
  if (!net.isIPv4(ip)) return null;
  try {
    const recs = await dns.resolveTxt(`${revIp(ip)}.origin.asn.cymru.com`);
    const line = recs.flat().join('');
    const [asn, prefix, country] = line.split('|').map((s) => s.trim());
    let org;
    try { const o = await dns.resolveTxt(`AS${asn}.asn.cymru.com`); org = o.flat().join('').split('|').pop().trim(); } catch {}
    return { asn: asn ? `AS${asn}` : undefined, prefix, country, org };
  } catch { return null; }
}

async function reverseDns(ip) { try { const n = await dns.reverse(ip); return n && n[0]; } catch { return undefined; } }

async function dnsblCheck(ip) {
  if (!net.isIPv4(ip)) return { listed: null, note: 'IPv4 only' };
  try {
    const a = await dns.resolve4(`${revIp(ip)}.zen.spamhaus.org`);
    // 127.255.255.x = query refused/blocked (e.g. from cloud resolvers), not a real listing
    if (a.some((x) => x.startsWith('127.255.255.'))) return { listed: null, note: 'blocklist unavailable from this network' };
    return { listed: true, codes: a };
  } catch (e) {
    if (e && e.code === 'ENOTFOUND') return { listed: false };
    return { listed: null, note: 'lookup error' };
  }
}

async function getDomainAgeDays(domain) {
  try {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 6000);
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: ctrl.signal, headers: { Accept: 'application/rdap+json' } });
    clearTimeout(t);
    if (!r.ok) return undefined;
    const j = await r.json();
    const reg = (j.events || []).find((e) => e.eventAction === 'registration');
    if (!reg) return undefined;
    return Math.floor((Date.now() - new Date(reg.eventDate)) / 86400000);
  } catch { return undefined; }
}

module.exports = { scanInjection, scanSecrets, analyzeUrl, luhn, maskSecret, torExitSet, asnLookup, reverseDns, dnsblCheck, getDomainAgeDays };
