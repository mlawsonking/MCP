// URL and IP analysis.
//
// `analyze` is local and structural: it reads the URL itself and says what is odd about its shape.
// Everything below it is cloud intel — reputation data we do not have on the machine — and each one
// says so, so a caller running offline can tell the difference between "checked, nothing found" and
// "could not check".

const net = require('net');
const dns = require('dns').promises;
const { RULES_VERSION } = require('../lib/version');
const { safeFetch, isPrivateIp } = require('../lib/net');

const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'gq', 'tk', 'ml', 'cf', 'work', 'click', 'link', 'country', 'kim', 'review', 'loan', 'date', 'racing', 'stream', 'win', 'bid', 'rest', 'cam', 'quest']);
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 'bl.ink']);
const BRANDS = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'instagram', 'coinbase', 'binance', 'metamask', 'wellsfargo', 'chase', 'bankofamerica'];

// Structural analysis of a URL. Local, deterministic, no lookups.
function analyze(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch {
    // The invalid path used to drop `rules_version`, so /api/check-url on garbage returned a
    // response missing a field the valid path always had. Same ruleset ran either way; say so.
    return { valid: false, flags: [{ id: 'invalid-url', severity: 'high' }], score: 40, rules_version: RULES_VERSION };
  }
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
  return { valid: true, host, tld, flags, score, rules_version: RULES_VERSION };
}

// ---------- Cloud intel. Each of these needs the network and each says when it could not run. ----------

function revIp(ip) { return ip.split('.').reverse().join('.'); }

let _torCache = { set: null, at: 0 };
async function torExitSet() {
  if (_torCache.set && Date.now() - _torCache.at < 3600_000) return _torCache.set;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 6000);
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
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 6000);
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: ctrl.signal, headers: { Accept: 'application/rdap+json' } });
    clearTimeout(t);
    if (!r.ok) return undefined;
    const j = await r.json();
    const reg = (j.events || []).find((e) => e.eventAction === 'registration');
    if (!reg) return undefined;
    return Math.floor((Date.now() - new Date(reg.eventDate)) / 86400000);
  } catch { return undefined; }
}

const INFO = {
  version: RULES_VERSION,
  local: ['analyze'],
  cloud: ['torExitSet (check.torproject.org)', 'asnLookup (Team Cymru DNS)', 'reverseDns', 'dnsblCheck (Spamhaus ZEN)', 'getDomainAgeDays (rdap.org)'],
  limits: 'Structural analysis only. A brand-new domain with a clean shape scores clean; reputation needs the cloud checks.',
};

module.exports = {
  analyze, safeFetch, isPrivateIp,
  torExitSet, asnLookup, reverseDns, dnsblCheck, getDomainAgeDays,
  SUSPICIOUS_TLDS, SHORTENERS, BRANDS, INFO, RULES_VERSION,
};
