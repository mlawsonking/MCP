// check-ip — IP reputation: Tor exit, ASN/org (Team Cymru), reverse DNS, datacenter, blocklist → verdict.
// GET /api/check-ip?ip=1.2.3.4
const net = require('net');
const { sendJson, handleOptions, isPrivateIp } = require('../lib/common.js');
const { torExitSet, asnLookup, reverseDns, dnsblCheck } = require('../lib/safety.js');

const DC = /(amazon|aws|google|microsoft|azure|digitalocean|ovh|hetzner|linode|akamai|fastly|vultr|cloudflare|oracle|alibaba|tencent|leaseweb|contabo|choopa|m247|hosting|datacenter|colo|server)/i;

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;
  const started = Date.now();
  const ip = String((req.query && req.query.ip) || '').trim();
  if (!ip || !net.isIP(ip)) return sendJson(res, 400, { ok: false, error: 'Missing or invalid ?ip=' });

  const priv = isPrivateIp(ip);
  const [torSet, asn, rdns, dnsbl] = await Promise.all([torExitSet(), asnLookup(ip), reverseDns(ip), dnsblCheck(ip)]);
  const tor = torSet ? torSet.has(ip) : null;

  const flags = [];
  let score = 0;
  if (priv) flags.push('private-or-reserved');
  if (tor) { score += 40; flags.push('tor-exit-node'); }
  if (dnsbl.listed === true) { score += 40; flags.push('on-spamhaus-blocklist'); }
  const org = (asn && asn.org) || '';
  const datacenter = DC.test(org);
  if (datacenter) { score += 10; flags.push('datacenter-hosting'); }

  score = Math.min(100, score);
  const verdict = score >= 40 ? 'high-risk' : score >= 15 ? 'caution' : 'low-risk';
  return sendJson(res, 200, {
    ok: true, ip, private: priv, tor_exit: tor, blocklist: dnsbl,
    asn: asn || undefined, reverse_dns: rdns, datacenter, score, verdict, flags, ms: Date.now() - started,
  });
};
