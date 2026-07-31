// GENERATED FILE - do not edit here. Your change will be overwritten.
// Source of truth: agent-guards/tools/firewall.js
// Regenerate: node scripts/sync-shared.js
// Agent Firewall tools. Five tools; three are fully local.
//
// Response shapes match what the hosted API returns today, field for field, because the
// agent-firewall-mcp package is a facade over this and anyone already parsing its output must keep
// working. Fields may be added, never renamed or removed.

const injection = require('../engines/injection');
const secrets = require('../engines/secrets');
const url = require('../engines/url');
const { safeFetch, isPrivateIp } = require('../lib/net');
const { unavailable } = require('./_schema');

const crypto = require('crypto');

// Datacenter/hosting orgs, used to flag an IP as infrastructure rather than a person.
const DC = /(amazon|aws|google|microsoft|azure|digitalocean|linode|ovh|hetzner|vultr|cloudflare|oracle|alibaba|tencent|contabo|scaleway|leaseweb|choopa|colocrossing)/i;

module.exports = [
  {
    name: 'scan_content',
    product: 'agent-firewall',
    description:
      'Scan untrusted text for prompt-injection patterns and Unicode obfuscation before an agent acts on it. ' +
      'Deterministic known-pattern matching plus hidden-character detection, not a classifier: novel phrasing is not covered. ' +
      'Pass text directly, or a url to fetch and scan.',
    needs: [],
    cloudWhen: 'a url argument is given (fetches that page)',
    input: {
      text: { type: 'string', optional: true, description: 'The text to scan.' },
      url: { type: 'string', optional: true, description: 'A page to fetch and scan instead of text. Fetching is SSRF-guarded.' },
    },
    async run(args, ctx) {
      const t0 = Date.now();
      let text = args.text;
      let source = 'text';
      if (!text && args.url) {
        if (ctx.offline) return unavailable('scan_content', ['the target URL'], 'offline mode: cannot fetch a URL to scan');
        const r = await safeFetch(args.url);
        if (!r.ok) return { ok: false, error: r.error || 'Could not fetch that URL', detail: r.detail };
        text = r.text;
        source = 'url';
      }
      if (!text) return { ok: false, error: 'Provide text or url' };
      const r = injection.scan(text);
      return {
        ok: true, source, length: text.length,
        risk: r.risk, score: r.score, verdict: r.verdict,
        findings: r.findings, categories: r.categories,
        rules_version: r.rules_version, ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'scan_secrets',
    product: 'agent-firewall',
    description:
      'Find API keys, tokens, private keys and PII in text and return a redacted copy with the secret VALUES removed. ' +
      'Fully local: the text never leaves the machine. Matches 22 known credential formats plus generic assignments; ' +
      'a secret in an unknown format is not detected.',
    needs: [],
    input: { text: { type: 'string', description: 'The text to scan.' } },
    async run(args) {
      const t0 = Date.now();
      const text = String(args.text || '');
      if (!text) return { ok: false, error: 'Provide text' };
      const r = secrets.scan(text);
      return {
        ok: true, length: text.length,
        found: r.found, secrets: r.secrets, pii: r.pii,
        verdict: r.verdict, findings: r.findings, redacted: r.redacted,
        rules_version: r.rules_version, ms: Date.now() - t0,
      };
    },
  },

  {
    name: 'check_url',
    product: 'agent-firewall',
    description:
      'Assess a URL before fetching or showing it: structure, lookalike brand domains, punycode, embedded credentials, ' +
      'abuse-prone TLDs, plus domain age. The structural half is local; domain age needs RDAP.',
    needs: ['rdap.org'],
    input: { url: { type: 'string', description: 'The URL to check.' } },
    async run(args, ctx) {
      const t0 = Date.now();
      const a = url.analyze(args.url);
      if (!a.valid) {
        return { ok: true, url: args.url, valid: false, verdict: 'malicious', score: a.score, flags: a.flags, rules_version: a.rules_version, ms: Date.now() - t0 };
      }
      let ageDays;
      let ageChecked = true;
      if (ctx.offline) { ageChecked = false; } else { ageDays = await url.getDomainAgeDays(a.host); if (ageDays === undefined) ageChecked = false; }
      let score = a.score;
      const flags = [...a.flags];
      if (ageDays !== undefined && ageDays < 30) { score = Math.min(100, score + 25); flags.push({ id: 'new-domain', severity: 'high', note: `registered ${ageDays} days ago` }); }
      const verdict = score >= 50 ? 'malicious' : score >= 25 ? 'suspicious' : 'safe';
      const out = {
        ok: true, url: args.url, valid: true, host: a.host,
        domain_age_days: ageDays, score, verdict, flags,
        rules_version: a.rules_version, ms: Date.now() - t0,
      };
      // Say when the age half did not run, so a clean verdict is not read as "checked everything".
      if (!ageChecked) out.checks_skipped = [{ id: 'domain-age', reason: ctx.offline ? 'offline mode' : 'RDAP lookup returned nothing' }];
      return out;
    },
  },

  {
    name: 'check_ip',
    product: 'agent-firewall',
    description:
      'Reputation for an IP address: Tor exit node, Spamhaus listing, ASN and owner, reverse DNS, datacenter or residential. ' +
      'Needs the network. Private and loopback addresses are answered locally.',
    needs: ['Team Cymru DNS', 'Spamhaus ZEN', 'check.torproject.org'],
    input: { ip: { type: 'string', description: 'IPv4 or IPv6 address.' } },
    async run(args, ctx) {
      const t0 = Date.now();
      const ip = String(args.ip || '').trim();
      if (!ip) return { ok: false, error: 'Provide ip' };
      if (isPrivateIp(ip)) {
        return { ok: true, ip, private: true, verdict: 'low-risk', flags: [{ id: 'private-address', severity: 'low' }], score: 0, ms: Date.now() - t0 };
      }
      if (ctx.offline) return unavailable('check_ip', ['Team Cymru', 'Spamhaus', 'the Tor exit list'], 'offline mode: IP reputation is entirely remote data');

      const [torSet, asn, rdns, blocklist] = await Promise.all([
        url.torExitSet(), url.asnLookup(ip), url.reverseDns(ip), url.dnsblCheck(ip),
      ]);
      const flags = [];
      let score = 0;
      const skipped = [];

      // Each of these three can fail independently, and a failure is not a clean result.
      const torExit = torSet ? torSet.has(ip) : null;
      if (torExit === null) skipped.push({ id: 'tor-exit-list', reason: 'list unavailable' });
      else if (torExit) { score += 35; flags.push({ id: 'tor-exit', severity: 'high' }); }

      if (blocklist.listed === null) skipped.push({ id: 'spamhaus', reason: blocklist.note || 'lookup failed' });
      else if (blocklist.listed) { score += 40; flags.push({ id: 'blocklisted', severity: 'high', note: (blocklist.codes || []).join() }); }

      if (!asn) skipped.push({ id: 'asn', reason: 'ASN lookup failed' });
      const datacenter = asn && asn.org ? DC.test(asn.org) : null;
      if (datacenter) { score += 10; flags.push({ id: 'datacenter', severity: 'low', note: asn.org }); }

      const verdict = score >= 40 ? 'high-risk' : score >= 15 ? 'caution' : 'low-risk';
      const out = {
        ok: true, ip, private: false, tor_exit: torExit, blocklist, asn,
        reverse_dns: rdns, datacenter, score, verdict, flags, ms: Date.now() - t0,
      };
      if (skipped.length) out.checks_skipped = skipped;
      return out;
    },
  },

  {
    name: 'check_password',
    product: 'agent-firewall',
    description:
      'Check whether a password appears in the Have I Been Pwned breach corpus. The password never leaves the machine: ' +
      'only the first 5 characters of its SHA-1 are sent (k-anonymity), and the match is done locally.',
    needs: ['api.pwnedpasswords.com'],
    input: { password: { type: 'string', description: 'The password to check. Only a 5-character hash prefix is transmitted.' } },
    async run(args, ctx) {
      const t0 = Date.now();
      const pw = String(args.password || '');
      if (!pw) return { ok: false, error: 'Provide password' };
      if (ctx.offline) return unavailable('check_password', ['api.pwnedpasswords.com'], 'offline mode: the breach corpus is remote');

      const sha1 = crypto.createHash('sha1').update(pw).digest('hex').toUpperCase();
      const prefix = sha1.slice(0, 5);
      const suffix = sha1.slice(5);
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 7000);
        const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { signal: ctrl.signal, headers: { 'Add-Padding': 'true' } });
        clearTimeout(timer);
        if (!r.ok) return unavailable('check_password', ['api.pwnedpasswords.com'], `HIBP returned HTTP ${r.status}`);
        const body = await r.text();
        let count = 0;
        for (const line of body.split('\n')) {
          const [hash, n] = line.trim().split(':');
          if (hash === suffix) { count = parseInt(n, 10) || 0; break; }
        }
        const verdict = count > 1000 ? 'severely-compromised' : count > 0 ? 'compromised' : 'safe';
        return {
          ok: true, pwned: count > 0, count, verdict,
          advice: count > 0 ? 'This password appears in known breaches. Do not use it.' : 'Not found in the breach corpus. That is not proof it is a good password.',
          ms: Date.now() - t0,
        };
      } catch (e) {
        return unavailable('check_password', ['api.pwnedpasswords.com'], String((e && e.message) || e));
      }
    },
  },
];
