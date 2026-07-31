// agent-guards core — the detection engines behind Package Guard, Agent Firewall, Payment Guard,
// Email Guard, Code Guard and Agent Web Tools.
//
// Everything here is deterministic: rules, lists and parsers. No model is called anywhere in a
// detection path, so the same input gives the same verdict and every verdict can name the rule that
// produced it.
//
// Engines split into two kinds and the split matters:
//
//   LOCAL   injection, secrets, code, url.analyze — pattern and structure work that runs on the
//           machine with no network. These work offline, always.
//   CLOUD   packages (OSV, npm, PyPI), payments (OFAC lists, scam lists, RPC, honeypot.is),
//           email.checkDomainAuth / isDisposable (DNS, disposable list), url reputation helpers.
//           These need the network. Offline they must say what they could not check — never answer
//           "safe" from an absent lookup.

const injection = require('./engines/injection');
const secrets = require('./engines/secrets');
const code = require('./engines/code');
const packages = require('./engines/packages');
const email = require('./engines/email');
const payments = require('./engines/payments');
const ens = require('./engines/ens');
const url = require('./engines/url');

const net = require('./lib/net');
const verdict = require('./lib/verdict');
const { RULES_VERSION, CODE_RULES_VERSION } = require('./lib/version');

// What each engine needs to do its job, in one machine-readable place. The MCP server uses this to
// mark cloud tools in their descriptions and to explain what --offline costs.
const CAPABILITIES = {
  injection: { local: true, cloud: [] },
  secrets: { local: true, cloud: [] },
  code: { local: true, cloud: [] },
  url: { local: true, cloud: ['rdap.org (domain age)', 'Team Cymru (ASN)', 'Spamhaus ZEN (blocklist)', 'check.torproject.org (exit list)'] },
  packages: { local: true, cloud: ['registry.npmjs.org', 'pypi.org', 'api.osv.dev (vulnerabilities)'] },
  email: { local: true, cloud: ['DNS (SPF/DMARC/MX)', 'disposable-email-domains list'] },
  payments: { local: true, cloud: ['OFAC sanctioned-address lists', 'ethereum-lists + ScamSniffer blocklists', 'public EVM RPC', 'honeypot.is'] },
};

module.exports = {
  injection,
  secrets,
  code,
  packages,
  email,
  payments,
  ens,
  url,

  // Shared internals, exported because the API layer and the MCP server both need them.
  safeFetch: net.safeFetch,
  isPrivateIp: net.isPrivateIp,
  Checks: verdict.Checks,
  stamp: verdict.stamp,
  summarize: verdict.summarize,

  CAPABILITIES,
  RULES_VERSION,
  CODE_RULES_VERSION,
};
