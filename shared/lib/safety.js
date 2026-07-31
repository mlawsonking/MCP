// Detection rulesets — the API-facing surface over the agent-guards core.
//
// The rules themselves no longer live here. Source of truth is `agent-guards/engines/`; this file
// re-exports it under the names the six APIs already import, so nothing in api/ had to change when
// the engines moved. Add a rule in the core, not here.
//
// The `./core/...` paths resolve in the DESTINATION, not here: `scripts/sync-shared.js` copies this
// file to `<product>/lib/safety.js` and the core to `<product>/lib/core/`, so they end up siblings.
// This file is a template and is not itself requireable from shared/lib.

const injection = require('./core/engines/injection');
const secrets = require('./core/engines/secrets');
const url = require('./core/engines/url');
const { RULES_VERSION } = require('./core/lib/version');

// Names kept exactly as the APIs import them.
const scanInjection = injection.scan;
const scanSecrets = secrets.scan;
const analyzeUrl = url.analyze;
const { luhn, maskSecret, SECRET_RULES, PII_RULES } = secrets;
const { INJECTION_RULES, OBFUSCATION_SIGNAL_IDS } = injection;
const { torExitSet, asnLookup, reverseDns, dnsblCheck, getDomainAgeDays } = url;

const RULESET_INFO = {
  version: RULES_VERSION,
  injection: { rules: INJECTION_RULES.length, obfuscation_signals: OBFUSCATION_SIGNAL_IDS.length, ids: INJECTION_RULES.map((r) => r.id) },
  secrets: { rules: SECRET_RULES.length, ids: SECRET_RULES.map((r) => r.id) },
  pii: { rules: PII_RULES.length, ids: PII_RULES.map((r) => r.id) },
};

module.exports = {
  scanInjection, scanSecrets, analyzeUrl, luhn, maskSecret,
  torExitSet, asnLookup, reverseDns, dnsblCheck, getDomainAgeDays,
  RULES_VERSION, RULESET_INFO, INJECTION_RULES, SECRET_RULES, PII_RULES, OBFUSCATION_SIGNAL_IDS,
};
